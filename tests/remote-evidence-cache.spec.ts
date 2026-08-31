/**
 * v0.6.0-alpha.3 Remote Evidence Cache contract matrix (C1–C12, D166–D174).
 *
 * Protocol-level tests against the HTTP mock registry with a REAL
 * RemoteEvidenceCache on disk. North-Star regressions:
 *   C5 ★ — online stale snapshot cannot hide newly attached Evidence
 *   C7 ★ — offline cache cannot return a partial Evidence set
 *   C9 ★ — fallback mutable tag cannot be pinned by stale local cache
 *
 * Frozen semantics under test (DESIGN-v0.6.0.md):
 *   - the cache is a CONTENT-ADDRESSED BYTE store (D166): OCI objects are
 *     keyed by their OCI digest (D167), every read revalidates the digest
 *     (D172), corruption fails loud — online deletes + re-fetches the SAME
 *     immutable digest, offline FAILS.
 *   - `M` immutable does NOT make `referrers(M)` immutable (D169): online
 *     enumeration is always remote; snapshots are freshness metadata only.
 *   - snapshots are all-or-nothing (D171): only complete enumerations are
 *     stored, atomically, and an incomplete run can never overwrite a
 *     known-complete one.
 *   - offline reuse is EXPLICIT (D174): online failures never degrade to
 *     stale snapshots; offline requires a complete snapshot + complete CAS
 *     or it fails OFFLINE_CACHE_INCOMPLETE (D170).
 *   - nothing cached is ever a trust verdict (C11), and the cache executes
 *     no code (C12).
 * @module tests/remote-evidence-cache.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { RemoteEvidenceCache } from '../src/evidence/remote/cache.ts'
import { discoverRemoteEvidenceCached, discoverRemoteEvidence } from '../src/evidence/remote/discovery.ts'
import { referrersTagFor } from '../src/evidence/remote/referrers.ts'
import {
  EVIDENCE_ARTIFACT_TYPES,
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
  type RemoteEvidenceLocator,
} from '../src/evidence/remote/types.ts'
import { buildOciManifest } from '../src/image/registry/manifest.ts'
import type { MockReferrerEntry } from './helpers/mock-registry.ts'
import { MockRegistry } from './helpers/mock-registry.ts'

const EMPTY_DESCRIPTOR = {
  mediaType: 'application/vnd.oci.empty.v1+json',
  digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  size: 2,
}

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-remote-ev-cache-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** ed25519 private key PEM file for signing evidence. */
function writeKey(root: string, label: string): string {
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyFile = join(root, `${label}.pem`)
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  return keyFile
}

const digestOf = (bytes: Buffer): string => `sha256:${sha256Hex(bytes)}`

/** An evidence envelope WITHOUT a required external document. */
function plainEnvelope(keyFile: string, contentHash: string, type: string, note: string): Buffer {
  const envelope = signEvidence({
    type,
    subjectContentHash: contentHash,
    statement: { schemaVersion: 1, format: 'dsh-test', note },
    keyPath: keyFile,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** An SBOM evidence envelope whose statement REQUIRES the external document (D159). */
function sbomEnvelope(keyFile: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'sbom',
    subjectContentHash: contentHash,
    statement: {
      format: 'cyclonedx-1.7',
      specVersion: '1.7',
      mediaType: 'application/vnd.cyclonedx+json',
      sbomDigest: { algorithm: 'sha256', value: sha256Hex(document) },
    },
    keyPath: keyFile,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** The OCI Evidence carrier manifest bytes (DESIGN-v0.6.0.md §2.1). */
function carrierManifest(
  subjectDigest: string,
  envelopeBytes: Buffer,
  opts: { artifactType: string; documentBytes?: Buffer },
): Buffer {
  const layers: Array<{ mediaType: string; digest: string; size: number }> = [
    { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: digestOf(envelopeBytes), size: envelopeBytes.length },
  ]
  if (opts.documentBytes !== undefined) {
    layers.push({ mediaType: EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE, digest: digestOf(opts.documentBytes), size: opts.documentBytes.length })
  }
  return Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    artifactType: opts.artifactType,
    subject: { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: subjectDigest, size: 1234 },
    config: EMPTY_DESCRIPTOR,
    layers,
  }), 'utf8')
}

/** A minimal valid OCI agent-image manifest for the mutable tag (v0.4 DSH envelope). */
function agentManifestBytes(blobBytes: Buffer): Buffer {
  const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: 'sha256:' + 'a'.repeat(64), mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
  const manifest = buildOciManifest(
    { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: digestOf(configBytes), size: configBytes.length },
    { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: digestOf(blobBytes), size: blobBytes.length },
  )
  return Buffer.from(JSON.stringify(manifest), 'utf8')
}

/** Publish an evidence object into the mock registry (blobs + carrier + referrer entry). */
function publishEvidence(
  mock: MockRegistry,
  opts: {
    subjectDigest: string
    envelopeBytes: Buffer
    documentBytes?: Buffer
    artifactType: string
  },
): MockReferrerEntry {
  mock.blobs.set(digestOf(opts.envelopeBytes), opts.envelopeBytes)
  if (opts.documentBytes !== undefined) mock.blobs.set(digestOf(opts.documentBytes), opts.documentBytes)
  const manifest = carrierManifest(opts.subjectDigest, opts.envelopeBytes, {
    artifactType: opts.artifactType,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
  })
  const manifestDigest = digestOf(manifest)
  mock.manifests.set(manifestDigest, { bytes: manifest, digest: manifestDigest })
  const entry: MockReferrerEntry = { digest: manifestDigest, size: manifest.length, artifactType: opts.artifactType }
  mock.setReferrers(opts.subjectDigest, [...(mock.referrers.get(opts.subjectDigest) ?? []), entry])
  return entry
}

interface BasicSetup {
  mock: MockRegistry
  root: string
  keyFile: string
  contentHash: string
  subjectDigest: string
  reference: string
  cacheRoot: string
  cache: RemoteEvidenceCache
}

/** Start a mock registry + publish the mutable tag + one plain evidence + a cache. */
async function setupBasic(): Promise<BasicSetup> {
  const mock = new MockRegistry()
  await mock.start()
  const root = tempRoot('c')
  const cacheRoot = tempRoot('cas')
  const keyFile = writeKey(root, 'key')
  const cache = new RemoteEvidenceCache(cacheRoot)

  const artifactBytes = Buffer.from('artifact-a-bytes')
  const contentHash = digestOf(artifactBytes)

  const agentManifest = agentManifestBytes(artifactBytes)
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return { mock, root, keyFile, contentHash, subjectDigest, reference, cacheRoot, cache }
}

/** Count GET requests for a specific kind of object path on the mock registry. */
function countRequests(mock: MockRegistry, pathContains: string): number {
  return mock.requests.filter((r) => r.method === 'GET' && r.path.includes(pathContains)).length
}

/** The locator the cache is keyed by for a reference (D157 canonical identity). */
function locatorFor(setup: BasicSetup): RemoteEvidenceLocator {
  return { registry: '127.0.0.1:' + setup.mock.port, repository: 'company/prod', subjectManifestDigest: setup.subjectDigest }
}

// ============================================================================
// C1 — manifest CAS hit: cached valid bytes are reused, digest revalidated
// ============================================================================
describe('C1: manifest CAS hit — no blob/manifest re-download when bytes are cached and valid (D166/D167/D172)', () => {
  it('a second online run reuses the cached evidence manifest and re-verifies it', async () => {
    const s = await setupBasic()
    const envelope = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'build-receipt')
    const entry = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    const first = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(first.complete).toBe(true)
    const manifestGetsAfterFirst = countRequests(s.mock, `/manifests/${encodeURIComponent(entry.digest)}`)

    const second = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(second.complete).toBe(true)
    if (!second.complete) return
    expect(second.candidates).toHaveLength(1)
    expect(second.candidates[0]?.evidenceType).toBe('provenance')
    // the evidence manifest was served from CAS — no second remote manifest GET
    expect(countRequests(s.mock, `/manifests/${encodeURIComponent(entry.digest)}`)).toBe(manifestGetsAfterFirst)
    expect(second.cache.objectCacheHits).toBeGreaterThanOrEqual(1)
    // digest revalidation happened on the hit (a corrupt CAS entry would have failed, see C3)
    expect(second.cache.objectCacheMisses).toBeLessThan(first.cache.objectCacheMisses + 1)
  })
})

// ============================================================================
// C2 — blob CAS hit: envelope/document bytes reused, full DSH verification rerun
// ============================================================================
describe('C2: blob CAS hit — cached envelope bytes are reused but still fully re-verified (D166/D168)', () => {
  it('cached envelope + document blobs are not re-downloaded; candidates are still re-derived', async () => {
    const s = await setupBasic()
    const document = Buffer.from('{"bom":{"components":[]}}')
    const envelope = sbomEnvelope(s.keyFile, s.contentHash, document)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, documentBytes: document, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    const blobGetsAfterFirst = countRequests(s.mock, '/blobs/')

    const second = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(second.complete).toBe(true)
    if (!second.complete) return
    expect(second.candidates).toHaveLength(1)
    expect(second.candidates[0]?.evidenceType).toBe('sbom')
    expect(second.candidates[0]?.document?.bytes).toEqual(document)
    // envelope + document blobs came from CAS — no new blob GETs (the tag
    // resolution GET and referrers GET are manifests, not blobs)
    expect(countRequests(s.mock, '/blobs/')).toBe(blobGetsAfterFirst)
    expect(second.cache.objectCacheHits).toBeGreaterThanOrEqual(2)
  })
})

// ============================================================================
// C3 — corrupted manifest cache: online repairs by re-fetch, offline FAILS
// ============================================================================
describe('C3: corrupted manifest cache — fail loud, never silent repair from wrong identity (D172)', () => {
  it('online: a corrupt CAS manifest is detected, deleted and re-fetched by the same digest', async () => {
    const s = await setupBasic()
    const envelope = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'runtime-1')
    const entry = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    // populate CAS via a first online run
    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(cache.getOciObject('manifests', entry.digest)).toBeDefined()

    // C3 — corrupt the cached manifest bytes in place (address A, bytes B)
    const hex = entry.digest.split(':')[1]!
    const corruptPath = join(s.cacheRoot, 'manifests', hex.slice(0, 6), hex)
    writeFileSync(corruptPath, Buffer.from('{"corrupt":true}'))

    const result = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(1)
    expect(result.cache.corruptionRepaired).toBe(true)
    // the repaired object is the TRUE identity-A bytes (verified on the next read)
    const repaired = cache.getOciObject('manifests', entry.digest)
    expect(repaired).toBeDefined()
    expect(repaired && digestOf(repaired)).toBe(entry.digest)
  })

  it('offline: a corrupt CAS manifest FAILS OFFLINE_CACHE_INCOMPLETE — there is no trusted re-fetch source', async () => {
    const s = await setupBasic()
    const envelope = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'p1')
    const entry = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })

    const hex = entry.digest.split(':')[1]!
    writeFileSync(join(s.cacheRoot, 'manifests', hex.slice(0, 6), hex), Buffer.from('{"corrupt":true}'))

    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const result = await discoverRemoteEvidenceCached({ reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('OFFLINE_CACHE_INCOMPLETE')
    if (result.error.kind === 'OFFLINE_CACHE_INCOMPLETE') expect(result.error.reason).toBe('corrupt-object')
    // no partial candidates may ever surface (C7)
    expect('candidates' in result ? (result as { candidates: unknown[] }).candidates.length : 0).toBe(0)
  })
})

// ============================================================================
// C4 — corrupted document cache: tampered cached bytes can never replay as verified
// ============================================================================
describe('C4: corrupted document cache — cached bytes are never "previously verified" (D172/N4)', () => {
  it('online: a tampered cached SBOM document is detected via digest revalidation, deleted and re-fetched', async () => {
    const s = await setupBasic()
    const document = Buffer.from('{"bom":{"components":[]}}')
    const envelope = sbomEnvelope(s.keyFile, s.contentHash, document)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, documentBytes: document, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })

    // C4 — tamper the cached DOCUMENT bytes in place
    const docDigest = digestOf(document)
    const hex = docDigest.split(':')[1]!
    writeFileSync(join(s.cacheRoot, 'blobs', hex.slice(0, 6), hex), Buffer.from('# TAMPERED DOCUMENT\n'))

    const result = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    // the candidate document is the true bytes — the tampered ones were
    // rejected by digest revalidation, never trusted "because verified before"
    expect(result.candidates[0]?.document?.bytes).toEqual(document)
    expect(result.cache.corruptionRepaired).toBe(true)
  })

  it('offline: a tampered cached document fails OFFLINE_CACHE_INCOMPLETE — the DSH verification chain is never bypassed', async () => {
    const s = await setupBasic()
    const document = Buffer.from('{"bom":{"components":[]}}')
    const envelope = sbomEnvelope(s.keyFile, s.contentHash, document)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envelope, documentBytes: document, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })

    const docDigest = digestOf(document)
    const hex = docDigest.split(':')[1]!
    writeFileSync(join(s.cacheRoot, 'blobs', hex.slice(0, 6), hex), Buffer.from('# TAMPERED DOCUMENT\n'))

    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const result = await discoverRemoteEvidenceCached({ reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('OFFLINE_CACHE_INCOMPLETE')
    if (result.error.kind === 'OFFLINE_CACHE_INCOMPLETE') expect(result.error.reason).toBe('corrupt-object')
  })
})

// ============================================================================
// C5 ★ North-Star: online stale snapshot cannot hide newly attached Evidence
// ============================================================================
describe('C5 ★ North-Star: online discovery always re-enumerates — a snapshot never shadows newer Evidence (D169/D174)', () => {
  it('after Evidence B is attached to M, online discovery returns [A, B], never the stale snapshot [A]', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    // T0: only Evidence A exists
    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const first = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(first.complete).toBe(true)
    if (!first.complete) return
    expect(first.candidates.map((c) => c.evidenceType)).toEqual(['provenance'])
    expect(first.cache.snapshotStored).toBe(true)

    // T1: Evidence B is attached to the SAME subject M
    const envB = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'b')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const second = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(second.complete).toBe(true)
    if (!second.complete) return
    const types = second.candidates.map((c) => c.evidenceType).sort()
    expect(types).toEqual(['attestation', 'provenance'])
    // the snapshot was refreshed too — but it never CAUSED the result
    expect(second.cache.snapshotStored).toBe(true)
  })
})

// ============================================================================
// C6 — offline complete snapshot: explicit offline reuse reconstructs candidates
// ============================================================================
describe('C6: offline — explicit reuse of a complete snapshot + complete CAS (D170/D174)', () => {
  it('with the registry unreachable, an explicit offline run reconstructs [A, B] from cache, source=cached-snapshot', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    const envB = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'b')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const online = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(online.complete).toBe(true)

    // registry is now unreachable
    await s.mock.stop()
    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const offline = await discoverRemoteEvidenceCached({ reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(offline.complete).toBe(true)
    if (!offline.complete) return
    expect(offline.source).toBe('cached-snapshot')
    expect(offline.cache.mode).toBe('offline')
    expect(offline.cache.snapshotHit).toBe(true)
    expect(offline.cache.objectCacheMisses).toBe(0)
    const types = offline.candidates.map((c) => c.evidenceType).sort()
    expect(types).toEqual(['attestation', 'provenance'])
    // candidates carry the full verified subject binding even offline
    for (const c of offline.candidates) {
      expect(c.subject.contentHash).toBe(s.contentHash)
      expect(c.subject.manifestDigest).toBe(s.subjectDigest)
    }
  })
})

// ============================================================================
// C7 ★ North-Star: offline cache can never return a partial Evidence set
// ============================================================================
describe('C7 ★ North-Star: offline without a complete snapshot + complete CAS fails loud (D170/D171)', () => {
  it('no snapshot → OFFLINE_CACHE_INCOMPLETE (no-snapshot)', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)
    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const result = await discoverRemoteEvidenceCached({ reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('OFFLINE_CACHE_INCOMPLETE')
    if (result.error.kind === 'OFFLINE_CACHE_INCOMPLETE') expect(result.error.reason).toBe('no-snapshot')
  })

  it('a snapshot present but a required OCI object missing → OFFLINE_CACHE_INCOMPLETE (missing-object), no partial set', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    const envB = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'b')
    const entryA = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(cache.hasDiscoverySnapshot(locatorFor(s))).toBe(true)

    // delete ONE required manifest from the CAS — the snapshot remains complete
    const hex = entryA.digest.split(':')[1]!
    rmSync(join(s.cacheRoot, 'manifests', hex.slice(0, 6), hex))

    await s.mock.stop()
    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const result = await discoverRemoteEvidenceCached({ reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('OFFLINE_CACHE_INCOMPLETE')
    if (result.error.kind === 'OFFLINE_CACHE_INCOMPLETE') expect(result.error.reason).toBe('missing-object')
  })

  it('incomplete enumerations can never be stored as a snapshot (D171 all-or-nothing)', () => {
    const s = setupBasicSyncNoServer()
    // putDiscoverySnapshot must refuse complete:false outright
    expect(() => {
      s.cache.putDiscoverySnapshot({
        registry: s.locator.registry,
        repository: s.locator.repository,
        subjectManifestDigest: s.locator.subjectManifestDigest,
        source: 'referrers-api',
        complete: false as never, // runtime violation of the type — must still be refused
        descriptors: [],
        capturedAt: new Date().toISOString(),
      })
    }).toThrow(/incomplete/)
  })
})

/** A cache without a running registry (for pure cache-contract tests). */
function setupBasicSyncNoServer(): { cache: RemoteEvidenceCache; locator: RemoteEvidenceLocator } {
  const cacheRoot = tempRoot('c7')
  const cache = new RemoteEvidenceCache(cacheRoot)
  const locator: RemoteEvidenceLocator = { registry: '127.0.0.1:59999', repository: 'company/prod', subjectManifestDigest: 'sha256:' + 'd'.repeat(64) }
  return { cache, locator }
}

// ============================================================================
// C8 — incomplete online enumeration is never snapshotted, never overwrites
// ============================================================================
describe('C8: incomplete online enumeration — snapshot stays all-or-nothing (D171)', () => {
  it('a failed page-2 enumeration returns complete=false and leaves the known-complete snapshot untouched', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    const envB = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'b')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // T0: a complete enumeration → snapshot [A, B]
    const first = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(first.complete).toBe(true)
    const before = cache.getDiscoverySnapshot(locatorFor(s))
    expect(before?.descriptors).toHaveLength(2)

    // T1: page-1 succeeds, page-2 fails → DISCOVERY_INCOMPLETE
    s.mock.referrersPageSize = 1
    s.mock.tamper.referrersPageStatus = 500
    const second = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(second.complete).toBe(false)
    if (second.complete) return
    expect(second.error.kind).toBe('DISCOVERY_INCOMPLETE')
    expect(second.cache.snapshotStored).toBe(false)

    // the previously-known-complete snapshot is UNCHANGED (no partial overwrite)
    const after = cache.getDiscoverySnapshot(locatorFor(s))
    expect(after?.descriptors).toHaveLength(2)
    expect(after?.capturedAt).toBe(before?.capturedAt)
  })
})

// ============================================================================
// C9 ★ North-Star: fallback mutable tag cannot be pinned by stale local cache
// ============================================================================
describe('C9 ★ North-Star: fallback tag drift — online re-resolves the CURRENT fallback index (D169/N1)', () => {
  it('when the referrers-tag moves from index I1 [A] to I2 [A, B], online discovery returns [A, B]', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    // force the standard referrers-tag fallback (native API 404)
    s.mock.tamper.referrersStatus = 404
    const tag = referrersTagFor(s.subjectDigest)

    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    const entryA = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    // fallback index I1 holds [A]
    const index1 = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [{ digest: entryA.digest, size: entryA.size, artifactType: entryA.artifactType }],
    }), 'utf8')
    s.mock.manifests.set(tag, { bytes: index1, digest: digestOf(index1) })

    const first = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(first.complete).toBe(true)
    if (!first.complete) return
    expect(first.candidates.map((c) => c.evidenceType)).toEqual(['provenance'])

    // T1 — the fallback tag moves to index I2 holding [A, B]
    const envB = plainEnvelope(s.keyFile, s.contentHash, 'attestation', 'b')
    const entryB = publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    const index2 = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [
        { digest: entryA.digest, size: entryA.size, artifactType: entryA.artifactType },
        { digest: entryB.digest, size: entryB.size, artifactType: entryB.artifactType },
      ],
    }), 'utf8')
    s.mock.manifests.set(tag, { bytes: index2, digest: digestOf(index2) })

    // online MUST re-resolve the current fallback tag — the cached I1 must not pin discovery
    const second = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(second.complete).toBe(true)
    if (!second.complete) return
    const types = second.candidates.map((c) => c.evidenceType).sort()
    expect(types).toEqual(['attestation', 'provenance'])
  })
})

// ============================================================================
// C10 — snapshot cache key keeps (registry, repository, M) identity domains
// ============================================================================
describe('C10: different repository, same M — snapshot cache is isolated (D157/D167)', () => {
  it('repoA and repoB share the subject digest but never share snapshots', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)

    // repoA's discovery fills repoA's snapshot only
    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    const locatorA: RemoteEvidenceLocator = { registry: '127.0.0.1:' + s.mock.port, repository: 'company/prod', subjectManifestDigest: s.subjectDigest }
    expect(cache.getDiscoverySnapshot(locatorA)).toBeDefined()

    // same M in a different repository — different key, no snapshot
    const locatorB: RemoteEvidenceLocator = { registry: '127.0.0.1:' + s.mock.port, repository: 'other/team', subjectManifestDigest: s.subjectDigest }
    expect(cache.getDiscoverySnapshot(locatorB)).toBeUndefined()
    expect(RemoteEvidenceCache.snapshotKey(locatorA)).not.toBe(RemoteEvidenceCache.snapshotKey(locatorB))
  })

  it('offline reuse of repoA@M cannot leak into repoB@M (identity domains stay separate)', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)
    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })

    await s.mock.stop()
    // repoB offline: same M, but NO snapshot was captured for repoB → fail loud
    const repoBRef = `127.0.0.1:${s.mock.port}/other/team/prod@${s.subjectDigest}`
    const result = await discoverRemoteEvidenceCached({ reference: repoBRef, actualContentHash: s.contentHash, mode: 'offline', cache })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('OFFLINE_CACHE_INCOMPLETE')
  })
})

// ============================================================================
// C11 — trust verdicts are never cached (structural, D166)
// ============================================================================
describe('C11: trust verdict never cached — the persistence layer has no authorization fields (D166)', () => {
  it('a stored snapshot contains no trusted/allow/deny/issuerTrusted/policyVerdict fields', async () => {
    const s = await setupBasic()
    const cache = new RemoteEvidenceCache(s.cacheRoot)
    const envA = plainEnvelope(s.keyFile, s.contentHash, 'provenance', 'a')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: envA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await discoverRemoteEvidenceCached({ reference: s.reference, actualContentHash: s.contentHash, cache })
    expect(result.complete).toBe(true)
    const snapshotJson = JSON.stringify(cache.getDiscoverySnapshot(locatorFor(s)))
    const statsJson = JSON.stringify(result.complete ? result.cache : {})
    for (const forbidden of ['trusted', 'allow', 'deny', 'issuerTrusted', 'policyVerdict']) {
      // key-based check: a base64 signature could randomly contain such a
      // substring, so we check JSON OBJECT KEYS, never raw text
      expect(collectJsonKeys(snapshotJson)).not.toContain(forbidden)
      expect(collectJsonKeys(statsJson)).not.toContain(forbidden)
    }
    // every cached OCI object (manifests + blobs) is also key-checked
    for (const kind of ['manifests', 'blobs'] as const) {
      for (const file of readDirRecursive(join(s.cacheRoot, kind))) {
        const content = readFileSync(file, 'utf8')
        for (const forbidden of ['trusted', 'allow', 'deny', 'issuerTrusted', 'policyVerdict']) {
          expect(collectJsonKeys(content)).not.toContain(forbidden)
        }
      }
    }
  })
})

/** All JSON object keys in a document, recursively (for C11 structural checks). */
function collectJsonKeys(json: string): string[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return []
  }
  const keys: string[] = []
  const walk = (value: unknown): void => {
    if (Array.isArray(value)) {
      for (const item of value) walk(item)
      return
    }
    if (value !== null && typeof value === 'object') {
      for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
        keys.push(key)
        walk(child)
      }
    }
  }
  walk(parsed)
  return keys
}

/** Recursively list files under a directory (may not exist). */
function readDirRecursive(dir: string): string[] {
  const out: string[] = []
  let entries: string[]
  try {
    entries = readdirSync(dir)
  } catch {
    return out
  }
  for (const entry of entries) {
    const full = join(dir, entry)
    try {
      if (statSync(full).isDirectory()) out.push(...readDirRecursive(full))
      else out.push(full)
    } catch {
      // ignore races
    }
  }
  return out
}

// ============================================================================
// C12 — the cache never executes code (structural, D148/D165)
// ============================================================================
describe('C12: cache does not execute code — no materialization, no shell, no boot (D148/D165)', () => {
  it('the cache implementation imports no process/exec/vm primitives', async () => {
    const cacheSource = readFileSync(new URL('../src/evidence/remote/cache.ts', import.meta.url), 'utf8')
    const discoverySource = readFileSync(new URL('../src/evidence/remote/discovery.ts', import.meta.url), 'utf8')
    const typesSource = readFileSync(new URL('../src/evidence/remote/types.ts', import.meta.url), 'utf8')
    for (const [name, source] of [['cache.ts', cacheSource], ['discovery.ts', discoverySource], ['types.ts', typesSource]] as const) {
      for (const forbidden of ['child_process', 'execSync', 'spawn(', 'pnpm', 'materialize', 'vm.', 'eval(']) {
        expect(source, `${name} must not contain ${forbidden}`).not.toContain(forbidden)
      }
    }
  })
})
