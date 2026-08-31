/**
 * v0.6.0-beta.2 Registry Interoperability contract matrix (I1–I12, D183–D190).
 *
 * Protocol-level tests against the HTTP mock registry in TWO profiles
 * (D183 — capability is decided by PROTOCOL RESPONSE, never by vendor name):
 *   - 'native':        OCI 1.1 native Referrers (OCI-Subject echo, /referrers 200)
 *   - 'fallback-only': no OCI-Subject, /referrers 404, standard referrers tag
 *
 * North-Star regressions:
 *   I3 ★ — native Referrers and standard fallback → SAME DSH Evidence semantics
 *   I8/I9 ★ — real GHCR round-trip (workflow-driven; scripts/ghcr-gate)
 *   I11/I12 ★ — independent OCI client ↔ dsh-pack mutual discoverability
 *
 * The point of beta.2: dsh-pack implements the OCI PROTOCOL, not a private
 * protocol that only works against our own mock fixture.
 * @module tests/registry-interoperability.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { publishRemoteEvidence } from '../src/evidence/remote/publication.ts'
import { discoverRemoteEvidence } from '../src/evidence/remote/discovery.ts'
import { buildVerifiedEvidenceSet } from '../src/evidence/remote/trust.ts'
import { referrersTagFor } from '../src/evidence/remote/referrers.ts'
import type { RemoteSubjectDescriptor, VerifiedEvidenceSet } from '../src/evidence/remote/types.ts'
import {
  EVIDENCE_ARTIFACT_TYPES,
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
} from '../src/evidence/remote/types.ts'
import { buildOciManifest } from '../src/image/registry/manifest.ts'
import { MockRegistry, type MockRegistryProfile } from './helpers/mock-registry.ts'

const EMPTY_DESCRIPTOR = {
  mediaType: 'application/vnd.oci.empty.v1+json',
  digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  size: 2,
}

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-interop-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const digestOf = (bytes: Buffer): string => `sha256:${sha256Hex(bytes)}`

/** ed25519 private key PEM for signing evidence. */
function writeKey(root: string, label: string): string {
  const { privateKey } = generateKeyPairSync('ed25519')
  const keyFile = join(root, `${label}.pem`)
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  return keyFile
}

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

/** An SBOM envelope whose statement REQUIRES the external document (D159). */
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

/** A minimal valid OCI agent-image manifest for the mutable tag. */
function agentManifestBytes(blobBytes: Buffer): Buffer {
  const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: 'sha256:' + 'a'.repeat(64), mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
  const manifest = buildOciManifest(
    { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: digestOf(configBytes), size: configBytes.length },
    { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: digestOf(blobBytes), size: blobBytes.length },
  )
  return Buffer.from(JSON.stringify(manifest), 'utf8')
}

interface InteropContext {
  mock: MockRegistry
  keyFile: string
  contentHash: string
  subjectDigest: string
  subjectDescriptor: RemoteSubjectDescriptor
  reference: string
}

/**
 * A registry in a given PROFILE (D183) with a real agent image at :prod → M.
 * The subject manifest EXISTS so discovery can resolve the tag to M (D149).
 * `sharedKeyFile` lets two registries sign with the SAME evidence key (I3 —
 * semantic equivalence must compare identical evidence bytes).
 */
async function setupRegistry(profile: MockRegistryProfile, sharedKeyFile?: string): Promise<InteropContext> {
  const mock = new MockRegistry({ profile })
  await mock.start()
  const root = tempRoot(profile)
  const keyFile = sharedKeyFile ?? writeKey(root, 'key')

  const artifactBytes = Buffer.from('artifact-a-bytes')
  const contentHash = digestOf(artifactBytes)
  const agentManifest = agentManifestBytes(artifactBytes)
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const subjectDescriptor: RemoteSubjectDescriptor = {
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    digest: subjectDigest,
    size: agentManifest.length,
  }
  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return { mock, keyFile, contentHash, subjectDigest, subjectDescriptor, reference }
}

/** Publish one evidence object, then discover ALL evidence for the subject. */
async function publishAndDiscover(
  ctx: InteropContext,
  opts: { envelopeBytes: Buffer; artifactType: string; documentBytes?: Buffer },
): Promise<{
  publishMode: 'native-referrers' | 'tag-fallback'
  discoverySource: 'referrers-api' | 'tag-fallback'
  candidates: import('../src/evidence/remote/types.ts').RemoteEvidenceCandidate[]
}> {
  const pub = await publishRemoteEvidence({
    reference: ctx.reference,
    subjectDescriptor: ctx.subjectDescriptor,
    envelopeBytes: opts.envelopeBytes,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
    artifactType: opts.artifactType,
  })
  const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
  if (!discovery.complete) throw new Error(`discovery incomplete: ${JSON.stringify(discovery.error)}`)
  return {
    publishMode: pub.mode,
    discoverySource: discovery.candidates[0]?.source ?? 'tag-fallback',
    candidates: discovery.candidates,
  }
}

/** Normalize a discovery result into the DSH semantic evidence set (I3 comparison key). */
function semanticSet(candidates: import('../src/evidence/remote/types.ts').RemoteEvidenceCandidate[]): VerifiedEvidenceSet {
  return buildVerifiedEvidenceSet(candidates)
}

// ============================================================================
// I1 — Native round-trip: publish → native Referrers → discover → same Evidence
// ============================================================================
describe('I1: native registry round-trip — publish + discover return the SAME Evidence (D188)', () => {
  it('publishes provenance natively and discovers it back with full verification', async () => {
    const ctx = await setupRegistry('native')
    const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'i1')

    const round = await publishAndDiscover(ctx, {
      envelopeBytes: envelope,
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    expect(round.publishMode).toBe('native-referrers')
    expect(round.discoverySource).toBe('referrers-api')
    expect(round.candidates).toHaveLength(1)
    const candidate = round.candidates[0]!
    expect(candidate.evidenceType).toBe('provenance')
    // full verification ran: subject anchored to the real M, contentHash == C
    expect(candidate.subject.manifestDigest).toBe(ctx.subjectDigest)
    expect(candidate.subject.contentHash).toBe(ctx.contentHash)
    // the discovered envelope is byte-identical to what we published
    expect(Buffer.from(JSON.stringify(candidate.envelope), 'utf8').equals(envelope)).toBe(true)
  })

  it('publishes an SBOM with its required document and discovers it back', async () => {
    const ctx = await setupRegistry('native')
    const document = Buffer.from('{"bom":{"components":[]}}')
    const envelope = sbomEnvelope(ctx.keyFile, ctx.contentHash, document)

    const round = await publishAndDiscover(ctx, {
      envelopeBytes: envelope,
      documentBytes: document,
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })
    expect(round.publishMode).toBe('native-referrers')
    expect(round.candidates).toHaveLength(1)
    expect(round.candidates[0]?.evidenceType).toBe('sbom')
    expect(round.candidates[0]?.document?.bytes).toEqual(document)
  })
})

// ============================================================================
// I2 — Fallback-only round-trip: publish → referrers tag → discover → same Evidence
// ============================================================================
describe('I2: fallback-only registry round-trip — same Evidence via the standard referrers tag (D184)', () => {
  it('publishes via the client-maintained fallback and discovers it back through the tag', async () => {
    const ctx = await setupRegistry('fallback-only')
    const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'i2')

    const round = await publishAndDiscover(ctx, {
      envelopeBytes: envelope,
      artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
    })
    expect(round.publishMode).toBe('tag-fallback')
    expect(round.discoverySource).toBe('tag-fallback')
    expect(round.candidates).toHaveLength(1)
    const candidate = round.candidates[0]!
    expect(candidate.evidenceType).toBe('attestation')
    expect(candidate.subject.manifestDigest).toBe(ctx.subjectDigest)
    expect(candidate.subject.contentHash).toBe(ctx.contentHash)
    // the standard referrers-tag index actually holds the descriptor
    const tag = referrersTagFor(ctx.subjectDigest)
    expect(ctx.mock.manifests.has(tag)).toBe(true)
  })
})

// ============================================================================
// I3 ★ North-Star: native Referrers == fallback → SAME DSH Evidence semantics
// ============================================================================
describe('I3 ★ North-Star: native Referrers and standard fallback produce the SAME DSH Evidence semantics (D184/D186)', () => {
  it('the same artifact + evidence published on both profiles normalizes to the same VerifiedEvidenceSet', async () => {
    // the SAME artifact bytes and the SAME evidence (SHARED signing key),
    // published on two registries with different capabilities — only the
    // transport differs
    const native = await setupRegistry('native')
    const fallback = await setupRegistry('fallback-only', native.keyFile)

    const document = Buffer.from('{"bom":{"components":[{"type":"library","name":"x"}]}}')
    const prov = plainEnvelope(native.keyFile, native.contentHash, 'build-provenance', 'i3')
    const sbom = sbomEnvelope(native.keyFile, native.contentHash, document)

    // publish BOTH evidence objects on BOTH registries
    for (const ctx of [native, fallback]) {
      await publishRemoteEvidence({
        reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
        envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      })
      await publishRemoteEvidence({
        reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
        envelopeBytes: sbom, documentBytes: document, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
      })
    }

    // discover BOTH — transport paths differ (native API vs referrers tag)
    const nativeDiscovery = await discoverRemoteEvidence({ reference: native.reference, actualContentHash: native.contentHash })
    const fallbackDiscovery = await discoverRemoteEvidence({ reference: fallback.reference, actualContentHash: fallback.contentHash })
    expect(nativeDiscovery.complete).toBe(true)
    expect(fallbackDiscovery.complete).toBe(true)
    if (!nativeDiscovery.complete || !fallbackDiscovery.complete) return

    // the enumeration sources genuinely differ…
    expect(nativeDiscovery.candidates.every((c) => c.source === 'referrers-api')).toBe(true)
    expect(fallbackDiscovery.candidates.every((c) => c.source === 'tag-fallback')).toBe(true)

    // …but the DSH semantic evidence is IDENTICAL (I3 — the interop North-Star).
    // VerifiedEvidenceSet deliberately contains NO OCI manifestDigest / transport
    // fields, so a deep equality here proves semantic equivalence (D184/D186).
    const nativeSet = semanticSet(nativeDiscovery.candidates)
    const fallbackSet = semanticSet(fallbackDiscovery.candidates)
    expect(JSON.stringify(nativeSet)).toBe(JSON.stringify(fallbackSet))
    expect(nativeSet.provenance).toHaveLength(1)
    expect(nativeSet.sbom).toHaveLength(1)
    // the published evidence is byte-identical across registries
    expect(nativeSet.provenance[0]?.statementDigest).toBe(fallbackSet.provenance[0]?.statementDigest)
  })
})

// ============================================================================
// I4 — Pagination variance: page size must not change the final candidate set
// ============================================================================
describe('I4: pagination variance — different page sizes yield the SAME candidate set (D186/D158)', () => {
  it('one-page vs two-per-page enumeration over 4 referrers is identical', async () => {
    const ctx = await setupRegistry('native')
    for (let i = 0; i < 4; i += 1) {
      const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', `i4-${i}`)
      await publishRemoteEvidence({
        reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
        envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      })
    }

    const digestSet = (r: Awaited<ReturnType<typeof discoverRemoteEvidence>>): string[] =>
      r.complete ? r.candidates.map((c) => c.referrerManifestDigest).sort() : []

    // Registry A: everything on one page
    const onePage = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    // Registry B: two per page (Link rel=next pagination)
    ctx.mock.referrersPageSize = 2
    const paged = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })

    expect(onePage.complete).toBe(true)
    expect(paged.complete).toBe(true)
    expect(digestSet(onePage)).toHaveLength(4)
    // D186 — page size is a transport detail: the semantic candidate set is identical
    expect(digestSet(paged)).toEqual(digestSet(onePage))
  })
})

// ============================================================================
// I5 — Filter support variance: filters-applied vs ignored → DSH verification identical
// ============================================================================
describe('I5: filter support variance — a registry that ignores artifactType never weakens verification (D186/D152)', () => {
  it('with no OCI-Filters-Applied confirmation the enumeration is treated as unfiltered and EVERY candidate is verified', async () => {
    const ctx = await setupRegistry('native')
    const prov = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'i5-p')
    const att = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'i5-a')
    await publishRemoteEvidence({
      reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
      envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    await publishRemoteEvidence({
      reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
      envelopeBytes: att, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
    })

    // Registry A confirms the filter (OCI-Filters-Applied: artifactType)
    ctx.mock.tamper.referrersFiltersApplied = true
    const filtered = await discoverRemoteEvidence({
      reference: ctx.reference, actualContentHash: ctx.contentHash,
      artifactTypes: [EVIDENCE_ARTIFACT_TYPES.provenance],
    })
    expect(filtered.complete).toBe(true)
    if (!filtered.complete) return
    expect(filtered.candidates.map((c) => c.evidenceType)).toEqual(['provenance'])

    // Registry B ignores the artifactType query (no confirmation header) — the
    // client MUST treat it as an unfiltered enumeration and verify EVERY
    // candidate (alpha.1 D152 note; a filter must never become a trust assumption)
    ctx.mock.tamper.referrersFiltersApplied = false
    const unfiltered = await discoverRemoteEvidence({
      reference: ctx.reference, actualContentHash: ctx.contentHash,
      artifactTypes: [EVIDENCE_ARTIFACT_TYPES.provenance],
    })
    expect(unfiltered.complete).toBe(true)
    if (!unfiltered.complete) return
    const types = unfiltered.candidates.map((c) => c.evidenceType).sort()
    expect(types).toEqual(['attestation', 'provenance'])
    // the extra candidate was FULLY verified (subject + contentHash binding)
    for (const c of unfiltered.candidates) {
      expect(c.subject.contentHash).toBe(ctx.contentHash)
    }
  })
})

// ============================================================================
// I6 — Ordering variance: referrer order must not change semantic dedup/ambiguity
// ============================================================================
describe('I6: ordering variance — referrer order never changes the semantic result (D186/D110)', () => {
  it('three evidence objects in any order normalize to the same VerifiedEvidenceSet', async () => {
    const ctx = await setupRegistry('native')
    const prov = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'i6-p')
    const sbomDoc = Buffer.from('{"bom":{"components":[]}}')
    const sbom = sbomEnvelope(ctx.keyFile, ctx.contentHash, sbomDoc)
    const att = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'i6-a')
    await publishRemoteEvidence({ reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await publishRemoteEvidence({ reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor, envelopeBytes: sbom, documentBytes: sbomDoc, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    await publishRemoteEvidence({ reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor, envelopeBytes: att, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const entries = ctx.mock.referrers.get(ctx.subjectDigest) ?? []
    expect(entries).toHaveLength(3)

    // three different registry return orders of the same referrer set
    const orders = [
      entries,
      [entries[2]!, entries[0]!, entries[1]!],
      [entries[1]!, entries[2]!, entries[0]!],
    ]
    const sets: string[] = []
    for (const order of orders) {
      ctx.mock.setReferrers(ctx.subjectDigest, order)
      const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
      expect(discovery.complete).toBe(true)
      if (!discovery.complete) return
      sets.push(JSON.stringify(semanticSet(discovery.candidates)))
    }
    // order is a transport detail — the DSH semantic set is identical (D186/D110)
    expect(sets[1]).toBe(sets[0])
    expect(sets[2]).toBe(sets[0])
  })
})

// ============================================================================
// I7 — Auth challenge: 401 → authenticate → retry; credentials never leak
// ============================================================================
describe('I7: auth challenge — Bearer/token flow works and credentials never enter identity or logs (D185)', () => {
  it('publish + discover succeed through the 401 challenge, and no credential leaks into stored objects or request logs', async () => {
    const mock = new MockRegistry({ requireAuth: true, profile: 'native' })
    await mock.start()
    const root = tempRoot('i7')
    const keyFile = writeKey(root, 'key')
    const artifactBytes = Buffer.from('artifact-a-bytes')
    const contentHash = digestOf(artifactBytes)
    const agentManifest = agentManifestBytes(artifactBytes)
    const subjectDigest = digestOf(agentManifest)
    mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
    mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })
    const subjectDescriptor: RemoteSubjectDescriptor = {
      mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: subjectDigest, size: agentManifest.length,
    }
    const reference = `127.0.0.1:${mock.port}/company/prod:prod`
    const credentials = { username: 'interop-user', password: 'interop-super-secret-pat' }

    // without credentials the registry challenges with 401 and discovery fails
    const anon = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(anon.complete).toBe(false)

    // with credentials: 401 challenge → token fetch → retry succeeds (D185)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'i7')
    const pub = await publishRemoteEvidence({
      reference, subjectDescriptor, envelopeBytes: envelope,
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance, credentials,
    })
    expect(pub.mode).toBe('native-referrers')
    const discovery = await discoverRemoteEvidence({ reference, actualContentHash: contentHash, credentials })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(1)

    // D185 — the credential must NOT leak: never into request paths…
    for (const req of mock.requests) {
      expect(req.path).not.toContain('interop-super-secret-pat')
      expect(req.path).not.toContain('interop-user')
    }
    // …never into stored blobs/manifests…
    for (const bytes of mock.blobs.values()) {
      expect(bytes.toString('utf8')).not.toContain('interop-super-secret-pat')
    }
    for (const entry of mock.manifests.values()) {
      expect(entry.bytes.toString('utf8')).not.toContain('interop-super-secret-pat')
    }
    // …and never into the Evidence identity (subject/envelope are pure DSH facts)
    const candidate = discovery.candidates[0]!
    expect(JSON.stringify(candidate.subject)).not.toContain('interop')
    expect(JSON.stringify(candidate.envelope)).not.toContain('interop-super-secret-pat')
  })
})

// ============================================================================
// I11 ★ North-Star: an INDEPENDENT OCI client can read what dsh-pack published
// ============================================================================
/**
 * I11 — an independent OCI client (e.g. `oras discover`) must be able to see
 * the artifact relationships dsh-pack wrote. `oras` is not installed in this
 * environment, so the oracle is a STANDALONE protocol reader that uses NO
 * dsh-pack discovery/carrier code — it only speaks the raw OCI wire format
 * (JSON shapes + digest addressing), exactly like oras would.
 */
describe('I11 ★ North-Star: independent OCI reader sees dsh-pack publications (D187/D188)', () => {
  it('native publication is a standards-valid artifact manifest indexed in a standards-valid referrers index', async () => {
    const ctx = await setupRegistry('native')
    const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'i11-native')
    const pub = await publishRemoteEvidence({
      reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
      envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    expect(pub.mode).toBe('native-referrers')

    // — independent protocol read #1: the evidence manifest is a valid OCI
    // artifact manifest whose subject is exactly M (what oras discover shows) —
    const manifestEntry = ctx.mock.manifests.get(pub.evidenceManifestDigest)
    expect(manifestEntry).toBeDefined()
    const manifest = JSON.parse(manifestEntry!.bytes.toString('utf8')) as {
      schemaVersion?: unknown; mediaType?: unknown; subject?: { digest?: unknown }; config?: { mediaType?: unknown; digest?: unknown }
    }
    expect(manifest.schemaVersion).toBe(2)
    expect(manifest.mediaType).toBe('application/vnd.oci.image.manifest.v1+json')
    expect(manifest.subject?.digest).toBe(ctx.subjectDigest)
    // empty config (OCI artifact manifest shape) — the DSH validator applies later
    expect(manifest.config?.mediaType).toBe('application/vnd.oci.empty.v1+json')

    // — independent protocol read #2: GET /referrers/M returns an image index
    // containing the evidence manifest descriptor (the referrers relationship) —
    const refResponse = await ctx.mock.baseUrl !== undefined ? await rawGet(`${ctx.mock.baseUrl}/v2/company/prod/referrers/${encodeURIComponent(ctx.subjectDigest)}`) : undefined
    expect(refResponse?.status).toBe(200)
    const index = JSON.parse(refResponse?.body ?? '{}') as { manifests?: Array<{ digest?: unknown }> }
    expect(index.manifests?.map((m) => m.digest)).toContain(pub.evidenceManifestDigest)
  })

  it('fallback publication lands in a standards-valid referrers-tag image index', async () => {
    const ctx = await setupRegistry('fallback-only')
    const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'i11-fallback')
    const pub = await publishRemoteEvidence({
      reference: ctx.reference, subjectDescriptor: ctx.subjectDescriptor,
      envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
    })
    expect(pub.mode).toBe('tag-fallback')

    // the standard referrers tag holds an OCI image index (what oras discover
    // --distribution-spec v1.1-referrers-tag would read)
    const tag = referrersTagFor(ctx.subjectDigest)
    const tagEntry = ctx.mock.manifests.get(tag)
    expect(tagEntry).toBeDefined()
    const index = JSON.parse(tagEntry!.bytes.toString('utf8')) as {
      schemaVersion?: unknown; mediaType?: unknown; manifests?: Array<{ digest?: unknown }>
    }
    expect(index.schemaVersion).toBe(2)
    expect(index.mediaType).toBe('application/vnd.oci.image.index.v1+json')
    expect(index.manifests?.map((m) => m.digest)).toContain(pub.evidenceManifestDigest)
    // the evidence manifest itself is digest-addressable and subject-anchored
    const manifestEntry = ctx.mock.manifests.get(pub.evidenceManifestDigest)
    expect(manifestEntry).toBeDefined()
    const manifest = JSON.parse(manifestEntry!.bytes.toString('utf8')) as { subject?: { digest?: unknown } }
    expect(manifest.subject?.digest).toBe(ctx.subjectDigest)
  })
})

/** Minimal raw HTTP GET for the independent protocol reader (no dsh-pack client). */
async function rawGet(url: string): Promise<{ status: number; body: string }> {
  const { default: http } = await import('node:http')
  return new Promise((resolve, reject) => {
    const req = http.get(url, (res) => {
      const chunks: Buffer[] = []
      res.on('data', (c: Buffer) => chunks.push(c))
      res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }))
    })
    req.on('error', reject)
  })
}

// ============================================================================
// I12 ★ North-Star: dsh-pack reads protocol-valid EXTERNAL publications
// ============================================================================
/**
 * I12 — dsh-pack must be able to VERIFY evidence published by an INDEPENDENT
 * OCI client (e.g. oras attach), not only data it wrote itself. The carrier
 * here is hand-built from the raw OCI wire shape (NO dsh-pack carrier builder
 * is used), with DSH-compatible layers — the only contract with dsh-pack is
 * the OCI protocol + the DSH envelope/document semantics.
 */
describe('I12 ★ North-Star: dsh-pack discovers + verifies an EXTERNAL protocol-valid publication (D189)', () => {
  it('an externally-constructed carrier in a native registry is discovered and fully verified', async () => {
    const ctx = await setupRegistry('native')
    const envelope = plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'i12-external')

    // independent client publishes: blobs + a HAND-BUILT carrier manifest +
    // the referrers relationship (what oras attach would produce)
    const envelopeDigest = digestOf(envelope)
    ctx.mock.blobs.set(envelopeDigest, envelope)
    const manifestBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      subject: { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: ctx.subjectDigest, size: 1234 },
      config: EMPTY_DESCRIPTOR,
      layers: [{ mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: envelopeDigest, size: envelope.length }],
    }), 'utf8')
    const manifestDigest = digestOf(manifestBytes)
    ctx.mock.manifests.set(manifestDigest, { bytes: manifestBytes, digest: manifestDigest })
    ctx.mock.setReferrers(ctx.subjectDigest, [
      { digest: manifestDigest, size: manifestBytes.length, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance },
    ])

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(1)
    expect(discovery.candidates[0]?.evidenceType).toBe('provenance')
    // the FULL OCI→DSH verification chain ran on externally-published data:
    // OCI digest → subject == M → strict carrier → envelope → contentHash == C
    expect(discovery.candidates[0]?.subject.manifestDigest).toBe(ctx.subjectDigest)
    expect(discovery.candidates[0]?.subject.contentHash).toBe(ctx.contentHash)
  })

  it('an external fallback-only publication is discovered through the referrers tag', async () => {
    const ctx = await setupRegistry('fallback-only')
    const document = Buffer.from('{"bom":{"components":[{"type":"library","name":"external"}]}}')
    const envelope = sbomEnvelope(ctx.keyFile, ctx.contentHash, document)

    // independent client: blobs + hand-built carrier + referrers-TAG index
    const envelopeDigest = digestOf(envelope)
    const documentDigest = digestOf(document)
    ctx.mock.blobs.set(envelopeDigest, envelope)
    ctx.mock.blobs.set(documentDigest, document)
    const manifestBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
      subject: { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: ctx.subjectDigest, size: 1234 },
      config: EMPTY_DESCRIPTOR,
      layers: [
        { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: envelopeDigest, size: envelope.length },
        { mediaType: EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE, digest: documentDigest, size: document.length },
      ],
    }), 'utf8')
    const manifestDigest = digestOf(manifestBytes)
    ctx.mock.manifests.set(manifestDigest, { bytes: manifestBytes, digest: manifestDigest })
    // the external client maintains the standard referrers tag itself
    const tag = referrersTagFor(ctx.subjectDigest)
    const indexBytes = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [{ digest: manifestDigest, size: manifestBytes.length, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom }],
    }), 'utf8')
    ctx.mock.manifests.set(tag, { bytes: indexBytes, digest: digestOf(indexBytes) })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(1)
    expect(discovery.candidates[0]?.evidenceType).toBe('sbom')
    // the statement-required document was verified against the external carrier
    expect(discovery.candidates[0]?.document?.bytes).toEqual(document)
  })
})
