/**
 * v0.6.0-alpha.1 Remote Evidence Discovery contract matrix (A1–A10).
 *
 * Protocol-level tests against the HTTP mock registry (NOT function mocks):
 * real GET referrers / Link rel=next pagination / referrers-tag fallback /
 * manifest + blob fetches, with injectable protocol failures.
 *
 * North-Star regressions: A4 (contentHash binding), A7 (pagination
 * completeness), A9 (document cardinality/digest).
 * @module tests/remote-evidence-discovery.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { discoverRemoteEvidence } from '../src/evidence/remote/discovery.ts'
import {
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
  EVIDENCE_ARTIFACT_TYPES,
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
  const dir = mkdtempSync(join(tmpdir(), `dsh-remote-ev-${label}-`))
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

/**
 * Publish an evidence object into the mock registry: envelope (+ document)
 * blobs, the carrier manifest (digest-addressable), and the referrer entry.
 */
function publishEvidence(
  mock: MockRegistry,
  opts: {
    subjectDigest: string
    envelopeBytes: Buffer
    documentBytes?: Buffer
    artifactType: string
    /** Override the OCI carrier subject (foreign subject tests, A3). */
    carrierSubject?: string
    /** Override the declared referrer artifactType (lies test, A5). */
    referrerArtifactType?: string
  },
): MockReferrerEntry {
  mock.blobs.set(digestOf(opts.envelopeBytes), opts.envelopeBytes)
  if (opts.documentBytes !== undefined) mock.blobs.set(digestOf(opts.documentBytes), opts.documentBytes)
  const manifest = carrierManifest(opts.carrierSubject ?? opts.subjectDigest, opts.envelopeBytes, {
    artifactType: opts.artifactType,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
  })
  const manifestDigest = digestOf(manifest)
  mock.manifests.set(manifestDigest, { bytes: manifest, digest: manifestDigest })
  const entry: MockReferrerEntry = {
    digest: manifestDigest,
    size: manifest.length,
    ...(opts.referrerArtifactType !== undefined ? { artifactType: opts.referrerArtifactType } : { artifactType: opts.artifactType }),
  }
  mock.setReferrers(opts.subjectDigest, [...(mock.referrers.get(opts.subjectDigest) ?? []), entry])
  return entry
}

/** Start a mock registry + publish the mutable tag and one plain evidence. */
async function setupBasic(): Promise<{ mock: MockRegistry; root: string; keyFile: string; contentHash: string; subjectDigest: string; reference: string }> {
  const mock = new MockRegistry()
  await mock.start()
  const root = tempRoot('a1')
  const keyFile = writeKey(root, 'key')

  // the artifact and its immutable anchor C
  const artifactBytes = Buffer.from('artifact-a-bytes')
  const contentHash = digestOf(artifactBytes)

  // the agent image manifest at the mutable tag :prod → digest M
  const agentManifest = agentManifestBytes(artifactBytes)
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return { mock, root, keyFile, contentHash, subjectDigest, reference }
}

describe('A1: native Referrers API discovers valid Evidence', () => {
  it('a single trusted evidence object is discovered + verified via the native API', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'build-receipt')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(1)
    expect(result.candidates[0]?.source).toBe('referrers-api')
    expect(result.candidates[0]?.evidenceType).toBe('provenance')
    expect(result.candidates[0]?.subject.manifestDigest).toBe(subjectDigest)
    expect(result.candidates[0]?.subject.contentHash).toBe(contentHash)
    expect(result.rejected).toHaveLength(0)
  })
})

describe('A2: tag resolves once to M — discovery never uses the tag (D149)', () => {
  it('candidates anchor on the resolved digest; a tag-keyed referrer set is never consulted', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const envelope = plainEnvelope(keyFile, contentHash, 'sbom', 'real-sbom')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    // a tag-keyed referrer set must NEVER be consulted (a broken implementation
    // that used the tag as the discovery key would surface this evidence)
    const tagKeyEnvelope = plainEnvelope(keyFile, contentHash, 'attestation', 'should-never-appear')
    publishEvidence(mock, { subjectDigest: 'prod', envelopeBytes: tagKeyEnvelope, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    const types = result.candidates.map((c) => c.evidenceType)
    expect(types).toContain('sbom')
    expect(types).not.toContain('attestation')
    for (const c of result.candidates) expect(c.subject.manifestDigest).toBe(subjectDigest)
  })
})

describe('A3: foreign OCI subject M2 rejected (D150)', () => {
  it('an evidence carrier whose subject is a different manifest digest is rejected', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const otherDigest = 'sha256:' + 'f'.repeat(64)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'foreign')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance, carrierSubject: otherDigest })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected).toHaveLength(1)
    expect(result.rejected[0]?.reason).toContain('foreign subject')
  })
})

describe('A4 ★ North-Star: correct OCI subject, wrong DSH contentHash → reject (D150)', () => {
  it('evidence subject.contentHash C2 ≠ independently-known C1 is rejected', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const wrongContentHash = 'sha256:' + 'e'.repeat(64)
    const envelope = plainEnvelope(keyFile, wrongContentHash, 'attestation', 'wrong-anchor')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected).toHaveLength(1)
    expect(result.rejected[0]?.reason).toContain('artifact contentHash')
  })
})

describe('A5: artifactType lies — verified Envelope.type wins (D152)', () => {
  it('the candidate evidenceType comes from the envelope, not the OCI declaration', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const envelope = plainEnvelope(keyFile, contentHash, 'sbom', 'really-sbom')
    publishEvidence(mock, {
      subjectDigest,
      envelopeBytes: envelope,
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
      referrerArtifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
    })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(1)
    expect(result.candidates[0]?.evidenceType).toBe('sbom')
    expect(result.candidates[0]?.declaredArtifactType).toBe(EVIDENCE_ARTIFACT_TYPES['runtime-attestation'])
  })
})

describe('A6: filter requested, OCI-Filters-Applied absent → treated as unfiltered (D152 note)', () => {
  it('without the confirmation header the response is an unfiltered enumeration and everything is verified', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'sbom', 'sbom-1'), artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'attestation', 'att-1'), artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await discoverRemoteEvidence({
      reference,
      actualContentHash: contentHash,
      artifactTypes: [EVIDENCE_ARTIFACT_TYPES.sbom], // filter requested — mock does NOT confirm it
    })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    const types = result.candidates.map((c) => c.evidenceType)
    // unfiltered: BOTH verified candidates surface (the filter must not become a trust assumption)
    expect(types).toContain('sbom')
    expect(types).toContain('attestation')
    expect(result.candidates).toHaveLength(2)
  })
})

describe('A7 ★ North-Star: pagination — ALL pages consumed before the result (D158)', () => {
  it('a two-page referrers enumeration yields the complete candidate set', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'sbom', 'page-1-ev'), artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'attestation', 'page-2-ev'), artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    mock.referrersPageSize = 1 // force pagination: page 1 → Link rel=next → page 2

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    const types = result.candidates.map((c) => c.evidenceType).sort()
    expect(types).toEqual(['attestation', 'sbom']) // BOTH pages consumed before forming the set
  })

  it('a page-2 failure makes the whole discovery incomplete — partial page-1 results are never returned', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'sbom', 'page-1-ev'), artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    publishEvidence(mock, { subjectDigest, envelopeBytes: plainEnvelope(keyFile, contentHash, 'attestation', 'page-2-ev'), artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    mock.referrersPageSize = 1
    mock.tamper.referrersPageStatus = 500 // the Link rel=next page fails

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('DISCOVERY_INCOMPLETE')
  })
})

describe('A8: duplicate/ambiguous envelope layer → INVALID_CARRIER (D159)', () => {
  it('a carrier with TWO envelope layers is rejected', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const envelope = plainEnvelope(keyFile, contentHash, 'sbom', 'dup-envelope')
    mock.blobs.set(digestOf(envelope), envelope)
    const layers = [
      { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: digestOf(envelope), size: envelope.length },
      { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: digestOf(envelope), size: envelope.length },
    ]
    const manifest = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
      subject: { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: subjectDigest, size: 1234 },
      config: EMPTY_DESCRIPTOR,
      layers,
    }), 'utf8')
    const manifestDigest = digestOf(manifest)
    mock.manifests.set(manifestDigest, { bytes: manifest, digest: manifestDigest })
    mock.setReferrers(subjectDigest, [{ digest: manifestDigest, size: manifest.length, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom }])

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected).toHaveLength(1)
    expect(result.rejected[0]?.reason).toContain('exactly one envelope')
  })
})

describe('A9 ★ North-Star: external document cardinality + digest (D159)', () => {
  it('a statement-required document present exactly once + digest-valid → candidate with document', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const document = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1 }), 'utf8')
    const envelope = sbomEnvelope(keyFile, contentHash, document)
    publishEvidence(mock, {
      subjectDigest,
      envelopeBytes: envelope,
      documentBytes: document,
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(1)
    expect(result.candidates[0]?.document?.digest).toBe(digestOf(document))
  })

  it('a required document that is MISSING is rejected', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const document = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1 }), 'utf8')
    const envelope = sbomEnvelope(keyFile, contentHash, document)
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom }) // no document layer

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected[0]?.reason).toContain('exactly one document')
  })

  it('a required document present TWICE is rejected', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const document = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1 }), 'utf8')
    const envelope = sbomEnvelope(keyFile, contentHash, document)
    mock.blobs.set(digestOf(envelope), envelope)
    mock.blobs.set(digestOf(document), document)
    const manifest = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
      subject: { mediaType: 'application/vnd.oci.image.manifest.v1+json', digest: subjectDigest, size: 1234 },
      config: EMPTY_DESCRIPTOR,
      layers: [
        { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: digestOf(envelope), size: envelope.length },
        { mediaType: EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE, digest: digestOf(document), size: document.length },
        { mediaType: EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE, digest: digestOf(document), size: document.length },
      ],
    }), 'utf8')
    const manifestDigest = digestOf(manifest)
    mock.manifests.set(manifestDigest, { bytes: manifest, digest: manifestDigest })
    mock.setReferrers(subjectDigest, [{ digest: manifestDigest, size: manifest.length, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom }])

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected[0]?.reason).toContain('exactly one document')
  })

  it('a document whose bytes do NOT match the statement digest is rejected (N4/D120 must not reopen)', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    const claimed = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1 }), 'utf8')
    const substituted = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1, components: [{ type: 'library', name: 'evil' }] }), 'utf8')
    const envelope = sbomEnvelope(keyFile, contentHash, claimed)
    publishEvidence(mock, {
      subjectDigest,
      envelopeBytes: envelope,
      documentBytes: substituted, // bytes differ from the statement's sbomDigest
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
    expect(result.rejected[0]?.reason).toContain('document digest mismatch')
  })
})

describe('A10: referrers 404 → standard fallback; 401/403/5xx → NO fallback (D151)', () => {
  it('404 + referrers-tag image index → candidates from the tag fallback', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    mock.tamper.referrersStatus = 404
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'fallback-ev')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    // the standard fallback: an image index at the <algorithm>-<hex> tag
    const entry = mock.referrers.get(subjectDigest)![0]!
    const index = Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.index.v1+json',
      manifests: [{ digest: entry.digest, size: entry.size, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance }],
    }), 'utf8')
    const fallbackTag = `sha256-${subjectDigest.slice('sha256:'.length)}`
    mock.manifests.set(fallbackTag, { bytes: index, digest: digestOf(index) })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(1)
    expect(result.candidates[0]?.source).toBe('tag-fallback')
    expect(result.candidates[0]?.evidenceType).toBe('provenance')
  })

  it('404 + missing fallback tag → complete with no candidates (missing evidence, fail-closed at policy time)', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    mock.tamper.referrersStatus = 404 // no fallback tag published at all

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(true)
    if (!result.complete) return
    expect(result.candidates).toHaveLength(0)
  })

  it('401 → REGISTRY_ERROR, NEVER fallback', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    mock.tamper.referrersStatus = 401
    // even a complete fallback tag must NOT be consulted on a non-404
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'must-not-surface')
    publishEvidence(mock, { subjectDigest, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const entry = mock.referrers.get(subjectDigest)![0]!
    const index = Buffer.from(JSON.stringify({ schemaVersion: 2, mediaType: 'application/vnd.oci.image.index.v1+json', manifests: [{ digest: entry.digest, size: entry.size }] }), 'utf8')
    mock.manifests.set(`sha256-${subjectDigest.slice('sha256:'.length)}`, { bytes: index, digest: digestOf(index) })

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('REGISTRY_ERROR')
    expect(result.error.status).toBe(401)
  })

  it('500 → REGISTRY_ERROR, NEVER fallback', async () => {
    const { mock, root, keyFile, contentHash, subjectDigest, reference } = await setupBasic()
    mock.tamper.referrersStatus = 500

    const result = await discoverRemoteEvidence({ reference, actualContentHash: contentHash })
    expect(result.complete).toBe(false)
    if (result.complete) return
    expect(result.error.kind).toBe('REGISTRY_ERROR')
    expect(result.error.status).toBe(500)
  })
})
