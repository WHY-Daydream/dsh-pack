/**
 * v0.6.0-alpha.2 Evidence Publication contract matrix (P1–P10).
 *
 * Protocol-level tests against the HTTP mock registry: real blob uploads,
 * manifest PUTs with OCI-Subject semantics, ETag conditional pushes and the
 * standard referrers-tag fallback with concurrent-update protection.
 *
 * North-Star regressions: P2 (missing subject acceptance), P9 (preserve +
 * append), P10 (no silent lost update under conditional HTTP).
 * @module tests/evidence-publication.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { publishRemoteEvidence } from '../src/evidence/remote/publication.ts'
import { referrersTagFor } from '../src/evidence/remote/referrers.ts'
import type { RemoteSubjectDescriptor } from '../src/evidence/remote/types.ts'
import { EVIDENCE_ARTIFACT_TYPES } from '../src/evidence/remote/types.ts'
import { MockRegistry } from './helpers/mock-registry.ts'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pub-${label}-`))
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

interface PubContext {
  mock: MockRegistry
  keyFile: string
  contentHash: string
  subjectDescriptor: RemoteSubjectDescriptor
  reference: string
}

/** A mock registry + everything needed to publish one Evidence object. */
async function setupPub(mock: MockRegistry): Promise<PubContext> {
  const root = tempRoot('p')
  const keyFile = writeKey(root, 'key')
  const contentHash = digestOf(Buffer.from('artifact-a-bytes'))
  const subjectDescriptor: RemoteSubjectDescriptor = {
    mediaType: 'application/vnd.oci.image.manifest.v1+json',
    digest: 'sha256:' + 'a'.repeat(64), // the subject manifest does NOT need to exist (D160)
    size: 1234,
  }
  return { mock, keyFile, contentHash, subjectDescriptor, reference: `127.0.0.1:${mock.port}/company/prod:prod` }
}

/** Read the fallback-tag image index stored in the mock (entries by digest). */
function fallbackIndexDigests(mock: MockRegistry, tag: string): string[] {
  const stored = mock.manifests.get(tag)
  if (stored === undefined) return []
  const index = JSON.parse(stored.bytes.toString('utf8')) as { manifests?: Array<{ digest?: unknown }> }
  return (index.manifests ?? []).map((m) => String(m.digest))
}

describe('P1: native Referrers publication succeeds with OCI-Subject = M (D162)', () => {
  it('publishes a provenance referrer via the native path', async () => {
    const mock = new MockRegistry()
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'p1')

    const result = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    expect(result.mode).toBe('native-referrers')
    expect(result.subjectManifestDigest).toBe(subjectDescriptor.digest)
    expect(result.fallback).toBeUndefined()
    // the evidence manifest + its blobs are stored (no dangling carrier)
    expect(mock.manifests.has(result.evidenceManifestDigest)).toBe(true)
    expect(mock.blobs.has(digestOf(envelope))).toBe(true)
  })
})

describe('P2 ★ North-Star: subject manifest ABSENT → publication still succeeds (D160)', () => {
  it('a forward subject reference with no existing subject manifest is accepted', async () => {
    const mock = new MockRegistry()
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    // guarantee: NO manifest exists for subjectDescriptor.digest anywhere
    expect(mock.manifests.has(subjectDescriptor.digest)).toBe(false)
    const envelope = plainEnvelope(keyFile, contentHash, 'attestation', 'p2-absent-subject')

    const result = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    expect(result.mode).toBe('native-referrers')
    expect(result.evidenceManifestDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  })
})

describe('P3: blobs are uploaded BEFORE the manifest (D161)', () => {
  it('empty config / envelope / document uploads all precede the evidence manifest PUT', async () => {
    const mock = new MockRegistry()
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const document = Buffer.from(JSON.stringify({ bomFormat: 'CycloneDX', version: 1 }), 'utf8')
    const envelope = sbomEnvelope(keyFile, contentHash, document)

    const result = await publishRemoteEvidence({
      reference,
      subjectDescriptor,
      envelopeBytes: envelope,
      documentBytes: document,
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })

    const puts = mock.requests.filter((r) => r.method === 'PUT').map((r) => r.path)
    // native path ⇒ the ONLY manifest PUT is the evidence manifest
    // (its digest is URL-encoded in the path: sha256%3A<hex>)
    const manifestPutIndex = puts.findIndex((p) => p.includes('/manifests/'))
    const blobPuts = puts.filter((p) => p.includes('/blobs/'))
    expect(manifestPutIndex).toBeGreaterThanOrEqual(0)
    expect(blobPuts.length).toBeGreaterThanOrEqual(3) // empty config + envelope + document
    for (const blobPath of blobPuts) {
      expect(puts.indexOf(blobPath)).toBeLessThan(manifestPutIndex)
    }
  })
})

describe('P4: a failing payload blob upload prevents the manifest (D161 — no dangling carrier)', () => {
  it('upload failure aborts publication and the evidence manifest never appears', async () => {
    const mock = new MockRegistry()
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'p4-fail')
    mock.tamper.uploadFailDigest = digestOf(envelope) // the envelope blob upload fails

    await expect(
      publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance }),
    ).rejects.toThrow()

    // no dangling carrier: the evidence manifest must NOT have been stored
    const manifestDigest = digestOf(Buffer.from(JSON.stringify({
      schemaVersion: 2,
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      subject: subjectDescriptor,
      config: { mediaType: 'application/vnd.oci.empty.v1+json', digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a', size: 2 },
      layers: [{ mediaType: 'application/vnd.dsh.evidence.envelope.v1+json', digest: digestOf(envelope), size: envelope.length }],
    }), 'utf8'))
    expect(mock.manifests.has(manifestDigest)).toBe(false)
  })
})

describe('P5: OCI-Subject absent → standard referrers-tag fallback (D162/D163)', () => {
  it('publication falls back to the sha256-<hex> tag and appends the descriptor', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubjectOmit = true
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'p5-fallback')

    const result = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    expect(result.mode).toBe('tag-fallback')
    const tag = referrersTagFor(subjectDescriptor.digest)
    expect(result.fallback?.tag).toBe(tag)
    expect(fallbackIndexDigests(mock, tag)).toEqual([result.evidenceManifestDigest])
  })
})

describe('P6: OCI-Subject wrong value → FAIL LOUD, never fallback (D162)', () => {
  it('a mismatched OCI-Subject acknowledgement aborts publication and no fallback tag is created', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubject = 'sha256:' + 'f'.repeat(64) // registry "acknowledges" the WRONG subject
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'p6-wrong-subject')

    await expect(
      publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance }),
    ).rejects.toThrow('OCI-Subject mismatch')
    // the wrong acknowledgement must NOT have triggered a fallback
    const tag = referrersTagFor(subjectDescriptor.digest)
    expect(mock.manifests.has(tag)).toBe(false)
  })
})

describe('P7: fallback tag 404 → start from an empty index and append (D163)', () => {
  it('a fresh registry (tag absent) yields exactly one appended descriptor', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubjectOmit = true
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const tag = referrersTagFor(subjectDescriptor.digest)
    expect(mock.manifests.has(tag)).toBe(false) // 404 → empty index start
    const envelope = plainEnvelope(keyFile, contentHash, 'capability', 'p7-empty-start')

    const result = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.capability })
    expect(result.mode).toBe('tag-fallback')
    expect(fallbackIndexDigests(mock, tag)).toEqual([result.evidenceManifestDigest])
  })
})

describe('P8: fallback dedup — publishing the same evidence twice is idempotent (D163)', () => {
  it('a second publish of the SAME descriptor does not create a duplicate entry', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubjectOmit = true
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelope = plainEnvelope(keyFile, contentHash, 'provenance', 'p8-dedup')

    const first = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const second = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelope, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    expect(second.evidenceManifestDigest).toBe(first.evidenceManifestDigest)
    expect(second.mode).toBe('tag-fallback')
    expect(second.fallback?.retries).toBe(0)
    const tag = referrersTagFor(subjectDescriptor.digest)
    expect(fallbackIndexDigests(mock, tag)).toEqual([first.evidenceManifestDigest]) // exactly one entry
  })
})

describe('P9 ★ North-Star: existing referrers are PRESERVED, new one appended (D163)', () => {
  it('publishing Evidence B after Evidence A keeps A and appends B', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubjectOmit = true
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const envelopeA = plainEnvelope(keyFile, contentHash, 'provenance', 'p9-A')
    const envelopeB = plainEnvelope(keyFile, contentHash, 'attestation', 'p9-B')

    const resultA = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelopeA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    const resultB = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelopeB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const tag = referrersTagFor(subjectDescriptor.digest)
    const digests = fallbackIndexDigests(mock, tag)
    expect(digests).toContain(resultA.evidenceManifestDigest) // A preserved
    expect(digests).toContain(resultB.evidenceManifestDigest) // B appended
    expect(digests).toHaveLength(2)
  })
})

describe('P10 ★ North-Star: conditional concurrent update — no silent lost update (D164)', () => {
  it('a stale If-Match push conflicts, then re-reads, merges and retries — both writes survive', async () => {
    const mock = new MockRegistry()
    mock.tamper.ociSubjectOmit = true
    await mock.start()
    const { keyFile, contentHash, subjectDescriptor, reference } = await setupPub(mock)
    const tag = referrersTagFor(subjectDescriptor.digest)

    // writer A publishes first → tag = [A]
    const envelopeA = plainEnvelope(keyFile, contentHash, 'provenance', 'p10-A')
    const resultA = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelopeA, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    // competing writer C publishes between B's READ and B's PUSH: the hook
    // injects the [A, C] index right before B's conditional push is evaluated
    const fakeC = 'sha256:' + 'c'.repeat(64)
    mock.beforeManifestPut = (ref: string): boolean => {
      if (ref !== tag) return false // not our tag — keep the hook for the next PUT
      const indexAC = Buffer.from(JSON.stringify({
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.index.v1+json',
        manifests: [
          { digest: resultA.evidenceManifestDigest, size: 1, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance },
          { digest: fakeC, size: 1 },
        ],
      }), 'utf8')
      mock.manifests.set(tag, { bytes: indexAC, digest: digestOf(indexAC) })
      return true
    }

    // writer B publishes → its conditional push hits the injected index → 412
    // → re-read → merge [A, C, B] → conditional retry → success
    const envelopeB = plainEnvelope(keyFile, contentHash, 'attestation', 'p10-B')
    const resultB = await publishRemoteEvidence({ reference, subjectDescriptor, envelopeBytes: envelopeB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    expect(resultB.mode).toBe('tag-fallback')
    expect(resultB.fallback?.concurrencyProtection).toBe('conditional')
    expect((resultB.fallback?.retries ?? 0)).toBeGreaterThanOrEqual(1) // the 412-retry path was exercised

    const digests = fallbackIndexDigests(mock, tag)
    expect(digests).toContain(resultA.evidenceManifestDigest) // A preserved
    expect(digests).toContain(fakeC) // C preserved (competing write NOT clobbered)
    expect(digests).toContain(resultB.evidenceManifestDigest) // B appended
    expect(digests).toHaveLength(3) // nothing lost
  })
})
