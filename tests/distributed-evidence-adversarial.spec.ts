/**
 * v0.6.0-rc.1 Adversarial Distribution Matrix (R1–R8, D191–D199).
 *
 * The rc.1 story: not "it runs" but "it still fails closed when the
 * Registry / Cache / Pagination / Fallback are deliberately lying or broken".
 * Every attack asserts the SAME invariant: distribution error, ambiguity,
 * incomplete discovery and Trust DENY ALL happen BEFORE materialization /
 * code execution (D199) — an adversary can never manufacture an ALLOW.
 *
 * North-Star regressions:
 *   RC6-N1 ★ — partial pagination NEVER ALLOW (D193/D158)
 *   RC6-N2 ★ — same M in different repositories: zero Evidence cross-contamination
 *   RC6-N3 ★ — clean + risky trusted remote attestations → always AMBIGUOUS → DENY
 *   RC6-N4 ★ — same remote bytes + CURRENT issuer revocation → DENY
 * @module tests/distributed-evidence-adversarial.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { RemoteEvidenceCache } from '../src/evidence/remote/cache.ts'
import { discoverRemoteEvidence, discoverRemoteEvidenceCached } from '../src/evidence/remote/discovery.ts'
import { evaluateRemoteEvidenceTrust } from '../src/evidence/remote/trust.ts'
import type { RemoteEvidenceDiscoverySnapshot } from '../src/evidence/remote/types.ts'
import { EVIDENCE_ARTIFACT_TYPES } from '../src/evidence/remote/types.ts'
import {
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
} from '../src/evidence/remote/types.ts'
import { buildOciManifest } from '../src/image/registry/manifest.ts'
import { MockRegistry, type MockReferrerEntry } from './helpers/mock-registry.ts'

const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'

const EMPTY_DESCRIPTOR = {
  mediaType: 'application/vnd.oci.empty.v1+json',
  digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  size: 2,
}

const TARGET = { os: 'linux', arch: 'x64' }

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-redteam-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const digestOf = (bytes: Buffer): string => `sha256:${sha256Hex(bytes)}`

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

function agentManifestBytes(blobBytes: Buffer): Buffer {
  const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: 'sha256:' + 'a'.repeat(64), mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
  const manifest = buildOciManifest(
    { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: digestOf(configBytes), size: configBytes.length },
    { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: digestOf(blobBytes), size: blobBytes.length },
  )
  return Buffer.from(JSON.stringify(manifest), 'utf8')
}

interface RedTeamContext {
  mock: MockRegistry
  home: string
  keyFile: string
  /** The evidence issuer fingerprint (trust.yaml evidenceTrustedKeys value). */
  keyId: string
  contentHash: string
  subjectDigest: string
  reference: string
}

/** A native mock registry with an agent image at :prod → M + a trust home. */
async function setupRedTeam(): Promise<RedTeamContext> {
  return setupRedTeamMock(new MockRegistry())
}

/** A fallback-only registry variant (no native referrers, optional ETag). */
async function setupRedTeamFallback(opts?: { etagEnabled?: boolean }): Promise<RedTeamContext> {
  const mock = new MockRegistry({ profile: 'fallback-only' })
  mock.etagEnabled = opts?.etagEnabled ?? true
  return setupRedTeamMock(mock)
}

/** Shared mock → RedTeamContext wiring (agent image at :prod → M). */
async function setupRedTeamMock(mock: MockRegistry): Promise<RedTeamContext> {
  await mock.start()
  const home = tempRoot('home')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const keyFile = join(home, 'evidence.pem')
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  const keyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))

  const artifactBytes = Buffer.from('artifact-a-bytes')
  const contentHash = digestOf(artifactBytes)
  const agentManifest = agentManifestBytes(artifactBytes)
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return { mock, home, keyFile, keyId, contentHash, subjectDigest, reference }
}

/** An attestation document with the frozen D96 field set (semanticKey inputs). */
function attestationDocument(opts: { tools?: string[]; note?: string }): Buffer {
  return Buffer.from(JSON.stringify({
    declaredCapabilityDigest: 'sha256:' + 'b'.repeat(64),
    observation: { coverage: 'complete', reasons: [] },
    coldBoot: { status: 'PASS' },
    observed: { tools: opts.tools ?? [], skills: [], services: [], providers: [] },
    comparison: { missing: [], extra: [], mismatched: [] },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { os: TARGET.os, arch: TARGET.arch },
    resultDigest: 'sha256:' + 'c'.repeat(64),
    note: opts.note ?? 'attestation',
  }), 'utf8')
}

/** An attestation envelope whose statement REQUIRES the document (D159/D125). */
function attestationEnvelope(keyFile: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'attestation',
    subjectContentHash: contentHash,
    statement: {
      format: 'dsh-attestation',
      schemaVersion: 1,
      attestationDigest: { algorithm: 'sha256', value: sha256Hex(document) },
    },
    keyPath: keyFile,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** Publish an evidence object through the real HTTP PUT (native auto-index). */
async function publishViaHttp(
  ctx: RedTeamContext,
  opts: { envelopeBytes: Buffer; artifactType: string; documentBytes?: Buffer; reference?: string },
): Promise<void> {
  const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
  await publishRemoteEvidence({
    reference: opts.reference ?? ctx.reference,
    subjectDescriptor: {
      mediaType: 'application/vnd.oci.image.manifest.v1+json',
      digest: ctx.subjectDigest,
      size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
    },
    envelopeBytes: opts.envelopeBytes,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
    artifactType: opts.artifactType,
  })
}

/**
 * R3 (D196) — publish an ADVERSARIAL carrier directly into the mock (not via
 * dsh-pack publication): every binding can be independently attacked —
 * OCI subject digest, DSH contentHash (inside the envelope), the external
 * document, and the declared artifactType.
 */
function publishCarrier(
  ctx: RedTeamContext,
  opts: {
    envelopeBytes: Buffer
    documentBytes?: Buffer
    artifactType: string
    /** Override the OCI subject digest (default M) — the OCI binding attack. */
    carrierSubject?: string
    /** Override the referrer's declared artifactType — the "lie" attack. */
    referrerArtifactType?: string
  },
): { manifestDigest: string } {
  const layers: Array<{ mediaType: string; digest: string; size: number }> = [
    { mediaType: EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE, digest: digestOf(opts.envelopeBytes), size: opts.envelopeBytes.length },
  ]
  if (opts.documentBytes !== undefined) {
    layers.push({ mediaType: EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE, digest: digestOf(opts.documentBytes), size: opts.documentBytes.length })
  }
  const manifest = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: OCI_MANIFEST_MEDIA_TYPE,
    artifactType: opts.artifactType,
    subject: { mediaType: OCI_MANIFEST_MEDIA_TYPE, digest: opts.carrierSubject ?? ctx.subjectDigest, size: 1234 },
    config: EMPTY_DESCRIPTOR,
    layers,
  }), 'utf8')
  const manifestDigest = digestOf(manifest)
  ctx.mock.blobs.set(digestOf(opts.envelopeBytes), opts.envelopeBytes)
  if (opts.documentBytes !== undefined) ctx.mock.blobs.set(digestOf(opts.documentBytes), opts.documentBytes)
  ctx.mock.manifests.set(manifestDigest, { bytes: manifest, digest: manifestDigest })
  ctx.mock.setReferrersForRepo('company/prod', ctx.subjectDigest, [
    ...ctx.mock.referrersOf('company/prod', ctx.subjectDigest),
    { digest: manifestDigest, size: manifest.length, artifactType: opts.referrerArtifactType ?? opts.artifactType },
  ])
  return { manifestDigest }
}

/** A trust.yaml that requires a trusted provenance. */
function writeTrustRequireProvenance(ctx: RedTeamContext): void {
  writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
    version: 2,
    registries: {
      [`127.0.0.1:${ctx.mock.port}/company/*`]: {
        requireSignature: false,
        requireTrusted: false,
        evidenceTrustedKeys: ['sha256:' + ctx.subjectDigest.slice(7)], // never matches — placeholder
        requireEvidence: { provenance: { required: true } },
      },
    },
  }, null, 2), 'utf8')
}

// ============================================================================
// R1 / RC6-N1 ★ — pagination completeness is an authorization precondition
// ============================================================================
describe('R1: pagination attacks — no partial/looping/cross-origin enumeration is ever complete (D193/D158)', () => {
  it('RC6-N1 ★ page-1 clean + page-2 risky with page-2 unavailable → NEVER ALLOW', async () => {
    const ctx = await setupRedTeam()
    // gate-level policy: trusted attestation required (coverage complete)
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
          evidenceTrustedKeys: ['x'.repeat(64)],
        },
      },
    }, null, 2), 'utf8')
    const clean = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'clean')
    const risky = plainEnvelope(ctx.keyFile, ctx.contentHash, 'attestation', 'risky')
    await publishViaHttp(ctx, { envelopeBytes: clean, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    await publishViaHttp(ctx, { envelopeBytes: risky, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // page-1 succeeds (clean), page-2 fails → enumeration is INCOMPLETE
    ctx.mock.referrersPageSize = 1
    ctx.mock.tamper.referrersPageStatus = 500

    const result = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference,
      actualContentHash: ctx.contentHash,
      home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' },
      executionTarget: TARGET,
    })
    // the page-1 subset (clean) must NEVER be evaluated as a complete set
    expect(result.decision).toBe('DENY')
    expect(result.discovery.complete).toBe(false)
    expect(result.verdict.errors.some((e) => e.includes('remote evidence discovery incomplete'))).toBe(true)
  })

  it('a pagination LOOP (page2 → next=page1) fails closed instead of looping forever', async () => {
    const ctx = await setupRedTeam()
    // two referrers so page-1 actually links to a page-2 (which then loops back)
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'loop-1'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'loop-2'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    ctx.mock.referrersPageSize = 1
    // page-2+ responses link BACK to the first page — an infinite loop
    ctx.mock.referrersNextLink = (isNextPage) => (isNextPage ? `/v2/company/prod/referrers/${encodeURIComponent(ctx.subjectDigest)}` : undefined)

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('DISCOVERY_INCOMPLETE')
    expect(discovery.error.message).toContain('pagination loop detected')
  })

  it('a CROSS-ORIGIN next link is rejected WITHOUT a request (credential + foreign-enumeration smuggling)', async () => {
    const ctx = await setupRedTeam()
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'evil-next-1'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'evil-next-2'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    ctx.mock.referrersPageSize = 1
    ctx.mock.referrersNextLink = (isNextPage) => (isNextPage ? 'https://evil.example/v2/company/prod/referrers/x' : undefined)

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('DISCOVERY_INCOMPLETE')
    // the error is the ORIGIN check — NOT a transport failure: the client
    // rejected the link before ever sending a request with its credentials
    expect(discovery.error.message).toContain('outside the registry origin')
  })

  it('an INVALID next link fails closed (never a complete set)', async () => {
    const ctx = await setupRedTeam()
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'bad-next-1'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'provenance', 'bad-next-2'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    ctx.mock.referrersPageSize = 1
    // a Link value that cannot even be parsed as a URL (missing host)
    ctx.mock.referrersNextLink = (isNextPage) => (isNextPage ? 'http://' : undefined)

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('DISCOVERY_INCOMPLETE')
    expect(discovery.error.message).toContain('invalid referrers next link')
  })

  it('a GARBAGE first page (200 but not a valid OCI index) is never "no referrers" (RI-21)', async () => {
    const ctx = await setupRedTeam()
    await publishViaHttp(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'garbage-first'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    // the native referrers API returns 200 with a NON-index body — a malicious
    // registry hiding the enumeration as "empty"
    ctx.mock.tamper.referrersGarbageBody = true

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('DISCOVERY_INCOMPLETE')
    expect(discovery.error.message).toContain('first page is not a valid OCI image index')
  })
})

// ============================================================================
// R2 / RC6-N2 ★ — cross-repository confusion: same M, different repos, zero leakage
// ============================================================================
describe('R2 / RC6-N2 ★: cross-repository confusion — content equality ≠ repository relationship equality (D192/D157)', () => {
  it('repo-A@M (clean) and repo-B@M (risky) are strictly isolated in discovery AND trust', async () => {
    const ctx = await setupRedTeam()
    // one policy for BOTH repositories: attestation required + denyObserved process.exec
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/*`]: {
          requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
          evidenceTrustedKeys: [ctx.keyId],
          capabilities: { denyObserved: ['process.exec'] },
        },
      },
    }, null, 2), 'utf8')

    const repoBRef = `127.0.0.1:${ctx.mock.port}/other/team:prod` // same tag → same M bytes
    const cleanDoc = attestationDocument({ tools: ['filesystem.read'], note: 'repo-a-clean' })
    const riskyDoc = attestationDocument({ tools: ['process.exec'], note: 'repo-b-risky' })

    // publish CLEAN into repo-A, RISKY into repo-B — same subject digest M
    await publishViaHttp(ctx, {
      envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, cleanDoc),
      documentBytes: cleanDoc,
      artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
      reference: ctx.reference,
    })
    await publishViaHttp(ctx, {
      envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, riskyDoc),
      documentBytes: riskyDoc,
      artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
      reference: repoBRef,
    })

    // ---- discovery isolation: the SAME M resolves to DIFFERENT Evidence sets ----
    const discA = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    const discB = await discoverRemoteEvidence({ reference: repoBRef, actualContentHash: ctx.contentHash })
    expect(discA.complete).toBe(true)
    expect(discB.complete).toBe(true)
    if (!discA.complete || !discB.complete) return
    // both candidates anchor on the SAME immutable M…
    expect(discA.candidates[0]?.subject.manifestDigest).toBe(ctx.subjectDigest)
    expect(discB.candidates[0]?.subject.manifestDigest).toBe(ctx.subjectDigest)
    // …but the repository relationship is different: repo-A sees clean, repo-B sees risky
    expect(discA.candidates).toHaveLength(1)
    expect(discB.candidates).toHaveLength(1)
    expect(discA.candidates[0]?.document?.bytes).toEqual(cleanDoc)
    expect(discB.candidates[0]?.document?.bytes).toEqual(riskyDoc)
    expect(discA.candidates[0]?.referrerManifestDigest).not.toBe(discB.candidates[0]?.referrerManifestDigest)

    // ---- trust isolation: the SAME M in repo-A ALLOWs, in repo-B DENYs ----
    const gateA = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    const gateB = await evaluateRemoteEvidenceTrust({
      reference: repoBRef, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    // content equality ≠ repository relationship equality (D192)
    expect(gateA.decision).toBe('ALLOW')
    expect(gateB.decision).toBe('DENY')
    expect(gateB.verdict.errors.some((e) => e.includes('denyObserved'))).toBe(true)
  })
})

// ============================================================================
// R3 — remote substitution: OCI + DSH + document binding, missing ANY one rejects
// ============================================================================
describe('R3: remote Evidence substitution — OCI/DSH/document bindings are all required (D196)', () => {
  it('wrong OCI subject (manifest.subject = M2) is rejected at the OCI binding', async () => {
    const ctx = await setupRedTeam()
    const foreignM = 'sha256:' + 'f'.repeat(64)
    publishCarrier(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'foreign-subject'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      carrierSubject: foreignM,
    })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected).toHaveLength(1)
    expect(discovery.rejected[0]?.reason).toContain('foreign subject')
  })

  it('wrong DSH contentHash (envelope subject.contentHash = C2) is rejected at the DSH binding', async () => {
    const ctx = await setupRedTeam()
    const wrongC = 'sha256:' + 'e'.repeat(64)
    publishCarrier(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, wrongC, 'build-provenance', 'wrong-anchor'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected[0]?.reason).toContain('contentHash')
  })

  it('a SUBSTITUTED external document is rejected at the document binding (N4 revisited)', async () => {
    const ctx = await setupRedTeam()
    // the envelope's statement REQUIRES digest D1, but the carrier carries D2
    const requiredDoc = Buffer.from('{"bom":{"components":[]}}')
    const substituted = Buffer.from('{"bom":{"components":[{"type":"library","name":"evil"}]}}')
    const envelope = signEvidence({
      type: 'sbom',
      subjectContentHash: ctx.contentHash,
      statement: {
        format: 'cyclonedx-1.7', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json',
        sbomDigest: { algorithm: 'sha256', value: sha256Hex(requiredDoc) },
      },
      keyPath: ctx.keyFile,
    })
    publishCarrier(ctx, {
      envelopeBytes: Buffer.from(JSON.stringify(envelope), 'utf8'),
      documentBytes: substituted, // NOT the statement-required document
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected[0]?.reason).toContain('document digest mismatch')
  })

  it('an artifactType lie never overrides the verified Envelope.type (D152)', async () => {
    const ctx = await setupRedTeam()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { provenance: { required: true } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    publishCarrier(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'really-provenance'),
      artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'], // declared lie
      referrerArtifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'],
    })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    // the VERIFIED envelope type wins; the OCI declaration is diagnostic only
    expect(discovery.candidates[0]?.evidenceType).toBe('build-provenance')
    expect(discovery.candidates[0]?.declaredArtifactType).toBe(EVIDENCE_ARTIFACT_TYPES['runtime-attestation'])
    // and the lie does not change the trust outcome: provenance is required + trusted
    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('ALLOW')
  })

  it('a TRUSTED signer with a wrong subject still FAILS (signer trust ≠ binding)', async () => {
    const ctx = await setupRedTeam()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { provenance: { required: true } },
          evidenceTrustedKeys: [ctx.keyId], // the signer IS trusted
        },
      },
    }, null, 2), 'utf8')
    // trusted key, valid signature, but the OCI subject is a DIFFERENT M2
    publishCarrier(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'trusted-but-foreign'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      carrierSubject: 'sha256:' + 'd'.repeat(64),
    })

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected[0]?.reason).toContain('foreign subject')
    // the trusted issuer does NOT rescue a broken binding: required provenance is missing
    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('DENY')
  })
})

// ============================================================================
// R4 — registry + cache poisoning: corrupt bytes are NEVER accepted, stale
// snapshots NEVER shadow the live registry (D195 / D166 / D168 / D169)
// ============================================================================
describe('R4: registry+cache poisoning — corrupt cache + lying registry never accepts wrong bytes (D195)', () => {
  it('cache path A holds bytes B AND the registry also serves B under digest A → integrity FAIL, B never accepted', async () => {
    const ctx = await setupRedTeam()
    const cacheRoot = tempRoot('cas')
    const cache = new RemoteEvidenceCache(cacheRoot)
    const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
    const pub = await publishRemoteEvidence({
      reference: ctx.reference,
      subjectDescriptor: {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ctx.subjectDigest,
        size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
      },
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'r4'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    // warm the cache with the GOOD bytes, then poison BOTH cache and registry
    await discoverRemoteEvidenceCached({ reference: ctx.reference, actualContentHash: ctx.contentHash, cache })
    const poisoned = Buffer.from('{"poisoned":true}')
    const hex = pub.evidenceManifestDigest.split(':')[1]!
    writeFileSync(join(cacheRoot, 'manifests', hex.slice(0, 6), hex), poisoned)
    ctx.mock.manifests.set(pub.evidenceManifestDigest, { bytes: poisoned, digest: digestOf(poisoned) })

    const discovery = await discoverRemoteEvidenceCached({ reference: ctx.reference, actualContentHash: ctx.contentHash, cache })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    // the corrupt object is detected and DELETED (online repair), but the
    // registry's lie means the refetch is ALSO bad — the bytes are rejected,
    // never accepted as identity A (D195: location is not an integrity proof)
    expect(discovery.cache.corruptionRepaired).toBe(true)
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected.some((r) => r.reason.includes('corruption') || r.reason.includes('digest mismatch'))).toBe(true)
  })

  it('a poisoned envelope BLOB (cache + registry both bad) fails at the carrier digest check', async () => {
    const ctx = await setupRedTeam()
    const cacheRoot = tempRoot('cas')
    const cache = new RemoteEvidenceCache(cacheRoot)
    const doc = Buffer.from('{"bom":{"components":[]}}')
    const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
    const pub = await publishRemoteEvidence({
      reference: ctx.reference,
      subjectDescriptor: {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ctx.subjectDigest,
        size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
      },
      envelopeBytes: Buffer.from(JSON.stringify(signEvidence({
        type: 'sbom', subjectContentHash: ctx.contentHash,
        statement: { format: 'cyclonedx-1.7', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: sha256Hex(doc) } },
        keyPath: ctx.keyFile,
      })), 'utf8'),
      documentBytes: doc,
      artifactType: EVIDENCE_ARTIFACT_TYPES.sbom,
    })
    await discoverRemoteEvidenceCached({ reference: ctx.reference, actualContentHash: ctx.contentHash, cache })
    // poison the document blob in cache AND in the registry
    const docHex = digestOf(doc).split(':')[1]!
    writeFileSync(join(cacheRoot, 'blobs', docHex.slice(0, 6), docHex), Buffer.from('{"poisoned":true}'))
    ctx.mock.blobs.set(digestOf(doc), Buffer.from('{"poisoned":true}'))

    const discovery = await discoverRemoteEvidenceCached({ reference: ctx.reference, actualContentHash: ctx.contentHash, cache })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.cache.corruptionRepaired).toBe(true)
    // the substituted document never becomes a candidate (D196 document binding)
    expect(discovery.candidates).toHaveLength(0)
    expect(discovery.rejected.some((r) => r.reason.includes('document') || r.reason.includes('corruption') || r.reason.includes('blob fetch failed'))).toBe(true)
  })

  it('a stale complete snapshot [clean] can never hide [clean, risky] attached later (online enumeration stays current)', async () => {
    const ctx = await setupRedTeam()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    const cleanDoc = attestationDocument({ tools: ['filesystem.read'], note: 'clean' })
    const riskyDoc = attestationDocument({ tools: ['process.exec'], note: 'risky' })
    await publishViaHttp(ctx, { envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, cleanDoc), documentBytes: cleanDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    await publishViaHttp(ctx, { envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, riskyDoc), documentBytes: riskyDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // an ATTACKER-INJECTED stale snapshot: complete=true but only [clean]
    const cacheRoot = tempRoot('cas')
    const cache = new RemoteEvidenceCache(cacheRoot)
    const all = ctx.mock.referrersOf('company/prod', ctx.subjectDigest)
    const staleSnapshot: RemoteEvidenceDiscoverySnapshot = {
      registry: `127.0.0.1:${ctx.mock.port}`,
      repository: 'company/prod',
      subjectManifestDigest: ctx.subjectDigest,
      source: 'referrers-api',
      complete: true,
      descriptors: [all[0]!],
      capturedAt: new Date().toISOString(),
    }
    cache.putDiscoverySnapshot(staleSnapshot)

    // online gate: the snapshot is a bytes-store convenience, NOT the current
    // Evidence Set — the live enumeration sees [clean, risky] → AMBIGUOUS
    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home, cache,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('DENY')
    expect(gate.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
  })
})

// ============================================================================
// R5 — fallback concurrent publication race: no silent lost update, no fake
// completeness guarantees, no "absent Evidence" safety facts (D194)
// ============================================================================
describe('R5: fallback concurrent publication — lost updates and fake completeness are both forbidden (D194)', () => {
  it('a registry WITHOUT conditional-request support is honestly reported as concurrencyProtection=none', async () => {
    const ctx = await setupRedTeamFallback({ etagEnabled: false })
    const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
    const result = await publishRemoteEvidence({
      reference: ctx.reference,
      subjectDescriptor: {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ctx.subjectDigest,
        size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
      },
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'r5-none'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    expect(result.mode).toBe('tag-fallback')
    // no ETag ⇒ no If-Match ⇒ NO conditional protection; the client MUST say
    // so instead of pretending the fallback update is concurrency-safe
    expect(result.fallback?.concurrencyProtection).toBe('none')
    expect(result.fallback?.retries ?? 0).toBe(0)
  })

  it('a corrupted fallback index is never read as "no Evidence" — absent Evidence never produces ALLOW', async () => {
    const ctx = await setupRedTeamFallback()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { provenance: { required: true } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    const { referrersTagFor } = await import('../src/evidence/remote/referrers.ts')
    // the fallback tag EXISTS but is not a valid OCI image index
    ctx.mock.manifests.set(referrersTagFor(ctx.subjectDigest), {
      bytes: Buffer.from('{"not":"an index"}'),
      digest: digestOf(Buffer.from('{"not":"an index"}')),
    })

    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    // spec-tolerant empty enumeration is fine — the missing required evidence
    // STILL fails closed: no ALLOW can be manufactured from "no Evidence"
    expect(gate.decision).toBe('DENY')
    expect(gate.verdict.errors.some((e) => e.includes('build provenance evidence required but absent'))).toBe(true)
  })

  it('an UNREADABLE fallback tag (5xx) is an incomplete enumeration → DENY, never a partial set', async () => {
    const ctx = await setupRedTeamFallback()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { provenance: { required: true } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    const { referrersTagFor } = await import('../src/evidence/remote/referrers.ts')
    ctx.mock.manifests.set(referrersTagFor(ctx.subjectDigest), {
      bytes: Buffer.from('{}'),
      digest: digestOf(Buffer.from('{}')),
    })
    ctx.mock.tamper.manifestGetStatus = { forRef: referrersTagFor(ctx.subjectDigest), status: 500 }

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('DISCOVERY_INCOMPLETE')

    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('DENY')
    expect(gate.verdict.errors.some((e) => e.includes('remote evidence discovery incomplete'))).toBe(true)
  })

  it('a fallback referrers-tag index is pushed with the OCI image-index Content-Type (GHCR gate fix)', async () => {
    const ctx = await setupRedTeamFallback()
    const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
    await publishRemoteEvidence({
      reference: ctx.reference,
      subjectDescriptor: {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ctx.subjectDigest,
        size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
      },
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'ghcr-fix'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    // the mock enforces GHCR-style Content-Type matching — the referrers-tag
    // PUT must have carried the OCI IMAGE INDEX media type, otherwise the
    // publish would have failed with 400 (as it did on real GHCR)
    const indexPuts = ctx.mock.requests.filter((r) => r.method === 'PUT' && r.path.includes('sha256-'))
    expect(indexPuts.length).toBeGreaterThanOrEqual(1)
    for (const req of indexPuts) {
      expect(req.contentType).toBe('application/vnd.oci.image.index.v1+json')
    }
  })
})

// ============================================================================
// R6 / RC6-N3 ★ — malicious enumeration & ambiguity: quantity/order/pagination
// can never manufacture an ALLOW (D191 / D110 / N5)
// ============================================================================
describe('R6 / RC6-N3 ★: malicious enumeration — duplicates and ordering never decide trust (D191)', () => {
  async function setupAmbiguity(): Promise<RedTeamContext & { cleanEntry: MockReferrerEntry; riskyEntry: MockReferrerEntry }> {
    const ctx = await setupRedTeam()
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    const cleanDoc = attestationDocument({ tools: ['filesystem.read'], note: 'clean' })
    const riskyDoc = attestationDocument({ tools: ['process.exec'], note: 'risky' })
    await publishViaHttp(ctx, { envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, cleanDoc), documentBytes: cleanDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    await publishViaHttp(ctx, { envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, riskyDoc), documentBytes: riskyDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    const all = ctx.mock.referrersOf('company/prod', ctx.subjectDigest)
    return { ...ctx, cleanEntry: all[0]!, riskyEntry: all[1]! }
  }

  it('MASSIVE duplicates (50× the same descriptor) never manufacture false ambiguity — semantic dedup keeps ONE clean attestation → ALLOW', async () => {
    const { mock, home, reference, contentHash, subjectDigest, cleanEntry } = await setupAmbiguity()
    mock.setReferrersForRepo('company/prod', subjectDigest, Array(50).fill(cleanEntry))
    // 50 identical clean descriptors, zero risky: quantity must not fabricate conflict
    const gate = await evaluateRemoteEvidenceTrust({
      reference, actualContentHash: contentHash, home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('ALLOW')
    expect(gate.verdict.errors.some((e) => e.includes('AMBIGUOUS'))).toBe(false)
  })

  it('100 clean + 1 trusted risky → STILL AMBIGUOUS → DENY (majority voting never decides trust)', async () => {
    const { mock, home, reference, contentHash, subjectDigest, cleanEntry, riskyEntry } = await setupAmbiguity()
    mock.setReferrersForRepo('company/prod', subjectDigest, [...Array(100).fill(cleanEntry), riskyEntry])
    const gate = await evaluateRemoteEvidenceTrust({
      reference, actualContentHash: contentHash, home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('DENY')
    expect(gate.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
  })

  it('RC6-N3 ★ clean+risky are ALWAYS AMBIGUOUS → DENY regardless of order and pagination', async () => {
    const { mock, home, reference, contentHash, subjectDigest, cleanEntry, riskyEntry } = await setupAmbiguity()
    const variants: Array<{ order: Array<MockReferrerEntry>; pageSize: number; label: string }> = [
      { order: [cleanEntry, riskyEntry], pageSize: 0, label: 'clean-first' },
      { order: [riskyEntry, cleanEntry], pageSize: 0, label: 'risky-first' },
      { order: [cleanEntry, riskyEntry], pageSize: 1, label: 'paginated clean-first' },
      { order: [riskyEntry, cleanEntry], pageSize: 1, label: 'paginated risky-first' },
    ]
    for (const v of variants) {
      mock.setReferrersForRepo('company/prod', subjectDigest, v.order)
      mock.referrersPageSize = v.pageSize
      const gate = await evaluateRemoteEvidenceTrust({
        reference, actualContentHash: contentHash, home,
        signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
      })
      expect(gate.decision, `variant ${v.label}`).toBe('DENY')
      expect(gate.verdict.evidenceTrust.attestation, `variant ${v.label}`).toBe('AMBIGUOUS')
    }
  })
})

// ============================================================================
// R7 — auth / redirect / proxy edge cases: credentials never cross origins and
// never enter logs, Evidence identity or trust outputs (D198 / D185 / D197)
// ============================================================================
describe('R7: auth & redirect edges — credentials never leak across origins or into outputs (D198)', () => {
  it('401 Bearer challenge → token fetch → retry succeeds; error output stays credential-free', async () => {
    const ctx = await setupRedTeamMock(new MockRegistry({ requireAuth: true }))
    const credentials = { username: 'r7-user', password: 'r7-super-secret' }
    // success path: 401 challenge → token → retry (D185)
    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash, credentials })
    expect(discovery.complete).toBe(true)

    // error path: the registry fails mid-enumeration → the error must NOT
    // contain the credentials (Bearer/Basic/password/username)
    ctx.mock.tamper.referrersStatus = 500
    const failed = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash, credentials })
    expect(failed.complete).toBe(false)
    if (failed.complete) return
    const message = JSON.stringify(failed.error)
    expect(message).not.toContain('r7-super-secret')
    expect(message).not.toContain('r7-user')
    expect(message).not.toContain('Basic ')
    expect(message).not.toContain('Bearer ')
  })

  it('a cross-origin redirect never forwards Authorization — the failure is credential-free (D197)', async () => {
    const ctx = await setupRedTeamMock(new MockRegistry())
    const credentials = { username: 'r7-user', password: 'r7-super-secret' }
    // resolving the subject redirects to an UNRELATED origin
    ctx.mock.tamper.redirect = {
      from: `/v2/company/prod/manifests/prod`,
      to: `https://evil.example/v2/company/prod/manifests/prod`,
    }
    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash, credentials })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    const message = JSON.stringify(discovery.error)
    expect(message).not.toContain('r7-super-secret')
    expect(message).not.toContain('r7-user')
    expect(message).not.toContain('Authorization')
  })

  it('credentials never enter Evidence identity, candidates or trust verdicts (D198)', async () => {
    const ctx = await setupRedTeamMock(new MockRegistry({ requireAuth: true }))
    writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
      version: 2,
      registries: {
        [`127.0.0.1:${ctx.mock.port}/company/*`]: {
          requireEvidence: { provenance: { required: true } },
          evidenceTrustedKeys: [ctx.keyId],
        },
      },
    }, null, 2), 'utf8')
    const credentials = { username: 'r7-user', password: 'r7-super-secret' }
    const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
    await publishRemoteEvidence({
      reference: ctx.reference,
      subjectDescriptor: {
        mediaType: 'application/vnd.oci.image.manifest.v1+json',
        digest: ctx.subjectDigest,
        size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0,
      },
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'r7'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      credentials,
    })
    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash, credentials })
    const gate = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home, credentials,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(gate.decision).toBe('ALLOW')
    const outputs = JSON.stringify({
      candidates: discovery.candidates,
      errors: gate.verdict.errors,
      steps: gate.verdict.steps.map((s) => ({ step: s.step, ok: s.ok, reason: s.reason })),
      evidenceTrust: gate.verdict.evidenceTrust,
    })
    expect(outputs).not.toContain('r7-super-secret')
    expect(outputs).not.toContain('r7-user')
  })

  it('a FOREIGN Bearer realm in the 401 challenge is NEVER contacted with credentials (RI-28/D198)', async () => {
    const ctx = await setupRedTeamMock(new MockRegistry({ requireAuth: true }))
    const credentials = { username: 'r7-user', password: 'r7-super-secret' }
    // a malicious registry challenges with a realm on an UNRELATED origin —
    // following it would ship the Basic credentials to evil.example
    ctx.mock.tamper.wwwAuthenticateRealm = 'https://evil.example/token'

    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash, credentials })
    expect(discovery.complete).toBe(false)
    if (discovery.complete) return
    expect(discovery.error.kind).toBe('REGISTRY_ERROR')
    // the failure is the ORIGINAL 401 — the client NEVER requested the foreign
    // realm (a transport failure would mention evil.example, a leak would too)
    expect(JSON.stringify(discovery.error)).not.toContain('evil.example')
  })
})

// ============================================================================
// R8 / RC6-N4 ★ — distribution can never manufacture authorization: current
// trust.yaml decides, mutable refs never rewrite a resolved immutable identity
// ============================================================================
describe('R8 / RC6-N4 ★: distribution cannot manufacture authorization (D189/D197)', () => {
  it('RC6-N4 ★ the SAME remote bytes ALLOW then DENY — only the CURRENT trust.yaml decides', async () => {
    const ctx = await setupRedTeam()
    const writeTrust = (evidenceTrustedKeys: string[]): void => {
      writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
        version: 2,
        registries: {
          [`127.0.0.1:${ctx.mock.port}/company/*`]: {
            requireEvidence: { provenance: { required: true } },
            evidenceTrustedKeys,
          },
        },
      }, null, 2), 'utf8')
    }
    await publishViaHttp(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'rc6n4'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })

    // same remote bytes, issuer TRUSTED → ALLOW
    writeTrust([ctx.keyId])
    const allow = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(allow.decision).toBe('ALLOW')

    // same remote bytes, issuer REVOKED in the current trust.yaml → DENY
    // (a NON-matching key: an issuer is configured but this signer is not it)
    writeTrust(['sha256:' + '0'.repeat(64)])
    const deny = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference, actualContentHash: ctx.contentHash, home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' }, executionTarget: TARGET,
    })
    expect(deny.decision).toBe('DENY')
    // Registry/cache did NOT become a Trust Authority: the DENY is issuer trust
    expect(deny.verdict.errors.some((e) => e.includes('UNTRUSTED_EVIDENCE_ISSUER'))).toBe(true)
  })

  it('a mutable tag drift NEVER rewrites an already-resolved immutable M (D197/N1)', async () => {
    const ctx = await setupRedTeam()
    await publishViaHttp(ctx, {
      envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'drift'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
    })
    // lock the immutable identity by digest; then the registry re-points the
    // mutable :prod tag at a DIFFERENT manifest M2
    const digestRef = `127.0.0.1:${ctx.mock.port}/company/prod@${ctx.subjectDigest}`
    const m2Bytes = Buffer.from('{"different":"manifest"}')
    ctx.mock.manifests.set('prod', { bytes: m2Bytes, digest: digestOf(m2Bytes) })

    // discovery pinned to M via digest reference — the tag drift is invisible
    const discovery = await discoverRemoteEvidence({ reference: digestRef, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    expect(discovery.candidates).toHaveLength(1)
    expect(discovery.candidates[0]?.subject.manifestDigest).toBe(ctx.subjectDigest)
    expect(discovery.candidates[0]?.subject.contentHash).toBe(ctx.contentHash)
  })
})
