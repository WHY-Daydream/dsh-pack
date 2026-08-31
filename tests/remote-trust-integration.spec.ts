/**
 * v0.6.0-beta.1 Remote Trust Integration contract matrix (B1–B12, D175–D182).
 *
 * Protocol-level tests against the HTTP mock registry + a REAL
 * RemoteEvidenceCache + a REAL trust.yaml, driving the Remote Trust Gate
 * (`evaluateRemoteEvidenceTrust`). North-Star regressions:
 *   B4 ★ — incomplete remote enumeration is never evaluated as a partial set
 *   B5 ★ — same cached bytes + CURRENT trustedKeys changed → verdict changes
 *   B8 ★ — remote conflicting trusted attestations → AMBIGUOUS → DENY
 *   B11 ★ — explicit offline cache can never authorize execution
 *
 * Frozen semantics under test (DESIGN-v0.6.0.md):
 *   - only complete=true ONLINE discovery can enter executable authorization
 *     (D175); a partial enumeration is a hard DENY, never a reduced set (B4)
 *   - trust is ALWAYS recomputed against the CURRENT trust.yaml — the cache
 *     never saves TRUSTED/ALLOW (D176) — so revocation always applies (B5)
 *   - offline cached Evidence is inspection/verification ONLY and can never
 *     satisfy executable ALLOW (D177); an online failure never silently
 *     degrades to a stale snapshot (D174/B11)
 *   - remote candidates reuse the existing D109/D110/D124–D128 semantic
 *     issuer/dedup/ambiguity rules — OCI manifestDigest, registry/push order
 *     and native/fallback/cache source are never selectors or Trust weights
 *     (D178/D179)
 *   - invalid/rejected remote objects never enter Policy (D180); a required
 *     Evidence type with no valid candidate is D101 MISSING → DENY (B3/B10)
 *   - the gate precedes materialization/pnpm/lifecycle (D181/B12)
 * @module tests/remote-trust-integration.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence, verifyEvidenceEnvelope } from '../src/evidence/envelope.ts'
import { RemoteEvidenceCache } from '../src/evidence/remote/cache.ts'
import { discoverRemoteEvidenceCached } from '../src/evidence/remote/discovery.ts'
import {
  assertRemoteEvidenceAllow,
  buildVerifiedEvidenceSet,
  evaluateRemoteEvidenceTrust,
} from '../src/evidence/remote/trust.ts'
import {
  EVIDENCE_ARTIFACT_TYPES,
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
} from '../src/evidence/remote/types.ts'
import {
  evaluateTrustPolicyV2,
  loadTrustPolicyFile,
  resolveTrustPolicyV2,
  type AttestationCandidate,
} from '../src/image/trust-policy-v2.ts'
import { buildOciManifest } from '../src/image/registry/manifest.ts'
import type { MockReferrerEntry } from './helpers/mock-registry.ts'
import { MockRegistry } from './helpers/mock-registry.ts'

const EMPTY_DESCRIPTOR = {
  mediaType: 'application/vnd.oci.empty.v1+json',
  digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  size: 2,
}

/** Fixed execution target for deterministic B-tests (D111). */
const TARGET = { os: 'linux', arch: 'x64' }

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-remote-trust-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const digestOf = (bytes: Buffer): string => `sha256:${sha256Hex(bytes)}`

/** A fresh ed25519 keypair; the public fingerprint is the DSH evidence issuer keyId. */
function makeKey(): { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']; keyId: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const keyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))
  return { privateKey, keyId }
}

/** An evidence envelope WITHOUT an external document. */
function plainEnvelope(key: string, contentHash: string, type: string, note: string): Buffer {
  const envelope = signEvidence({
    type,
    subjectContentHash: contentHash,
    statement: { schemaVersion: 1, format: 'dsh-test', note },
    keyPath: key,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** An SBOM envelope whose statement REQUIRES the external document (D159). */
function sbomEnvelope(key: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'sbom',
    subjectContentHash: contentHash,
    statement: {
      format: 'cyclonedx-1.7',
      specVersion: '1.7',
      mediaType: 'application/vnd.cyclonedx+json',
      sbomDigest: { algorithm: 'sha256', value: sha256Hex(document) },
    },
    keyPath: key,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** An attestation document with the frozen D96 field set (semanticKey inputs). */
function attestationDocument(opts: {
  os?: string
  arch?: string
  coverage?: 'complete' | 'partial' | 'unknown'
  tools?: string[]
  note?: string
}): Buffer {
  return Buffer.from(JSON.stringify({
    declaredCapabilityDigest: 'sha256:' + 'b'.repeat(64),
    observation: { coverage: opts.coverage ?? 'complete', reasons: [] },
    coldBoot: { status: 'PASS' },
    observed: { tools: opts.tools ?? [], skills: [], services: [], providers: [] },
    comparison: { missing: [], extra: [], mismatched: [] },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { os: opts.os ?? TARGET.os, arch: opts.arch ?? TARGET.arch },
    resultDigest: 'sha256:' + 'c'.repeat(64),
    note: opts.note ?? 'attestation',
  }), 'utf8')
}

/** An attestation envelope whose statement REQUIRES the document (D159/D125). */
function attestationEnvelope(key: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'attestation',
    subjectContentHash: contentHash,
    statement: {
      format: 'dsh-attestation',
      schemaVersion: 1,
      attestationDigest: { algorithm: 'sha256', value: sha256Hex(document) },
    },
    keyPath: key,
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

/** A minimal valid OCI agent-image manifest for the mutable tag. */
function agentManifestBytes(blobBytes: Buffer): Buffer {
  const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: 'sha256:' + 'a'.repeat(64), mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
  const manifest = buildOciManifest(
    { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: digestOf(configBytes), size: configBytes.length },
    { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: digestOf(blobBytes), size: blobBytes.length },
  )
  return Buffer.from(JSON.stringify(manifest), 'utf8')
}

/** Publish an evidence object into the mock registry; returns the referrer entry. */
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

interface TrustSetup {
  mock: MockRegistry
  home: string
  cacheRoot: string
  cache: RemoteEvidenceCache
  artifactKey: { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']; keyId: string }
  evidenceKey: { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey']; keyId: string }
  contentHash: string
  subjectDigest: string
  reference: string
  signature: { status: 'VALID' | 'INVALID' | 'MISSING'; trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A' }
}

/** Start a mock registry + agent image + cache + home + keys. */
async function setupTrust(): Promise<TrustSetup> {
  const mock = new MockRegistry()
  await mock.start()
  const home = tempRoot('home')
  const cacheRoot = tempRoot('cas')
  const cache = new RemoteEvidenceCache(cacheRoot)

  const artifactKey = makeKey()
  const evidenceKey = makeKey()

  const artifactBytes = Buffer.from('artifact-a-bytes')
  const contentHash = digestOf(artifactBytes)

  const agentManifest = agentManifestBytes(artifactBytes)
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return {
    mock, home, cacheRoot, cache, artifactKey, evidenceKey,
    contentHash, subjectDigest, reference,
    // the caller supplies verified artifact signer facts (D19: VALID ≠ TRUSTED)
    signature: { status: 'VALID', trust: 'VERIFIED' },
  }
}

/** Write a v2 trust.yaml into $DSH_HOME. */
function writeTrustYaml(home: string, registries: Record<string, unknown>): void {
  writeFileSync(join(home, 'trust.yaml'), JSON.stringify({ version: 2, registries }, null, 2), 'utf8')
}

/** The registry pattern matching the setup reference's repository. */
function repoPattern(setup: TrustSetup): string {
  return `127.0.0.1:${setup.mock.port}/company/*`
}

/** A trust.yaml rule that trusts the evidence key and requires all three types. */
function fullRequireRule(setup: TrustSetup): Record<string, unknown> {
  return {
    requireSignature: true,
    requireTrusted: true,
    trustedKeys: [setup.artifactKey.keyId],
    evidenceTrustedKeys: [setup.evidenceKey.keyId],
    requireEvidence: {
      provenance: { required: true },
      sbom: { required: true },
      runtimeAttestation: { required: true, coverage: 'complete' },
    },
  }
}

/** keyPath for signEvidence (writes the private key to disk). */
function writeKeyPath(root: string, key: { privateKey: ReturnType<typeof generateKeyPairSync>['privateKey'] }, label: string): string {
  const file = join(root, `${label}.pem`)
  writeFileSync(file, key.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  return file
}

// ============================================================================
// B1 — full happy-path chain → ALLOW
// ============================================================================
describe('B1: trusted artifact + trusted provenance/SBOM/attestation + correct target → ALLOW', () => {
  it('a complete online discovery with all required trusted evidence passes the gate', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')

    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'receipt')
    const sbomDoc = Buffer.from('{"bom":{"components":[]}}')
    const sbom = sbomEnvelope(keyPath, s.contentHash, sbomDoc)
    const attDoc = attestationDocument({ tools: [] })
    const att = attestationEnvelope(keyPath, s.contentHash, attDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: sbom, documentBytes: sbomDoc, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: attDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference,
      actualContentHash: s.contentHash,
      home: s.home,
      cache: s.cache,
      signature: s.signature,
      executionTarget: TARGET,
    })
    expect(result.decision).toBe('ALLOW')
    expect(result.discovery.complete).toBe(true)
    expect(result.discovery.mode).toBe('referrers-api')
    expect(result.verdict.evidenceTrust).toEqual({ provenance: 'VERIFIED', sbom: 'VERIFIED', attestation: 'VERIFIED' })
    // D181 — an ALLOW is exactly what the executable path may proceed on
    expect(() => assertRemoteEvidenceAllow(result)).not.toThrow()
  })
})

// ============================================================================
// B2 — valid Evidence + untrusted issuer → DENY before materialization
// ============================================================================
describe('B2: valid Evidence from an UNTRUSTED issuer → DENY (D109: VALID ≠ TRUSTED)', () => {
  it('a correctly-verified provenance signed by a key outside evidenceTrustedKeys is denied', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    // the evidence is signed by a DIFFERENT key (not the trusted evidence key)
    const rogue = makeKey()
    const keyPath = writeKeyPath(s.home, rogue, 'rogue')
    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'rogue-receipt')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference,
      actualContentHash: s.contentHash,
      home: s.home,
      cache: s.cache,
      signature: s.signature,
      executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.provenance).toBe('UNTRUSTED')
    // D181/B12 — a DENY must hard-stop the executable path
    expect(() => assertRemoteEvidenceAllow(result)).toThrow(/blocked before materialization/)
  })
})

// ============================================================================
// B3 — remote Evidence wrong contentHash → rejected → required missing → DENY
// ============================================================================
describe('B3: remote Evidence with wrong DSH contentHash → rejected → MISSING → DENY (D150/D101)', () => {
  it('an evidence bound to contentHash C2 ≠ independently-known C1 is rejected and the required type is missing', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    const wrongContentHash = 'sha256:' + 'e'.repeat(64)
    const prov = plainEnvelope(keyPath, wrongContentHash, 'build-provenance', 'wrong-anchor')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference,
      actualContentHash: s.contentHash,
      home: s.home,
      cache: s.cache,
      signature: s.signature,
      executionTarget: TARGET,
    })
    // the object was discovered but REJECTED (D180 — never a policy input)
    expect(result.discovery.complete).toBe(true)
    expect(result.discovery.rejected.length).toBeGreaterThan(0)
    expect(result.discovery.rejected[0]?.reason).toContain('contentHash')
    // required provenance has no valid candidate → D101 MISSING → DENY
    expect(result.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.provenance).toBe('ABSENT')
  })
})

// ============================================================================
// B4 ★ North-Star: incomplete remote enumeration → never a partial evaluation
// ============================================================================
describe('B4 ★ North-Star: incomplete enumeration is never evaluated as a partial Evidence set (D175/D158)', () => {
  it('a page-2 failure makes the gate DENY with no partial candidates consumed', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'p1')
    const attDoc = attestationDocument({ tools: [] })
    const att = attestationEnvelope(keyPath, s.contentHash, attDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: attDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // page 1 succeeds, page 2 fails → the enumeration is INCOMPLETE
    s.mock.referrersPageSize = 1
    s.mock.tamper.referrersPageStatus = 500

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference,
      actualContentHash: s.contentHash,
      home: s.home,
      cache: s.cache,
      signature: s.signature,
      executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.discovery.complete).toBe(false)
    // NO partial Evidence set may ever be evaluated — even though page-1
    // contained a perfectly valid provenance that would have passed on its own
    expect(result.verdict.errors.some((e) => e.includes('remote evidence discovery incomplete'))).toBe(true)
  })
})

// ============================================================================
// B5 ★ North-Star: same cached bytes + CURRENT trustedKeys changed → verdict changes
// ============================================================================
describe('B5 ★ North-Star: the CURRENT trust.yaml always re-decides — the cache never saves authorization (D176)', () => {
  it('a CAS cache hit does not survive an evidence-issuer revocation in trust.yaml', async () => {
    const s = await setupTrust()
    // B5 focuses on issuer revocation: require provenance only (the issuer
    // trust decision is what must flip when trust.yaml changes)
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { provenance: { required: true } },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'receipt')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const opts = {
      reference: s.reference,
      actualContentHash: s.contentHash,
      home: s.home,
      cache: s.cache,
      signature: s.signature,
      executionTarget: TARGET,
    }

    // T0 — the trusted issuer is in trust.yaml → ALLOW, and the CAS is warm
    const first = await evaluateRemoteEvidenceTrust(opts)
    expect(first.decision).toBe('ALLOW')
    expect(first.verdict.evidenceTrust.provenance).toBe('VERIFIED')

    // T1 — the SAME trust.yaml path now REVOKES the evidence issuer
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [],
        requireEvidence: { provenance: { required: true } },
      },
    })

    // the same cached bytes + current policy → the verdict MUST change (B5)
    const second = await evaluateRemoteEvidenceTrust(opts)
    expect(second.decision).toBe('DENY')
    expect(second.verdict.evidenceTrust.provenance).toBe('UNTRUSTED')
    expect(second.discovery.cache.objectCacheHits).toBeGreaterThanOrEqual(1) // bytes WERE cached — but trust is re-decided
  })
})

// ============================================================================
// B6 — stale snapshot=[clean] cannot hide a newly attached risky Evidence
// ============================================================================
describe('B6: online re-enumeration sees a newly attached risky attestation — the snapshot never shadows it (D169)', () => {
  it('after Registry attaches a process.exec attestation, online gate evaluation sees it and DENYs', async () => {
    const s = await setupTrust()
    // policy: attestation trusted + denyObserved process.exec
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
        capabilities: { denyObserved: ['process.exec'] },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')

    // T0 — only a CLEAN attestation exists → ALLOW
    const cleanDoc = attestationDocument({ tools: ['filesystem.read'] })
    const cleanAtt = attestationEnvelope(keyPath, s.contentHash, cleanDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: cleanAtt, documentBytes: cleanDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const first = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(first.decision).toBe('ALLOW')

    // T1 — the Registry attaches a RISKY attestation (observed process.exec)
    const riskyDoc = attestationDocument({ tools: ['process.exec'] })
    const riskyAtt = attestationEnvelope(keyPath, s.contentHash, riskyDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: riskyAtt, documentBytes: riskyDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // online gate: fresh enumeration → the risky evidence is VISIBLE. With
    // BOTH the clean and the risky attestation present, the two trusted
    // attestations carry CONFLICTING semantics → AMBIGUOUS → DENY (D110).
    // If the stale snapshot [clean] had shadowed the new attestation, the
    // gate would have ALLOWed — any DENY here proves the fresh enumeration.
    const second = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(second.decision).toBe('DENY')
    expect(second.discovery.complete).toBe(true)
    expect(second.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
    expect(second.verdict.errors.some((e) => e.includes('AMBIGUOUS'))).toBe(true)
  })
})

// ============================================================================
// B7 — foreign execution-target attestation → DENY
// ============================================================================
describe('B7: an attestation for a DIFFERENT execution target cannot satisfy the current target (D111)', () => {
  it('attested darwin/arm64 while evaluating linux/x64 → execution-target DENY', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    const foreignDoc = attestationDocument({ os: 'darwin', arch: 'arm64' })
    const att = attestationEnvelope(keyPath, s.contentHash, foreignDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: foreignDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.verdict.errors.some((e) => e.includes('does not match current execution target'))).toBe(true)
  })
})

// ============================================================================
// B8 ★ North-Star: remote conflicting trusted attestations → AMBIGUOUS → DENY
// ============================================================================
describe('B8 ★ North-Star: two trusted same-target attestations with CONFLICTING semantics → AMBIGUOUS → DENY (D110)', () => {
  it('two trusted attestations observing different facts for the same target are ambiguous', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    // two attestations: same target, DIFFERENT observed facts → different semantic keys
    const docA = attestationDocument({ tools: ['filesystem.read'], note: 'run-a' })
    const docB = attestationDocument({ tools: ['process.exec'], note: 'run-b' })
    const attA = attestationEnvelope(keyPath, s.contentHash, docA)
    const attB = attestationEnvelope(keyPath, s.contentHash, docB)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: attA, documentBytes: docA, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: attB, documentBytes: docB, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
    expect(result.verdict.errors.some((e) => e.includes('AMBIGUOUS'))).toBe(true)
  })
})

// ============================================================================
// B9 — equivalent remote Evidence through different OCI manifests → semantic dedup
// ============================================================================
describe('B9: equivalent Evidence via DIFFERENT OCI manifests is deduplicated, not falsely AMBIGUOUS (D178/D110)', () => {
  it('two OCI carriers holding the SAME DSH attestation semantic result → single candidate, ALLOW', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { runtimeAttestation: { required: true, coverage: 'complete' } },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    // the SAME document bytes published through TWO different OCI manifests
    // (different manifestDigests, identical DSH semantic result)
    const doc = attestationDocument({ tools: ['filesystem.read'], note: 'same-run' })
    const att = attestationEnvelope(keyPath, s.contentHash, doc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: doc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: doc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    // the two OCI manifestDigests are distinct, but the DSH semantic identity
    // is ONE — NOT a false AMBIGUOUS (D110 semantic dedup, B9)
    expect(result.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })
})

// ============================================================================
// B10 — required Evidence absent → D101 MISSING → DENY
// ============================================================================
describe('B10: required Evidence absent → MISSING → DENY (D101)', () => {
  it('a policy requiring sbom with no sbom in the registry is denied', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, {
      [repoPattern(s)]: {
        requireSignature: true,
        requireTrusted: true,
        trustedKeys: [s.artifactKey.keyId],
        evidenceTrustedKeys: [s.evidenceKey.keyId],
        requireEvidence: { sbom: { required: true } },
      },
    })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    // only provenance is published — the REQUIRED sbom does not exist
    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'receipt')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.sbom).toBe('ABSENT')
    expect(result.verdict.errors.some((e) => e.includes('required but absent'))).toBe(true)
  })
})

// ============================================================================
// B11 ★ North-Star: offline cached Evidence can never authorize execution
// ============================================================================
describe('B11 ★ North-Star: offline cached snapshot → inspection only, executable authorization MUST NOT ALLOW (D174/D177)', () => {
  it('an online gate NEVER degrades to a cached snapshot on registry failure — hard DENY', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    const prov = plainEnvelope(keyPath, s.contentHash, 'build-provenance', 'receipt')
    const sbomDoc = Buffer.from('{"bom":{"components":[]}}')
    const sbom = sbomEnvelope(keyPath, s.contentHash, sbomDoc)
    const attDoc = attestationDocument({ tools: [] })
    const att = attestationEnvelope(keyPath, s.contentHash, attDoc)
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: sbom, documentBytes: sbomDoc, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: att, documentBytes: attDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // warm the cache with a successful online ALLOW (snapshot + CAS populated)
    const warm = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(warm.decision).toBe('ALLOW')

    // the registry is now UNREACHABLE — the gate must NOT silently use the
    // cached snapshot as authorization (D174: online failure ≠ implicit offline)
    await s.mock.stop()
    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')
    expect(result.discovery.complete).toBe(false)
    expect(result.discovery.source).toBe('remote') // never 'cached-snapshot' through the gate
    expect(() => assertRemoteEvidenceAllow(result)).toThrow(/blocked before materialization/)

    // EXPLICIT offline CAN inspect/verify the cached snapshot (inspection path)
    const offlineRef = `127.0.0.1:${s.mock.port}/company/prod@${s.subjectDigest}`
    const inspection = await discoverRemoteEvidenceCached({
      reference: offlineRef, actualContentHash: s.contentHash, mode: 'offline', cache: s.cache,
    })
    expect(inspection.complete).toBe(true)
    if (!inspection.complete) return
    expect(inspection.source).toBe('cached-snapshot')
    const inspected = buildVerifiedEvidenceSet(inspection.candidates)
    expect(inspected.attestation.length).toBeGreaterThan(0)
    // inspection can even run the evaluator — but this is NOT authorization:
    // the executable gate has no offline mode and never returns this verdict
    const decision = resolveTrustPolicyV2(loadTrustPolicyFile(s.home), `127.0.0.1:${s.mock.port}/company/prod`)
    const inspectionVerdict = evaluateTrustPolicyV2(decision, {
      signature: s.signature,
      executionTarget: TARGET,
      provenance: inspected.provenance,
      sbom: inspected.sbom,
      attestation: inspected.attestation,
    })
    expect(inspectionVerdict.ok).toBe(true) // verification/inspection succeeds
    // ...but the gate result type/API has NO offline path — a cached-snapshot
    // verdict can never be handed to assertRemoteEvidenceAllow (D177)
  })
})

// ============================================================================
// B12 — policy DENY/error → materialize/pnpm/lifecycle NEVER happens
// ============================================================================
describe('B12: a DENY/error verdict hard-stops the executable path before any materialization (D181)', () => {
  it('assertRemoteEvidenceAllow throws for a DENY — nothing materializes afterwards', async () => {
    const s = await setupTrust()
    writeTrustYaml(s.home, { [repoPattern(s)]: fullRequireRule(s) })
    const keyPath = writeKeyPath(s.home, s.evidenceKey, 'evidence')
    // rogue issuer → DENY (B2 scenario, now asserting the materialization stop)
    const rogue = makeKey()
    const roguePath = writeKeyPath(s.home, rogue, 'rogue')
    const prov = plainEnvelope(roguePath, s.contentHash, 'build-provenance', 'rogue')
    publishEvidence(s.mock, { subjectDigest: s.subjectDigest, envelopeBytes: prov, artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })

    const result = await evaluateRemoteEvidenceTrust({
      reference: s.reference, actualContentHash: s.contentHash, home: s.home, cache: s.cache, signature: s.signature, executionTarget: TARGET,
    })
    expect(result.decision).toBe('DENY')

    // the executable path MUST stop here — before any pnpm/lifecycle can run.
    // The gate performs no materialization itself; assertRemoteEvidenceAllow
    // is the D181 boundary that run/install must cross only on ALLOW.
    let materialized = false
    try {
      assertRemoteEvidenceAllow(result)
      materialized = true // would only happen on ALLOW
    } catch {
      // expected: DENY hard-stop
    }
    expect(materialized).toBe(false)
    // the gate created NO profile/pnpm artifacts — nothing was materialized
    expect(existsSync(join(s.home, 'profiles'))).toBe(false)
  })
})
