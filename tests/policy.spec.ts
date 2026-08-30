/**
 * v0.5 beta.2 trust.yaml v2 / Trust Policy Binding test matrix
 * (DESIGN-v0.5.0.md §10, D100–D111): T0–T15 + North-Stars — the evaluation
 * chain consumes VERIFIED inputs only (D100), missing required evidence is
 * DENY (D101), coverage is ordered (D102), the runtime matrix is a
 * compatibility gate (D103), denyObserved consumes observed only (D104),
 * Evidence Signature VALID ≠ Evidence Issuer TRUSTED (D109), candidate
 * selection is deterministic and ambiguity fail-closed (D110), and the
 * attestation environment must exactly match the current execution target
 * (D111). v1 stays compatible (D107), and the auditable step chain explains
 * every ALLOW/DENY (D106).
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultPackager } from '../src/service.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import {
  evaluateTrustPolicyV2, loadTrustPolicyFile, resolveTrustPolicyV2, validateTrustPolicyV2,
  type AttestationCandidate, type PolicyEvidenceInput, type ProvenanceCandidate,
  type SbomCandidate, type TrustPolicyV2Decision,
} from '../src/image/trust-policy-v2.js'
import { TRUST_POLICY_VERSION } from '../src/image/trust-policy.js'
import type { DependencyTree } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-policy-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// --- fixtures ---

// 64-hex fingerprints (bare, as recomputed from an embedded public key).
const KEY_RELEASE = 'a'.repeat(64)   // trusted artifact/release key
const KEY_ATTESTOR = 'b'.repeat(64)  // trusted evidence/attestor key
const KEY_ATTACKER = 'c'.repeat(64)  // untrusted

const MINIMAL_DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: {}, closure: {}, localDeps: [], warnings: [],
}

async function makePack(rows: Record<string, unknown>[] = []): Promise<Buffer> {
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: {},
    configHash: computeConfigHash({ rows }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-beta.2' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: 'web-profile', version: '1.0.0', private: true, dependencies: {} }) },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
    { path: 'resolved/composition.json', content: prettyJson({ rows }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson(MINIMAL_DEP_TREE) },
    { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

/** A policy decision carrying every v2 constraint (for the pure-chain tests). */
function fullDecision(): TrustPolicyV2Decision {
  return {
    requireSignature: true,
    requireTrusted: true,
    requireEvidence: {
      provenance: { origin: 'build-time', trustedKeys: [`SHA256:${KEY_RELEASE}`] },
      sbom: { required: true, trustedKeys: [`SHA256:${KEY_RELEASE}`] },
      runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] },
    },
    allowedRepositories: ['github.com/company/*'],
    runtimeOs: ['linux'],
    runtimeArch: ['x64'],
    denyObserved: ['process.exec', 'network.unrestricted'],
  }
}

/** Verified inputs that satisfy every constraint of `fullDecision()`. */
function fullInputs(): PolicyEvidenceInput {
  return {
    signature: { status: 'VALID', trust: 'VERIFIED' },
    executionTarget: { os: 'linux', arch: 'x64' },
    provenance: [{
      verified: true, keyId: KEY_RELEASE, statementDigest: 'sha256:' + '1'.repeat(64),
      origin: 'build-time', repository: 'github.com/company/app',
    }],
    sbom: [{
      verified: true, keyId: KEY_RELEASE, statementDigest: 'sha256:' + '2'.repeat(64),
      documentKey: '3'.repeat(64),
    }],
    attestation: [{
      verified: true, keyId: KEY_ATTESTOR, statementDigest: 'sha256:' + '4'.repeat(64),
      documentKey: '5'.repeat(64), coverage: 'complete',
      environment: { os: 'linux', arch: 'x64' }, observed: ['filesystem.read'],
    }],
  }
}

/** A verified provenance candidate (defaults mirror fullInputs). */
function provCand(over: Partial<ProvenanceCandidate> = {}): ProvenanceCandidate {
  return {
    verified: true, keyId: KEY_RELEASE, statementDigest: 'sha256:' + '1'.repeat(64),
    origin: 'build-time', repository: 'github.com/company/app', ...over,
  }
}

function sbomCand(over: Partial<SbomCandidate> = {}): SbomCandidate {
  return { verified: true, keyId: KEY_RELEASE, statementDigest: 'sha256:' + '2'.repeat(64), documentKey: '3'.repeat(64), ...over }
}

function attCand(over: Partial<AttestationCandidate> = {}): AttestationCandidate {
  return {
    verified: true, keyId: KEY_ATTESTOR, statementDigest: 'sha256:' + '4'.repeat(64),
    documentKey: '5'.repeat(64), coverage: 'complete',
    environment: { os: 'linux', arch: 'x64' }, observed: ['filesystem.read'], ...over,
  }
}

/** Write a trust.yaml into the temp home (v1 or v2). */
function writeTrustYaml(home: string, text: string): void {
  mkdirSync(home, { recursive: true })
  writeFileSync(join(home, 'trust.yaml'), text)
}

// --- T0–T15: the evaluation chain (pure) ---

describe('T0–T15: evaluateTrustPolicyV2 chain (pure)', () => {
  it('T0: every requirement satisfied → ALLOW with the full 16-step audit chain', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), fullInputs())
    expect(verdict.ok).toBe(true)
    expect(verdict.decision).toBe('ALLOW')
    expect(verdict.errors).toEqual([])
    expect(verdict.steps.every((s) => s.ok)).toBe(true)
    // the frozen 16-step chain (D106) — artifact trust and every evidence
    // issuer are audited separately (D109)
    const stepNames = verdict.steps.map((s) => s.step)
    expect(stepNames).toEqual([
      'artifact-signature', 'artifact-trust',
      'provenance-presence', 'provenance-signature', 'provenance-issuer', 'provenance-origin', 'source',
      'sbom-presence', 'sbom-signature', 'sbom-issuer',
      'attestation-presence', 'attestation-signature', 'attestation-issuer', 'attestation-coverage',
      'execution-target', 'capability-policy',
    ])
    expect(verdict.artifactTrust).toBe('VERIFIED')
    expect(verdict.evidenceTrust).toEqual({ provenance: 'VERIFIED', sbom: 'VERIFIED', attestation: 'VERIFIED' })
  })

  it('T1 (North-Star 1): valid signature + forbidden capability → DENY', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(),
      attestation: [attCand({ observed: ['filesystem.read', 'process.exec'] })],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'capability-policy')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('process.exec')
    // the signature itself was VALID — the DENY comes from the capability policy
    expect(verdict.steps.find((s) => s.step === 'artifact-signature')?.ok).toBe(true)
  })

  it('T3 (North-Star 3): trusted artifact + attested env ≠ current execution target → DENY (D111)', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(),
      attestation: [attCand({ environment: { os: 'darwin', arch: 'arm64' } })],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('darwin/arm64')
    expect(step?.reason).toContain('linux/x64')
    expect(verdict.steps.find((s) => s.step === 'artifact-trust')?.ok).toBe(true)
  })

  it('T5: required coverage complete but attestation partial → DENY (D102)', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(),
      attestation: [attCand({ coverage: 'partial' })],
    })
    expect(verdict.decision).toBe('DENY')
    expect(verdict.steps.find((s) => s.step === 'attestation-coverage')?.reason).toContain('partial < required complete')
  })

  it('D102 ordering: partial required + unknown actual → DENY; partial required + complete actual → ALLOW', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: { runtimeAttestation: { required: true, coverage: 'partial', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] } },
    }
    const unknown = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [attCand({ coverage: 'unknown' })],
    })
    expect(unknown.decision).toBe('DENY')
    expect(unknown.steps.find((s) => s.step === 'attestation-coverage')?.ok).toBe(false)
    const complete = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [attCand({ coverage: 'complete' })],
    })
    expect(complete.decision).toBe('ALLOW')
  })

  it('T4: requireEvidence.sbom but no sbom evidence → DENY (D101: missing = DENY)', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), { ...fullInputs(), sbom: [] })
    expect(verdict.decision).toBe('DENY')
    expect(verdict.steps.find((s) => s.step === 'sbom-presence')?.ok).toBe(false)
  })

  it('T6: provenance absent / origin not build-time → DENY', () => {
    const absent = evaluateTrustPolicyV2(fullDecision(), { ...fullInputs(), provenance: [] })
    expect(absent.decision).toBe('DENY')
    expect(absent.steps.find((s) => s.step === 'provenance-presence')?.ok).toBe(false)

    const wrongOrigin = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(), provenance: [provCand({ origin: 'post-build-receipt' })],
    })
    expect(wrongOrigin.decision).toBe('DENY')
    expect(wrongOrigin.steps.find((s) => s.step === 'provenance-origin')?.reason).toContain('post-build-receipt')
  })

  it('T7: denyObserved NOT hit + everything else satisfied → ALLOW', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), fullInputs())
    expect(verdict.decision).toBe('ALLOW')
    expect(verdict.steps.find((s) => s.step === 'capability-policy')?.ok).toBe(true)
  })

  it('D104: denyObserved consumes observed only — declared-but-not-observed is not denied', () => {
    const decision: TrustPolicyV2Decision = {
      denyObserved: ['process.exec'],
      requireEvidence: { runtimeAttestation: { required: true, trustedKeys: [`SHA256:${KEY_ATTESTOR}`] } },
    }
    const verdict = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [attCand({ observed: ['filesystem.read'] })],
    })
    expect(verdict.decision).toBe('ALLOW')
  })

  it('D100/D101: requireSignature + MISSING → DENY; requireTrusted + UNTRUSTED → DENY', () => {
    const decision: TrustPolicyV2Decision = { requireSignature: true, requireTrusted: true }
    const missing = evaluateTrustPolicyV2(decision, {
      ...fullInputs(), signature: { status: 'MISSING', trust: 'N/A' },
    })
    expect(missing.decision).toBe('DENY')
    expect(missing.steps.find((s) => s.step === 'artifact-signature')?.reason).toContain('missing')
    const untrusted = evaluateTrustPolicyV2(decision, {
      ...fullInputs(), signature: { status: 'VALID', trust: 'UNTRUSTED' },
    })
    expect(untrusted.decision).toBe('DENY')
    expect(untrusted.steps.find((s) => s.step === 'artifact-trust')?.ok).toBe(false)
  })

  it('T9 (D108): no weakening path — v2 constraints are enforced unconditionally', () => {
    // there is no CLI-like input that can turn OFF a file requirement: the
    // resolved decision carries the requirement and the evaluation enforces it
    const decision: TrustPolicyV2Decision = {
      requireEvidence: {
        runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] },
      },
    }
    const withTrustedSignature = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [attCand({ coverage: 'partial' })],
    })
    expect(withTrustedSignature.decision).toBe('DENY') // still DENY — nothing can loosen it
  })

  // ---- D109: Evidence Signature VALID ≠ Evidence Issuer TRUSTED ----

  it('T10: untrusted evidence issuer → DENY UNTRUSTED_EVIDENCE_ISSUER (North-Star)', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: { runtimeAttestation: { required: true, trustedKeys: [`SHA256:${KEY_ATTESTOR}`] } },
    }
    // cryptographically VALID + subject-bound, but signed by an unknown key
    const verdict = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [attCand({ keyId: KEY_ATTACKER })],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'attestation-issuer')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('UNTRUSTED_EVIDENCE_ISSUER')
    expect(verdict.evidenceTrust.attestation).toBe('UNTRUSTED')
    // the envelope itself was VALID — the DENY is purely the issuer boundary
    expect(verdict.steps.find((s) => s.step === 'attestation-signature')?.ok).toBe(true)
  })

  it('T10b: required evidence with NO trusted issuer configured → fail-closed DENY (D109)', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: { runtimeAttestation: { required: true } }, // no trustedKeys anywhere
    }
    const verdict = evaluateTrustPolicyV2(decision, fullInputs())
    expect(verdict.decision).toBe('DENY')
    expect(verdict.steps.find((s) => s.step === 'attestation-issuer')?.reason).toContain('no trusted issuer configured')
  })

  it('T11: artifact signer ≠ evidence signer — both trusted → ALLOW (no signer-equality coupling)', () => {
    const decision: TrustPolicyV2Decision = {
      requireSignature: true,
      requireTrusted: true,
      trustedKeys: [`SHA256:${KEY_RELEASE}`], // artifact signer only
      requireEvidence: { runtimeAttestation: { required: true, trustedKeys: [`SHA256:${KEY_ATTESTOR}`] } },
    }
    const verdict = evaluateTrustPolicyV2(decision, fullInputs())
    expect(verdict.decision).toBe('ALLOW')
    expect(verdict.steps.find((s) => s.step === 'artifact-trust')?.ok).toBe(true)
    expect(verdict.steps.find((s) => s.step === 'attestation-issuer')?.ok).toBe(true)
  })

  it('T11b: shared rule-level evidenceTrustedKeys fallback works for every type (D109)', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: {
        provenance: { origin: 'build-time' },
        sbom: { required: true },
        runtimeAttestation: { required: true, coverage: 'complete' },
      },
      evidenceTrustedKeys: [`SHA256:${KEY_RELEASE}`, `SHA256:${KEY_ATTESTOR}`],
    }
    const verdict = evaluateTrustPolicyV2(decision, fullInputs())
    expect(verdict.decision).toBe('ALLOW')
    expect(verdict.evidenceTrust).toEqual({ provenance: 'VERIFIED', sbom: 'VERIFIED', attestation: 'VERIFIED' })
  })

  // ---- D110: deterministic selection, ambiguity fail-closed ----

  it('T12: fake clean attestation from an untrusted issuer cannot override a trusted bad one', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: { runtimeAttestation: { required: true, trustedKeys: [`SHA256:${KEY_ATTESTOR}`] } },
      denyObserved: ['process.exec'],
    }
    // trusted attestation observed process.exec; attacker clean attestation observed []
    const verdict = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      attestation: [
        attCand({ documentKey: 'd'.repeat(64), observed: ['process.exec'] }),
        attCand({ keyId: KEY_ATTACKER, documentKey: 'e'.repeat(64), observed: [] }),
      ],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'capability-policy')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('process.exec') // the trusted evidence still drives the DENY
  })

  it('T13: two conflicting trusted attestations (same target/coverage/issuer) → DENY AMBIGUOUS', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(),
      attestation: [
        attCand({ documentKey: 'd'.repeat(64), observed: [] }),
        attCand({ documentKey: 'e'.repeat(64), observed: ['process.exec'] }),
      ],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('AMBIGUOUS')
  })

  it('T13b: two equivalent trusted candidates (same statement) are NOT ambiguous (D110)', () => {
    const verdict = evaluateTrustPolicyV2(fullDecision(), {
      ...fullInputs(),
      attestation: [
        attCand({ documentKey: '5'.repeat(64) }),
        attCand({ documentKey: '5'.repeat(64) }),
      ],
    })
    expect(verdict.decision).toBe('ALLOW')
  })

  it('D110 provenance: two conflicting trusted provenance statements → DENY AMBIGUOUS', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: { provenance: { origin: 'build-time', trustedKeys: [`SHA256:${KEY_RELEASE}`] } },
    }
    const verdict = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      provenance: [
        provCand({ statementDigest: 'sha256:' + '6'.repeat(64), repository: 'github.com/company/a' }),
        provCand({ statementDigest: 'sha256:' + '7'.repeat(64), repository: 'github.com/company/b' }),
      ],
    })
    expect(verdict.decision).toBe('DENY')
    expect(verdict.steps.find((s) => s.step === 'provenance-issuer')?.reason).toContain('AMBIGUOUS')
  })

  // ---- D111: execution-target binding ----

  it('T14: attestation for another platform — both platforms allowed by policy → still DENY', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: {
        runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] },
      },
      runtimeOs: ['linux', 'darwin'], // both are "theoretically allowed"
      runtimeArch: ['x64', 'arm64'],
    }
    // current execution target is linux/x64; the ONLY attestation is darwin/arm64
    const verdict = evaluateTrustPolicyV2(decision, {
      ...fullInputs(),
      executionTarget: { os: 'linux', arch: 'x64' },
      attestation: [attCand({ environment: { os: 'darwin', arch: 'arm64' } })],
    })
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('does not match current execution target')
  })

  it('T15: exact target match → PASS (execution-target binds current host target)', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: {
        runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] },
      },
      runtimeOs: ['linux'],
      runtimeArch: ['x64'],
    }
    const verdict = evaluateTrustPolicyV2(decision, fullInputs())
    expect(verdict.decision).toBe('ALLOW')
    expect(verdict.steps.find((s) => s.step === 'execution-target')?.ok).toBe(true)
  })

  it('D111: current target outside the policy matrix → DENY even with a matching attestation', () => {
    const decision: TrustPolicyV2Decision = {
      requireEvidence: {
        runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: [`SHA256:${KEY_ATTESTOR}`] },
      },
      runtimeOs: ['darwin'], // the current linux host is NOT allowed
      runtimeArch: ['arm64'],
    }
    const verdict = evaluateTrustPolicyV2(decision, fullInputs())
    expect(verdict.decision).toBe('DENY')
    const step = verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('not in allowed runtime matrix')
  })
})

// --- resolution + validation + loading ---

describe('D52/D53/D107: resolution, validation, loading', () => {
  it('D52: most-specific match wins (longest pattern)', () => {
    const policy = validateTrustPolicyV2({
      version: 2,
      registries: {
        'ghcr.io/company/*': { requireEvidence: { sbom: { required: true } } },
        'ghcr.io/company/prod-*': { requireEvidence: { runtimeAttestation: { required: true } } },
      },
    })
    expect(policy.ok).toBe(true)
    if (!policy.ok) return
    const decision = resolveTrustPolicyV2(policy.policy, 'ghcr.io/company/prod-app')
    expect(decision.matchedRule).toBe('ghcr.io/company/prod-*')
    expect(decision.requireEvidence?.runtimeAttestation?.required).toBe(true)
  })

  it('D53: no match → permissive defaults', () => {
    const policy = validateTrustPolicyV2({ version: 2, registries: { 'ghcr.io/company/*': { requireSignature: true } } })
    if (!policy.ok) return
    const decision = resolveTrustPolicyV2(policy.policy, 'docker.io/library/nginx')
    expect(decision.requireSignature).toBe(false)
    expect(decision.matchedRule).toBeUndefined()
  })

  it('D109: evidenceTrustedKeys resolves into the decision (shared fallback)', () => {
    const policy = validateTrustPolicyV2({
      version: 2,
      registries: {
        'ghcr.io/company/*': {
          evidenceTrustedKeys: ['SHA256:abc'],
          requireEvidence: { runtimeAttestation: { required: true } },
        },
      },
    })
    if (!policy.ok) return
    const decision = resolveTrustPolicyV2(policy.policy, 'ghcr.io/company/app')
    expect(decision.evidenceTrustedKeys).toEqual(['SHA256:abc'])
  })

  it('T8 (D107): version 1 file loads and resolves with v1 semantics', () => {
    const home = tempRoot('t8')
    writeTrustYaml(home, `version: ${TRUST_POLICY_VERSION}\nregistries:\n  "ghcr.io/company/*":\n    requireSignature: true\n`)
    const loaded = loadTrustPolicyFile(home)
    expect(loaded).toBeDefined()
    if (loaded === undefined) return
    expect((loaded as { version: number }).version).toBe(TRUST_POLICY_VERSION)
    const decision = resolveTrustPolicyV2(loaded, 'ghcr.io/company/prod-app')
    expect(decision.requireSignature).toBe(true)
    // v1 files carry no v2 constraints (D107 — additive only)
    expect(decision.requireEvidence).toBeUndefined()
    expect(decision.denyObserved).toBeUndefined()
  })

  it('validation: v2 schema rejects bad coverage / denyObserved / trustedKeys types', () => {
    const bad = validateTrustPolicyV2({
      version: 2,
      registries: {
        'ghcr.io/company/*': {
          requireEvidence: {
            runtimeAttestation: { coverage: '80%', trustedKeys: 'abc' },
            sbom: { required: 'yes' },
          },
          evidenceTrustedKeys: 'abc',
          capabilities: { denyObserved: 'process.exec' },
        },
      },
    })
    expect(bad.ok).toBe(false)
    if (bad.ok) return
    expect(bad.errors.some((e) => e.includes('coverage must be complete|partial|unknown'))).toBe(true)
    expect(bad.errors.some((e) => e.includes('denyObserved must be an array'))).toBe(true)
    expect(bad.errors.some((e) => e.includes('runtimeAttestation.trustedKeys must be an array of strings'))).toBe(true)
    expect(bad.errors.some((e) => e.includes('evidenceTrustedKeys must be an array of strings'))).toBe(true)
    expect(bad.errors.some((e) => e.includes('sbom.required must be boolean'))).toBe(true)
  })

  it('validation: v2 schema accepts the D109 per-type trustedKeys shape', () => {
    const ok = validateTrustPolicyV2({
      version: 2,
      registries: {
        'ghcr.io/company/*': {
          requireEvidence: {
            provenance: { required: true, origin: 'build-time', trustedKeys: ['SHA256:aa'] },
            sbom: { required: true, trustedKeys: ['SHA256:aa'] },
            runtimeAttestation: { required: true, coverage: 'complete', trustedKeys: ['SHA256:bb'] },
          },
          evidenceTrustedKeys: ['SHA256:aa', 'SHA256:bb'],
        },
      },
    })
    expect(ok.ok).toBe(true)
  })

  it('loading: missing file → undefined; unknown version → throws', () => {
    const home = tempRoot('t8b')
    expect(loadTrustPolicyFile(home)).toBeUndefined()
    writeTrustYaml(home, 'version: 3\nregistries: {}\n')
    expect(() => loadTrustPolicyFile(home)).toThrow(/version must be/)
  })
})

// --- service integration (packager.policy — verified inputs only, D100) ---

describe('packager.policy: service-level integration', () => {
  interface EvidenceSignSpec {
    type: 'build-provenance' | 'sbom' | 'attestation'
    statement: Record<string, unknown>
    key: string
  }

  /** Signed pack + full evidence collection in the default collection root. */
  async function buildSignedPackWithEvidence(
    root: string,
    opts: {
      coverage?: 'complete' | 'partial' | 'unknown'
      observed?: string[]
      environment?: { os: string; arch: string }
      evidenceKey?: string
      extra?: EvidenceSignSpec[]
    } = {},
  ): Promise<{ packFile: string; keyId: string; collectionRoot: string }> {
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const key = generateKeypair(root)
    const signed = await signPackFile(packFile, { key: key.privateKey })
    const evidence = new DefaultEvidenceService()
    const evidenceKey = opts.evidenceKey ?? key.privateKey
    await evidence.sign(signed.file, {
      type: 'build-provenance',
      statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/app' } },
      key: evidenceKey,
    })
    await evidence.sign(signed.file, {
      type: 'sbom',
      statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: 'a'.repeat(64) } },
      key: evidenceKey,
    })
    const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
    const env = opts.environment ?? { os: 'linux', arch: 'x64' }
    const doc = {
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'test' },
      coldBoot: { status: 'PASS' },
      observation: { coverage: opts.coverage ?? 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: opts.observed ?? [] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' },
      environment: { dsh: 'x', node: 'x', os: env.os, arch: env.arch },
      resultDigest: 'sha256:' + 'b'.repeat(64),
    }
    const docText = JSON.stringify(doc)
    const docHex = sha256Hex(docText)
    const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
    mkdirSync(dirname(docFile), { recursive: true })
    writeFileSync(docFile, docText)
    await evidence.sign(signed.file, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
      key: evidenceKey,
    })
    for (const extra of opts.extra ?? []) {
      await evidence.sign(signed.file, { type: extra.type, statement: extra.statement, key: extra.key })
    }
    return { packFile: signed.file, keyId: key.keyId, collectionRoot }
  }

  const EVIDENCE_TRUSTED_KEYS = (keyId: string): string => `    evidenceTrustedKeys:\n      - "SHA256:${keyId}"\n`

  it('T0 service: full verified chain → ALLOW', async () => {
    const root = tempRoot('svc-t0')
    const { packFile, keyId } = await buildSignedPackWithEvidence(root)
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
${EVIDENCE_TRUSTED_KEYS(keyId)}
    requireEvidence:
      provenance:
        origin: build-time
      sbom: true
      runtimeAttestation:
        required: true
        coverage: complete
    source:
      allowedRepositories:
        - "github.com/company/*"
    runtime:
      os: [linux]
      arch: [x64]
    capabilities:
      denyObserved:
        - process.exec
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(packFile, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.errors).toEqual([])
    expect(result.verdict.evidenceTrust).toEqual({ provenance: 'VERIFIED', sbom: 'VERIFIED', attestation: 'VERIFIED' })
    expect(result.executionTarget).toEqual({ os: 'linux', arch: 'x64' })
  })

  it('T2 (North-Star 2): contentHash unchanged + attestation document tampered → DENY', async () => {
    const root = tempRoot('svc-t2')
    const { packFile, keyId, collectionRoot } = await buildSignedPackWithEvidence(root)
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
${EVIDENCE_TRUSTED_KEYS(keyId)}
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
`)
    // attacker rewrites the attestation document (coverage lifted) — the
    // document digest no longer matches the envelope statement (D100)
    const docDir = join(collectionRoot, 'documents')
    const docName = readdirSync(docDir).filter((n) => n.endsWith('.json'))[0] as string
    const docPath = join(docDir, docName)
    const tampered = readFileSync(docPath, 'utf8').replace('"complete"', '"partial"')
    expect(tampered).not.toBe(readFileSync(docPath, 'utf8'))
    writeFileSync(docPath, tampered)

    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(packFile, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    // contentHash is unchanged — but the tampered evidence is no longer verified → DENY
    expect(result.contentHash).toBe(await computePackContentHash(readFileSync(packFile)))
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.steps.find((s) => s.step === 'attestation-signature')?.ok).toBe(false)
  })

  it('T4 service: requireEvidence.sbom but no sbom evidence → DENY', async () => {
    const root = tempRoot('svc-t4')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireEvidence:
      sbom: true
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(packFile, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.steps.find((s) => s.step === 'sbom-presence')?.ok).toBe(false)
  })

  it('T10 service: attestation signed by an attacker key → DENY UNTRUSTED_EVIDENCE_ISSUER', async () => {
    const root = tempRoot('svc-t10')
    const releaseKey = generateKeypair(join(root, 'release'))
    const attackerKey = generateKeypair(join(root, 'attacker'))
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const signed = await signPackFile(packFile, { key: releaseKey.privateKey })
    // provenance + sbom signed by the trusted release key; attestation signed
    // by the attacker key — artifact signature is VALID but the attestation
    // issuer is NOT in the policy's trusted keys (D109)
    const evidence = new DefaultEvidenceService()
    const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
    const docText = JSON.stringify({
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'test' },
      coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: [] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
      resultDigest: 'sha256:' + 'b'.repeat(64),
    })
    const docHex = sha256Hex(docText)
    const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
    mkdirSync(dirname(docFile), { recursive: true })
    writeFileSync(docFile, docText)
    await evidence.sign(signed.file, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
      key: attackerKey.privateKey,
    })
    // sign provenance + sbom with the trusted release key against `signed.file`
    await evidence.sign(signed.file, {
      type: 'build-provenance',
      statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/app' } },
      key: releaseKey.privateKey,
    })
    await evidence.sign(signed.file, {
      type: 'sbom',
      statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: 'a'.repeat(64) } },
      key: releaseKey.privateKey,
    })

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKey.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        trustedKeys:
          - "SHA256:${releaseKey.keyId}"
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(signed.file, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('DENY')
    const step = result.verdict.steps.find((s) => s.step === 'attestation-issuer')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('UNTRUSTED_EVIDENCE_ISSUER')
  })

  it('T11 service: artifact signer ≠ evidence signer, both trusted → ALLOW', async () => {
    const root = tempRoot('svc-t11')
    const releaseKey = generateKeypair(join(root, 'release'))
    const attestorKey = generateKeypair(join(root, 'attestor'))
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const signed = await signPackFile(packFile, { key: releaseKey.privateKey })
    const evidence = new DefaultEvidenceService()
    await evidence.sign(signed.file, {
      type: 'build-provenance',
      statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/app' } },
      key: attestorKey.privateKey,
    })
    await evidence.sign(signed.file, {
      type: 'sbom',
      statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: 'a'.repeat(64) } },
      key: attestorKey.privateKey,
    })
    const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
    const docText = JSON.stringify({
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'test' },
      coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: [] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
      resultDigest: 'sha256:' + 'b'.repeat(64),
    })
    const docHex = sha256Hex(docText)
    const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
    mkdirSync(dirname(docFile), { recursive: true })
    writeFileSync(docFile, docText)
    await evidence.sign(signed.file, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
      key: attestorKey.privateKey,
    })

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKey.keyId}"
    requireEvidence:
      provenance:
        origin: build-time
      sbom: true
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${attestorKey.keyId}"
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(signed.file, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('ALLOW')
  })

  it('T12 service: trusted bad attestation beats attacker clean attestation → DENY on process.exec', async () => {
    const root = tempRoot('svc-t12')
    const trustedKey = generateKeypair(join(root, 'trusted'))
    const attackerKey = generateKeypair(join(root, 'attacker'))
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const signed = await signPackFile(packFile, { key: trustedKey.privateKey })
    const evidence = new DefaultEvidenceService()
    const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
    const docText = JSON.stringify({
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'test' },
      coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: ['process.exec'] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
      resultDigest: 'sha256:' + 'b'.repeat(64),
    })
    const docHex = sha256Hex(docText)
    const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
    mkdirSync(dirname(docFile), { recursive: true })
    writeFileSync(docFile, docText)
    await evidence.sign(signed.file, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
      key: trustedKey.privateKey,
    })
    // attacker appends a CLEAN attestation for the same artifact
    const cleanDoc = JSON.stringify({
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'fake' },
      coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: [] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
      resultDigest: 'sha256:' + 'b'.repeat(64),
    })
    const cleanHex = sha256Hex(cleanDoc)
    const cleanFile = join(collectionRoot, 'documents', `${cleanHex}.attestation.json`)
    writeFileSync(cleanFile, cleanDoc)
    await evidence.sign(signed.file, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: cleanHex } },
      key: attackerKey.privateKey,
    })

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${trustedKey.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
        trustedKeys:
          - "SHA256:${trustedKey.keyId}"
    capabilities:
      denyObserved:
        - process.exec
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(signed.file, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('DENY')
    const step = result.verdict.steps.find((s) => s.step === 'capability-policy')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('process.exec')
  })

  it('T13 service: two conflicting trusted attestations → DENY AMBIGUOUS', async () => {
    const root = tempRoot('svc-t13')
    const trustedKey = generateKeypair(root)
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const signed = await signPackFile(packFile, { key: trustedKey.privateKey })
    const evidence = new DefaultEvidenceService()
    const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
    const mkAttestation = async (providers: string[], runId: string): Promise<void> => {
      const doc = JSON.stringify({
        schemaVersion: 1, subject: { contentHash: 'ignored' },
        metadata: { observedAt: '2026-08-30T00:00:00Z', runId },
        coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
        observed: { tools: [], skills: [], services: [], providers },
        comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
        effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
        cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
        resultDigest: 'sha256:' + 'b'.repeat(64),
      })
      const hex = sha256Hex(doc)
      const file = join(collectionRoot, 'documents', `${hex}.attestation.json`)
      mkdirSync(dirname(file), { recursive: true })
      writeFileSync(file, doc)
      await evidence.sign(signed.file, {
        type: 'attestation',
        statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: hex } },
        key: trustedKey.privateKey,
      })
    }
    await mkAttestation([], 'run-1')
    await mkAttestation(['process.exec'], 'run-2')

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${trustedKey.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
        trustedKeys:
          - "SHA256:${trustedKey.keyId}"
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(signed.file, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('DENY')
    const step = result.verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('AMBIGUOUS')
  })

  it('T14 service: wrong execution target → DENY even though the policy allows both platforms', async () => {
    const root = tempRoot('svc-t14')
    const { packFile, keyId } = await buildSignedPackWithEvidence(root, { environment: { os: 'darwin', arch: 'arm64' } })
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
${EVIDENCE_TRUSTED_KEYS(keyId)}
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
    runtime:
      os: [linux, darwin]
      arch: [x64, arm64]
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(packFile, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('DENY')
    const step = result.verdict.steps.find((s) => s.step === 'execution-target')
    expect(step?.ok).toBe(false)
    expect(step?.reason).toContain('does not match current execution target')
  })

  it('T15 service: exact target match → ALLOW', async () => {
    const root = tempRoot('svc-t15')
    const { packFile, keyId } = await buildSignedPackWithEvidence(root)
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
${EVIDENCE_TRUSTED_KEYS(keyId)}
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
    runtime:
      os: [linux]
      arch: [x64]
`)
    const packager = new DefaultPackager({ home, installedDshVersion: '0.1.0-rc.5' })
    const result = await packager.policy(packFile, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.steps.find((s) => s.step === 'execution-target')?.ok).toBe(true)
  })
})
