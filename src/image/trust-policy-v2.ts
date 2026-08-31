/**
 * v0.5 beta.2 trust.yaml v2 — Trust Policy Binding (DESIGN-v0.5.0.md §10,
 * D100–D111). The v2 policy extends the v0.4.2 local policy (trust-policy.ts)
 * with evidence requirements, runtime matrix and capability constraints; the
 * EVALUATION chain only consumes ALREADY-VERIFIED evidence (D100 — the caller
 * verifies envelopes + subject binding before passing inputs here). Missing
 * required evidence is DENY, never "skip" (D101); coverage is compared
 * complete > partial > unknown (D102); runtime matrix is a compatibility gate,
 * not identity (D103); denyObserved consumes observed capabilities only
 * (D104).
 *
 * D109: Evidence Signature VALID ≠ Evidence Issuer TRUSTED — each required
 * evidence type must resolve a trusted issuer list (per-type trustedKeys, or
 * the rule-level evidenceTrustedKeys fallback; the artifact trustedKeys are
 * NEVER reused for evidence). No trusted issuer configured → fail-closed DENY.
 *
 * D110: Evidence candidate selection is deterministic and fail-closed — 0
 * trusted candidates → DENY; >1 trusted candidates with non-equivalent
 * statements/documents → DENY AMBIGUOUS (no first/latest-wins; digest pinning
 * is future work).
 *
 * D111: a consumed runtime attestation's environment must exactly match the
 * current execution target (three-way: attested env == current target ∈
 * policy runtime matrix).
 *
 * v1 files keep their exact semantics (D107).
 * @module @why-daydream/dsh-pack/image/trust-policy-v2
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import YAML from 'yaml'
import {
  TRUST_POLICY_FILE, TRUST_POLICY_VERSION,
  patternMatches, validateTrustPolicy, type TrustPolicyDecision, type TrustPolicyFile,
} from './trust-policy.ts'

export const TRUST_POLICY_V2_VERSION = 2

/** D102: coverage is an ordered quality — partial < complete, unknown < any. */
const COVERAGE_ORDER: Record<'complete' | 'partial' | 'unknown', number> = {
  unknown: 0, partial: 1, complete: 2,
}

/** Evidence requirements of one v2 rule (all optional — present = enforced). */
export interface TrustPolicyV2Evidence {
  /** Provenance (build-time capture + source). Presence of the block = required unless `required: false` (D101). */
  provenance?: { required?: boolean; origin?: string; trustedKeys?: string[] }
  /** `true` = required (short form, D101); object form adds the D109 issuer pin. */
  sbom?: boolean | { required?: boolean; trustedKeys?: string[] }
  runtimeAttestation?: { required?: boolean; coverage?: 'complete' | 'partial' | 'unknown'; trustedKeys?: string[] }
}

/** One registry rule — v1 fields (D107) plus the v2 constraints. */
export interface TrustPolicyV2Rule {
  requireSignature?: boolean
  requireTrusted?: boolean
  /** Artifact signer fingerprints — NEVER reused as evidence trust (D109). */
  trustedKeys?: string[]
  /** D109: shared trusted evidence issuers — fallback when a type has no per-type trustedKeys. */
  evidenceTrustedKeys?: string[]
  requireEvidence?: TrustPolicyV2Evidence
  source?: { allowedRepositories?: string[] }
  runtime?: { os?: string[]; arch?: string[] }
  capabilities?: { denyObserved?: string[] }
}

/** The frozen trust.yaml v2 schema (§10.2). */
export interface TrustPolicyV2File {
  version: 2
  registries: Record<string, TrustPolicyV2Rule>
}

/** A resolved v2 decision for one repository (most-specific match wins, D52). */
export interface TrustPolicyV2Decision extends TrustPolicyDecision {
  requireEvidence?: TrustPolicyV2Evidence
  /** D109: shared trusted evidence issuer fallback. */
  evidenceTrustedKeys?: string[]
  allowedRepositories?: string[]
  runtimeOs?: string[]
  runtimeArch?: string[]
  denyObserved?: string[]
}

/** One evidence candidate discovered in the collection for this artifact (D100/D110). */
export interface EvidenceCandidate {
  /** D100: envelope self-integrity + subject == contentHash verified (attestation additionally requires the document digest match). */
  verified: boolean
  /** The verified signer fingerprint (64 hex, recomputed from the embedded public key) — '' when unverified. */
  keyId: string
  /** The envelope's canonical statement digest — D110 equivalence key for provenance. */
  statementDigest: string
}

/** A verified/unverified build-provenance candidate. */
export interface ProvenanceCandidate extends EvidenceCandidate {
  origin?: string
  repository?: string
}

/** A verified/unverified SBOM candidate — documentKey is the D110 semantic document key. */
export interface SbomCandidate extends EvidenceCandidate {
  documentKey?: string
}

/**
 * A verified/unverified runtime-attestation candidate. Per D125 the semantic
 * identity of an attestation is the normalized resultDigest + execution target
 * + coverage — NOT the document digest (the document embeds non-deterministic
 * run metadata, D96, so two runs that observed the same facts have different
 * document digests). `semanticKey` carries that identity; `documentKey` keeps
 * the raw document digest for audit/tests.
 */
export interface AttestationCandidate extends EvidenceCandidate {
  documentKey?: string
  /** D125 semantic identity: normalized resultDigest + os/arch target + coverage. */
  semanticKey?: string
  coverage?: 'complete' | 'partial' | 'unknown'
  environment?: { os: string; arch: string }
  observed: string[]
}

/**
 * Verified inputs the policy is allowed to consume (D100). The CALLER is
 * responsible for verifying each envelope (self-integrity + subject binding +
 * attestation document digest) and passing every candidate — verified AND
 * unverified — so the evaluation can report presence / signature / issuer
 * separately (D106) and select deterministically (D110).
 */
export interface PolicyEvidenceInput {
  /** Verified signature state (VALID ≠ TRUSTED is preserved, D19). */
  signature: { status: 'VALID' | 'INVALID' | 'MISSING'; trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A' }
  /** D111: the current execution target (process.platform / process.arch at policy time). */
  executionTarget: { os: string; arch: string }
  /** All discovered build-provenance candidates, sorted deterministically by file name. */
  provenance: ProvenanceCandidate[]
  /** All discovered sbom candidates, sorted deterministically by file name. */
  sbom: SbomCandidate[]
  /** All discovered runtime-attestation candidates, sorted deterministically by file name. */
  attestation: AttestationCandidate[]
}

/** One auditable evaluation step (D106). */
export interface PolicyStep {
  step: string
  ok: boolean
  reason?: string
}

/** Per-evidence-type issuer trust summary (D109) — surfaced by /pack policy. */
export type EvidenceIssuerStatus = 'VERIFIED' | 'UNTRUSTED' | 'AMBIGUOUS' | 'ABSENT' | 'N/A'

/** The explicit, auditable outcome: ALLOW / DENY with the step chain (D106). */
export interface TrustPolicyV2Verdict {
  ok: boolean
  decision: 'ALLOW' | 'DENY'
  steps: PolicyStep[]
  errors: string[]
  /** The artifact signature status (from the verified v0.3/v0.4 section). */
  signature: 'VALID' | 'INVALID' | 'MISSING'
  /** D109: artifact signer trust summary. */
  artifactTrust: 'VERIFIED' | 'UNTRUSTED' | 'N/A'
  /** D109: per-evidence-type issuer trust summary. */
  evidenceTrust: { provenance: EvidenceIssuerStatus; sbom: EvidenceIssuerStatus; attestation: EvidenceIssuerStatus }
}

/** The full `/pack policy` outcome for one artifact (verified inputs only, D100). */
export interface PolicyEvaluationResult {
  contentHash: string
  /** The repository the policy was resolved for (provenance source by default). */
  repository: string
  decision: TrustPolicyV2Decision
  verdict: TrustPolicyV2Verdict
  /** D111: the execution target the policy was evaluated against. */
  executionTarget: { os: string; arch: string }
}

/** Normalize a key fingerprint (`SHA256:<hex>` / `sha256:<hex>` / bare hex → lowercase hex, D55-style). */
function normalizeKeyFingerprint(k: string): string {
  return k.toLowerCase().replace(/^sha256:/, '')
}

/** D109: is the verified signer fingerprint in the policy's trusted issuer list? */
function keyInList(keyId: string, keys: string[]): boolean {
  const want = normalizeKeyFingerprint(keyId)
  return keys.some((k) => normalizeKeyFingerprint(k) === want)
}

/**
 * D109: the effective trusted issuer list for one evidence type — per-type
 * trustedKeys first, then the rule-level evidenceTrustedKeys fallback. The
 * artifact trustedKeys are NEVER consulted for evidence (different roles:
 * Release Key vs Builder Key vs Attestor Key).
 */
function evidenceTrustedKeysFor(
  decision: TrustPolicyV2Decision,
  type: 'provenance' | 'sbom' | 'attestation',
): string[] | undefined {
  const evidence = decision.requireEvidence
  if (evidence === undefined) return undefined
  let perType: string[] | undefined
  if (type === 'provenance') perType = evidence.provenance?.trustedKeys
  else if (type === 'sbom') perType = typeof evidence.sbom === 'object' && evidence.sbom !== null ? evidence.sbom.trustedKeys : undefined
  else perType = evidence.runtimeAttestation?.trustedKeys
  if (perType !== undefined && perType.length > 0) return [...perType]
  if (decision.evidenceTrustedKeys !== undefined && decision.evidenceTrustedKeys.length > 0) return [...decision.evidenceTrustedKeys]
  return undefined
}

/** Load `$DSH_HOME/trust.yaml` in either version (D107: v1 keeps its semantics). */
export function loadTrustPolicyFile(home: string): TrustPolicyFile | TrustPolicyV2File | undefined {
  const file = join(home, TRUST_POLICY_FILE)
  if (!existsSync(file)) return undefined
  let parsed: unknown
  try {
    parsed = YAML.parse(readFileSync(file, 'utf8'))
  } catch {
    throw new Error(`invalid trust.yaml: not parseable YAML`)
  }
  const version = (parsed as { version?: unknown } | null)?.version
  if (version === TRUST_POLICY_VERSION) {
    const v1 = validateTrustPolicy(parsed)
    if (!v1.ok) throw new Error(`invalid trust.yaml: ${v1.errors.join('; ')}`)
    return v1.policy
  }
  if (version === TRUST_POLICY_V2_VERSION) {
    const v2 = validateTrustPolicyV2(parsed)
    if (!v2.ok) throw new Error(`invalid trust.yaml: ${v2.errors.join('; ')}`)
    return v2.policy
  }
  throw new Error(`invalid trust.yaml: version must be ${TRUST_POLICY_VERSION} or ${TRUST_POLICY_V2_VERSION}`)
}

const TRUSTED_KEYS_FIELD = 'trustedKeys must be an array of strings'

/** Validate an unknown value as the frozen trust.yaml v2 schema (§10.2). */
export function validateTrustPolicyV2(
  value: unknown,
): { ok: true; policy: TrustPolicyV2File } | { ok: false; errors: string[] } {
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['trust.yaml is not an object'] }
  const v = value as Record<string, unknown>
  const errors: string[] = []

  if (v.version !== TRUST_POLICY_V2_VERSION) errors.push(`version must be ${TRUST_POLICY_V2_VERSION}`)
  if (v.registries === null || typeof v.registries !== 'object') {
    errors.push('registries must be an object')
  } else {
    for (const [pattern, rawRule] of Object.entries(v.registries as Record<string, unknown>)) {
      const rule = rawRule as Record<string, unknown> | undefined
      if (rule === null || typeof rule !== 'object') {
        errors.push(`rule ${JSON.stringify(pattern)} must be an object`)
        continue
      }
      if (rule.requireSignature !== undefined && typeof rule.requireSignature !== 'boolean') {
        errors.push(`rule ${JSON.stringify(pattern)}: requireSignature must be boolean`)
      }
      if (rule.requireTrusted !== undefined && typeof rule.requireTrusted !== 'boolean') {
        errors.push(`rule ${JSON.stringify(pattern)}: requireTrusted must be boolean`)
      }
      if (rule.trustedKeys !== undefined) {
        if (!Array.isArray(rule.trustedKeys) || rule.trustedKeys.some((k) => typeof k !== 'string')) {
          errors.push(`rule ${JSON.stringify(pattern)}: ${TRUSTED_KEYS_FIELD}`)
        }
      }
      if (rule.evidenceTrustedKeys !== undefined) {
        if (!Array.isArray(rule.evidenceTrustedKeys) || rule.evidenceTrustedKeys.some((k) => typeof k !== 'string')) {
          errors.push(`rule ${JSON.stringify(pattern)}: evidenceTrustedKeys must be an array of strings`)
        }
      }
      if (rule.requireEvidence !== undefined) {
        const evidence = rule.requireEvidence as Record<string, unknown> | null
        if (evidence === null || typeof evidence !== 'object') {
          errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence must be an object`)
        } else {
          if (evidence.provenance !== undefined) {
            const provenance = evidence.provenance as Record<string, unknown> | null
            if (provenance === null || typeof provenance !== 'object') {
              errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.provenance must be an object`)
            } else {
              if (provenance.required !== undefined && typeof provenance.required !== 'boolean') {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.provenance.required must be boolean`)
              }
              if (provenance.origin !== undefined && typeof provenance.origin !== 'string') {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.provenance.origin must be a string`)
              }
              if (provenance.trustedKeys !== undefined
                && (!Array.isArray(provenance.trustedKeys) || provenance.trustedKeys.some((k) => typeof k !== 'string'))) {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.provenance.${TRUSTED_KEYS_FIELD}`)
              }
            }
          }
          if (evidence.sbom !== undefined) {
            const sbom = evidence.sbom as boolean | Record<string, unknown> | null
            if (typeof sbom !== 'boolean') {
              if (sbom === null || typeof sbom !== 'object') {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.sbom must be boolean or an object`)
              } else {
                if (sbom.required !== undefined && typeof sbom.required !== 'boolean') {
                  errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.sbom.required must be boolean`)
                }
                if (sbom.trustedKeys !== undefined
                  && (!Array.isArray(sbom.trustedKeys) || sbom.trustedKeys.some((k) => typeof k !== 'string'))) {
                  errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.sbom.${TRUSTED_KEYS_FIELD}`)
                }
              }
            }
          }
          if (evidence.runtimeAttestation !== undefined) {
            const attestation = evidence.runtimeAttestation as Record<string, unknown> | null
            if (attestation === null || typeof attestation !== 'object') {
              errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.runtimeAttestation must be an object`)
            } else {
              if (attestation.required !== undefined && typeof attestation.required !== 'boolean') {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.runtimeAttestation.required must be boolean`)
              }
              if (attestation.coverage !== undefined
                && !['complete', 'partial', 'unknown'].includes(String(attestation.coverage))) {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.runtimeAttestation.coverage must be complete|partial|unknown`)
              }
              if (attestation.trustedKeys !== undefined
                && (!Array.isArray(attestation.trustedKeys) || attestation.trustedKeys.some((k) => typeof k !== 'string'))) {
                errors.push(`rule ${JSON.stringify(pattern)}: requireEvidence.runtimeAttestation.${TRUSTED_KEYS_FIELD}`)
              }
            }
          }
        }
      }
      if (rule.source !== undefined) {
        const source = rule.source as Record<string, unknown> | null
        if (source === null || typeof source !== 'object') {
          errors.push(`rule ${JSON.stringify(pattern)}: source must be an object`)
        } else if (source.allowedRepositories !== undefined
          && (!Array.isArray(source.allowedRepositories) || source.allowedRepositories.some((r) => typeof r !== 'string'))) {
          errors.push(`rule ${JSON.stringify(pattern)}: source.allowedRepositories must be an array of strings`)
        }
      }
      if (rule.runtime !== undefined) {
        const runtime = rule.runtime as Record<string, unknown> | null
        if (runtime === null || typeof runtime !== 'object') {
          errors.push(`rule ${JSON.stringify(pattern)}: runtime must be an object`)
        } else {
          for (const key of ['os', 'arch'] as const) {
            if (runtime[key] !== undefined && (!Array.isArray(runtime[key]) || runtime[key]!.some((x) => typeof x !== 'string'))) {
              errors.push(`rule ${JSON.stringify(pattern)}: runtime.${key} must be an array of strings`)
            }
          }
        }
      }
      if (rule.capabilities !== undefined) {
        const capabilities = rule.capabilities as Record<string, unknown> | null
        if (capabilities === null || typeof capabilities !== 'object') {
          errors.push(`rule ${JSON.stringify(pattern)}: capabilities must be an object`)
        } else if (capabilities.denyObserved !== undefined
          && (!Array.isArray(capabilities.denyObserved) || capabilities.denyObserved.some((c) => typeof c !== 'string'))) {
          errors.push(`rule ${JSON.stringify(pattern)}: capabilities.denyObserved must be an array of strings`)
        }
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, policy: value as unknown as TrustPolicyV2File }
}

/**
 * Resolve the decision for one repository from a v1 OR v2 policy file.
 * Most-specific match wins (D52); no match → permissive v0.4.1 defaults (D53).
 */
export function resolveTrustPolicyV2(
  policy: TrustPolicyFile | TrustPolicyV2File | undefined,
  remoteRepository: string,
): TrustPolicyV2Decision {
  if (policy === undefined) return { requireSignature: false, requireTrusted: false }
  const matches: { pattern: string; rule: Record<string, unknown> }[] = []
  for (const [pattern, rule] of Object.entries(policy.registries)) {
    if (patternMatches(pattern, remoteRepository)) matches.push({ pattern, rule: rule as unknown as Record<string, unknown> })
  }
  if (matches.length === 0) return { requireSignature: false, requireTrusted: false } // D53

  matches.sort((a, b) => b.pattern.length - a.pattern.length || a.pattern.localeCompare(b.pattern))
  const best = matches[0]!.rule
  const decision: TrustPolicyV2Decision = {
    requireSignature: best.requireSignature === true,
    requireTrusted: best.requireTrusted === true,
    ...(Array.isArray(best.trustedKeys) && best.trustedKeys.length > 0 ? { trustedKeys: [...best.trustedKeys as string[]] } : {}),
    ...(Array.isArray(best.evidenceTrustedKeys) && best.evidenceTrustedKeys.length > 0
      ? { evidenceTrustedKeys: [...best.evidenceTrustedKeys as string[]] }
      : {}),
    matchedRule: matches[0]!.pattern,
  }
  const evidence = best.requireEvidence as TrustPolicyV2Evidence | undefined
  if (evidence !== undefined && typeof evidence === 'object') decision.requireEvidence = evidence
  const source = best.source as { allowedRepositories?: string[] } | undefined
  if (source !== undefined && typeof source === 'object' && Array.isArray(source.allowedRepositories)) {
    decision.allowedRepositories = [...source.allowedRepositories]
  }
  const runtime = best.runtime as { os?: string[]; arch?: string[] } | undefined
  if (runtime !== undefined && typeof runtime === 'object') {
    if (Array.isArray(runtime.os)) decision.runtimeOs = [...runtime.os]
    if (Array.isArray(runtime.arch)) decision.runtimeArch = [...runtime.arch]
  }
  const capabilities = best.capabilities as { denyObserved?: string[] } | undefined
  if (capabilities !== undefined && typeof capabilities === 'object' && Array.isArray(capabilities.denyObserved)) {
    decision.denyObserved = [...capabilities.denyObserved]
  }
  return decision
}

/**
 * The full evaluation chain (D100–D111): artifact signature → artifact trust →
 * per-evidence-type presence / signature / issuer (D109) / origin / coverage →
 * source → execution-target (D111, three-way match) → capability policy →
 * ALLOW / DENY. Evidence candidates are selected deterministically (D110):
 * 0 trusted = DENY, >1 non-equivalent = DENY AMBIGUOUS. Every step is recorded
 * for audit (D106); any failed step makes the verdict DENY.
 */
export function evaluateTrustPolicyV2(
  decision: TrustPolicyV2Decision,
  input: PolicyEvidenceInput,
): TrustPolicyV2Verdict {
  const steps: PolicyStep[] = []
  const errors: string[] = []

  const fail = (step: string, reason: string): void => {
    steps.push({ step, ok: false, reason })
    errors.push(reason)
  }
  const pass = (step: string): void => { steps.push({ step, ok: true }) }
  const cannotEvaluate = (step: string, upstream: string): void =>
    fail(step, `cannot evaluate: ${upstream} failed`)

  const evidenceTrust = {
    provenance: 'N/A' as EvidenceIssuerStatus,
    sbom: 'N/A' as EvidenceIssuerStatus,
    attestation: 'N/A' as EvidenceIssuerStatus,
  }

  // 1. artifact signature (D29/D19 preserved: VALID ≠ TRUSTED)
  if (decision.requireSignature) {
    if (input.signature.status === 'VALID') pass('artifact-signature')
    else fail('artifact-signature', `signature required but ${input.signature.status === 'MISSING' ? 'missing' : 'invalid'}`)
  } else {
    pass('artifact-signature')
  }

  // 2. trusted artifact signer
  if (decision.requireTrusted) {
    if (input.signature.trust === 'VERIFIED') pass('artifact-trust')
    else fail('artifact-trust', 'trusted key required but signer is not verified')
  } else {
    pass('artifact-trust')
  }

  // ---- provenance: presence → signature → issuer (D109+D110) → origin (D101) ----
  const provConfig = decision.requireEvidence?.provenance
  const provRequired = provConfig !== undefined && provConfig.required !== false
  const provConsumed = provRequired
    || (decision.allowedRepositories !== undefined && decision.allowedRepositories.length > 0)
  let provSelected: ProvenanceCandidate | undefined
  if (!provConsumed) {
    pass('provenance-presence'); pass('provenance-signature'); pass('provenance-issuer'); pass('provenance-origin')
  } else if (input.provenance.length === 0) {
    if (provRequired) {
      fail('provenance-presence', 'build provenance evidence required but absent')
      evidenceTrust.provenance = 'ABSENT'
      cannotEvaluate('provenance-signature', 'provenance-presence')
      cannotEvaluate('provenance-issuer', 'provenance-presence')
      cannotEvaluate('provenance-origin', 'provenance-presence')
    } else {
      pass('provenance-presence'); pass('provenance-signature'); pass('provenance-issuer'); pass('provenance-origin')
    }
  } else {
    pass('provenance-presence')
    const verified = input.provenance.filter((c) => c.verified)
    if (verified.length === 0) {
      fail('provenance-signature', 'no provenance candidate passed envelope + subject verification')
      evidenceTrust.provenance = 'ABSENT'
      cannotEvaluate('provenance-issuer', 'provenance-signature')
      cannotEvaluate('provenance-origin', 'provenance-signature')
    } else {
      pass('provenance-signature')
      const keys = evidenceTrustedKeysFor(decision, 'provenance')
      if (keys === undefined || keys.length === 0) {
        fail('provenance-issuer', 'no trusted issuer configured for provenance evidence (D109: VALID ≠ TRUSTED)')
        evidenceTrust.provenance = 'UNTRUSTED'
        cannotEvaluate('provenance-origin', 'provenance-issuer')
      } else {
        const trusted = verified.filter((c) => c.keyId !== '' && keyInList(c.keyId, keys))
        if (trusted.length === 0) {
          fail('provenance-issuer', `UNTRUSTED_EVIDENCE_ISSUER: provenance signed by ${verified.map((c) => `SHA256:${c.keyId}`).join(', ')} — none in trustedKeys`)
          evidenceTrust.provenance = 'UNTRUSTED'
          cannotEvaluate('provenance-origin', 'provenance-issuer')
        } else {
          const distinct = new Set(trusted.map((c) => c.statementDigest))
          if (distinct.size > 1) {
            fail('provenance-issuer', `AMBIGUOUS: ${trusted.length} trusted provenance candidates with ${distinct.size} non-equivalent statements (D110)`)
            evidenceTrust.provenance = 'AMBIGUOUS'
            cannotEvaluate('provenance-origin', 'provenance-issuer')
          } else {
            pass('provenance-issuer')
            provSelected = trusted[0]!
            evidenceTrust.provenance = 'VERIFIED'
            const originRequired = provConfig?.origin
            if (originRequired !== undefined && provSelected.origin !== originRequired) {
              fail('provenance-origin', `provenance origin ${JSON.stringify(provSelected.origin)} does not satisfy required ${JSON.stringify(originRequired)}`)
            } else {
              pass('provenance-origin')
            }
          }
        }
      }
    }
  }

  // 3. source (D105) — consumes the selected provenance's repository
  if (decision.allowedRepositories !== undefined && decision.allowedRepositories.length > 0) {
    if (provSelected === undefined) {
      fail('source', 'allowedRepositories set but no trusted provenance repository available')
    } else if (decision.allowedRepositories.some((pattern) => patternMatches(pattern, provSelected.repository ?? ''))) {
      pass('source')
    } else {
      fail('source', `repository ${JSON.stringify(provSelected.repository)} not in allowedRepositories`)
    }
  } else {
    pass('source')
  }

  // ---- sbom: presence → signature → issuer (D109+D110) ----
  const sbomConfig = decision.requireEvidence?.sbom
  const sbomObject = typeof sbomConfig === 'object' && sbomConfig !== null ? sbomConfig : undefined
  const sbomRequired = sbomConfig === true || (sbomObject !== undefined && sbomObject.required !== false)
  if (!sbomRequired) {
    pass('sbom-presence'); pass('sbom-signature'); pass('sbom-issuer')
  } else if (input.sbom.length === 0) {
    fail('sbom-presence', 'sbom evidence required but absent')
    evidenceTrust.sbom = 'ABSENT'
    cannotEvaluate('sbom-signature', 'sbom-presence')
    cannotEvaluate('sbom-issuer', 'sbom-presence')
  } else {
    pass('sbom-presence')
    const verified = input.sbom.filter((c) => c.verified)
    if (verified.length === 0) {
      fail('sbom-signature', 'no sbom candidate passed envelope + subject verification')
      evidenceTrust.sbom = 'ABSENT'
      cannotEvaluate('sbom-issuer', 'sbom-signature')
    } else {
      pass('sbom-signature')
      const keys = evidenceTrustedKeysFor(decision, 'sbom')
      if (keys === undefined || keys.length === 0) {
        fail('sbom-issuer', 'no trusted issuer configured for sbom evidence (D109: VALID ≠ TRUSTED)')
        evidenceTrust.sbom = 'UNTRUSTED'
      } else {
        const trusted = verified.filter((c) => c.keyId !== '' && keyInList(c.keyId, keys))
        if (trusted.length === 0) {
          fail('sbom-issuer', `UNTRUSTED_EVIDENCE_ISSUER: sbom signed by ${verified.map((c) => `SHA256:${c.keyId}`).join(', ')} — none in trustedKeys`)
          evidenceTrust.sbom = 'UNTRUSTED'
        } else {
          const distinct = new Set(trusted.map((c) => c.documentKey ?? c.statementDigest))
          if (distinct.size > 1) {
            fail('sbom-issuer', `AMBIGUOUS: ${trusted.length} trusted sbom candidates with ${distinct.size} distinct documents (D110)`)
            evidenceTrust.sbom = 'AMBIGUOUS'
          } else {
            pass('sbom-issuer')
            evidenceTrust.sbom = 'VERIFIED'
          }
        }
      }
    }
  }

  // ---- runtime attestation: presence → signature → issuer (D109) → coverage (D102) → execution-target (D111+D110) ----
  const attConfig = decision.requireEvidence?.runtimeAttestation
  const attRequired = attConfig?.required === true
  const attConsumed = attConfig !== undefined
    || (decision.denyObserved !== undefined && decision.denyObserved.length > 0)
    || (decision.runtimeOs !== undefined && decision.runtimeOs.length > 0)
    || (decision.runtimeArch !== undefined && decision.runtimeArch.length > 0)
  let coverageOk: AttestationCandidate[] | undefined
  let attRejected: string | undefined
  if (!attConsumed) {
    pass('attestation-presence'); pass('attestation-signature'); pass('attestation-issuer'); pass('attestation-coverage')
  } else if (input.attestation.length === 0) {
    if (attRequired) {
      fail('attestation-presence', 'runtime attestation required but absent')
      evidenceTrust.attestation = 'ABSENT'
      cannotEvaluate('attestation-signature', 'attestation-presence')
      cannotEvaluate('attestation-issuer', 'attestation-presence')
      cannotEvaluate('attestation-coverage', 'attestation-presence')
      attRejected = 'attestation-presence'
    } else {
      pass('attestation-presence'); pass('attestation-signature'); pass('attestation-issuer'); pass('attestation-coverage')
    }
  } else {
    pass('attestation-presence')
    const verified = input.attestation.filter((c) => c.verified)
    if (verified.length === 0) {
      fail('attestation-signature', 'no attestation candidate passed envelope + subject + document verification')
      evidenceTrust.attestation = 'ABSENT'
      cannotEvaluate('attestation-issuer', 'attestation-signature')
      cannotEvaluate('attestation-coverage', 'attestation-signature')
      attRejected = 'attestation-signature'
    } else {
      pass('attestation-signature')
      const keys = evidenceTrustedKeysFor(decision, 'attestation')
      if (keys === undefined || keys.length === 0) {
        fail('attestation-issuer', 'no trusted issuer configured for runtime attestation evidence (D109: VALID ≠ TRUSTED)')
        evidenceTrust.attestation = 'UNTRUSTED'
        cannotEvaluate('attestation-coverage', 'attestation-issuer')
        attRejected = 'attestation-issuer'
      } else {
        const trusted = verified.filter((c) => c.keyId !== '' && keyInList(c.keyId, keys))
        if (trusted.length === 0) {
          fail('attestation-issuer', `UNTRUSTED_EVIDENCE_ISSUER: attestation signed by ${verified.map((c) => `SHA256:${c.keyId}`).join(', ')} — none in trustedKeys`)
          evidenceTrust.attestation = 'UNTRUSTED'
          cannotEvaluate('attestation-coverage', 'attestation-issuer')
          attRejected = 'attestation-issuer'
        } else {
          pass('attestation-issuer')
          const requiredCoverage = attConfig?.coverage
          coverageOk = trusted
          if (requiredCoverage !== undefined) {
            coverageOk = trusted.filter((c) => c.coverage !== undefined && COVERAGE_ORDER[c.coverage] >= COVERAGE_ORDER[requiredCoverage])
            if (coverageOk.length === 0) {
              const best = trusted
                .map((c) => c.coverage)
                .filter((x): x is 'complete' | 'partial' | 'unknown' => x !== undefined)
                .sort((a, b) => COVERAGE_ORDER[a] - COVERAGE_ORDER[b])
                .at(-1)
              fail('attestation-coverage', `attestation coverage ${best ?? 'unknown'} < required ${requiredCoverage}`)
              evidenceTrust.attestation = 'ABSENT'
              attRejected = 'attestation-coverage'
            } else {
              pass('attestation-coverage')
            }
          } else {
            pass('attestation-coverage')
          }
        }
      }
    }
  }

  // 4. execution-target (D111: attested env == current target ∈ policy matrix; D110 uniqueness)
  const matrixSet = (decision.runtimeOs !== undefined && decision.runtimeOs.length > 0)
    || (decision.runtimeArch !== undefined && decision.runtimeArch.length > 0)
  let attSelected: AttestationCandidate | undefined
  if (matrixSet) {
    const osOk = decision.runtimeOs === undefined || decision.runtimeOs.length === 0
      || decision.runtimeOs.includes(input.executionTarget.os)
    const archOk = decision.runtimeArch === undefined || decision.runtimeArch.length === 0
      || decision.runtimeArch.includes(input.executionTarget.arch)
    if (!osOk || !archOk) {
      fail('execution-target', `execution target ${input.executionTarget.os}/${input.executionTarget.arch} not in allowed runtime matrix (D103)`)
    } else {
      evaluateAttestationTarget()
    }
  } else if (attConsumed) {
    evaluateAttestationTarget()
  } else {
    pass('execution-target')
  }

  function evaluateAttestationTarget(): void {
    if (attRejected !== undefined) {
      fail('execution-target', `cannot evaluate: ${attRejected} failed`)
      return
    }
    if (coverageOk === undefined || coverageOk.length === 0) {
      pass('execution-target')
      return
    }
    const targetMatched = coverageOk.filter((c) =>
      c.environment !== undefined
      && c.environment.os === input.executionTarget.os
      && c.environment.arch === input.executionTarget.arch)
    if (targetMatched.length === 0) {
      const attested = coverageOk
        .map((c) => (c.environment === undefined ? '(no environment)' : `${c.environment.os}/${c.environment.arch}`))
        .join(', ')
      fail('execution-target', `attested environment (${attested}) does not match current execution target ${input.executionTarget.os}/${input.executionTarget.arch} — exact match required (D111)`)
    } else {
      const distinct = new Set(targetMatched.map((c) => c.semanticKey ?? c.documentKey ?? c.statementDigest))
      if (distinct.size > 1) {
        fail('execution-target', `AMBIGUOUS: ${targetMatched.length} trusted attestations for ${input.executionTarget.os}/${input.executionTarget.arch} with ${distinct.size} non-equivalent attestation semantics (D110/D125)`)
        evidenceTrust.attestation = 'AMBIGUOUS'
      } else {
        pass('execution-target')
        attSelected = targetMatched[0]!
        if (evidenceTrust.attestation === 'N/A') evidenceTrust.attestation = 'VERIFIED'
      }
    }
  }

  // 5. capability policy (D104: denyObserved consumes observed only)
  if (decision.denyObserved !== undefined && decision.denyObserved.length > 0) {
    if (attSelected !== undefined) {
      const hits = attSelected.observed.filter((id) => decision.denyObserved!.includes(id))
      if (hits.length > 0) {
        fail('capability-policy', `observed capabilities hit denyObserved: ${hits.join(', ')}`)
      } else {
        pass('capability-policy')
      }
    } else if (attConsumed && attRejected !== undefined) {
      fail('capability-policy', `cannot evaluate: ${attRejected} failed`)
    } else {
      pass('capability-policy')
    }
  } else {
    pass('capability-policy')
  }

  const ok = errors.length === 0
  return {
    ok,
    decision: ok ? 'ALLOW' : 'DENY',
    steps,
    errors,
    signature: input.signature.status,
    artifactTrust: input.signature.trust,
    evidenceTrust,
  }
}
