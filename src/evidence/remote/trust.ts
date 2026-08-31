/**
 * v0.6.0-beta.1 Remote Trust Integration (DESIGN-v0.6.0.md, D175–D182):
 * the bridge between remote Evidence DISCOVERY and the CURRENT trust policy
 * semantic layer.
 *
 * The KEY boundary: remote Evidence being discovered/downloaded/cached — even
 * with valid signatures — does NOT by itself qualify the Agent to run. Only
 * the CURRENT trust.yaml evaluation produces ALLOW/DENY. This module therefore
 * never makes trust decisions; it only maps verified remote candidates into
 * the SAME `VerifiedEvidenceSet` shape the local collection path produces, so
 * both paths feed ONE `evaluateTrustPolicyV2()` (D178 — the Policy semantic
 * layer is reused, the storage layer is never faked).
 *
 * Explicitly NOT here (D166/D176/D177):
 *   - no cached trust verdicts, no `trusted/allow/deny` persistence
 *   - no offline → executable authorization (beta.1: offline cached evidence
 *     is inspection/verification only, never an executable ALLOW)
 *   - no OCI manifestDigest / registry order / push order / native-vs-fallback
 *     source becoming an Evidence selector or Trust weight (D179)
 * @module @why-daydream/dsh-pack/evidence/remote/trust
 */

import { ATTESTATION_EVIDENCE_TYPE } from '../attestation.ts'
import { attestationSemanticFields } from '../attestation.ts'
import { SBOM_EVIDENCE_TYPE } from '../sbom.ts'
import { verifyEvidenceEnvelope } from '../envelope.ts'
import {
  evaluateTrustPolicyV2,
  loadTrustPolicyFile,
  resolveTrustPolicyV2,
  type TrustPolicyV2Verdict,
} from '../../image/trust-policy-v2.ts'
import type {
  AttestationCandidate,
  ProvenanceCandidate,
  SbomCandidate,
} from '../../image/trust-policy-v2.ts'
import { parseRemoteReference, type RemoteReference } from '../../image/registry/reference.ts'
import { repository as remoteRepositoryOf } from '../../image/reference.ts'
import type { RegistryCredentials } from '../../image/registry/auth.ts'
import { discoverRemoteEvidenceCached } from './discovery.ts'
import type { RemoteEvidenceCache } from './cache.ts'
import type {
  EvidenceCacheStats,
  RejectedRemoteEvidence,
  RemoteEvidenceCandidate,
} from './types.ts'

/** DSH build-provenance evidence envelope type (local collection path constant). */
const PROVENANCE_EVIDENCE_TYPE = 'build-provenance'

/**
 * D175/D178 — the policy evaluator's evidence input, INDEPENDENT of where the
 * evidence came from. Local Evidence Collection and Remote Discovery both
 * produce this shape; `evaluateTrustPolicyV2()` consumes it directly. There is
 * deliberately NO storage/transport field here: a candidate from a CAS hit and
 * a candidate from a fresh registry fetch are indistinguishable to the policy
 * (D179 — transport source never influences Trust weight).
 */
export interface VerifiedEvidenceSet {
  provenance: ProvenanceCandidate[]
  sbom: SbomCandidate[]
  attestation: AttestationCandidate[]
}

/**
 * D178 — map fully-verified REMOTE candidates into the policy evidence set.
 * Every remote candidate has ALREADY passed the discovery chain (OCI digest +
 * subject == M + strict carrier + DSH envelope verification +
 * subject.contentHash == independently-known C, D150/D152/D159), so each maps
 * to a `verified: true` candidate with the SAME semantic fields the local
 * collection path computes:
 *
 *   - provenance: origin (capture mode) + repository (statement source)
 *   - sbom:       documentKey (the statement-required document digest)
 *   - attestation: documentKey + D125 semantic fields (coverage/environment/
 *                 observed/semanticKey) via the SHARED `attestationSemanticFields`
 *
 * The signer keyId is RECOMPUTED from the embedded public key (verifyEvidenceEnvelope),
 * never taken from an untrusted declaration. The OCI manifestDigest is NOT part
 * of any semantic identity — two OCI manifests carrying the same DSH semantic
 * result are equivalent duplicates (D110), not a conflict (B9).
 */
export function buildVerifiedEvidenceSet(candidates: RemoteEvidenceCandidate[]): VerifiedEvidenceSet {
  const set: VerifiedEvidenceSet = { provenance: [], sbom: [], attestation: [] }
  for (const candidate of candidates) {
    // evidenceType is the VERIFIED Envelope.type (never the OCI artifactType, D152)
    if (candidate.evidenceType === PROVENANCE_EVIDENCE_TYPE) {
      set.provenance.push(provenanceCandidate(candidate))
    } else if (candidate.evidenceType === SBOM_EVIDENCE_TYPE) {
      set.sbom.push(sbomCandidate(candidate))
    } else if (candidate.evidenceType === ATTESTATION_EVIDENCE_TYPE) {
      set.attestation.push(attestationCandidate(candidate))
    }
    // 'capability' evidence never enters the policy set — policy consumes
    // provenance/sbom/attestation only (capability manifests are declarations)
  }
  return set
}

/** Recompute the verified signer fingerprint + statement digest (D100 semantics). */
function verifiedBase(candidate: RemoteEvidenceCandidate): { verified: boolean; keyId: string; statementDigest: string } {
  const verdict = verifyEvidenceEnvelope(candidate.envelope)
  if (!verdict.ok) {
    // A discovery-verified candidate must re-verify here; if it somehow does
    // not, it must NEVER surface as trusted (fail-closed, D19: VALID ≠ TRUSTED).
    return { verified: false, keyId: '', statementDigest: candidate.envelope.statementDigest }
  }
  return { verified: true, keyId: verdict.keyId, statementDigest: candidate.envelope.statementDigest }
}

/** Provenance candidate: origin + repository read from the verified statement. */
function provenanceCandidate(candidate: RemoteEvidenceCandidate): ProvenanceCandidate {
  const base = verifiedBase(candidate)
  const statement = candidate.envelope.statement as { capture?: { mode?: unknown }; source?: { repository?: unknown } } | undefined
  return {
    ...base,
    ...(typeof statement?.capture?.mode === 'string' ? { origin: statement.capture.mode } : {}),
    ...(typeof statement?.source?.repository === 'string' ? { repository: statement.source.repository } : {}),
  }
}

/** SBOM candidate: documentKey is the statement-required document digest. */
function sbomCandidate(candidate: RemoteEvidenceCandidate): SbomCandidate {
  const base = verifiedBase(candidate)
  const statement = candidate.envelope.statement as { sbomDigest?: { value?: unknown } } | undefined
  const digestValue = statement?.sbomDigest?.value
  if (typeof digestValue !== 'string' || digestValue === '') return { ...base }
  // The carrier layer already enforced: statement references a document ⇒ the
  // carrier MUST carry exactly one document whose bytes hash to that digest
  // (D159) — the digest match was verified during discovery.
  return { ...base, documentKey: digestValue }
}

/**
 * Attestation candidate: documentKey + D125 semantic identity from the VERIFIED
 * document. The document bytes were digest-verified during discovery (D159), so
 * the semantic fields are computed from trusted bytes via the shared function —
 * identical semantics to the local collection path (D178).
 */
function attestationCandidate(candidate: RemoteEvidenceCandidate): AttestationCandidate {
  const base = verifiedBase(candidate)
  const statement = candidate.envelope.statement as { attestationDigest?: { value?: unknown } } | undefined
  const digestValue = statement?.attestationDigest?.value
  if (!base.verified || typeof digestValue !== 'string' || digestValue === '' || candidate.document === undefined) {
    // A remote attestation without a verified document is NOT self-consistent
    // (mirrors the local path: missing/mismatched document ⇒ UNVERIFIED, D99/D100).
    return { ...base, verified: false, observed: [] }
  }
  const semantics = attestationSemanticFields(Buffer.from(candidate.document.bytes))
  return {
    ...base,
    documentKey: digestValue,
    ...(semantics.semanticKey !== undefined ? { semanticKey: semantics.semanticKey } : {}),
    ...(semantics.coverage !== undefined ? { coverage: semantics.coverage } : {}),
    ...(semantics.environment !== undefined ? { environment: semantics.environment } : {}),
    observed: semantics.observed,
  }
}

// ============================================================================
// Remote Trust Gate (D175–D182)
// ============================================================================

/**
 * D175/D177 — the gate input. `signature` carries the artifact signer facts
 * from the caller's verified artifact chain (D19/D29: VALID ≠ TRUSTED — the
 * caller runs the v0.3/v0.4 verification before invoking the gate). There is
 * NO offline mode here: beta.1 gate semantics are ONLINE-ONLY. Offline cached
 * Evidence is for inspection/verification only and can never produce an
 * executable ALLOW (D177); callers wanting to inspect offline must combine
 * `discoverRemoteEvidenceCached(mode: 'offline')` + `buildVerifiedEvidenceSet`
 * themselves, and that result must never be treated as authorization.
 */
export interface RemoteEvidenceTrustOptions {
  /** Fully-qualified remote image reference, e.g. `ghcr.io/company/agent:prod` or `...@sha256:M`. */
  reference: string
  /** The INDEPENDENTLY verified artifact contentHash C (D150 — never read from evidence itself). */
  actualContentHash: string
  /** DSH_HOME — the CURRENT trust.yaml is re-read and re-resolved on EVERY gate call (D176). */
  home: string
  /** CAS for immutable object fetch optimization only — never a trust input (D166/D182). */
  cache?: RemoteEvidenceCache
  credentials?: RegistryCredentials
  /** D111 — the execution target the policy is evaluated against. */
  executionTarget?: { os: string; arch: string }
  /** D176 — artifact signer facts (VALID ≠ TRUSTED is preserved, D19). */
  signature: { status: 'VALID' | 'INVALID' | 'MISSING'; trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A' }
  /** Repository for policy resolution — default: the remote `(registry/repo)` of the reference (D157). */
  repository?: string
}

/** The discovery audit facts attached to a gate result (D179 — transport metadata, never trust weight). */
export interface RemoteEvidenceGateDiscovery {
  complete: boolean
  /** Where the enumeration came from — the gate is always online; 'cached-snapshot' is impossible here (D174/D177). */
  source: 'remote' | 'cached-snapshot'
  /** native Referrers API vs standard referrers-tag fallback (D179). */
  mode: 'referrers-api' | 'tag-fallback'
  cache: EvidenceCacheStats
  /** Invalid/rejected remote objects — diagnostics ONLY, never policy inputs (D180). */
  rejected: RejectedRemoteEvidence[]
}

/** The auditable gate outcome: decision + full step chain + discovery audit. */
export interface RemoteEvidenceTrustResult {
  decision: 'ALLOW' | 'DENY'
  verdict: TrustPolicyV2Verdict
  /** The repository the policy was resolved for. */
  repository: string
  executionTarget: { os: string; arch: string }
  discovery: RemoteEvidenceGateDiscovery
}

/** A DENY verdict for an evaluation that could not even run (REFERENCE_ERROR / incomplete discovery). */
function cannotEvaluateVerdict(signature: { status: 'VALID' | 'INVALID' | 'MISSING'; trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A' }, reason: string): TrustPolicyV2Verdict {
  return {
    ok: false,
    decision: 'DENY',
    steps: [{ step: 'remote-evidence-discovery', ok: false, reason }],
    errors: [reason],
    signature: signature.status,
    artifactTrust: signature.trust,
    evidenceTrust: { provenance: 'N/A', sbom: 'N/A', attestation: 'N/A' },
  }
}

/**
 * D175/D176/D177/D178/D180/D181 — the beta.1 Remote Trust Gate:
 *
 *   remote ref → resolve tag once → immutable M → ONLINE remote Evidence
 *   discovery (complete=true REQUIRED — a partial enumeration is never
 *   evaluated, D175/B4) → VerifiedEvidenceSet (rejects stay diagnostics,
 *   D180) → CURRENT trust.yaml decision (D176) → evaluateTrustPolicyV2 →
 *   ALLOW/DENY.
 *
 * The gate performs NO materialization, NO pnpm, NO lifecycle — it is the
 * authorization decision ONLY (D181: the caller MUST invoke it before any
 * materialization; D182: pull/cache stay in the distribution layer, never a
 * Trust Authority). The registry order, push order, native-vs-fallback source
 * and CAS-hit are audit metadata only (D179) — they never change Trust weight.
 */
export async function evaluateRemoteEvidenceTrust(
  opts: RemoteEvidenceTrustOptions,
): Promise<RemoteEvidenceTrustResult> {
  const executionTarget = opts.executionTarget ?? { os: process.platform, arch: process.arch }

  // 1. resolve the reference ONCE to the immutable (registry, repo, M) identity
  let ref: RemoteReference
  try {
    ref = parseRemoteReference(opts.reference)
  } catch (error) {
    const reason = `cannot parse remote reference: ${String(error)}`
    return {
      decision: 'DENY',
      verdict: cannotEvaluateVerdict(opts.signature, reason),
      repository: '',
      executionTarget,
      discovery: { complete: false, source: 'remote', mode: 'referrers-api', cache: EMPTY_CACHE_STATS('online'), rejected: [] },
    }
  }
  const repository = opts.repository ?? remoteRepositoryOf(ref)

  // 2. ONLINE discovery — ALWAYS remote enumeration (D169/D175/D177): a
  //    snapshot cache never shadows newer Evidence and an online failure
  //    never degrades to a stale cached snapshot (D174).
  const discovery = await discoverRemoteEvidenceCached({
    reference: opts.reference,
    actualContentHash: opts.actualContentHash,
    ...(opts.cache !== undefined ? { cache: opts.cache } : {}),
    ...(opts.credentials !== undefined ? { credentials: opts.credentials } : {}),
    mode: 'online',
  })

  if (!discovery.complete) {
    // D175/B4 — NO partial policy evaluation: an incomplete enumeration is a
    // hard DENY, never a reduced Evidence set.
    const reason = `remote evidence discovery incomplete (${discovery.error.kind}): ${discovery.error.message}`
    return {
      decision: 'DENY',
      verdict: cannotEvaluateVerdict(opts.signature, reason),
      repository,
      executionTarget,
      discovery: {
        complete: false,
        source: 'remote',
        mode: discoverySourceMode(discovery.error),
        cache: discovery.cache,
        rejected: [],
      },
    }
  }

  // 3. verified candidates → the SAME policy evidence set the local path uses
  const evidence = buildVerifiedEvidenceSet(discovery.candidates)

  // 4. CURRENT trust.yaml — re-read and re-resolved on every gate call (D176):
  //    the cache never saves TRUSTED/ALLOW, so revocation/edits always apply.
  const decision = resolveTrustPolicyV2(loadTrustPolicyFile(opts.home), repository)

  // 5. evaluate — the full D100–D111 chain (issuer trust D109, semantic
  //    dedup D110, coverage D102, execution target D111, capabilities D104).
  const verdict = evaluateTrustPolicyV2(decision, {
    signature: opts.signature,
    executionTarget,
    provenance: evidence.provenance,
    sbom: evidence.sbom,
    attestation: evidence.attestation,
  })

  return {
    decision: verdict.decision,
    verdict,
    repository,
    executionTarget,
    discovery: {
      complete: true,
      source: 'remote',
      mode: discovery.mode,
      cache: discovery.cache,
      rejected: discovery.rejected,
    },
  }
}

/** Incomplete-discovery audit: remember which enumeration path was attempted. */
function discoverySourceMode(error: { kind: string }): 'referrers-api' | 'tag-fallback' {
  // The native API is always attempted first; the fallback only after a 404.
  // Keep the audit honest about the ATTEMPTED path (D179 — metadata only).
  return 'referrers-api'
}

/** Zeroed cache stats for evaluations that never reached the discovery layer. */
function EMPTY_CACHE_STATS(mode: 'online' | 'offline'): EvidenceCacheStats {
  return {
    mode,
    objectCacheHits: 0,
    objectCacheMisses: 0,
    snapshotHit: false,
    snapshotStored: false,
    corruptionRepaired: false,
  }
}

/**
 * D181 — the gate for EXECUTABLE paths (run/install): a non-ALLOW verdict
 * throws BEFORE any materialization can happen. Fail-closed: DENY and
 * evaluation errors are both hard stops.
 */
export function assertRemoteEvidenceAllow(result: RemoteEvidenceTrustResult): void {
  if (result.decision !== 'ALLOW') {
    throw new Error(
      `dsh-pack: remote trust gate blocked before materialization (${result.decision}): `
      + result.verdict.errors.join('; '),
    )
  }
}
