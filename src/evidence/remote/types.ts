/**
 * v0.6.0-alpha.1 Remote Evidence Discovery types (DESIGN-v0.6.0.md §2–§8,
 * D149–D159): the internal contracts for discovering DSH Evidence objects
 * attached to an Agent Image in an OCI registry.
 *
 * Scope: read/discovery only. There are deliberately NO trust verdicts here —
 * VALID Evidence ≠ TRUSTED Evidence, and no policy/ALLOW field exists in any
 * candidate type. alpha.1 answers "which remote Evidence exist and are they
 * complete/valid", never "do I trust them".
 * @module @why-daydream/dsh-pack/evidence/remote/types
 */

import type { EvidenceEnvelope } from '../../types.ts'

/** The four DSH Evidence artifact types (DESIGN-v0.6.0.md §2.3). */
export const EVIDENCE_ARTIFACT_TYPES = {
  provenance: 'application/vnd.dsh.evidence.provenance.v1+json',
  sbom: 'application/vnd.dsh.evidence.sbom.v1+json',
  capability: 'application/vnd.dsh.evidence.capability.v1+json',
  'runtime-attestation': 'application/vnd.dsh.evidence.runtime-attestation.v1+json',
} as const

/** OCI carrier layer media types (DESIGN-v0.6.0.md §2.3). */
export const EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE = 'application/vnd.dsh.evidence.envelope.v1+json'
export const EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE = 'application/vnd.dsh.evidence.document.v1+json'

/**
 * D157 — Remote discovery anchor. A remote locator is
 * `(registry, repository, OciManifestDigest)`; a bare manifest digest is NOT a
 * complete remote identity (referrers live in the same repository namespace as
 * the subject).
 */
export interface RemoteEvidenceLocator {
  registry: string
  repository: string
  subjectManifestDigest: string
}

/** An OCI referrer descriptor exactly as enumerated — UNTRUSTED metadata (D152). */
export interface ReferrerDescriptor {
  digest: string
  size: number
  artifactType?: string
  annotations?: Record<string, string>
}

/** Which discovery path produced a candidate (diagnostic; never a trust input). */
export type DiscoverySource = 'referrers-api' | 'tag-fallback'

/**
 * A remote Evidence candidate AFTER full OCI + DSH verification (D150/D152):
 * carries VERIFIED facts only. The evidenceType is always the verified
 * Envelope.type — never the OCI artifactType.
 */
export interface RemoteEvidenceCandidate {
  source: DiscoverySource
  subject: {
    registry: string
    repository: string
    manifestDigest: string
    contentHash: string
  }
  referrerManifestDigest: string
  /** Untrusted OCI declaration — diagnostic only (D152). */
  declaredArtifactType?: string
  /** Authoritative after DSH verification (verified Envelope.type). */
  evidenceType: string
  envelope: EvidenceEnvelope
  document?: {
    mediaType: string
    digest: string
    bytes: Uint8Array
  }
}

/** A single invalid Evidence object (discovery itself may still be complete). */
export interface RejectedRemoteEvidence {
  referrerManifestDigest: string
  reason: string
  /** Untrusted OCI declaration — diagnostic only. */
  declaredArtifactType?: string
}

/** Why enumeration could not complete (D158: partial enumeration ≠ complete set). */
export type RemoteEvidenceDiscoveryError =
  | { kind: 'DISCOVERY_INCOMPLETE'; message: string }
  | { kind: 'REGISTRY_ERROR'; status: number; message: string }
  | { kind: 'REFERENCE_ERROR'; message: string }
  | { kind: 'INVALID_CARRIER'; message: string }

/**
 * The result of remote Evidence discovery. `complete: true` means the ENTIRE
 * enumeration was consumed (D158) — invalid single objects go to `rejected`,
 * but an incomplete enumeration must NEVER surface as a partial candidate set.
 * beta.1 policy integration MUST only consume `complete: true` results.
 */
export type RemoteEvidenceDiscoveryResult =
  | {
      complete: true
      candidates: RemoteEvidenceCandidate[]
      rejected: RejectedRemoteEvidence[]
    }
  | {
      complete: false
      error: RemoteEvidenceDiscoveryError
    }

// ============================================================================
// alpha.2 — Evidence Publication (D160–D165)
// ============================================================================

/**
 * D160 — the OCI `subject` field is a FULL descriptor (image-spec §Manifest),
 * not a bare digest. The publication target is
 * `(registry, repository, subjectDescriptor)` where `subjectDescriptor.digest
 * === M`. The subject manifest may not exist yet (forward reference is valid —
 * distribution-spec requires accepting it); clients MUST NOT preflight its
 * existence.
 */
export interface RemoteSubjectDescriptor {
  mediaType: string
  digest: string
  size: number
}

/** Which distribution path acknowledged the publication (D162). */
export type EvidencePublicationMode = 'native-referrers' | 'tag-fallback'

/**
 * The result of publishing one Evidence object. Contains TRANSPORT facts
 * only — deliberately no trust verdicts (alpha.2 is still the distribution
 * layer: VALID Evidence ≠ TRUSTED Evidence).
 */
export interface EvidencePublicationResult {
  repository: string
  subjectManifestDigest: string
  evidenceManifestDigest: string
  mode: EvidencePublicationMode
  /** Present only when the registry did not natively acknowledge the subject (D162/D163). */
  fallback?: {
    tag: string
    /** D164 — whether the fallback update used conditional HTTP protection. */
    concurrencyProtection: 'conditional' | 'none'
    retries: number
  }
}

// ============================================================================
// alpha.3 — Remote Evidence Cache (D166–D174)
// ============================================================================

/**
 * D166 — the Remote Evidence Cache is a CONTENT-ADDRESSED BYTE cache, never a
 * trust cache. Nothing cached here is ever a trust/policy verdict: no
 * `trusted`, `allow`, `deny`, `issuerTrusted` or `policyVerdict` field exists
 * in any cached structure. Cache eviction or absence changes availability and
 * performance only (D173), never trust semantics.
 */

/**
 * D169/D170 — a DISCOVERY SNAPSHOT is one fully-consumed (D158) remote
 * enumeration captured at a point in time: `M` is immutable, but
 * `referrers(M)` is APPENDABLE (D155), so a snapshot is never a permanent
 * fact about the Evidence Set. `capturedAt` is freshness metadata for
 * availability decisions only — it is NEVER a trust input and NEVER a
 * latest-wins selector (N5/D127 stay intact).
 *
 * Only `complete: true` enumerations may be stored as a snapshot (D171):
 * a partial enumeration must never be cached as — or overwrite a
 * previously-known-complete — snapshot.
 */
export interface RemoteEvidenceDiscoverySnapshot {
  /** Canonical identity domain (D157/D167): (registry, repository, M). */
  registry: string
  repository: string
  subjectManifestDigest: string
  /** Which path produced the enumeration — re-observed on every online run. */
  source: 'referrers-api' | 'tag-fallback'
  /** Always true for a stored snapshot (D171). */
  complete: true
  /** The full referrer descriptor set, exactly as enumerated (untrusted metadata). */
  descriptors: ReferrerDescriptor[]
  /** Freshness metadata ONLY (D169): never used for selection/trust. */
  capturedAt: string
  /** Transport validators (diagnostic; not a trust input). */
  validator?: {
    etag?: string
    lastModified?: string
  }
}

/**
 * D174 — cache mode. `online` keeps REMOTE enumeration authoritative (the
 * snapshot cache never shadows newer referrers; CAS may only skip immutable
 * object downloads). `offline` is EXPLICIT — an online failure must never
 * silently degrade to a cached snapshot (D174); only an explicit `offline`
 * call may reconstruct candidates from a complete snapshot + cached objects.
 */
export type EvidenceCacheMode = 'online' | 'offline'

/**
 * D170 — an offline cache GAP: a required immutable object is not fully
 * present (missing or corrupt) in the CAS. Raised by the CAS-backed
 * blob fetcher so the carrier's strict validation can distinguish an
 * availability gap (fail loud, never partial) from a genuine
 * INVALID_CARRIER rejection.
 */
export class OfflineCacheGapError extends Error {
  constructor(
    readonly reason: 'missing-object' | 'corrupt-object',
    readonly what: string,
  ) {
    super(`offline cache gap (${reason}): ${what}`)
    this.name = 'OfflineCacheGapError'
  }
}

/** Offline reconstruction failure reasons (D170/D171 — fail loud, never partial). */
export type OfflineCacheError =
  | { kind: 'OFFLINE_CACHE_INCOMPLETE'; reason: 'no-snapshot' | 'missing-object' | 'corrupt-object'; message: string }
  | { kind: 'REGISTRY_ERROR'; status: number; message: string }
  | { kind: 'REFERENCE_ERROR'; message: string }

/**
 * Transport-level bookkeeping of one discovery run (C11: contains NO trust
 * fields). `snapshotStored` is true only when a complete enumeration was
 * captured (D171); `snapshotShadowedOnline` would never occur by design —
 * online results always come from fresh remote enumeration.
 */
export interface EvidenceCacheStats {
  mode: EvidenceCacheMode
  objectCacheHits: number
  objectCacheMisses: number
  snapshotHit: boolean
  snapshotStored: boolean
  /** True when a corrupt CAS object was detected, deleted and re-fetched (D172, online only). */
  corruptionRepaired: boolean
}

/**
 * The result of remote Evidence discovery WITH cache participation (alpha.3).
 * `complete: true` results are exactly the alpha.1 candidates — the cache
 * never adds, drops or reorders candidates; `source` says where the
 * enumeration came from (fresh remote vs explicit offline snapshot reuse).
 */
export type RemoteEvidenceDiscoveryResultCached =
  | {
      complete: true
      candidates: RemoteEvidenceCandidate[]
      rejected: RejectedRemoteEvidence[]
      /** Where the enumeration was sourced (D169/D174). */
      source: 'remote' | 'cached-snapshot'
      cache: EvidenceCacheStats
    }
  | {
      complete: false
      error: RemoteEvidenceDiscoveryError | OfflineCacheError
      cache: EvidenceCacheStats
    }
