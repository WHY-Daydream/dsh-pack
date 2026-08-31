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
