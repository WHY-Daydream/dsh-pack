/**
 * The three digest identities (DESIGN-v0.4.1.md §2, D32): even though all are
 * `string` at runtime, distinct named aliases make the domain of every
 * signature explicit and grep-auditable — preventing cross-domain mixing like
 * `verifyContentHash(manifestDigest)` or handing an OCI blobDigest to the
 * local store. Import from HERE (image-level, dependency-free); registry
 * code re-exports via registry/types.ts.
 *
 *   DshContentDigest    → DSH semantic identity (signing/trust anchor, D33)
 *   OciBlobDigest       → SHA256 over raw .dshpack/config bytes (OCI layer)
 *   OciManifestDigest   → SHA256 over the canonical OCI manifest JSON
 * @module @why-daydream/dsh-pack/image/digests
 */

/** DSH semantic identity — signature/trust anchor (D33, unchanged from v0.3). */
export type DshContentDigest = string

/** OCI layer descriptor digest — SHA256 over the raw archive bytes. */
export type OciBlobDigest = string

/** OCI manifest digest — SHA256 over the canonical OCI manifest JSON. */
export type OciManifestDigest = string
