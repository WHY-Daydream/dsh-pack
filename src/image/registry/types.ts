/**
 * v0.4.1 three-digest separation (DESIGN-v0.4.1.md §2, D32): contentHash,
 * OCI blobDigest and OCI manifestDigest are THREE different identities and
 * must never share an alias — even though they are all `string` at runtime,
 * distinct named types prevent bugs like `verifyContentHash(manifestDigest)`.
 * @module @why-daydream/dsh-pack/image/registry/types
 */

/** DSH semantic identity — signature/trust anchor (D33, unchanged from v0.3). */
export type DshContentDigest = string

/** OCI layer descriptor digest — SHA256 over the raw .dshpack archive bytes. */
export type OciBlobDigest = string

/** OCI manifest digest — SHA256 over the canonical OCI manifest JSON. */
export type OciManifestDigest = string
