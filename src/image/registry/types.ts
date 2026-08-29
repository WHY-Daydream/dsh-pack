/**
 * v0.4.1 three-digest separation (DESIGN-v0.4.1.md §2, D32): contentHash,
 * OCI blobDigest and OCI manifestDigest are THREE different identities and
 * must never share an alias — even though they are all `string` at runtime,
 * distinct named types prevent bugs like `verifyContentHash(manifestDigest)`.
 * The canonical definitions live in image/digests.ts (dependency-free);
 * this module re-exports them for registry-scoped imports.
 * @module @why-daydream/dsh-pack/image/registry/types
 */

export type { DshContentDigest, OciBlobDigest, OciManifestDigest } from '../digests.ts'
