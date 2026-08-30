/**
 * v0.4 ImageStore seam (DESIGN-v0.4.md §10): the store abstracts how blobs,
 * manifests and tag refs are persisted. v0.4.0 ships the content-addressed
 * LocalImageStore; OCI / GHCR / enterprise providers implement the same
 * interface later (D31) — Remote is just another Provider.
 * @module @why-daydream/dsh-pack/image/store
 */

import type { ImageManifest } from './manifest.ts'
import type { DshContentDigest } from './digests.ts'

/** One tag reference in the store (for `image ls`). */
export interface ImageRefEntry {
  repo: string
  tag: string
  manifestDigest: string
}

/** v0.4 ImageStore contract (frozen). */
export interface ImageStore {
  /** Write a content-addressed blob keyed by its DSH contentHash (D21/D32). */
  putBlob(digest: DshContentDigest, bytes: Buffer): Promise<void>
  getBlob(digest: DshContentDigest): Promise<Buffer | undefined>
  hasBlob(digest: DshContentDigest): Promise<boolean>

  /** Write a manifest; its digest must match the canonical JSON (invariant). */
  putManifest(digest: string, manifest: ImageManifest): Promise<void>
  getManifest(digest: string): Promise<ImageManifest | undefined>
  removeManifest(digest: string): Promise<void>

  /** Mutable tag alias: repo:tag → manifestDigest (atomic replace = tag update). */
  setTag(repo: string, tag: string, manifestDigest: string): Promise<void>
  getTag(repo: string, tag: string): Promise<string | undefined>
  removeTag(repo: string, tag: string): Promise<void>

  /** Remove a blob by contentHash (v0.4.0: direct; reference counting is v0.4.1). */
  removeBlob(digest: DshContentDigest): Promise<void>

  /** All tag refs, for `image ls`. */
  listRefs(): Promise<ImageRefEntry[]>

  /** All stored manifest digests, for local GC (DESIGN-v0.4.2.md D57–D63). */
  listManifestDigests(): Promise<string[]>
  /** All stored blob digests (contentHash), for local GC. */
  listBlobDigests(): Promise<DshContentDigest[]>
  /** Stored size in bytes of a manifest (undefined when absent). */
  getManifestSize(digest: string): Promise<number | undefined>
  /** Stored size in bytes of a blob (undefined when absent). */
  getBlobSize(digest: DshContentDigest): Promise<number | undefined>
}
