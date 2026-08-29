/**
 * v0.4 ImageStore seam (DESIGN-v0.4.md §10): the store abstracts how blobs,
 * manifests and tag refs are persisted. v0.4.0 ships the content-addressed
 * LocalImageStore; OCI / GHCR / enterprise providers implement the same
 * interface later (D31) — Remote is just another Provider.
 * @module @why-daydream/dsh-pack/image/store
 */

import type { ImageManifest } from './manifest.ts'

/** One tag reference in the store (for `image ls`). */
export interface ImageRefEntry {
  repo: string
  tag: string
  manifestDigest: string
}

/** v0.4 ImageStore contract (frozen). */
export interface ImageStore {
  /** Write a content-addressed blob; digest must match the bytes (invariant). */
  putBlob(digest: string, bytes: Buffer): Promise<void>
  getBlob(digest: string): Promise<Buffer | undefined>
  hasBlob(digest: string): Promise<boolean>

  /** Write a manifest; its digest must match the canonical JSON (invariant). */
  putManifest(digest: string, manifest: ImageManifest): Promise<void>
  getManifest(digest: string): Promise<ImageManifest | undefined>
  removeManifest(digest: string): Promise<void>

  /** Mutable tag alias: repo:tag → manifestDigest (atomic replace = tag update). */
  setTag(repo: string, tag: string, manifestDigest: string): Promise<void>
  getTag(repo: string, tag: string): Promise<string | undefined>
  removeTag(repo: string, tag: string): Promise<void>

  /** Remove a blob (v0.4.0: direct; reference counting is v0.4.1). */
  removeBlob(digest: string): Promise<void>

  /** All tag refs, for `image ls`. */
  listRefs(): Promise<ImageRefEntry[]>
}
