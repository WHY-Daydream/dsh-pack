/**
 * v0.4 image resolution (DESIGN-v0.4.md §10): tag/digest → manifest, with the
 * artifact blob verified present. digest-first by construction — a tag is only
 * an entry point; the resolved manifest digest and artifact digest are the
 * immutable identities (D21/D22). Missing blobs fail before any boot (D27).
 * @module @why-daydream/dsh-pack/image/resolver
 */

import { imageManifestDigest, type ImageManifest } from './manifest.ts'
import type { ImageReference } from './reference.ts'
import { repository } from './reference.ts'
import type { ImageStore } from './store.ts'
import type { DshContentDigest } from './digests.ts'

export interface ResolvedImage {
  ref: ImageReference
  manifest: ImageManifest
  manifestDigest: string
  /** = manifest.artifact.digest = pack contentHash (D21). */
  artifactDigest: DshContentDigest
}

export class ImageResolveError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ImageResolveError'
  }
}

/** Resolve a reference against a store; throws ImageResolveError when missing. */
export async function resolveImage(store: ImageStore, ref: ImageReference): Promise<ResolvedImage> {
  let manifest: ImageManifest | undefined
  let manifestDigest: string | undefined

  if (ref.digest !== undefined) {
    manifestDigest = ref.digest
    manifest = await store.getManifest(ref.digest)
    if (manifest === undefined) {
      throw new ImageResolveError(`manifest ${ref.digest} not found in local store`)
    }
  } else if (ref.tag !== undefined) {
    manifestDigest = await store.getTag(repository(ref), ref.tag)
    if (manifestDigest === undefined) {
      throw new ImageResolveError(`tag ${repository(ref)}:${ref.tag} not found in local store`)
    }
    manifest = await store.getManifest(manifestDigest)
    if (manifest === undefined) {
      throw new ImageResolveError(`manifest ${manifestDigest} for tag ${ref.tag} is missing`)
    }
  } else {
    throw new ImageResolveError('image reference must carry a tag or a digest')
  }

  if (imageManifestDigest(manifest) !== manifestDigest) {
    throw new ImageResolveError(
      `manifest digest mismatch: stored ${manifestDigest}, recomputed ${imageManifestDigest(manifest)}`,
    )
  }

  const artifactDigest = manifest.artifact.digest
  if (!(await store.hasBlob(artifactDigest))) {
    throw new ImageResolveError(`artifact blob ${artifactDigest} missing from local store`)
  }
  return { ref, manifest, manifestDigest, artifactDigest }
}
