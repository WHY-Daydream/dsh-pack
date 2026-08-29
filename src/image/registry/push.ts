/**
 * v0.4.1 push pipeline (DESIGN-v0.4.1.md §4, D32/D37): resolve the LOCAL
 * image → verifyPack self-attestation (never push a broken artifact) →
 * upload the `.dshpack` raw bytes as the OCI layer (blobDigest = SHA256 over
 * RAW bytes, ≠ contentHash) → upload the DSH Image Manifest as the config
 * blob → PUT the standard OCI envelope (Docker-Content-Digest verified by
 * the client). Content of the registry is never trusted back.
 * @module @why-daydream/dsh-pack/image/registry/push
 */

import { canonicalJson } from '../../canonical.ts'
import { IMAGE_MANIFEST_MEDIA_TYPE as DSH_IMAGE_MANIFEST_MEDIA_TYPE } from '../manifest.ts'
import { ImageResolveError, resolveImage } from '../resolver.ts'
import { parseReference } from '../reference.ts'
import type { ImageStore } from '../store.ts'
import { verifyPack } from '../../verify.ts'
import { loadRegistryCredentials } from './auth.ts'
import { RegistryClient } from './client.ts'
import { digestOf } from './descriptor.ts'
import { buildOciManifest, DSH_PACK_LAYER_MEDIA_TYPE } from './manifest.ts'
import { parseRemoteReference, registryBaseUrl, repoPath } from './reference.ts'
import type { DshContentDigest, OciBlobDigest, OciManifestDigest } from './types.ts'

export interface PushResult {
  remoteRef: string
  ociManifestDigest: OciManifestDigest
  blobDigest: OciBlobDigest
  contentHash: DshContentDigest
}

export interface PushContext {
  installedDshVersion: string
}

/** Push a local image to an OCI registry (frozen §4 order). */
export async function pushImage(
  store: ImageStore,
  localRef: string,
  remoteRefInput: string,
  context: PushContext,
): Promise<PushResult> {
  const remoteRef = parseRemoteReference(remoteRefInput)

  // resolve the LOCAL image (registry-less local ref, or a full-name tag)
  const resolved = await resolveImage(store, parseReference(localRef))
  const bytes = await store.getBlob(resolved.artifactDigest)
  if (bytes === undefined) {
    throw new ImageResolveError(`artifact blob ${resolved.artifactDigest} missing from local store`)
  }

  // self-attestation: refuse to push an artifact that fails its own verification
  const { report } = await verifyPack(bytes, { installedDshVersion: context.installedDshVersion })
  if (!report.ok) {
    const failed = report.sections.filter((s) => s.status === 'fail').map((s) => `${s.name}: ${s.detail ?? ''}`)
    throw new Error(`refusing to push an artifact that fails verification: ${failed.join('; ')}`)
  }

  const client = new RegistryClient({
    baseUrl: registryBaseUrl(remoteRef.registry),
    repo: repoPath(remoteRef),
    credentials: loadRegistryCredentials(remoteRef.registry),
  })

  // 1. .dshpack layer — blobDigest over RAW bytes (D32: ≠ contentHash)
  const blobDigest = digestOf(bytes)
  await client.uploadBlob(blobDigest, bytes)

  // 2. config blob — the DSH Image Manifest (D36)
  const configBytes = Buffer.from(canonicalJson(resolved.manifest), 'utf8')
  const configBlobDigest = digestOf(configBytes)
  await client.uploadBlob(configBlobDigest, configBytes)

  // 3. standard OCI envelope (D34/D35/D37) → PUT manifest
  const ociManifest = buildOciManifest(
    { mediaType: DSH_IMAGE_MANIFEST_MEDIA_TYPE, digest: configBlobDigest, size: configBytes.length },
    { mediaType: DSH_PACK_LAYER_MEDIA_TYPE, digest: blobDigest, size: bytes.length },
  )
  const manifestBytes = Buffer.from(canonicalJson(ociManifest), 'utf8')
  const tagOrDigest = remoteRef.tag ?? (remoteRef.digest as string)
  const ociManifestDigest = await client.putManifest(tagOrDigest, manifestBytes)

  const repo = repoPath(remoteRef)
  return {
    remoteRef: `${remoteRef.registry}/${repo}:${remoteRef.tag ?? ociManifestDigest}`,
    ociManifestDigest,
    blobDigest,
    contentHash: resolved.artifactDigest,
  }
}
