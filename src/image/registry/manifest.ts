/**
 * v0.4.1 OCI envelope (DESIGN-v0.4.1.md §3, D34–D37): the registry's top-level
 * manifest is the STANDARD OCI Image Manifest (schemaVersion 2) with
 * `artifactType = vnd.dsh.agent.image.v1`; the DSH Image Manifest travels as
 * the config blob and the `.dshpack` as a single layer. We never publish a
 * custom top-level manifest media type (unknown types break old registries).
 * @module @why-daydream/dsh-pack/image/registry/manifest
 */

import { canonicalJson, sha256Hex } from '../../canonical.ts'
import { IMAGE_MANIFEST_MEDIA_TYPE as DSH_IMAGE_MANIFEST_MEDIA_TYPE } from '../manifest.ts'
import { SHA256_RE } from './descriptor.ts'
import type { OciManifestDigest } from './types.ts'

export const OCI_IMAGE_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
export const DSH_AGENT_ARTIFACT_TYPE = 'application/vnd.dsh.agent.image.v1'
export const DSH_PACK_LAYER_MEDIA_TYPE = 'application/vnd.dsh.pack.v1+gzip'

/** An OCI descriptor (digest = sha256 of the referenced content's raw bytes). */
export interface OciDescriptor {
  mediaType: string
  digest: string
  size: number
}

/** Frozen v0.4.1 OCI top-level envelope (D34–D37). */
export interface OciImageManifest {
  schemaVersion: 2
  mediaType: typeof OCI_IMAGE_MANIFEST_MEDIA_TYPE
  artifactType: typeof DSH_AGENT_ARTIFACT_TYPE
  /** DSH Image Manifest (config blob, D36). */
  config: OciDescriptor
  /** exactly one .dshpack layer (D37). */
  layers: OciDescriptor[]
}

export function buildOciManifest(config: OciDescriptor, layer: OciDescriptor): OciImageManifest {
  return {
    schemaVersion: 2,
    mediaType: OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    artifactType: DSH_AGENT_ARTIFACT_TYPE,
    config,
    layers: [layer],
  }
}

/** OCI manifest digest = sha256 over the canonical manifest JSON bytes. */
export function ociManifestDigest(manifest: OciImageManifest): OciManifestDigest {
  return `sha256:${sha256Hex(canonicalJson(manifest))}` as OciManifestDigest
}

/** Validate an unknown value as our OCI envelope (D34–D37, one layer only). */
export function validateOciManifest(
  value: unknown,
): { ok: true; manifest: OciImageManifest } | { ok: false; errors: string[] } {
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['manifest is not an object'] }
  const m = value as Record<string, unknown>
  const errors: string[] = []

  if (m.schemaVersion !== 2) errors.push('schemaVersion must be 2')
  if (m.mediaType !== OCI_IMAGE_MANIFEST_MEDIA_TYPE) {
    errors.push(`mediaType must be "${OCI_IMAGE_MANIFEST_MEDIA_TYPE}"`)
  }
  if (m.artifactType !== DSH_AGENT_ARTIFACT_TYPE) {
    errors.push(`artifactType must be "${DSH_AGENT_ARTIFACT_TYPE}"`)
  }
  const config = m.config as Record<string, unknown> | undefined
  if (
    config === undefined
    || config.mediaType !== DSH_IMAGE_MANIFEST_MEDIA_TYPE
    || typeof config.digest !== 'string' || !SHA256_RE.test(config.digest)
    || typeof config.size !== 'number' || config.size <= 0
  ) {
    errors.push(`config descriptor must be the DSH Image Manifest (${DSH_IMAGE_MANIFEST_MEDIA_TYPE}) with a sha256 digest and positive size`)
  }
  if (!Array.isArray(m.layers) || m.layers.length !== 1) {
    errors.push('layers must contain exactly one .dshpack layer (D37)')
  } else {
    const layer = m.layers[0] as Record<string, unknown> | undefined
    if (
      layer === undefined || typeof layer !== 'object'
      || layer.mediaType !== DSH_PACK_LAYER_MEDIA_TYPE
      || typeof layer.digest !== 'string' || !SHA256_RE.test(layer.digest)
      || typeof layer.size !== 'number' || layer.size <= 0
    ) {
      errors.push(`layer descriptor must be the .dshpack (${DSH_PACK_LAYER_MEDIA_TYPE}) with a sha256 digest and positive size`)
    }
  }

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, manifest: m as unknown as OciImageManifest }
}
