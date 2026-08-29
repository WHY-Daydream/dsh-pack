/**
 * v0.4 Image Manifest (DESIGN-v0.4.md §6, D24): distribution metadata that is
 * SEPARATE from the `.dshpack` v1 runtime artifact (which stays frozen, D23).
 * The manifest lives in the store's `manifests/`, never inside the pack.
 * `artifact.digest` = pack contentHash (the single immutable identity, D21).
 * @module @why-daydream/dsh-pack/image/manifest
 */

import { canonicalJson, sha256Hex } from '../canonical.ts'

export const IMAGE_MANIFEST_MEDIA_TYPE = 'application/vnd.dsh.image.manifest.v1+json'
export const PACK_MEDIA_TYPE = 'application/vnd.dsh.pack.v1+gzip'
export const IMAGE_MANIFEST_SCHEMA_VERSION = 1
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

/** Frozen v1 image manifest schema (DESIGN-v0.4.md §6). */
export interface ImageManifest {
  schemaVersion: 1
  mediaType: typeof IMAGE_MANIFEST_MEDIA_TYPE
  artifact: {
    /** = pack contentHash — the immutable identity anchor. */
    digest: string
    /** pack byte size. */
    size: number
    mediaType: typeof PACK_MEDIA_TYPE
  }
  configHash: string
  platform: {
    /** exact dsh build version (run compatibility, §14). */
    dshVersion: string
    /** semver range, default `>=24`. */
    node?: string
    /** semver range, default `>=10`. */
    pnpm?: string
  }
  /** OCI-compatible annotations (D31). */
  annotations?: Record<string, string>
}

export interface BuildImageManifestInput {
  artifactDigest: string
  artifactSize: number
  configHash: string
  dshVersion: string
  node?: string
  pnpm?: string
  annotations?: Record<string, string>
}

/** Build a schema-v1 image manifest. */
export function buildImageManifest(input: BuildImageManifestInput): ImageManifest {
  const manifest: ImageManifest = {
    schemaVersion: IMAGE_MANIFEST_SCHEMA_VERSION,
    mediaType: IMAGE_MANIFEST_MEDIA_TYPE,
    artifact: { digest: input.artifactDigest, size: input.artifactSize, mediaType: PACK_MEDIA_TYPE },
    configHash: input.configHash,
    platform: {
      dshVersion: input.dshVersion,
      ...(input.node !== undefined ? { node: input.node } : {}),
      ...(input.pnpm !== undefined ? { pnpm: input.pnpm } : {}),
    },
  }
  if (input.annotations !== undefined && Object.keys(input.annotations).length > 0) {
    manifest.annotations = { ...input.annotations }
  }
  return manifest
}

/** Manifest digest = sha256 over the canonical (sorted, compact) manifest JSON. */
export function imageManifestDigest(manifest: ImageManifest): string {
  return `sha256:${sha256Hex(canonicalJson(manifest))}`
}

/** Validate an unknown manifest value against schema v1. */
export function validateImageManifest(
  value: unknown,
): { ok: true; manifest: ImageManifest } | { ok: false; errors: string[] } {
  const errors: string[] = []
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['manifest is not an object'] }
  const m = value as Record<string, unknown>

  if (m.schemaVersion !== IMAGE_MANIFEST_SCHEMA_VERSION) {
    errors.push(`schemaVersion must be ${IMAGE_MANIFEST_SCHEMA_VERSION}`)
  }
  if (m.mediaType !== IMAGE_MANIFEST_MEDIA_TYPE) {
    errors.push(`mediaType must be "${IMAGE_MANIFEST_MEDIA_TYPE}"`)
  }
  const artifact = m.artifact as Record<string, unknown> | undefined
  if (artifact === undefined || typeof artifact.digest !== 'string' || !DIGEST_RE.test(artifact.digest)) {
    errors.push('artifact.digest must be sha256:<64 hex>')
  }
  if (artifact === undefined || typeof artifact.size !== 'number' || artifact.size <= 0) {
    errors.push('artifact.size must be a positive number')
  }
  if (artifact === undefined || artifact.mediaType !== PACK_MEDIA_TYPE) {
    errors.push(`artifact.mediaType must be "${PACK_MEDIA_TYPE}"`)
  }
  if (typeof m.configHash !== 'string' || !DIGEST_RE.test(m.configHash)) {
    errors.push('configHash must be sha256:<64 hex>')
  }
  const platform = m.platform as Record<string, unknown> | undefined
  if (platform === undefined || typeof platform.dshVersion !== 'string' || platform.dshVersion === '') {
    errors.push('platform.dshVersion must be a non-empty string')
  }

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, manifest: m as unknown as ImageManifest }
}
