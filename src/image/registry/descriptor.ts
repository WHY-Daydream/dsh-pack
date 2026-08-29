/**
 * v0.4.1 OCI descriptor verification (DESIGN-v0.4.1.md §2/§5, D32/D38):
 * every digest is recomputed from the ACTUAL raw bytes — the registry's
 * headers are never trusted. Transport integrity is established before any
 * DSH-level verification runs (D39).
 * @module @why-daydream/dsh-pack/image/registry/descriptor
 */

import { sha256Hex } from '../../canonical.ts'
import type { OciBlobDigest, OciManifestDigest } from './types.ts'

export const SHA256_RE = /^sha256:[0-9a-f]{64}$/

/** Digest of raw bytes (OCI blob/manifest digests share this computation). */
export function digestOf(bytes: Buffer): OciBlobDigest {
  return `sha256:${sha256Hex(bytes)}` as OciBlobDigest
}

export function isValidDigest(digest: string): boolean {
  return SHA256_RE.test(digest)
}

/** Verify a digest against recomputed bytes; throws with a precise label. */
export function assertDigestMatch(what: string, actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error(
      `${what} digest mismatch: expected ${expected}, actual ${actual} (transport integrity failure)`,
    )
  }
}

/** Verify a descriptor { mediaType, digest, size } against actual bytes. */
export function verifyDescriptorBytes(
  what: string,
  descriptor: { digest: string; size: number },
  bytes: Buffer,
): void {
  if (bytes.length !== descriptor.size) {
    throw new Error(
      `${what} size mismatch: expected ${descriptor.size}, actual ${bytes.length} (transport integrity failure)`,
    )
  }
  assertDigestMatch(what, digestOf(bytes), descriptor.digest)
}

/** OCI manifest digest over canonical manifest JSON bytes. */
export function manifestDigestOf(canonicalJsonBytes: string): OciManifestDigest {
  return `sha256:${sha256Hex(Buffer.from(canonicalJsonBytes, 'utf8'))}` as OciManifestDigest
}
