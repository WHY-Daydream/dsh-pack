/**
 * v0.4.2 image lock (DESIGN-v0.4.2.md §9, D46–D49): pins a mutable remote tag
 * to an IMMUTABLE OCI manifest digest. `dsh-lock.json` carries NO trust
 * semantics (D47) — its only job is Mutable Reference → Immutable Reference;
 * a locked image still runs the full OCI → DSH → Signature → Trust chain
 * (D49). Minimal fields only: contentHash / blobDigest / signature / trust /
 * configHash / runtime versions stay OUT — all resolvable from the immutable
 * manifest. The lock object is the OCI manifestDigest (D48), never the DSH
 * contentHash.
 * @module @why-daydream/dsh-pack/image/lockfile
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { prettyJson } from '../canonical.ts'
import type { OciManifestDigest } from './digests.ts'

export const LOCKFILE_SCHEMA_VERSION = 1
export const DEFAULT_LOCKFILE = 'dsh-lock.json'
const MANIFEST_DIGEST_RE = /^sha256:[0-9a-f]{64}$/

/** One pinned mapping (D48): mutable ref → immutable OCI manifest digest. */
export interface LockEntry {
  /** immutable ref: `repo@sha256:<manifestDigest>`. */
  resolved: string
  /** the OCI manifest digest — the lock object (not contentHash/blobDigest). */
  manifestDigest: OciManifestDigest
}

/** Frozen dsh-lock.json schema (DESIGN-v0.4.2.md §9). */
export interface DshLockfile {
  schemaVersion: 1
  /** key = the mutable ref, e.g. `ghcr.io/org/agent:prod`. */
  images: Record<string, LockEntry>
}

export function emptyLockfile(): DshLockfile {
  return { schemaVersion: LOCKFILE_SCHEMA_VERSION, images: {} }
}

/** Validate an unknown value as a dsh-lock.json (frozen schema). */
export function validateLockfile(
  value: unknown,
): { ok: true; lockfile: DshLockfile } | { ok: false; errors: string[] } {
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['lockfile is not an object'] }
  const lf = value as Record<string, unknown>
  const errors: string[] = []

  if (lf.schemaVersion !== LOCKFILE_SCHEMA_VERSION) {
    errors.push(`schemaVersion must be ${LOCKFILE_SCHEMA_VERSION}`)
  }
  if (lf.images === null || typeof lf.images !== 'object') {
    errors.push('images must be an object')
  } else {
    for (const [mutableRef, rawEntry] of Object.entries(lf.images as Record<string, unknown>)) {
      const entry = rawEntry as Record<string, unknown> | undefined
      const resolvedOk = entry !== undefined && typeof entry.resolved === 'string' && entry.resolved.includes('@sha256:')
      const digestOk = entry !== undefined && typeof entry.manifestDigest === 'string'
        && MANIFEST_DIGEST_RE.test(entry.manifestDigest)
      if (!resolvedOk || !digestOk) {
        errors.push(
          `entry ${JSON.stringify(mutableRef)} must carry resolved (repo@sha256:...) and manifestDigest (sha256:<64 hex>)`,
        )
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, lockfile: lf as unknown as DshLockfile }
}

/** Load a lockfile; missing file → empty lockfile; broken file → throw. */
export function loadLockfile(file: string): DshLockfile {
  if (!existsSync(file)) return emptyLockfile()
  let parsed: unknown
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'))
  } catch {
    throw new Error(`invalid lockfile ${file}: not parseable JSON`)
  }
  const result = validateLockfile(parsed)
  if (!result.ok) throw new Error(`invalid lockfile ${file}: ${result.errors.join('; ')}`)
  return result.lockfile
}

/** Persist a lockfile (pretty JSON + trailing newline, atomic-ish). */
export function saveLockfile(file: string, lockfile: DshLockfile): void {
  mkdirSync(dirname(file), { recursive: true })
  writeFileSync(file, `${prettyJson(lockfile)}\n`)
}

/** Add (or replace) one mutable→immutable mapping. */
export function addLockEntry(
  lockfile: DshLockfile,
  mutableRef: string,
  manifestDigest: OciManifestDigest,
  resolved: string,
): DshLockfile {
  lockfile.images[mutableRef] = { resolved, manifestDigest }
  return lockfile
}
