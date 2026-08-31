/**
 * v0.6.0-alpha.3 Remote Evidence Cache (DESIGN-v0.6.0.md, D166–D174):
 * a CONTENT-ADDRESSED BYTE cache — never a trust cache (D166).
 *
 * Two layers:
 *   1. OCI Object CAS — `manifests/<digest>` + `blobs/<digest>`:
 *      immutable objects keyed by their OCI digest (D167). Every read
 *      RECOMPUTES sha256 over the cached bytes and compares to the key
 *      (D172): a path named `sha256-A` holding bytes B is CORRUPTION,
 *      surfaced fail-loud (and, online, deleted + re-fetched — it is never
 *      silently repaired into identity A).
 *   2. Discovery Snapshot — keyed by canonical `(registry, repository, M)`
 *      (D157/D167): ONE complete (D158) enumeration at a point in time.
 *      `M` immutable does NOT make `referrers(M)` immutable (D169) — a
 *      snapshot is freshness/availability metadata, never a trust input,
 *      never a latest-wins selector (N5/D127). Only `complete: true`
 *      enumerations are ever written, and atomically: a partial
 *      enumeration can never create or overwrite a snapshot (D171).
 *
 * The cache is deliberately UNINTELLIGENT about policy: it never imports
 * trust-policy, never holds `trusted/allow/deny`, and eviction or absence
 * changes availability/performance only (D173). No TTL / LRU / GC in
 * alpha.3.
 * @module @why-daydream/dsh-pack/evidence/remote/cache
 */

import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { sha256Hex } from '../../canonical.ts'
import type { RemoteEvidenceDiscoverySnapshot, RemoteEvidenceLocator } from './types.ts'

/** A CAS entry that failed digest revalidation (D172). */
export class CacheCorruptionError extends Error {
  constructor(digest: string, actual: string) {
    super(`cache corruption detected: object at ${digest} has actual digest ${actual} (D172 — fail loud, no silent repair)`)
    this.name = 'CacheCorruptionError'
    this.digest = digest
    this.actualDigest = actual
  }
  /** The digest the object was addressed BY. */
  readonly digest: string
  /** The digest the cached bytes ACTUALLY hash to. */
  readonly actualDigest: string
}

function sha256Of(bytes: Buffer): string {
  return `sha256:${sha256Hex(bytes)}`
}

/**
 * The remote Evidence cache. Directory layout:
 *
 *   <root>/manifests/<sha256>/<hex>     — evidence manifest objects (CAS)
 *   <root>/blobs/<sha256>/<hex>         — envelope/document blobs (CAS)
 *   <root>/snapshots/<sha256>/<hex>     — discovery snapshots (canonical key)
 */
export class RemoteEvidenceCache {
  private readonly root: string

  constructor(root: string) {
    this.root = root
    mkdirSync(join(root, 'manifests'), { recursive: true })
    mkdirSync(join(root, 'blobs'), { recursive: true })
    mkdirSync(join(root, 'snapshots'), { recursive: true })
  }

  // ── OCI Object CAS (D166/D167/D172) ─────────────────────────────────────

  /** CAS path for a digest (split so filenames stay short). */
  private objectPath(kind: 'manifests' | 'blobs', digest: string): string {
    const [, hex = ''] = digest.split(':')
    return join(this.root, kind, hex.slice(0, 6), hex)
  }

  /**
   * D167/D172 — fetch an immutable object BY digest. A hit RECOMPUTES the
   * digest over the cached bytes and throws CacheCorruptionError on mismatch
   * (never returns wrong-identity bytes). Miss → undefined (caller fetches
   * remote and stores).
   */
  getOciObject(kind: 'manifests' | 'blobs', digest: string): Buffer | undefined {
    const path = this.objectPath(kind, digest)
    if (!existsSync(path)) return undefined
    const bytes = readFileSync(path)
    const actual = sha256Of(bytes)
    if (actual !== digest) {
      throw new CacheCorruptionError(digest, actual)
    }
    return bytes
  }

  /** D166 — store immutable bytes under their digest (verified by caller). */
  putOciObject(kind: 'manifests' | 'blobs', digest: string, bytes: Buffer): void {
    // re-assert identity on write too: never file B under A
    if (sha256Of(bytes) !== digest) {
      throw new CacheCorruptionError(digest, sha256Of(bytes))
    }
    const path = this.objectPath(kind, digest)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, bytes)
  }

  /** D172 (online) — delete a corrupt object so it can be re-fetched. */
  deleteCorruptObject(kind: 'manifests' | 'blobs', digest: string): void {
    rmSync(this.objectPath(kind, digest), { force: true })
  }

  /** True when the object is present AND digest-valid (used by offline checks). */
  hasOciObject(kind: 'manifests' | 'blobs', digest: string): boolean {
    try {
      return this.getOciObject(kind, digest) !== undefined
    } catch (error) {
      if (error instanceof CacheCorruptionError) return false
      throw error
    }
  }

  // ── Discovery Snapshot (D169/D170/D171) ────────────────────────────────

  /**
   * D157/D167 — canonical snapshot key: sha256 over the canonical
   * `(registry|repository|subjectM)` string. Identity domains stay separate:
   * never keyed by tag (N1) and never by DSH contentHash (D167).
   */
  static snapshotKey(locator: RemoteEvidenceLocator): string {
    const canonical = `${locator.registry}|${locator.repository}|${locator.subjectManifestDigest}`
    return createHash('sha256').update(canonical, 'utf8').digest('hex')
  }

  /**
   * D171 — read the last KNOWN-COMPLETE snapshot for a locator (or undefined).
   * A snapshot is all-or-nothing: this method only ever returns stored
   * `complete: true` snapshots; a corrupt snapshot file fails loud.
   */
  getDiscoverySnapshot(locator: RemoteEvidenceLocator): RemoteEvidenceDiscoverySnapshot | undefined {
    const hex = RemoteEvidenceCache.snapshotKey(locator)
    const path = join(this.root, 'snapshots', hex.slice(0, 6), hex)
    if (!existsSync(path)) return undefined
    const bytes = readFileSync(path)
    const parsed = JSON.parse(bytes.toString('utf8')) as RemoteEvidenceDiscoverySnapshot
    // re-validate the stored identity — the snapshot must still match its key
    if (
      parsed.registry !== locator.registry ||
      parsed.repository !== locator.repository ||
      parsed.subjectManifestDigest !== locator.subjectManifestDigest ||
      parsed.complete !== true ||
      !Array.isArray(parsed.descriptors)
    ) {
      throw new CacheCorruptionError(hex, 'identity-mismatch')
    }
    return parsed
  }

  /**
   * D171 — atomically store ONE COMPLETE snapshot (all-or-nothing). Only
   * `complete: true` snapshots are accepted; writing is a temp+rename so a
   * snapshot file is never observed half-written.
   */
  putDiscoverySnapshot(snapshot: RemoteEvidenceDiscoverySnapshot): void {
    if (snapshot.complete !== true) {
      throw new Error('refusing to cache an incomplete discovery snapshot (D171)')
    }
    const hex = RemoteEvidenceCache.snapshotKey({
      registry: snapshot.registry,
      repository: snapshot.repository,
      subjectManifestDigest: snapshot.subjectManifestDigest,
    })
    const path = join(this.root, 'snapshots', hex.slice(0, 6), hex)
    mkdirSync(dirname(path), { recursive: true })
    const tmp = `${path}.tmp-${process.pid}`
    writeFileSync(tmp, Buffer.from(JSON.stringify(snapshot), 'utf8'))
    // rename is atomic on POSIX — readers see old or new, never partial
    renameSync(tmp, path)
  }

  /** D173 (test/diagnostic) — drop a snapshot; availability only, no trust effect. */
  deleteDiscoverySnapshot(locator: RemoteEvidenceLocator): void {
    const hex = RemoteEvidenceCache.snapshotKey(locator)
    rmSync(join(this.root, 'snapshots', hex.slice(0, 6), hex), { force: true })
  }

  /** True when a snapshot exists for the locator (diagnostic only). */
  hasDiscoverySnapshot(locator: RemoteEvidenceLocator): boolean {
    try {
      return this.getDiscoverySnapshot(locator) !== undefined
    } catch {
      return false
    }
  }
}
