/**
 * v0.4 content-addressed local image store (DESIGN-v0.4.md §7, D25):
 * `$DSH_HOME/images/` with `blobs/sha256/<hex>`, `manifests/sha256/<hex>` and
 * `refs/<repo path>/<tag>`. Every write is atomic (tmp + rename); blobs are
 * immutable by construction — a digest must match its bytes or the write fails.
 * @module @why-daydream/dsh-pack/image/local-store
 */

import { randomUUID } from 'node:crypto'
import {
  existsSync, mkdirSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { canonicalJson, sha256Hex } from '../canonical.ts'
import type { DshContentDigest } from './digests.ts'
import { DIGEST_RE } from './reference.ts'
import { imageManifestDigest, validateImageManifest, type ImageManifest } from './manifest.ts'
import type { ImageRefEntry, ImageStore } from './store.ts'

/** Atomic write: tmp file + rename (same filesystem rename is atomic). */
function atomicWrite(target: string, content: Buffer | string): void {
  const tmp = `${target}.tmp-${randomUUID()}`
  writeFileSync(tmp, content)
  renameSync(tmp, target)
}

/** Content-addressed local store rooted at `$DSH_HOME/images`. */
export class LocalImageStore implements ImageStore {
  private readonly blobsDir: string
  private readonly manifestsDir: string
  private readonly refsDir: string

  constructor(root: string) {
    this.blobsDir = join(root, 'blobs', 'sha256')
    this.manifestsDir = join(root, 'manifests', 'sha256')
    this.refsDir = join(root, 'refs')
    mkdirSync(this.blobsDir, { recursive: true })
    mkdirSync(this.manifestsDir, { recursive: true })
  }

  private blobPath(digest: DshContentDigest): string {
    return join(this.blobsDir, digest.slice('sha256:'.length))
  }

  private manifestPath(digest: string): string {
    return join(this.manifestsDir, digest.slice('sha256:'.length))
  }

  /** refs/<repo>/<tag> — repo components validated (no traversal). */
  private refPath(repo: string, tag: string): string {
    if (repo === '' || repo.startsWith('/') || repo.includes('..')) {
      throw new Error(`invalid repository path ${JSON.stringify(repo)}`)
    }
    if (tag === '' || tag.includes('/') || tag.includes('..')) {
      throw new Error(`invalid tag ${JSON.stringify(tag)}`)
    }
    return join(this.refsDir, repo, tag)
  }

  async putBlob(digest: DshContentDigest, bytes: Buffer): Promise<void> {
    // The digest is the pack contentHash ANCHOR (D21), not sha256 of the raw
    // bytes — the anchor↔bytes correspondence is established by the importer
    // (computePackContentHash) and re-verified at run time. The store only
    // enforces the digest FORMAT and the content-addressing consistency rule:
    // same digest → same bytes (idempotent) or FAIL.
    if (!DIGEST_RE.test(digest)) {
      throw new Error(`invalid blob digest ${JSON.stringify(digest)} (expect sha256:<64 hex>)`)
    }
    const target = this.blobPath(digest)
    if (existsSync(target)) {
      if (readFileSync(target).equals(bytes)) return // idempotent re-import
      throw new Error(`blob ${digest} already exists with different content (content-addressing violation)`)
    }
    atomicWrite(target, bytes)
  }

  async getBlob(digest: DshContentDigest): Promise<Buffer | undefined> {
    const target = this.blobPath(digest)
    return existsSync(target) ? readFileSync(target) : undefined
  }

  async hasBlob(digest: DshContentDigest): Promise<boolean> {
    return existsSync(this.blobPath(digest))
  }

  async putManifest(digest: string, manifest: ImageManifest): Promise<void> {
    const actual = imageManifestDigest(manifest)
    if (actual !== digest) {
      throw new Error(`manifest digest mismatch: expected ${digest}, actual ${actual}`)
    }
    const target = this.manifestPath(digest)
    const serialized = `${JSON.stringify(manifest, null, 2)}\n`
    if (existsSync(target)) {
      // Idempotency is SEMANTIC: the same digest + same content must succeed
      // regardless of JSON key order in the stored file (canonicalJson sorts
      // keys — an import-built manifest and a pull-parsed one serialize
      // differently but carry identical content).
      let existing: unknown
      try {
        existing = JSON.parse(readFileSync(target, 'utf8'))
      } catch {
        throw new Error(`manifest ${digest} already exists with different content`)
      }
      if (canonicalJson(existing) === canonicalJson(manifest)) return // idempotent re-import
      throw new Error(`manifest ${digest} already exists with different content`)
    }
    atomicWrite(target, serialized)
  }

  async getManifest(digest: string): Promise<ImageManifest | undefined> {
    const target = this.manifestPath(digest)
    if (!existsSync(target)) return undefined
    const parsed = validateImageManifest(JSON.parse(readFileSync(target, 'utf8')))
    if (!parsed.ok) throw new Error(`corrupt stored manifest ${digest}: ${parsed.errors.join('; ')}`)
    return parsed.manifest
  }

  async setTag(repo: string, tag: string, manifestDigest: string): Promise<void> {
    const target = this.refPath(repo, tag)
    mkdirSync(join(this.refsDir, repo), { recursive: true })
    atomicWrite(target, `${manifestDigest}\n`)
  }

  async getTag(repo: string, tag: string): Promise<string | undefined> {
    const target = this.refPath(repo, tag)
    if (!existsSync(target)) return undefined
    const digest = readFileSync(target, 'utf8').trim()
    return digest === '' ? undefined : digest
  }

  async removeTag(repo: string, tag: string): Promise<void> {
    rmSync(this.refPath(repo, tag), { force: true })
  }

  async removeManifest(digest: string): Promise<void> {
    rmSync(this.manifestPath(digest), { force: true })
  }

  async removeBlob(digest: DshContentDigest): Promise<void> {
    rmSync(this.blobPath(digest), { force: true })
  }

  async listRefs(): Promise<ImageRefEntry[]> {
    const out: ImageRefEntry[] = []
    if (!existsSync(this.refsDir)) return out
    const walk = (dir: string, prefix: string): void => {
      for (const name of readdirSync(dir)) {
        const absolute = join(dir, name)
        const rel = prefix === '' ? name : `${prefix}/${name}`
        if (statSync(absolute).isDirectory()) walk(absolute, rel)
        else if (existsSync(absolute)) {
          const digest = readFileSync(absolute, 'utf8').trim()
          if (digest !== '') {
            const lastSlash = rel.lastIndexOf('/')
            out.push({
              repo: lastSlash === -1 ? '' : rel.slice(0, lastSlash),
              tag: lastSlash === -1 ? rel : rel.slice(lastSlash + 1),
              manifestDigest: digest,
            })
          }
        }
      }
    }
    walk(this.refsDir, '')
    return out.sort((a, b) => `${a.repo}:${a.tag}`.localeCompare(`${b.repo}:${b.tag}`))
  }
}
