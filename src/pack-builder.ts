/**
 * Deterministic pack building (DESIGN.md §3.1, §7.2, §7.4): assembles the
 * `.dshpack` tar.gz with sorted entries, mtime=0, normalized modes, computes
 * per-file checksums and the non-self-referential contentHash, and safely
 * extracts archives (MUST-4: path-traversal / symlink / device rejection).
 * @module @why-daydream/dsh-pack/pack-builder
 */

import {
  mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { Readable } from 'node:stream'
import * as tar from 'tar'
import { prettyJson, sha256Hex } from './canonical.ts'

/** One file to pack. */
export interface PackFileEntry {
  /** Archive path, always forward-slash, no leading `./`. */
  path: string
  content: string | Buffer
}

export interface BuiltPack {
  /** The deterministic tar.gz bytes. */
  buffer: Buffer
  /** path → sha256 (every entry except checksums.json itself). */
  files: Record<string, string>
  /** sha256 over the sorted `path:hash` inventory. */
  contentHash: string
}

/** Build the deterministic archive from in-memory entries (DESIGN.md §7.2). */
export async function buildTarGz(entries: PackFileEntry[]): Promise<BuiltPack> {
  const files: Record<string, string> = {}
  const sorted = [...entries].sort((a, b) => a.path.localeCompare(b.path))
  const staging = mkdtempSync(join(tmpdir(), 'dsh-pack-'))
  try {
    for (const entry of sorted) {
      const absolute = safeJoin(staging, entry.path)
      mkdirSync(dirname(absolute), { recursive: true })
      writeFileSync(absolute, entry.content)
      files[entry.path] = sha256Hex(Buffer.from(entry.content))
    }
    const contentHash = computeContentHash(files)
    const fileList = sorted.map((entry) => entry.path)
    const buffer = await createArchive(staging, fileList)
    return { buffer, files, contentHash }
  } finally {
    rmSync(staging, { recursive: true, force: true })
  }
}

/** Deterministic tar.gz over already-written files (mtime=0, portable modes). */
async function createArchive(cwd: string, fileList: string[]): Promise<Buffer> {
  const chunks: Buffer[] = []
  await new Promise<void>((resolvePromise, reject) => {
    const stream = tar.c({
      cwd,
      gzip: true,
      portable: true,
      strict: true,
      mtime: new Date(0),
    }, fileList)
    stream.on('data', (chunk: Buffer) => chunks.push(chunk))
    stream.on('end', resolvePromise)
    stream.on('error', reject)
  })
  return Buffer.concat(chunks)
}

/** contentHash = sha256 over the sorted `path:fileSha256` inventory (§7.4). */
export function computeContentHash(files: Record<string, string>): string {
  const lines = Object.entries(files)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([path, hash]) => `${path}:${hash}`)
  return `sha256:${sha256Hex(lines.join('\n'))}`
}

/** checksums.json content (files map excludes checksums.json — no self-reference). */
export function checksumsJson(contentHash: string, files: Record<string, string>): string {
  return prettyJson({ schemaVersion: 1, contentHash, files })
}

const SAFE_TYPES = new Set(['File', 'OldFile', 'Directory'])
const UNSAFE_TYPES = new Set(['SymbolicLink', 'Link', 'CharacterDevice', 'BlockDevice', 'FIFO'])

/**
 * Safe extraction (MUST-4, DESIGN.md §8.4): every entry path must normalize
 * below the destination root; symlink / hardlink / device / FIFO entries are
 * rejected. Violations are collected while extracting (filter returns false,
 * so nothing hostile is written) and the whole extraction then fails loud —
 * callers never consume a partially-hostile tree.
 */
export async function extractTarGz(buffer: Buffer, dest: string): Promise<void> {
  mkdirSync(dest, { recursive: true })
  const violations: string[] = []
  await new Promise<void>((resolvePromise, reject) => {
    const extractor = tar.x({
      cwd: dest,
      strict: true,
      filter: (path: string, entry: unknown) => {
        const normalized = path.split(/[\\/]/).filter((part) => part !== '' && part !== '.').join('/')
        if (normalized === '..' || normalized.startsWith('../') || path.startsWith('/')
          || /(^|\/)\.\.($|\/)/.test(path)) {
          violations.push(`unsafe archive entry path: ${path}`)
          return false
        }
        const type = (entry as { type?: string }).type
        if (type !== undefined) {
          if (UNSAFE_TYPES.has(type)) {
            violations.push(`unsafe archive entry type ${type} at ${path}`)
            return false
          }
          if (!SAFE_TYPES.has(type)) {
            violations.push(`unsupported archive entry type ${type} at ${path}`)
            return false
          }
          return true
        }
        // Stats-style entry (no ReadEntry type): allow only directories.
        const isDirectory = (entry as { isDirectory?: () => boolean }).isDirectory?.()
        if (isDirectory !== true) {
          violations.push(`unsupported archive entry at ${path}`)
          return false
        }
        return true
      },
    })
    const source = Readable.from([buffer])
    source.on('error', reject)
    extractor.on('close', resolvePromise)
    extractor.on('error', reject)
    source.pipe(extractor)
  })
  if (violations.length > 0) {
    throw new Error(violations.join('; '))
  }
}

/** Join a path inside a root, rejecting escapes. */
function safeJoin(root: string, relativePath: string): string {
  const clean = relativePath.split('/').filter((part) => part !== '' && part !== '.').join('/')
  if (clean === '..' || clean.startsWith('../') || clean.startsWith('/') || /(^|\/)\.\.($|\/)/.test(clean)) {
    throw new Error(`unsafe archive entry path: ${relativePath}`)
  }
  return join(root, clean)
}

export interface PackArchive {
  /** Extracted temp root (caller must clean up). */
  root: string
  manifest: Record<string, unknown>
  /** All files under root, relative paths. */
  files: string[]
}

/** Extract an archive to a temp dir and load its manifest (used by verify/inspect/install). */
export async function openPack(buffer: Buffer): Promise<PackArchive> {
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-open-'))
  await extractTarGz(buffer, root)
  const files = collectFiles(root)
  if (!files.includes('manifest.json')) {
    throw new Error('dsh-pack: archive has no manifest.json — not a .dshpack')
  }
  const manifest = JSON.parse(readFileSync(join(root, 'manifest.json'), 'utf8')) as Record<string, unknown>
  return { root, manifest, files }
}

/** Recursively collect relative file paths under a root, sorted. */
export function collectFiles(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, prefix: string): void => {
    for (const name of readdirSync(dir)) {
      const absolute = join(dir, name)
      const rel = prefix === '' ? name : `${prefix}/${name}`
      if (statSync(absolute).isDirectory()) walk(absolute, rel)
      else out.push(rel)
    }
  }
  walk(root, '')
  return out.sort()
}
