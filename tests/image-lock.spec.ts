/**
 * v0.4.2 dsh-lock.json unit tests (DESIGN-v0.4.2.md §9, D46–D48): the lockfile
 * is a minimal Mutable Reference → Immutable Reference pin — the lock object
 * is the OCI manifestDigest (never contentHash/blobDigest), it carries no
 * trust semantics (D47), and broken files are loudly rejected.
 */
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  DEFAULT_LOCKFILE, addLockEntry, emptyLockfile, loadLockfile, saveLockfile, validateLockfile,
} from '../src/image/lockfile.js'
import type { OciManifestDigest } from '../src/image/digests.js'

const DIGEST_A = `sha256:${'a'.repeat(64)}` as OciManifestDigest
const tempDirs: string[] = []
function tempRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-pack-lock-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('dsh-lock.json (D46–D48)', () => {
  it('empty → add → save → load roundtrip preserves the mapping', () => {
    const file = join(tempRoot(), DEFAULT_LOCKFILE)
    const mutableRef = 'ghcr.io/org/agent:prod'
    const resolved = `ghcr.io/org/agent@${DIGEST_A}`
    const lockfile = addLockEntry(emptyLockfile(), mutableRef, DIGEST_A, resolved)
    saveLockfile(file, lockfile)

    const loaded = loadLockfile(file)
    expect(loaded.schemaVersion).toBe(1)
    expect(loaded.images[mutableRef]).toEqual({ resolved, manifestDigest: DIGEST_A })
    // minimal schema (prettyJson sorts keys): no contentHash/blobDigest/
    // signature/trust/configHash at either level
    const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    expect(Object.keys(raw).sort()).toEqual(['images', 'schemaVersion'])
    const entry = (raw['images'] as Record<string, Record<string, unknown>>)[mutableRef]
    expect(Object.keys(entry).sort()).toEqual(['manifestDigest', 'resolved'])
  })

  it('missing file → empty lockfile; broken JSON → FAIL; wrong schema → FAIL', () => {
    const root = tempRoot()
    expect(loadLockfile(join(root, 'nope.json'))).toEqual(emptyLockfile())

    const badJson = join(root, 'bad-json.json')
    writeFileSync(badJson, '{ not json')
    expect(() => loadLockfile(badJson)).toThrow(/not parseable/)

    const wrongSchema = join(root, 'wrong-schema.json')
    writeFileSync(wrongSchema, JSON.stringify({ schemaVersion: 99, images: {} }))
    expect(() => loadLockfile(wrongSchema)).toThrow(/schemaVersion/)
  })

  it('rejects entries whose lock object is not an OCI manifest digest (D48)', () => {
    const root = tempRoot()
    const file = join(root, 'bad-entry.json')
    writeFileSync(file, JSON.stringify({
      schemaVersion: 1,
      images: { 'ghcr.io/org/agent:prod': { resolved: 'ghcr.io/org/agent@sha256:' + 'a'.repeat(64), manifestDigest: 'sha256:zzz' } },
    }))
    expect(() => loadLockfile(file)).toThrow(/must carry/)
    expect(validateLockfile({ schemaVersion: 1, images: { x: { resolved: 'no-at', manifestDigest: DIGEST_A } } }).ok).toBe(false)
  })
})
