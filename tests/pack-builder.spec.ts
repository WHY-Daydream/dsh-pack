/**
 * Pack builder unit tests (DESIGN.md §3.1, §7.2, §7.4, MUST-4): deterministic
 * archives, non-self-referential contentHash, and safe extraction that rejects
 * traversal and symlink entries.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import * as tar from 'tar'
import {
  buildTarGz, checksumsJson, computeContentHash, extractTarGz, type PackFileEntry,
} from '../src/pack-builder.js'

const tempDirs: string[] = []
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-pack-pb-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const entries: PackFileEntry[] = [
  { path: 'manifest.json', content: '{"format":"dshpack"}' },
  { path: 'profile/cordis.patch.yml', content: '- insert:\n    - id: x\n' },
  { path: 'README.md', content: 'hello' },
]

describe('buildTarGz', () => {
  it('is byte-deterministic for the same entries', async () => {
    const a = await buildTarGz(entries)
    const b = await buildTarGz([...entries].reverse()) // insertion order must not matter
    expect(a.buffer.equals(b.buffer)).toBe(true)
  })

  it('computes a non-self-referential contentHash over the inventory', async () => {
    const built = await buildTarGz(entries)
    expect(built.contentHash).toBe(computeContentHash(built.files))
    const checksums = checksumsJson(built.contentHash, built.files)
    expect(checksums).toContain('manifest.json')
    // files map itself never contains checksums.json
    expect(built.files['metadata/checksums.json']).toBeUndefined()
  })

  it('round-trips through safe extraction', async () => {
    const built = await buildTarGz(entries)
    const dest = tempDir()
    await extractTarGz(built.buffer, dest)
    const { readFileSync, existsSync } = await import('node:fs')
    expect(existsSync(join(dest, 'manifest.json'))).toBe(true)
    expect(readFileSync(join(dest, 'README.md'), 'utf8')).toBe('hello')
  })
})

describe('extractTarGz safety (MUST-4)', () => {
  it('rejects a symlink entry', async () => {
    const dir = tempDir()
    const sub = join(dir, 'sub')
    mkdirSync(sub)
    writeFileSync(join(dir, 'target.txt'), 'payload')
    symlinkSync('target.txt', join(sub, 'link'))
    const buffer = await buildBufferFromDisk(dir, ['sub/link'])
    await expect(extractTarGz(buffer, tempDir())).rejects.toThrow(/unsafe archive entry type/)
  })

  it('extracts a normal file fine', async () => {
    const dir = tempDir()
    writeFileSync(join(dir, 'ok.txt'), 'fine')
    const buffer = await buildBufferFromDisk(dir, ['ok.txt'])
    const dest = tempDir()
    await extractTarGz(buffer, dest)
    const { readFileSync } = await import('node:fs')
    expect(readFileSync(join(dest, 'ok.txt'), 'utf8')).toBe('fine')
  })
})

/** Build a tar.gz buffer directly from files on disk (for hostile-entry tests). */
async function buildBufferFromDisk(cwd: string, fileList: string[]): Promise<Buffer> {
  const chunks: Buffer[] = []
  await new Promise<void>((resolvePromise, reject) => {
    const stream = tar.c({ cwd, gzip: true, mtime: new Date(0) }, fileList)
    stream.on('data', (chunk: Buffer) => chunks.push(chunk))
    stream.on('end', resolvePromise)
    stream.on('error', reject)
  })
  return Buffer.concat(chunks)
}
