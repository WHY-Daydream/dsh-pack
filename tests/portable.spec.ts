/**
 * Portable vendoring unit tests (DESIGN.md v0.2 --portable): local closure DFS
 * (transitive + cycle detection), vendored tgz layout and integrity, and the
 * directory→tarball lockfile rewrite (validated shape from the pnpm v11
 * experiment of 2026-08-29).
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { afterEach, describe, expect, it } from 'vitest'
import * as tar from 'tar'
import { parseYaml } from '../src/canonical.js'
import {
  buildPortablePlan, collectLocalClosure, rewriteLockfileForPortable, tgzIntegrity,
} from '../src/portable.js'
import { PackError } from '../src/service.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-portable-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** List the entry paths inside a tgz buffer (tar.t only accepts paths/streams). */
async function listTgz(tgz: Buffer): Promise<string[]> {
  const entries: string[] = []
  await new Promise<void>((resolvePromise, reject) => {
    const parser = tar.t({ onentry: (entry) => entries.push(entry.path) })
    parser.on('close', resolvePromise)
    parser.on('error', reject)
    Readable.from([tgz]).pipe(parser)
  })
  return entries
}

/** Extract a file's text from a tgz buffer. */
async function readTgzFile(tgz: Buffer, target: string): Promise<string> {
  const files: Record<string, string> = {}
  await new Promise<void>((resolvePromise, reject) => {
    const parser = tar.t({ onentry: (entry) => {
      const chunks: Buffer[] = []
      entry.on('data', (c: Buffer) => chunks.push(c))
      entry.on('end', () => { files[entry.path] = Buffer.concat(chunks).toString('utf8') })
    } })
    parser.on('close', resolvePromise)
    parser.on('error', reject)
    Readable.from([tgz]).pipe(parser)
  })
  const content = files[target]
  if (content === undefined) throw new Error(`no ${target} entry in tgz (have: ${Object.keys(files).join(', ')})`)
  return content
}

/** Build the fixture: profile → file:../local/a-tool → file:../b-lib. */
function makeFixture(root: string): { profileDir: string; deps: Record<string, string> } {
  const local = join(root, 'local')
  mkdirSync(join(local, 'a-tool'), { recursive: true })
  mkdirSync(join(local, 'b-lib'), { recursive: true })
  writeFileSync(join(local, 'b-lib', 'package.json'), JSON.stringify({
    name: '@xp/b-lib', version: '1.0.0', main: 'index.js',
  }))
  writeFileSync(join(local, 'b-lib', 'index.js'), 'module.exports = { b: true }\n')
  writeFileSync(join(local, 'a-tool', 'package.json'), JSON.stringify({
    name: '@xp/a-tool', version: '1.0.0', main: 'index.js',
    dependencies: { '@xp/b-lib': 'file:../b-lib' },
  }))
  writeFileSync(join(local, 'a-tool', 'index.js'), 'module.exports = { a: true }\n')

  const profileDir = join(root, 'profiles', 'web')
  mkdirSync(profileDir, { recursive: true })
  const deps = { '@xp/a-tool': 'file:../../local/a-tool' }
  // Realistic pnpm v9 lockfile: packages keys + snapshot deps use the
  // PROJECT-relative path (../../local/... from profiles/web), which for the
  // transitive b-lib differs from its declared spec (file:../b-lib).
  writeFileSync(join(profileDir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      '@xp/a-tool':
        specifier: file:../../local/a-tool
        version: file:../../local/a-tool

packages:

  '@xp/a-tool@file:../../local/a-tool':
    resolution: {directory: ../../local/a-tool, type: directory}

  '@xp/b-lib@file:../../local/b-lib':
    resolution: {directory: ../../local/b-lib, type: directory}

snapshots:

  '@xp/a-tool@file:../../local/a-tool':
    dependencies:
      '@xp/b-lib': file:../../local/b-lib

  '@xp/b-lib@file:../../local/b-lib': {}
`)
  return { profileDir, deps }
}

describe('collectLocalClosure', () => {
  it('walks the transitive local closure post-order and dedupes', () => {
    const root = tempRoot('closure')
    const { profileDir, deps } = makeFixture(root)
    const closure = collectLocalClosure(profileDir, deps)
    expect(closure.map((p) => p.name)).toEqual(['@xp/b-lib', '@xp/a-tool'])
    expect(closure[0]).toMatchObject({ version: '1.0.0', kind: 'directory', tgz: 'xp-b-lib-1.0.0.tgz' })
    expect(closure[1]).toMatchObject({ version: '1.0.0', kind: 'directory', tgz: 'xp-a-tool-1.0.0.tgz' })
  })

  it('detects local dependency cycles', () => {
    const root = tempRoot('cycle')
    const dirA = join(root, 'a')
    const dirB = join(root, 'b')
    mkdirSync(dirA, { recursive: true })
    mkdirSync(dirB, { recursive: true })
    writeFileSync(join(dirA, 'package.json'), JSON.stringify({
      name: 'a', version: '1.0.0', dependencies: { b: 'file:../b' },
    }))
    writeFileSync(join(dirB, 'package.json'), JSON.stringify({
      name: 'b', version: '1.0.0', dependencies: { a: 'file:../a' },
    }))
    const profileDir = join(root, 'profiles', 'web')
    mkdirSync(profileDir, { recursive: true })
    expect(() => collectLocalClosure(profileDir, { a: 'file:../../a' }))
      .toThrowError(PackError)
    expect(() => collectLocalClosure(profileDir, { a: 'file:../../a' }))
      .toThrow(/cycle/i)
  })
})

describe('buildPortablePlan', () => {
  it('produces package/-prefixed tgzs with rewritten internal specs', async () => {
    const root = tempRoot('plan')
    const { profileDir, deps } = makeFixture(root)
    const plan = await buildPortablePlan(profileDir, deps)

    // staged direct dep uses the pack-relative form (MUST-2)
    expect(plan.stagedDeps['@xp/a-tool']).toBe('file:./packages/xp-a-tool-1.0.0.tgz')
    // spec rewrites target the install-side vendor location
    expect(plan.specRewrites['file:../../local/a-tool']).toBe('file:vendor/xp-a-tool-1.0.0.tgz')
    expect(plan.specRewrites['file:../b-lib']).toBe('file:vendor/xp-b-lib-1.0.0.tgz')

    // tgz layout: package/ prefix (npm convention), both packages present
    const aTgz = plan.tgzs['xp-a-tool-1.0.0.tgz']
    const bTgz = plan.tgzs['xp-b-lib-1.0.0.tgz']
    expect(aTgz).toBeDefined()
    expect(bTgz).toBeDefined()

    const entries = await listTgz(aTgz as Buffer)
    expect(entries.every((path) => path.startsWith('package/'))).toBe(true)

    // the vendored a-tool package.json has the rewritten transitive spec
    const pkgJson = JSON.parse(await readTgzFile(aTgz as Buffer, 'package/package.json')) as {
      dependencies: Record<string, string>
    }
    expect(pkgJson.dependencies['@xp/b-lib']).toBe('file:vendor/xp-b-lib-1.0.0.tgz')
  })

  it('computes pnpm-format integrity for the vendored tgzs', async () => {
    const root = tempRoot('integrity')
    const { profileDir, deps } = makeFixture(root)
    const plan = await buildPortablePlan(profileDir, deps)
    const tgz = plan.tgzs['xp-a-tool-1.0.0.tgz'] as Buffer
    expect(tgzIntegrity(tgz)).toMatch(/^sha512-[A-Za-z0-9+/=]+$/)
  })
})

describe('rewriteLockfileForPortable', () => {
  it('rewrites directory-form entries to the vendored tarball form', async () => {
    const root = tempRoot('lockfile')
    const { profileDir, deps } = makeFixture(root)
    const plan = await buildPortablePlan(profileDir, deps)
    expect(plan.lockfile).toBeDefined()
    const lock = parseYaml(plan.lockfile as string) as Record<string, unknown>

    const importers = lock.importers as { '.': { dependencies: Record<string, { specifier: string; version: string }> } }
    expect(importers['.'].dependencies['@xp/a-tool']).toEqual({
      specifier: 'file:vendor/xp-a-tool-1.0.0.tgz',
      version: 'file:vendor/xp-a-tool-1.0.0.tgz',
    })

    const pkgMap = lock.packages as Record<string, Record<string, unknown>>
    const aEntry = pkgMap['@xp/a-tool@file:vendor/xp-a-tool-1.0.0.tgz']
    expect(aEntry).toBeDefined()
    expect(aEntry.version).toBe('1.0.0')
    const resolution = aEntry.resolution as { integrity: string; tarball: string }
    expect(resolution.tarball).toBe('file:vendor/xp-a-tool-1.0.0.tgz')
    expect(resolution.integrity).toBe(tgzIntegrity(plan.tgzs['xp-a-tool-1.0.0.tgz'] as Buffer))
    // no directory-form keys survive
    expect(Object.keys(pkgMap).some((key) => key.includes('file:../../local') || key.includes('file:../b-lib'))).toBe(false)

    const snapshots = lock.snapshots as Record<string, { dependencies: Record<string, string> }>
    expect(snapshots['@xp/a-tool@file:vendor/xp-a-tool-1.0.0.tgz'].dependencies['@xp/b-lib'])
      .toBe('file:vendor/xp-b-lib-1.0.0.tgz')
    expect(snapshots['@xp/b-lib@file:vendor/xp-b-lib-1.0.0.tgz']).toBeDefined()
  })

  it('returns undefined when the profile has no lockfile', async () => {
    const root = tempRoot('nolock')
    const { profileDir, deps } = makeFixture(root)
    rmSync(join(profileDir, 'pnpm-lock.yaml'))
    expect(rewriteLockfileForPortable(profileDir, [], {})).toBeUndefined()
  })
})
