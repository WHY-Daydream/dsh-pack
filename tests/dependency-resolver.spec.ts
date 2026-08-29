/**
 * Dependency resolver unit tests (DESIGN.md §5): spec classification, lockfile
 * closure parsing, non-portable detection (D7) and staged lockfile rewriting
 * (MUST-2).
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import {
  classifySpec, isFloatingGithubSpec, parsePackageKey, resolveDependencies, rewriteLockfileForStaging,
} from '../src/dependency-resolver.js'

const tempDirs: string[] = []
function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-pack-dep-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('classifySpec', () => {
  it('classifies every spec kind', () => {
    expect(classifySpec('^1.2.3')).toBe('npm')
    expect(classifySpec('github:WHY-Daydream/x#abc')).toBe('github')
    expect(classifySpec('git+https://github.com/a/b.git')).toBe('github')
    expect(classifySpec('file:../x.tgz')).toBe('tarball')
    expect(classifySpec('file:../x')).toBe('file')
    expect(classifySpec('link:../x')).toBe('link')
  })
})

describe('isFloatingGithubSpec', () => {
  it('flags unpinned github specs', () => {
    expect(isFloatingGithubSpec('github:WHY-Daydream/x')).toBe(true)
    expect(isFloatingGithubSpec('github:WHY-Daydream/x#abc1234')).toBe(false)
  })
})

describe('parsePackageKey', () => {
  it('parses scoped and peer-suffixed lockfile keys', () => {
    expect(parsePackageKey('foo@1.2.3')).toEqual({ name: 'foo', version: '1.2.3' })
    expect(parsePackageKey('/@scope/x@1.0.0')).toEqual({ name: '@scope/x', version: '1.0.0' })
    expect(parsePackageKey('foo@1.0.0(peer@2)')).toEqual({ name: 'foo', version: '1.0.0' })
    expect(parsePackageKey('nonsense')).toBeUndefined()
  })
})

describe('resolveDependencies', () => {
  it('builds the closure from pnpm-lock.yaml and flags local deps', () => {
    const dir = tempDir()
    const direct = {
      'dsh-tool-bulkhead': '0.1.0',
      'dsh-local': 'link:../../dsh-local',
      'dsh-flaky': 'github:WHY-Daydream/flaky',
      'dsh-tgz': 'file:../dist/x.tgz',
    }
    writeFileSync(join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'
importers:
  '.':
    dependencies:
      dsh-tool-bulkhead:
        specifier: 0.1.0
        version: 0.1.0
      dsh-local:
        specifier: link:../../dsh-local
        version: link:../../dsh-local
      dsh-tgz:
        specifier: file:../dist/x.tgz
        version: file:../dist/x.tgz
packages:
  dsh-tool-bulkhead@0.1.0:
    resolution: {integrity: sha512-aaaa}
  undici@7.0.0:
    resolution: {integrity: sha512-bbbb}
`)
    const tree = resolveDependencies(dir, direct, ['dsh-tool-bulkhead'])
    expect(tree.closure['dsh-tool-bulkhead']).toBe('0.1.0')
    expect(tree.closure['undici']).toBe('7.0.0') // transitive member of the closure
    expect(tree.localDeps.map((d) => d.kind).sort()).toEqual(['link', 'tarball'])
    expect(tree.warnings.some((w) => w.includes('floating'))).toBe(true)
    expect(tree.lockfile).toContain('lockfileVersion 9.0')
  })

  it('uses the packages-entry version for tarball-form keys (v0.2 vendored tgz)', () => {
    const dir = tempDir()
    const direct = { '@xp/a-tool': 'file:vendor/xp-a-tool-1.0.0.tgz' }
    writeFileSync(join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'
importers:
  '.':
    dependencies:
      '@xp/a-tool':
        specifier: file:vendor/xp-a-tool-1.0.0.tgz
        version: file:vendor/xp-a-tool-1.0.0.tgz
packages:
  '@xp/a-tool@file:vendor/xp-a-tool-1.0.0.tgz':
    resolution: {integrity: sha512-aaaa, tarball: file:vendor/xp-a-tool-1.0.0.tgz}
    version: 1.0.0
  '@xp/b-lib@file:vendor/xp-b-lib-1.0.0.tgz':
    resolution: {integrity: sha512-bbbb, tarball: file:vendor/xp-b-lib-1.0.0.tgz}
    version: 1.0.0
snapshots:
  '@xp/a-tool@file:vendor/xp-a-tool-1.0.0.tgz':
    dependencies:
      '@xp/b-lib': file:vendor/xp-b-lib-1.0.0.tgz
  '@xp/b-lib@file:vendor/xp-b-lib-1.0.0.tgz': {}
`)
    const tree = resolveDependencies(dir, direct, [])
    // identity = name + version, never the vendored spec string
    expect(tree.closure['@xp/a-tool']).toBe('1.0.0')
    expect(tree.closure['@xp/b-lib']).toBe('1.0.0')
  })

  it('degrades to declared specs with a warning when the lockfile is missing', () => {
    const dir = tempDir()
    const tree = resolveDependencies(dir, { foo: '^1.0.0' }, [])
    expect(tree.lockfile).toBe('MISSING')
    expect(tree.closure['foo']).toBe('^1.0.0')
    expect(tree.warnings.some((w) => w.includes('unverified'))).toBe(true)
  })
})

describe('rewriteLockfileForStaging', () => {
  it('rewrites vendored tarball importer specs AND the packages key (MUST-2)', () => {
    const dir = tempDir()
    writeFileSync(join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'
importers:
  '.':
    dependencies:
      dsh-tgz:
        specifier: file:../dist/x.tgz
        version: file:../dist/x.tgz
packages:
  dsh-tgz@file:../dist/x.tgz:
    resolution: {integrity: sha512-cccc}
`)
    const staged = rewriteLockfileForStaging(dir, { 'dsh-tgz': 'file:./packages/x.tgz' })
    // Install-side final state: importer specifier + version = file:vendor/<tgz>
    expect(staged).toContain('specifier: file:vendor/x.tgz')
    expect(staged).toContain('version: file:vendor/x.tgz')
    // The packages: resolution key is rewritten so --frozen-lockfile resolves
    expect(staged).toContain('dsh-tgz@file:vendor/x.tgz:')
    // No trace of the original local path
    expect(staged).not.toContain('file:../dist/x.tgz')
    expect(staged).not.toContain('file:./packages/')
    // The resolution integrity survives the key rewrite
    expect(staged).toContain('sha512-cccc')
  })

  it('rewrites scoped tarball packages keys with the leading slash variant', () => {
    const dir = tempDir()
    writeFileSync(join(dir, 'pnpm-lock.yaml'), `lockfileVersion: '9.0'
importers:
  '.':
    dependencies:
      '@scope/tool':
        specifier: file:../dist/tool.tgz
        version: file:../dist/tool.tgz
packages:
  /@scope/tool@file:../dist/tool.tgz:
    resolution: {integrity: sha512-dddd}
`)
    const staged = rewriteLockfileForStaging(dir, { '@scope/tool': 'file:./packages/tool.tgz' })
    expect(staged).toContain('/@scope/tool@file:vendor/tool.tgz:')
    expect(staged).not.toContain('file:../dist/tool.tgz')
  })

  it('returns undefined when there is no lockfile', () => {
    const dir = tempDir()
    expect(rewriteLockfileForStaging(dir, {})).toBeUndefined()
  })
})
