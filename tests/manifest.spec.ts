/**
 * Manifest unit tests (DESIGN.md §3.3, §7.3): the configHash formula is the
 * frozen Portable Profile Configuration Hash — deterministic, time-independent
 * and invariant to tarball spec rewriting (MUST-2).
 */
import { describe, expect, it } from 'vitest'
import { bundleIdentities, buildManifest, computeConfigHash, validateManifest } from '../src/manifest.js'
import type { DependencyTree, Manifest } from '../src/types.js'

const composition = { rows: [{ id: 'llm-deepseek', temperature: 0.3 }] }
const closure = { 'dsh-tool-bulkhead': '0.1.0', undici: '7.0.0' }
const identities = [{ name: 'dsh-tool-bulkhead', version: '0.1.0' }]

describe('computeConfigHash', () => {
  it('is deterministic for identical inputs', () => {
    const a = computeConfigHash(composition, identities, closure)
    const b = computeConfigHash(composition, identities, closure)
    expect(a).toBe(b)
    expect(a).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('changes when the composition changes', () => {
    const other = { rows: [{ id: 'llm-deepseek', temperature: 0.7 }] }
    expect(computeConfigHash(other, identities, closure)).not.toBe(computeConfigHash(composition, identities, closure))
  })

  it('is invariant to tarball spec rewriting (identity = name + locked version)', () => {
    const treeA: DependencyTree = { lockfile: 'x', direct: { foo: 'file:../x.tgz' }, closure: { foo: '1.0.0' }, localDeps: [], warnings: [] }
    const treeB: DependencyTree = { lockfile: 'x', direct: { foo: 'file:./packages/x.tgz' }, closure: { foo: '1.0.0' }, localDeps: [], warnings: [] }
    const idA = bundleIdentities(['foo'], treeA)
    const idB = bundleIdentities(['foo'], treeB)
    expect(idA).toEqual(idB)
    expect(computeConfigHash(composition, idA, treeA.closure)).toBe(computeConfigHash(composition, idB, treeB.closure))
  })
})

describe('buildManifest / validateManifest', () => {
  const base = {
    profileName: 'web',
    excludedLayersPresent: true,
    dshVersion: '0.1.0-rc.5',
    nodeVersion: '24.6.0',
    pnpmVersion: '10.15.0',
    platform: 'linux-x64',
    bundles: ['@deepseek-ai/dsh-base'],
    dependencies: { '@deepseek-ai/dsh-base': '0.1.0-rc.5' },
    redacted: 2,
    configHash: 'sha256:' + 'a'.repeat(64),
    installable: true,
    portable: true,
    packagerVersion: '0.1.0',
    createdAt: '2026-08-28T00:00:00Z',
  }

  it('records secrets only when redacted > 0', () => {
    const withSecrets = buildManifest(base)
    expect(withSecrets.secrets).toEqual({ redacted: 2 })
    const clean = buildManifest({ ...base, redacted: 0 })
    expect(clean.secrets).toBeUndefined()
  })

  it('validates a well-formed manifest', () => {
    const parsed = validateManifest(buildManifest(base))
    expect(parsed.ok).toBe(true)
  })

  it('rejects unknown schema majors and bad configHash format', () => {
    const manifest: Manifest = buildManifest(base)
    const bad = validateManifest({ ...manifest, schemaVersion: 2 })
    expect(bad.ok).toBe(false)
    if (!bad.ok) expect(bad.errors.join()).toContain('schemaVersion')
    const badHash = validateManifest({ ...manifest, configHash: 'md5:abc' })
    expect(badHash.ok).toBe(false)
  })
})
