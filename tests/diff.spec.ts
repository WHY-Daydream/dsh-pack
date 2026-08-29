/**
 * Pack diff unit tests (DESIGN.md v0.2): four-domain drift detection between
 * two synthetic packs — Manifest fields, Bundles, Config leaves and
 * Dependencies — plus the configHash verdict.
 */
import { describe, expect, it } from 'vitest'
import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { diffPacks } from '../src/diff.js'
import { prettyJson } from '../src/canonical.js'

const HASH_A = 'sha256:' + 'a'.repeat(64)
const HASH_B = 'sha256:' + 'b'.repeat(64)

/** Build a minimal .dshpack buffer with the given manifest + resolved files. */
async function makePack(
  overrides: {
    manifest?: Record<string, unknown>
    bundles?: string[]
    dependencies?: Record<string, string>
    closure?: Record<string, string>
    rows?: Record<string, unknown>[]
    configHash?: string
  } = {},
): Promise<Buffer> {
  const rows = overrides.rows ?? [
    { id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.3 } },
    { id: 'timeout-policy', timeoutMs: 30000 },
  ]
  const bundles = overrides.bundles ?? ['@deepseek-ai/dsh-base']
  const dependencies = overrides.dependencies ?? { '@deepseek-ai/dsh-base': '0.1.0-rc.5' }
  const closure = overrides.closure ?? { '@deepseek-ai/dsh-base': '0.1.0-rc.5', undici: '7.0.0' }
  const manifest: Record<string, unknown> = {
    format: 'dshpack',
    schemaVersion: 1,
    profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true,
    portable: true,
    bundles,
    dependencies,
    configHash: overrides.configHash ?? HASH_A,
    createdAt: '2026-08-28T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.1.0' },
    ...overrides.manifest,
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: 'web-profile', private: true, dependencies }) },
    { path: 'resolved/composition.json', content: prettyJson({ rows }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson({ lockfile: 'pnpm-lock.yaml', direct: dependencies, closure, localDeps: [], warnings: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: 'sha256:' + 'c'.repeat(64), files: {} }) },
  ]
  const built = await buildTarGz(entries)
  return built.buffer
}

describe('diffPacks', () => {
  it('reports no differences for identical packs', async () => {
    const a = await makePack()
    const b = await makePack()
    const diff = await diffPacks(a, b)
    expect(diff.manifest).toHaveLength(0)
    expect(diff.bundles).toHaveLength(0)
    expect(diff.config).toHaveLength(0)
    expect(diff.dependencies).toHaveLength(0)
    expect(diff.configHashEqual).toBe(true)
  })

  it('detects manifest field drift', async () => {
    const a = await makePack()
    const b = await makePack({ manifest: { installable: false, portable: false } })
    const diff = await diffPacks(a, b)
    expect(diff.manifest.map((c) => c.field).sort()).toEqual(['installable', 'portable'])
  })

  it('detects bundle additions, removals and version changes', async () => {
    const a = await makePack({
      bundles: ['@deepseek-ai/dsh-base', 'dsh-chaos'],
      closure: { '@deepseek-ai/dsh-base': '0.1.0-rc.5', 'dsh-chaos': '0.1.0', undici: '7.0.0' },
    })
    const b = await makePack({
      bundles: ['@deepseek-ai/dsh-base', 'dsh-tool-idempotency'],
      closure: { '@deepseek-ai/dsh-base': '0.1.0-rc.6', 'dsh-tool-idempotency': '0.1.0', undici: '7.0.0' },
      configHash: HASH_B,
    })
    const diff = await diffPacks(a, b)
    const byName = new Map(diff.bundles.map((c) => [c.name, c]))
    expect(byName.get('dsh-chaos')).toMatchObject({ kind: 'removed', before: '0.1.0' })
    expect(byName.get('dsh-tool-idempotency')).toMatchObject({ kind: 'added', after: '0.1.0' })
    expect(byName.get('@deepseek-ai/dsh-base')).toMatchObject({ kind: 'changed', before: '0.1.0-rc.5', after: '0.1.0-rc.6' })
    expect(diff.configHashEqual).toBe(false)
  })

  it('detects leaf-level config drift', async () => {
    const a = await makePack()
    const b = await makePack({
      rows: [
        { id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.7, maxTokens: 4096 } },
        { id: 'timeout-policy', timeoutMs: 10000 },
      ],
      configHash: HASH_B,
    })
    const diff = await diffPacks(a, b)
    const byPath = new Map(diff.config.map((c) => [c.path, c]))
    expect(byPath.get('llm-deepseek.config.temperature')).toMatchObject({ kind: 'changed', before: 0.3, after: 0.7 })
    expect(byPath.get('llm-deepseek.config.maxTokens')).toMatchObject({ kind: 'added', after: 4096 })
    expect(byPath.get('timeout-policy.timeoutMs')).toMatchObject({ kind: 'changed', before: 30000, after: 10000 })
  })

  it('detects spec and locked-version dependency changes', async () => {
    const a = await makePack({
      dependencies: { 'dsh-tool-bulkhead': '0.1.0' },
      closure: { 'dsh-tool-bulkhead': '0.1.0', undici: '7.0.0' },
    })
    const b = await makePack({
      dependencies: { 'dsh-tool-bulkhead': '^0.2.0' },
      closure: { 'dsh-tool-bulkhead': '0.2.0', undici: '7.0.0' },
      configHash: HASH_B,
    })
    const diff = await diffPacks(a, b)
    expect(diff.dependencies).toEqual([
      {
        name: 'dsh-tool-bulkhead',
        specBefore: '0.1.0',
        specAfter: '^0.2.0',
        versionBefore: '0.1.0',
        versionAfter: '0.2.0',
      },
    ])
  })

  it('fails loud on a malformed manifest', async () => {
    const a = await makePack()
    const b = await makePack({ manifest: { schemaVersion: 2 } })
    await expect(diffPacks(a, b)).rejects.toThrow(/schemaVersion/)
  })
})
