/**
 * v0.4 DefaultImageService unit tests (DESIGN-v0.4.md §10): import (blob +
 * manifest + tag, digest = contentHash D21), inspect, mutable tags (D22),
 * remove (tag / digest forms) and digest-first resolution.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { computeConfigHash } from '../src/manifest.js'
import { buildTarGz, checksumsJson, type PackFileEntry } from '../src/pack-builder.js'
import { prettyJson } from '../src/canonical.js'
import { LocalImageStore } from '../src/image/local-store.js'
import { DefaultImageService } from '../src/image/service.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-imgsvc-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** Minimal valid .dshpack on disk. */
async function makePackFile(dir: string): Promise<string> {
  const rows = [{ id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.3 } }]
  const manifest = {
    format: 'dshpack',
    schemaVersion: 1,
    profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true,
    portable: true,
    bundles: [],
    dependencies: {},
    configHash: computeConfigHash({ rows }, [], {}),
    createdAt: '2026-08-29T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.4.0' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: 'web-profile', private: true, dependencies: {} }) },
    { path: 'resolved/composition.json', content: prettyJson({ rows }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson({ lockfile: 'pnpm-lock.yaml', direct: {}, closure: {}, localDeps: [], warnings: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
    { path: 'README.md', content: '# web\n' },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: checksumsJson(built.contentHash, built.files) },
  ])
  const file = join(dir, 'agent.dshpack')
  writeFileSync(file, final.buffer)
  return file
}

function makeService(root: string): { images: DefaultImageService; home: string } {
  const home = join(root, 'home')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
    home,
    installedDshVersion: DSH_VERSION,
  })
  return { images, home }
}

describe('DefaultImageService', () => {
  it('imports a pack with digest = contentHash and applies a mutable tag', async () => {
    const root = tempRoot('import')
    const { images } = makeService(root)
    const file = await makePackFile(root)
    const imported = await images.import(file, { tag: 'why-daydream/agent:v1' })
    expect(imported.digest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(imported.ref).toBe('why-daydream/agent:v1')

    const refs = await images.list()
    expect(refs).toEqual([
      { repo: 'why-daydream/agent', tag: 'v1', manifestDigest: imported.manifestDigest },
    ])
    // blob is content-addressed under its digest
    expect(existsSync(join(root, 'store', 'blobs', 'sha256', imported.digest.slice(7)))).toBe(true)
  })

  it('rejects digest-form --tag and non-existent packs', async () => {
    const root = tempRoot('badtag')
    const { images } = makeService(root)
    const file = await makePackFile(root)
    await expect(images.import(file, { tag: 'agent@sha256:' + 'a'.repeat(64) })).rejects.toThrow(/tag reference/)
    await expect(images.import(join(root, 'nope.dshpack'))).rejects.toThrow(/not found/)
  })

  it('inspects manifest + artifact facts + signature status', async () => {
    const root = tempRoot('inspect')
    const { images } = makeService(root)
    const file = await makePackFile(root)
    const imported = await images.import(file, { tag: 'org/agent:prod' })
    const info = await images.inspect('org/agent:prod')
    expect(info.artifactDigest).toBe(imported.digest)
    expect(info.configHash).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(info.manifest.platform.dshVersion).toBe(DSH_VERSION)
    expect(info.manifest.artifact.mediaType).toBe('application/vnd.dsh.pack.v1+gzip')
    // unsigned pack → MISSING (signature optional by default)
    expect(info.signature).toBe('MISSING')
    expect(info.trust).toBe('N/A')
  })

  it('tags are mutable aliases onto the same digest; remove clears tag or image', async () => {
    const root = tempRoot('tagrm')
    const { images } = makeService(root)
    const file = await makePackFile(root)
    const imported = await images.import(file, { tag: 'org/agent:v1' })

    await images.tag('org/agent:v1', 'org/agent:latest')
    const refs = await images.list()
    const v1 = refs.find((e) => e.tag === 'v1')
    const latest = refs.find((e) => e.tag === 'latest')
    expect(v1?.manifestDigest).toBe(imported.manifestDigest)
    expect(latest?.manifestDigest).toBe(imported.manifestDigest)

    // tag form removal keeps the image
    await images.remove('org/agent:v1')
    expect((await images.list()).find((e) => e.tag === 'v1')).toBeUndefined()
    expect(existsSync(join(root, 'store', 'manifests', 'sha256', imported.manifestDigest.slice(7)))).toBe(true)

    // digest form removal clears manifest + blob
    await images.remove(`org/agent@${imported.manifestDigest}`)
    expect(existsSync(join(root, 'store', 'manifests', 'sha256', imported.manifestDigest.slice(7)))).toBe(false)
    expect(existsSync(join(root, 'store', 'blobs', 'sha256', imported.digest.slice(7)))).toBe(false)
  })

  it('resolves by tag and digest (digest-first)', async () => {
    const root = tempRoot('resolve')
    const { images } = makeService(root)
    const file = await makePackFile(root)
    const imported = await images.import(file, { tag: 'org/agent:v1' })
    const byTag = await images.resolve('org/agent:v1')
    expect(byTag.artifactDigest).toBe(imported.digest)
    const byDigest = await images.resolve(`org/agent@${imported.manifestDigest}`)
    expect(byDigest.manifestDigest).toBe(imported.manifestDigest)
  })
})
