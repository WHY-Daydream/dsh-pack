/**
 * v0.4.2 local image prune E2E (DESIGN-v0.4.2.md §12, D57–D63): mark-and-
 * sweep reachability over refs → manifests → blobs. Only UNREACHABLE objects
 * are removed (D58); a blob reachable through ANY manifest/ref is kept (D60);
 * dry-run default, --apply deletes (D61); runtime cache report-only (D62);
 * dsh-lock.json / trust.yaml are NOT GC roots (D63). Pure LOCAL imports — no
 * registry involved.
 */
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import type { DshContentDigest, OciManifestDigest } from '../src/image/digests.js'
import { LocalImageStore } from '../src/image/local-store.js'
import { imageManifestDigest, type ImageManifest } from '../src/image/manifest.js'
import { DefaultImageService } from '../src/image/service.js'
import { addLockEntry, emptyLockfile, saveLockfile } from '../src/image/lockfile.js'
import { DefaultPackager } from '../src/service.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-prune-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function pnpmAvailable(): Promise<boolean> {
  try {
    await execFileAsync('pnpm', ['--version'], { timeout: 10_000 })
    return true
  } catch {
    return false
  }
}
const hasPnpm = await pnpmAvailable()

/** Machine A: build a portable pack (temperature varies contentHash). */
async function makePack(root: string, outDir: string, temperature = 0.3): Promise<string> {
  const homeA = join(root, 'homeA')
  mkdirSync(join(homeA, 'profiles', 'web'), { recursive: true })
  const profileA = join(homeA, 'profiles', 'web')
  writeFileSync(join(profileA, 'package.json'), JSON.stringify({
    name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
  }, null, 2))
  writeFileSync(join(profileA, 'cordis.patch.yml'), `# web
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: ${temperature}
`)
  await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 60_000 })

  const packager = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.2' })
  return (await packager.pack({ profile: 'web', outDir, portable: true })).file
}

function makeImageEnv(root: string): { images: DefaultImageService; home: string; store: LocalImageStore } {
  const home = join(root, 'home')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const store = new LocalImageStore(join(root, 'store'))
  const images = new DefaultImageService(store, { home, installedDshVersion: DSH_VERSION })
  return { images, home, store }
}

describe('local image prune（DESIGN-v0.4.2.md §12，D57–D63）', () => {
  it.runIf(hasPnpm)('T0: 无 orphan → prune 0 项，全部 reachable', async () => {
    const root = tempRoot('t0')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root)
    await images.import(file, { tag: 'org/app:v1' })

    const result = await images.prune({ apply: true })
    expect(result.orphanManifests).toEqual([])
    expect(result.orphanBlobs).toEqual([])
    expect(result.reclaimableBytes).toBe(0)
    expect(result.reachableManifests).toBe(1)
    expect(result.reachableBlobs).toBe(1)
    expect(await store.listManifestDigests()).toHaveLength(1)
  })

  it.runIf(hasPnpm)('T1: 删唯一 tag 后 manifest+blob 不可达 → prune 删除', async () => {
    const root = tempRoot('t1')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root, 0.3)
    const orphan = await makePack(root, mkdtempSync(join(root, 'out-')), 0.7)
    await images.import(file, { tag: 'org/app:v1' })
    await images.import(orphan) // no tag → immediately unreachable
    await images.remove('org/app:v1')

    const result = await images.prune({ apply: true })
    expect(result.orphanManifests).toHaveLength(2)
    expect(result.orphanBlobs).toHaveLength(2)
    expect(await store.listManifestDigests()).toEqual([])
    expect(await store.listBlobDigests()).toEqual([])
  })

  it.runIf(hasPnpm)('T2: 两 tag 指向同 digest，删一个 → manifest/blob 保留（F-A 延续）', async () => {
    const root = tempRoot('t2')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root)
    await images.import(file, { tag: 'org/app:a' })
    await images.import(file, { tag: 'org/app:b' })
    await images.remove('org/app:a')

    const result = await images.prune({ apply: true })
    expect(result.orphanManifests).toEqual([])
    expect(result.orphanBlobs).toEqual([])
    expect(await store.listManifestDigests()).toHaveLength(1)
    expect(await store.listBlobDigests()).toHaveLength(1)
  })

  it.runIf(hasPnpm)('T3: 两 manifest 共享同一 blob，其一 orphan → manifest 删，blob 保留（D60）', async () => {
    const root = tempRoot('t3')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root)
    await images.import(file, { tag: 'org/app:v1' })
    const refs = await store.listRefs()
    const m1 = refs[0]!.manifestDigest
    const manifest = (await store.getManifest(m1)) as ImageManifest
    const blobDigest = manifest.artifact.digest

    // store-level construction: a second DISTINCT manifest referencing the
    // SAME blob (real imports cannot produce this — contentHash anchors the
    // pack bytes, D21; same anchor + different bytes would be a violation)
    const copy: ImageManifest = { ...manifest, annotations: { note: 'shared-blob-probe' } }
    const m2 = imageManifestDigest(copy)
    await store.putManifest(m2, copy)
    await store.setTag('org/app', 'shared', m2)
    await images.remove('org/app:v1') // M1's only ref gone → M1 orphan

    const result = await images.prune({ apply: true })
    expect(result.orphanManifests.map((e) => e.digest)).toContain(m1)
    expect(result.orphanBlobs).toEqual([]) // blob still reachable via M2
    expect(await store.getBlob(blobDigest)).toBeDefined()

    // the blob is finally reclaimed once its LAST manifest is gone
    await images.remove('org/app:shared')
    const again = await images.prune({ apply: true })
    expect(again.orphanBlobs.map((e) => e.digest)).toContain(blobDigest)
    expect(await store.getBlob(blobDigest)).toBeUndefined()
  })

  it.runIf(hasPnpm)('T4: orphan manifest 指向 orphan blob → 两者一起删除', async () => {
    const root = tempRoot('t4')
    const { images, store } = makeImageEnv(root)
    const orphan = await makePack(root, root)
    await images.import(orphan) // untagged → manifest + blob both orphan

    const result = await images.prune({ apply: true })
    expect(result.orphanManifests).toHaveLength(1)
    expect(result.orphanBlobs).toHaveLength(1)
    expect(await store.listManifestDigests()).toEqual([])
    expect(await store.listBlobDigests()).toEqual([])
  })

  it.runIf(hasPnpm)('T5: dry-run → 结果正确但磁盘完全不改变（D61）', async () => {
    const root = tempRoot('t5')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root, 0.3)
    const orphan = await makePack(root, mkdtempSync(join(root, 'out-')), 0.7)
    await images.import(file, { tag: 'org/app:v1' })
    await images.import(orphan)

    const dry = await images.prune() // NO --apply
    expect(dry.applied).toBe(false)
    expect(dry.orphanManifests).toHaveLength(1)
    expect(dry.orphanBlobs).toHaveLength(1)
    expect(dry.reclaimableBytes).toBeGreaterThan(0)
    // disk unchanged
    expect(await store.getManifest(dry.orphanManifests[0]!.digest)).toBeDefined()
    expect(await store.getBlob(dry.orphanBlobs[0]!.digest as DshContentDigest)).toBeDefined()

    const applied = await images.prune({ apply: true })
    expect(applied.orphanManifests).toHaveLength(1)
    expect(await store.getBlob(dry.orphanBlobs[0]!.digest as DshContentDigest)).toBeUndefined()
  })

  it.runIf(hasPnpm)('T6: 二次 --apply 幂等 no-op + 存活 refs 完好', async () => {
    const root = tempRoot('t6')
    const { images, store } = makeImageEnv(root)
    const file = await makePack(root, root, 0.3)
    const orphan = await makePack(root, mkdtempSync(join(root, 'out-')), 0.7)
    await images.import(file, { tag: 'org/app:v1' })
    await images.import(orphan)

    const first = await images.prune({ apply: true })
    expect(first.orphanManifests).toHaveLength(1)
    const second = await images.prune({ apply: true })
    expect(second.orphanManifests).toEqual([])
    expect(second.orphanBlobs).toEqual([])
    expect(second.reclaimableBytes).toBe(0)
    // surviving refs are intact and resolvable after the sweep
    expect((await images.resolve('org/app:v1')).manifest.configHash).toBeDefined()
    expect(await store.listManifestDigests()).toHaveLength(1)
  })

  it.runIf(hasPnpm)('T7: .run-* 残留永不删除（D62 保守，无活跃 marker）', async () => {
    const root = tempRoot('t7')
    const { images, home } = makeImageEnv(root)
    mkdirSync(join(home, 'profiles', '.run-probe'), { recursive: true })
    writeFileSync(join(home, 'profiles', '.run-probe', '.keep'), 'x')

    const result = await images.prune({ apply: true })
    expect(result.runtimeCache).toHaveLength(1)
    expect(result.runtimeCache[0]!.profile).toBe('.run-probe')
    expect(result.runtimeCache[0]!.bytes).toBeGreaterThan(0)
    expect(existsSync(join(home, 'profiles', '.run-probe'))).toBe(true) // untouched
  })

  it.runIf(hasPnpm)('T8: runtime 报告正确 + D63：lockfile 不是 GC Root，locked 无 ref → prune 删', async () => {
    const root = tempRoot('t8')
    const { images, home, store } = makeImageEnv(root)
    const orphan = await makePack(root, root)
    await images.import(orphan) // untagged → orphan
    // a dsh-lock.json exists (D63): it must NOT keep the local orphan alive
    const lockfile = addLockEntry(
      emptyLockfile(),
      'ghcr.io/org/agent:prod',
      `sha256:${'a'.repeat(64)}` as OciManifestDigest,
      `ghcr.io/org/agent@sha256:${'a'.repeat(64)}`,
    )
    saveLockfile(join(root, 'dsh-lock.json'), lockfile)

    const dry = await images.prune()
    expect(dry.orphanManifests).toHaveLength(1)
    expect(dry.orphanBlobs).toHaveLength(1)
    expect(dry.runtimeCache).toEqual([])

    const applied = await images.prune({ apply: true })
    expect(applied.orphanManifests).toHaveLength(1)
    expect(await store.listManifestDigests()).toEqual([])
    expect(await store.listBlobDigests()).toEqual([])
    // runtime dir untouched (no .run-* in this env)
    expect(existsSync(join(home, 'profiles'))).toBe(true)
  })
})
