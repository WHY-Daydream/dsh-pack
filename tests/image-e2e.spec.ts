/**
 * v0.4 North-Star E2E (DESIGN-v0.4.md §17, frozen): the four acceptance
 * criteria through the real pipeline —
 *   1. run 闭环：pack --portable → sign → image import --tag agent:v1 →
 *      删原 Profile → run → temporary runtime → configHash == original →
 *      Signature VALID → Trust VERIFIED
 *   2. tag 语义：image tag agent:v1 agent:latest → 同一 digest
 *   3. tamper：篡改本地 blob → run → boot 前 FAIL
 *   4. untrusted：未在白名单的 key 签名 → run --require-trusted → FAIL
 *      （Signature 仍 VALID，VALID ≠ TRUSTED）
 * Skipped when `pnpm` is not available on PATH.
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { bundleIdentities, computeConfigHash } from '../src/manifest.js'
import { buildSnapshot } from '../src/config-snapshot.js'
import { resolveDependencies } from '../src/dependency-resolver.js'
import { LocalImageStore } from '../src/image/local-store.js'
import { DefaultImageService } from '../src/image/service.js'
import { loadProfileDir, resolveInstallAnchor } from '../src/profile-reader.js'
import { DefaultPackager } from '../src/service.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-imge2e-${label}-`))
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

/** Machine A: a signed, runnable profile → .dshpack. */
async function makeSignedPack(root: string, outDir: string): Promise<{ file: string; keyId: string }> {
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
        temperature: 0.3
`)
  await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 60_000 })

  const packager = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.0' })
  const packed = await packager.pack({ profile: 'web', outDir, portable: true })
  const key = await packager.keygen({ outDir })
  const signed = await packager.sign(packed.file, { key: key.privateKey, signer: 'why-daydream' })
  return { file: signed.file, keyId: key.keyId }
}

/** Machine B: fresh home + local image store. */
function makeImageEnv(root: string): { images: DefaultImageService; home: string } {
  const home = join(root, 'homeB')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
    home,
    installedDshVersion: DSH_VERSION,
  })
  return { images, home }
}

describe('v0.4 North-Star E2E', () => {
  it.runIf(hasPnpm)('criterion 1+2: run 闭环（configHash 一致 + VALID + VERIFIED）+ tag 同 digest', async () => {
    const root = tempRoot('main')
    const { file, keyId } = await makeSignedPack(root, root)
    const { images, home } = makeImageEnv(root)

    const imported = await images.import(file, { tag: 'why-daydream/agent:v1' })
    expect(imported.ref).toBe('why-daydream/agent:v1')

    // criterion 2: tag → latest shares the same manifest digest
    await images.tag('why-daydream/agent:v1', 'why-daydream/agent:latest')
    const refs = await images.list()
    const v1 = refs.find((e) => e.tag === 'v1')
    const latest = refs.find((e) => e.tag === 'latest')
    expect(v1?.manifestDigest).toBe(imported.manifestDigest)
    expect(latest?.manifestDigest).toBe(imported.manifestDigest)

    // criterion 1: run with the signer's key pinned → temporary runtime
    process.env.DSH_PACK_TRUSTED_KEYS = keyId
    const run = await images.run('why-daydream/agent:v1', {})
    delete process.env.DSH_PACK_TRUSTED_KEYS
    expect(run.temporary).toBe(true)
    expect(run.profile).toMatch(/^\.run-/)
    expect(run.signature).toBe('VALID')
    expect(run.trust).toBe('VERIFIED')
    expect(run.boot).toBe(`dsh --profile ${run.profile}`)

    // the materialized temporary runtime reproduces the original configHash
    const loaded = loadProfileDir(run.profile, home)
    const anchor = resolveInstallAnchor()
    const snapshot = buildSnapshot(loaded, home, anchor.anchor)
    const depTree = resolveDependencies(loaded.dir, loaded.manifest.dependencies ?? {}, [])
    const recomputed = computeConfigHash(snapshot.composition, bundleIdentities([], depTree), depTree.closure)
    expect(recomputed).toBe(run.configHash)
  })

  it.runIf(hasPnpm)('criterion 3: 篡改本地 blob → run boot 前 FAIL', async () => {
    const root = tempRoot('tamper')
    const { file } = await makeSignedPack(root, root)
    const { images } = makeImageEnv(root)
    const imported = await images.import(file, { tag: 'org/agent:prod' })

    // tamper the content-addressed blob on disk
    const blobPath = join(root, 'store', 'blobs', 'sha256', imported.digest.slice(7))
    writeFileSync(blobPath, '# TAMPERED ARTIFACT\n')

    await expect(images.run('org/agent:prod', {})).rejects.toThrow(/verification failed before boot/)
  })

  it.runIf(hasPnpm)('criterion 4: untrusted 签名 → run --require-trusted FAIL（Signature 仍 VALID）', async () => {
    const root = tempRoot('untrusted')
    const { file, keyId } = await makeSignedPack(root, root)

    // a SECOND signer (keyB) not in the whitelist
    const keyB = await (async () => {
      const packagerB = new DefaultPackager({ home: join(root, 'homeB'), installedDshVersion: DSH_VERSION, packagerVersion: '0.4.0' })
      return packagerB.keygen({ outDir: root })
    })()
    const bytes = readFileSync(file)
    const { signPackBuffer } = await import('../src/sign.js')
    const { buffer: signedByB } = await signPackBuffer(bytes, { keyPath: keyB.privateKey, force: true })

    const { images } = makeImageEnv(root)
    const bFile = join(root, 'agent-b.dshpack')
    writeFileSync(bFile, signedByB)
    await images.import(bFile, { tag: 'org/agent:untrusted' })

    // whitelist pins key A; the image is signed by key B → VALID but UNTRUSTED
    process.env.DSH_PACK_TRUSTED_KEYS = keyId
    await expect(images.run('org/agent:untrusted', { requireTrusted: true })).rejects.toThrow(/trust policy rejected/)
    delete process.env.DSH_PACK_TRUSTED_KEYS

    // without require-trusted the same image runs (signature VALID, trust UNTRUSTED)
    process.env.DSH_PACK_TRUSTED_KEYS = keyId
    const run = await images.run('org/agent:untrusted', {})
    delete process.env.DSH_PACK_TRUSTED_KEYS
    expect(run.signature).toBe('VALID')
    expect(run.trust).toBe('UNTRUSTED')
  })
})
