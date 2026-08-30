/**
 * v0.4.1 North-Star E2E (DESIGN-v0.4.1.md §11, frozen): the six acceptance
 * criteria through the real pipeline against a LOCAL OCI mock registry
 * (same Distribution protocol subset as GHCR, with injectable tamper modes).
 * Criteria 4/5 must be DISTINGUISHABLE: 4 = OCI transport integrity failure
 * (blob digest over actual bytes), 5 = DSH artifact integrity failure
 * (contentHash vs config). Real GHCR verification stays manual/CI (needs
 * DSH_REGISTRY_USERNAME/TOKEN). Criterion 6 needs pnpm (run materializes).
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { LocalImageStore } from '../src/image/local-store.js'
import { DefaultImageService } from '../src/image/service.js'
import { DefaultPackager } from '../src/service.js'
import { MockRegistry } from './helpers/mock-registry.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-reg-e2e-${label}-`))
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

/** Machine A: a signed, runnable profile → .dshpack (temperature is the knob). */
async function makeSignedPack(root: string, outDir: string, temperature = 0.3): Promise<{ file: string; keyId: string }> {
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

  const packager = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.1' })
  const packed = await packager.pack({ profile: 'web', outDir, portable: true })
  // unique key dir per call — keygen writes deterministic filenames
  const key = await packager.keygen({ outDir: mkdtempSync(join(outDir, 'keys-')) })
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

const remoteRefOf = (mock: MockRegistry, repo: string, ref: string): string => `127.0.0.1:${mock.port}/${repo}:${ref}`
const remoteDigestRefOf = (mock: MockRegistry, repo: string, digest: string): string => `127.0.0.1:${mock.port}/${repo}@${digest}`

describe('v0.4.1 North-Star E2E (local OCI mock registry)', () => {
  it('criterion 1+2: push → 删 store → pull → contentHash 相同 + Signature VALID + Trust VERIFIED', async () => {
    const root = tempRoot('loop')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file, keyId } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      const pushed = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      expect(pushed.contentHash).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(pushed.ociManifestDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(pushed.blobDigest).not.toBe(pushed.contentHash) // D32: transport ≠ semantic identity

      // fresh machine: pull with the signer's key pinned
      const freshRoot = tempRoot('loop-fresh')
      const { images: imagesB } = makeImageEnv(freshRoot)
      process.env.DSH_PACK_TRUSTED_KEYS = keyId
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'v1'))
      delete process.env.DSH_PACK_TRUSTED_KEYS

      expect(pulled.contentHash).toBe(pushed.contentHash)
      expect(pulled.signature).toBe('VALID')
      expect(pulled.trust).toBe('VERIFIED')
      // the local tag mirror makes the remote ref locally addressable
      await expect(imagesB.resolve(remoteRefOf(mock, 'org/agent', 'v1'))).resolves.toMatchObject({
        artifactDigest: pushed.contentHash,
      })
    } finally {
      await mock.stop()
    }
  })

  it('criterion 3: tag 更新 → 新 manifest；旧 digest 仍可精确 pull（tag mutable / digest immutable）', async () => {
    const root = tempRoot('tagmut')
    const mock = new MockRegistry()
    await mock.start()
    try {
      // unique pack outDir per call — pack writes deterministic filenames
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.7) // different configHash/contentHash
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      await images.import(b.file, { tag: 'org/agent:v2' })
      const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'v1')) // tag update
      expect(pushedB.ociManifestDigest).not.toBe(pushedA.ociManifestDigest)

      // old manifest digest A is still precisely pullable (digest form)
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const byDigest = await imagesB.pull(remoteDigestRefOf(mock, 'org/agent', pushedA.ociManifestDigest))
      expect(byDigest.contentHash).toBe(pushedA.contentHash)

      // the tag now resolves to B
      const byTag = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'v1'))
      expect(byTag.contentHash).toBe(pushedB.contentHash)
    } finally {
      await mock.stop()
    }
  })

  it('criterion 4: registry 返回篡改 blob → OCI transport integrity FAIL，DSH verify 不执行', async () => {
    const root = tempRoot('tamper')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      const pushed = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))

      // corrupt the pack blob AFTER push (mock reads tamper at request time)
      mock.tamper = { blobDigest: pushed.blobDigest }
      const freshRoot = join(root, 'fresh')
      const { images: imagesB } = makeImageEnv(freshRoot)
      const attempt = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'v1')).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      const message = (attempt as Error).message
      expect(message).toMatch(/transport integrity failure/)
      expect(message).not.toMatch(/artifact integrity|DSH verification/) // DSH verify never ran
      // nothing was imported into the store
      expect((await imagesB.list()).length).toBe(0)
    } finally {
      await mock.stop()
    }
  })

  it('criterion 5: 合法 blob 但 config contentHash 不符 → DSH artifact integrity FAIL（transport 已过）', async () => {
    const root = tempRoot('cfgdrift')
    const mock = new MockRegistry({ tamper: { configContentHash: 'sha256:' + 'f'.repeat(64) } })
    await mock.start()
    try {
      const { file } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))

      const freshRoot = join(root, 'fresh')
      const { images: imagesB } = makeImageEnv(freshRoot)
      const attempt = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'v1')).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      const message = (attempt as Error).message
      // transport checks passed (blob/config digests fine) — the failure is the
      // DSH semantic binding between the pack and the config's contentHash
      expect(message).toMatch(/artifact integrity failure/)
      expect(message).not.toMatch(/transport integrity failure/)
      expect((await imagesB.list()).length).toBe(0)
    } finally {
      await mock.stop()
    }
  })

  it('criterion 6: signed but untrusted → pull 可缓存 → run --require-trusted boot 前 FAIL', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('untrusted')
    const mock = new MockRegistry()
    await mock.start()
    try {
      // pack signed by keyB
      const { file } = await makeSignedPack(root, root)
      const packagerB = new DefaultPackager({ home: join(root, 'homeB'), installedDshVersion: DSH_VERSION, packagerVersion: '0.4.1' })
      const keyB = await packagerB.keygen({ outDir: root })
      const { signPackBuffer } = await import('../src/sign.js')
      const { readFileSync } = await import('node:fs')
      const { buffer: signedByB } = await signPackBuffer(readFileSync(file), { keyPath: keyB.privateKey, force: true })
      const bFile = join(root, 'agent-b.dshpack')
      writeFileSync(bFile, signedByB)

      const { images, home } = makeImageEnv(root)
      await images.import(bFile, { tag: 'org/agent:untrusted' })
      await images.push('org/agent:untrusted', remoteRefOf(mock, 'org/agent', 'untrusted'))

      // fresh machine pulls with whitelist = a trusted key (keyB is not trusted) → caches fine
      const freshRoot = join(root, 'fresh')
      const { images: imagesB, home: homeB } = makeImageEnv(freshRoot)
      const trustedKey = await packagerB.keygen({ outDir: mkdtempSync(join(root, 'keys-')) })
      process.env.DSH_PACK_TRUSTED_KEYS = trustedKey.keyId
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'untrusted'))
      expect(pulled.signature).toBe('VALID')
      expect(pulled.trust).toBe('UNTRUSTED')

      // run --require-trusted must FAIL before boot, leaving no runtime
      const attempt = await imagesB.run(remoteRefOf(mock, 'org/agent', 'untrusted'), { requireTrusted: true })
        .catch((error: Error) => error)
      delete process.env.DSH_PACK_TRUSTED_KEYS
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
      expect(readdirSync(join(homeB, 'profiles')).some((p) => p.startsWith('.run-'))).toBe(false)
      void home
    } finally {
      await mock.stop()
    }
  })

  it('blob upload 幂等（invariant 7）：同 image 重复 push → 第二次 HEAD 命中跳过上传，blobDigest 不变', async () => {
    const root = tempRoot('upload-idem')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      const first = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const second = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v2')) // same blob, new tag
      expect(second.blobDigest).toBe(first.blobDigest)
      expect(second.contentHash).toBe(first.contentHash)
      // the registry holds exactly ONE copy of the blob (HEAD-hit skip path)
      expect(mock.blobs.has(first.blobDigest)).toBe(true)
      expect([...mock.blobs.keys()].filter((d) => d === first.blobDigest)).toHaveLength(1)
    } finally {
      await mock.stop()
    }
  })

  it('auth: Bearer challenge → token fetch → 重试成功（anonymous/token 之外的最小子集）', async () => {
    const root = tempRoot('auth')
    const mock = new MockRegistry({ requireAuth: true })
    await mock.start()
    try {
      const { file } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      // credentials come from the env (username + PAT) → Bearer challenge flow
      process.env['DSH_REGISTRY_USERNAME'] = 'pat-user'
      process.env['DSH_REGISTRY_TOKEN'] = 'anything'
      const pushed = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      delete process.env['DSH_REGISTRY_USERNAME']
      delete process.env['DSH_REGISTRY_TOKEN']
      expect(pushed.ociManifestDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    } finally {
      await mock.stop()
    }
  })
})

describe('image lock（DESIGN-v0.4.2.md §9，D46–D49）', () => {
  it('T0: tag 漂移后 locked digest 仍拉旧 artifact（D46/D48）', async () => {
    const root = tempRoot('lock-t0')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

      // lock prod → immutable @manifestDigestA
      const lockFile = join(root, 'dsh-lock.json')
      const locked = await images.lock(remoteRefOf(mock, 'org/agent', 'prod'), { file: lockFile })
      expect(locked.resolved).toBe(remoteDigestRefOf(mock, 'org/agent', pushedA.ociManifestDigest))
      expect(locked.manifestDigest).toBe(pushedA.ociManifestDigest)
      const stored = JSON.parse(readFileSync(lockFile, 'utf8'))
      expect(stored.images[remoteRefOf(mock, 'org/agent', 'prod')].manifestDigest).toBe(pushedA.ociManifestDigest)

      // tag drift: prod → manifest B
      await images.import(b.file, { tag: 'org/agent:v2' })
      await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))

      // using the lock (pull the locked resolved ref) still gets A
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const pulled = await imagesB.pull(locked.resolved)
      expect(pulled.contentHash).toBe(pushedA.contentHash)
    } finally {
      await mock.stop()
    }
  })

  it('T1: 锁文件写不存在的 digest → pull FAIL（registry 404，nothing imported）', async () => {
    const root = tempRoot('lock-t1')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const bogusDigest = 'sha256:' + 'a'.repeat(64)
      const { images } = makeImageEnv(join(root, 'fresh'))
      const attempt = await images.pull(`127.0.0.1:${mock.port}/org/agent@${bogusDigest}`).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/manifest GET failed/)
      expect((await images.list()).length).toBe(0)
    } finally {
      await mock.stop()
    }
  })

  it('T2: registry 返回与 locked digest 不匹配的 manifest → transport integrity FAIL', async () => {
    const root = tempRoot('lock-t2')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))
      await images.import(b.file, { tag: 'org/agent:v2' })
      await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'dev'))

      // malicious registry: serve dev's manifest bytes under A's locked digest
      mock.tamper = { manifestSwap: { forDigest: pushedA.ociManifestDigest, serveTag: 'dev' } }
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const attempt = await imagesB.pull(`127.0.0.1:${mock.port}/org/agent@${pushedA.ociManifestDigest}`)
        .catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/manifest digest mismatch.*transport integrity failure/)
      expect((await imagesB.list()).length).toBe(0) // nothing imported
    } finally {
      await mock.stop()
    }
  })
})
