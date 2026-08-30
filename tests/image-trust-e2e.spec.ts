/**
 * v0.4.2 trust.yaml E2E (DESIGN-v0.4.2.md §11, D50–D56): the LOCAL Remote
 * Image Execution Policy applied at run() — T1–T9 acceptance criteria plus
 * the lock × trust orthogonality combo (version identity vs trust policy).
 * Pull/cache stays permissive (D56); run evaluates the policy BEFORE
 * materialization (no .run-* on policy failure). GHCR 8/8 remains the v0.4.2
 * hard Release Gate — this suite is mock-registry business logic only (D41).
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
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
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-trust-e2e-${label}-`))
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

/** Machine A: build a portable pack (optionally signed). */
async function makePack(root: string, outDir: string, temperature = 0.3, sign = false): Promise<{ file: string; keyId?: string }> {
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
  const packed = await packager.pack({ profile: 'web', outDir, portable: true })
  if (!sign) return { file: packed.file }
  const key = await packager.keygen({ outDir: mkdtempSync(join(outDir, 'keys-')) })
  const signed = await packager.sign(packed.file, { key: key.privateKey, signer: 'why-daydream' })
  return { file: signed.file, keyId: key.keyId }
}

function makeImageEnv(root: string): { images: DefaultImageService; home: string } {
  const home = join(root, 'home')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
    home,
    installedDshVersion: DSH_VERSION,
  })
  return { images, home }
}

const remoteRefOf = (mock: MockRegistry, repo: string, ref: string): string => `127.0.0.1:${mock.port}/${repo}:${ref}`
const remoteDigestRefOf = (mock: MockRegistry, repo: string, digest: string): string => `127.0.0.1:${mock.port}/${repo}@${digest}`
const repoOf = (mock: MockRegistry, repo: string): string => `127.0.0.1:${mock.port}/${repo}`

function writeTrustPolicy(home: string, yaml: string): void {
  writeFileSync(join(home, 'trust.yaml'), yaml)
}

describe('trust.yaml execution policy (D50–D56)', () => {
  it.runIf(hasPnpm)('T0: 无 trust.yaml → 完全保持 v0.4.1 行为（signed run PASS）', async () => {
    const root = tempRoot('t0')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const run = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {})
      expect(run.temporary).toBe(true)
      expect(run.trust).toBe('N/A') // no policy, no whitelist → permissive
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T1: requireSignature + unsigned → run FAIL before materialization', async () => {
    const root = tempRoot('t1')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, false) // unsigned
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireSignature: true\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/signature required/)
      expect(readdirSync(join(home, 'profiles')).some((p) => p.startsWith('.run-'))).toBe(false)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T2: requireSignature + signed unknown key → PASS（无 requireTrusted）', async () => {
    const root = tempRoot('t2')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireSignature: true\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const run = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {})
      expect(run.signature).toBe('VALID')
      expect(run.trust).toBe('N/A')
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T3: requireTrusted + signed unknown key → FAIL（fingerprint 不在 trustedKeys）', async () => {
    const root = tempRoot('t3')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${'b'.repeat(64)}\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T4: requireTrusted + 签名者 keyId 在 trustedKeys → PASS', async () => {
    const root = tempRoot('t4')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file, keyId } = await makePack(root, root, 0.3, true)
      expect(keyId).toMatch(/^[0-9a-f]{64}$/)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${keyId}\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const run = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {})
      expect(run.signature).toBe('VALID')
      expect(run.trust).toBe('VERIFIED')
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T5: 父规则宽松、子规则严格 → most-specific 生效（D52）', async () => {
    const root = tempRoot('t5')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1
registries:
  "${repoOf(mock, 'org/*')}":
    requireSignature: false
  "${repoOf(mock, 'org/prod-*')}":
    requireTrusted: true
    trustedKeys:
      - SHA256:${'b'.repeat(64)}
`)
      await images.import(file, { tag: 'org/prod-agent:v1' })
      await images.push('org/prod-agent:v1', remoteRefOf(mock, 'org/prod-agent', 'v1'))
      // the loose org/* rule would PASS; the specific prod-* rule requires a
      // trusted key the signer doesn't have → the specific rule must win
      const attempt = await images.run(remoteRefOf(mock, 'org/prod-agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T6: CLI --require-trusted + policy requireTrusted=false → effective=true（D54 只能收紧）', async () => {
    const root = tempRoot('t6')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: false\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))

      // policy false + CLI false → PASS
      await expect(images.run(remoteRefOf(mock, 'org/agent', 'v1'), {})).resolves.toMatchObject({ trust: 'N/A' })
      // policy false + CLI --require-trusted → effective TRUE → FAIL without a whitelist
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), { requireTrusted: true })
        .catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T7: policy requireTrusted=true + CLI 无额外约束 → 仍生效', async () => {
    const root = tempRoot('t7')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${'b'.repeat(64)}\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T8: signer label 匹配但 key fingerprint 不匹配 → UNTRUSTED（D55）', async () => {
    const root = tempRoot('t8')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true) // signed with signer 'why-daydream'
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${'b'.repeat(64)}\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('T9: untrusted pull → cache 成功；run → policy FAIL before materialization（D56）', async () => {
    const root = tempRoot('t9')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file } = await makePack(root, root, 0.3, true)
      const { images, home } = makeImageEnv(root)
      writeTrustPolicy(home, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${'b'.repeat(64)}\n`)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'v1'))

      // pull is cache-only (D56): succeeds; policy NOT evaluated → trust is
      // the v0.3 env-marker value (N/A without a whitelist), not UNTRUSTED
      const pulled = await images.pull(remoteRefOf(mock, 'org/agent', 'v1'))
      expect(pulled.signature).toBe('VALID')
      expect(pulled.trust).toBe('N/A')

      // run evaluates the policy → FAIL before materialization
      const attempt = await images.run(remoteRefOf(mock, 'org/agent', 'v1'), {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
      expect(readdirSync(join(home, 'profiles')).some((p) => p.startsWith('.run-'))).toBe(false)
    } finally {
      await mock.stop()
    }
  })

  it.runIf(hasPnpm)('lock × trust 正交：同一 lock 版本不变；trustedKeys 移除后 trust FAIL', async () => {
    const root = tempRoot('locktrust')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makePack(root, mkdtempSync(join(root, 'out-')), 0.3, true)
      const b = await makePack(root, mkdtempSync(join(root, 'out-')), 0.7, true)
      expect(a.keyId).toBeDefined()
      const { images } = makeImageEnv(root)
      await images.import(a.file as string, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

      // lock prod → @manifestDigestA (immutable pin, D46/D48)
      const lockFile = join(root, 'dsh-lock.json')
      const locked = await images.lock(remoteRefOf(mock, 'org/agent', 'prod'), { file: lockFile })
      expect(locked.resolved).toBe(remoteDigestRefOf(mock, 'org/agent', pushedA.ociManifestDigest))

      // tag drift: prod → manifest B
      await images.import(b.file as string, { tag: 'org/agent:v2' })
      await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))

      // trust.yaml trusts A's key → run the LOCK (digest form) → pulls A + trust PASS
      const envB = makeImageEnv(join(root, 'machine-b'))
      const { images: imagesB, home: homeB } = envB
      writeTrustPolicy(homeB, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${a.keyId}\n`)
      const run1 = await imagesB.run(locked.resolved, {})
      expect(run1.digest).toBe(pushedA.contentHash) // still the OLD artifact A
      expect(run1.trust).toBe('VERIFIED')

      // A's key removed from trustedKeys → SAME lock: version unchanged, trust FAIL
      writeTrustPolicy(homeB, `version: 1\nregistries:\n  "${repoOf(mock, 'org/agent')}":\n    requireTrusted: true\n    trustedKeys:\n      - SHA256:${'b'.repeat(64)}\n`)
      const stillA = await imagesB.pull(locked.resolved) // pull stays cache-only (D56)
      expect(stillA.contentHash).toBe(pushedA.contentHash) // version identity unchanged
      const runProfilesBefore = readdirSync(join(homeB, 'profiles')).filter((p) => p.startsWith('.run-'))
      const attempt = await imagesB.run(locked.resolved, {}).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/trust policy rejected/)
      // the FAILED run created NO NEW runtime (run1's .run-* may still exist)
      const runProfilesAfter = readdirSync(join(homeB, 'profiles')).filter((p) => p.startsWith('.run-'))
      expect(runProfilesAfter.length).toBe(runProfilesBefore.length)
    } finally {
      await mock.stop()
    }
  })
})
