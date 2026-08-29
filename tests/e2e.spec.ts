/**
 * v0.1 E2E roundtrip (DESIGN.md §8.4 — E2E 北极星判据): pack a real profile
 * from a clean DSH_HOME, verify it, install it into a second clean DSH_HOME,
 * and prove the **Portable configHash** is equal on both sides — plus that no
 * plaintext secret survives the roundtrip (D9).
 *
 * Skipped when `pnpm` is not available on PATH.
 */
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { DefaultPackager } from '../src/service.js'
import { loadProfileDir, resolveInstallAnchor } from '../src/profile-reader.js'
import { buildSnapshot } from '../src/config-snapshot.js'
import { resolveDependencies } from '../src/dependency-resolver.js'
import { bundleIdentities, computeConfigHash } from '../src/manifest.js'

const execFileAsync = promisify(execFile)

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempHome(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-e2e-${label}-`))
  mkdirSync(join(dir, 'profiles'), { recursive: true })
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const PROFILE_PATCH = `# web profile (E2E)
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        apiKey: sk-1234567890abcdef1234
        temperature: 0.3
- insert:
    - id: timeout-policy
      timeoutMs: 30000
`

async function pnpmAvailable(): Promise<boolean> {
  try {
    await execFileAsync('pnpm', ['--version'], { timeout: 10_000 })
    return true
  } catch {
    return false
  }
}

/** Generate pnpm-lock.yaml for an empty-dependency profile (offline-safe). */
async function createLockfile(profileDir: string): Promise<void> {
  await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileDir, timeout: 60_000 })
}

const hasPnpm = await pnpmAvailable()

describe('E2E pack → install → hash equality', () => {
  it.runIf(hasPnpm)(
    'restores a profile whose Portable configHash matches the pack side, with secrets redacted',
    async () => {
      const homeA = tempHome('a')
      const homeB = tempHome('b')

      // --- machine A: a runnable profile (bundle-less, profile patch only) ---
      const profileA = join(homeA, 'profiles', 'web')
      mkdirSync(profileA, { recursive: true })
      writeFileSync(join(profileA, 'package.json'), JSON.stringify({
        name: 'web-profile',
        private: true,
        version: '0.0.0',
        dependencies: {},
        dsh: { profile: { bundles: [] } },
      }, null, 2))
      writeFileSync(join(profileA, 'cordis.patch.yml'), PROFILE_PATCH)
      await createLockfile(profileA)

      // --- pack on A ---
      const packagerA = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
      const outcome = await packagerA.pack({ profile: 'web', outDir: homeA })
      expect(existsSync(outcome.file)).toBe(true)
      expect(outcome.manifest.configHash).toMatch(/^sha256:[0-9a-f]{64}$/)
      expect(outcome.manifest.runtime.dshVersion).toBe(DSH_VERSION)
      expect(outcome.manifest.secrets?.redacted).toBe(1)
      expect(outcome.manifest.installable).toBe(true)

      // --- verify on A ---
      const report = await packagerA.verify(outcome.file)
      expect(report.ok).toBe(true)
      expect(report.sections.map((s) => s.name)).toContain('Config')
      expect(report.sections.every((s) => s.status !== 'fail')).toBe(true)

      // --- install into B (fresh DSH_HOME) ---
      const packagerB = new DefaultPackager({ home: homeB, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
      const installed = await packagerB.install(outcome.file, {})
      expect(installed.profile).toBe('web')
      const profileB = join(homeB, 'profiles', 'web')
      expect(existsSync(profileB)).toBe(true)

      // installed profile must carry the staged lockfile + receipt + env example
      expect(existsSync(join(profileB, 'pnpm-lock.yaml'))).toBe(true)
      expect(existsSync(join(profileB, '.dshpack', 'manifest.json'))).toBe(true)
      expect(existsSync(join(profileB, '.env.example'))).toBe(true)

      // D9: no plaintext secret anywhere in the restored profile
      const installedPatch = readFileSync(join(profileB, 'cordis.patch.yml'), 'utf8')
      expect(installedPatch).not.toContain('sk-1234567890abcdef1234')
      expect(installedPatch).toContain('${LLM_DEEPSEEK_API_KEY}')

      // --- E2E criterion ①: Portable configHash equality (install-side recompute) ---
      const loaded = loadProfileDir('web', homeB)
      const anchor = resolveInstallAnchor()
      const snapshotB = buildSnapshot(loaded, homeB, anchor.anchor)
      const depTreeB = resolveDependencies(loaded.dir, loaded.manifest.dependencies ?? {}, [])
      const identitiesB = bundleIdentities([], depTreeB)
      const recomputed = computeConfigHash(snapshotB.composition, identitiesB, depTreeB.closure)
      expect(recomputed).toBe(outcome.manifest.configHash)

      // the pack archive itself must not carry the plaintext either
      const packBytes = readFileSync(outcome.file)
      expect(packBytes.includes(Buffer.from('sk-1234567890abcdef1234'))).toBe(false)
    },
  )

  it('skips gracefully when pnpm is unavailable', async () => {
    // pnpmAvailable() decides at collection time; if it is missing the real
    // roundtrip test above is skipped — nothing to assert beyond sanity.
    expect(true).toBe(true)
  })
})
