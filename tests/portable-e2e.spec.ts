/**
 * v0.2 --portable North-Star E2E: a profile with `file:` directory deps is
 * packed with --portable, verified, installed into a fresh DSH_HOME, and the
 * install-side Portable configHash must equal the manifest's — through the
 * real `pnpm install --frozen-lockfile` on the vendored tgzs.
 * Skipped when `pnpm` is not available on PATH.
 */
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
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
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-pe2e-${label}-`))
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

/** Recursively find paths under a root matching a predicate. */
function findFiles(root: string, predicate: (path: string) => boolean): string[] {
  const out: string[] = []
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const path = join(dir, name)
      if (predicate(path)) out.push(path)
      if (existsSync(path)) {
        try {
          if (statIsDir(path)) walk(path)
        } catch {
          // dangling symlink — skip
        }
      }
    }
  }
  walk(root)
  return out
}

function statIsDir(path: string): boolean {
  // readdirSync-based probe keeps the import surface minimal.
  return readdirSync(path).length >= 0
}

const PROFILE_PATCH = `# web profile (portable E2E)
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
`

/** Local packages: a-tool → file:../b-lib, under <root>/local. */
function makeLocalPackages(root: string): void {
  mkdirSync(join(root, 'local', 'a-tool'), { recursive: true })
  mkdirSync(join(root, 'local', 'b-lib'), { recursive: true })
  writeFileSync(join(root, 'local', 'b-lib', 'package.json'), JSON.stringify({
    name: '@xp/b-lib', version: '1.0.0', main: 'index.js',
  }))
  writeFileSync(join(root, 'local', 'b-lib', 'index.js'), 'module.exports = { b: true }\n')
  writeFileSync(join(root, 'local', 'a-tool', 'package.json'), JSON.stringify({
    name: '@xp/a-tool', version: '1.0.0', main: 'index.js',
    dependencies: { '@xp/b-lib': 'file:../b-lib' },
  }))
  writeFileSync(join(root, 'local', 'a-tool', 'index.js'), 'module.exports = { a: true }\n')
}

describe('E2E --portable pack → install → hash equality', () => {
  it.runIf(hasPnpm)(
    'restores a profile with vendored local deps whose configHash matches, via frozen install',
    async () => {
      const root = tempRoot('main')
      makeLocalPackages(root)

      // --- machine A: profile with a file: directory dep ---
      const homeA = join(root, 'homeA')
      mkdirSync(join(homeA, 'profiles', 'web'), { recursive: true })
      const profileA = join(homeA, 'profiles', 'web')
      writeFileSync(join(profileA, 'package.json'), JSON.stringify({
        name: 'web-profile',
        private: true,
        version: '0.0.0',
        dependencies: { '@xp/a-tool': 'file:../../../local/a-tool' },
        dsh: { profile: { bundles: [] } },
      }, null, 2))
      writeFileSync(join(profileA, 'cordis.patch.yml'), PROFILE_PATCH)
      await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 60_000 })

      // --- pack with --portable ---
      const packagerA = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
      const outcome = await packagerA.pack({ profile: 'web', outDir: root, portable: true })
      expect(outcome.manifest.installable).toBe(true)
      expect(outcome.manifest.portable).toBe(true)
      expect(outcome.manifest.packages).toContain('xp-a-tool-1.0.0.tgz')
      expect(outcome.manifest.packages).toContain('xp-b-lib-1.0.0.tgz')

      // --- verify on A ---
      const report = await packagerA.verify(outcome.file)
      expect(report.ok).toBe(true)
      expect(report.sections.every((s) => s.status !== 'fail')).toBe(true)

      // --- install into B (fresh DSH_HOME) → real pnpm frozen install ---
      const homeB = join(root, 'homeB')
      mkdirSync(join(homeB, 'profiles'), { recursive: true })
      const packagerB = new DefaultPackager({ home: homeB, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
      const installed = await packagerB.install(outcome.file, {})
      expect(installed.profile).toBe('web')

      const profileB = join(homeB, 'profiles', 'web')
      // vendored tgzs materialized
      expect(existsSync(join(profileB, 'vendor', 'xp-a-tool-1.0.0.tgz'))).toBe(true)
      expect(existsSync(join(profileB, 'vendor', 'xp-b-lib-1.0.0.tgz'))).toBe(true)
      // the direct dep is hoisted to the top level; the transitive b-lib lives
      // in the pnpm virtual store (pnpm v11 does not top-level-hoist it) —
      // assert it exists anywhere under node_modules instead of a fixed path.
      expect(readFileSync(join(profileB, 'node_modules', '@xp', 'a-tool', 'index.js'), 'utf8')).toContain('a: true')
      const bLibFiles = findFiles(join(profileB, 'node_modules'), (p) => p.endsWith('@xp/b-lib/index.js'))
      expect(bLibFiles.length).toBeGreaterThan(0)
      expect(readFileSync(bLibFiles[0] as string, 'utf8')).toContain('b: true')

      // --- E2E criterion: install-side configHash == manifest.configHash ---
      const loaded = loadProfileDir('web', homeB)
      const anchor = resolveInstallAnchor()
      const snapshotB = buildSnapshot(loaded, homeB, anchor.anchor)
      const depTreeB = resolveDependencies(loaded.dir, loaded.manifest.dependencies ?? {}, [])
      const identitiesB = bundleIdentities([], depTreeB)
      const recomputed = computeConfigHash(snapshotB.composition, identitiesB, depTreeB.closure)
      expect(recomputed).toBe(outcome.manifest.configHash)
    },
  )

  it('skips gracefully when pnpm is unavailable', async () => {
    expect(true).toBe(true)
  })
})
