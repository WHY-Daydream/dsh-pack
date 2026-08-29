/**
 * Service-level protocol tests (DESIGN.md §5.2/D7, §7.5/D15): the preflight
 * gate for non-portable directory deps and the exact runtime version match.
 * Pnpm-free: these paths abort before any `pnpm install` is spawned.
 */
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { DefaultPackager } from '../src/service.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempHome(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-svc-${label}-`))
  mkdirSync(join(dir, 'profiles'), { recursive: true })
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** Create a minimal runnable profile with the given direct dependencies. */
function makeProfile(home: string, name: string, dependencies: Record<string, string>): void {
  const dir = join(home, 'profiles', name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: `${name}-profile`,
    private: true,
    version: '0.0.0',
    dependencies,
    dsh: { profile: { bundles: [] } },
  }, null, 2))
  writeFileSync(join(dir, 'cordis.patch.yml'), `# ${name} profile
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
`)
}

describe('D7: non-portable directory deps', () => {
  it('fail the pack by default with exit code 1', async () => {
    const home = tempHome('d7a')
    makeProfile(home, 'web', { 'dsh-local': 'link:../../dsh-local' })
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
    await expect(packager.pack({ profile: 'web', outDir: home })).rejects.toThrow(/Non-portable dependency detected/)
  })

  it('produce installable:false AND portable:false when --allow-nonportable is passed', async () => {
    const home = tempHome('d7b')
    makeProfile(home, 'web', { 'dsh-local': 'file:../../dsh-local' })
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
    const outcome = await packager.pack({ profile: 'web', outDir: home, allowNonportable: true })
    expect(outcome.manifest.installable).toBe(false)
    expect(outcome.manifest.portable).toBe(false)
  })

  it('keeps tarball deps portable and installable (vendored, MUST-2)', async () => {
    const home = tempHome('d7c')
    makeProfile(home, 'web', { 'dsh-tgz': 'file:../dist/x.tgz' })
    // the referenced tarball must exist on the pack machine (it gets vendored)
    const distDir = join(home, 'profiles', 'dist')
    mkdirSync(distDir, { recursive: true })
    writeFileSync(join(distDir, 'x.tgz'), 'fake-tgz-bytes')
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
    const outcome = await packager.pack({ profile: 'web', outDir: home })
    expect(outcome.manifest.installable).toBe(true)
    expect(outcome.manifest.portable).toBe(true)
  })
})

describe('D15: exact runtime version match', () => {
  it('verify reports a DSH Version FAIL when the installed dsh differs', async () => {
    const home = tempHome('d15a')
    makeProfile(home, 'web', {})
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
    const outcome = await packager.pack({ profile: 'web', outDir: home })
    expect((await packager.verify(outcome.file)).ok).toBe(true)

    const mismatched = new DefaultPackager({ home, installedDshVersion: '0.2.0', packagerVersion: 'test' })
    const report = await mismatched.verify(outcome.file)
    expect(report.ok).toBe(false)
    const section = report.sections.find((s) => s.name === 'DSH Version')
    expect(section?.status).toBe('fail')

    const ignored = await mismatched.verify(outcome.file, { ignoreRuntimeVersion: true })
    expect(ignored.ok).toBe(true)
    expect(ignored.sections.find((s) => s.name === 'DSH Version')?.status).toBe('warn')
  })

  it('install rejects a mismatched runtime version before touching anything', async () => {
    const homeA = tempHome('d15b')
    makeProfile(homeA, 'web', {})
    const packagerA = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: 'test' })
    const outcome = await packagerA.pack({ profile: 'web', outDir: homeA })

    const homeB = tempHome('d15c')
    const packagerB = new DefaultPackager({ home: homeB, installedDshVersion: '0.2.0', packagerVersion: 'test' })
    await expect(packagerB.install(outcome.file, {})).rejects.toThrow(/built for dsh/)
    // nothing was written into the target home
    expect(existsSync(join(homeB, 'profiles', 'web'))).toBe(false)
  })
})
