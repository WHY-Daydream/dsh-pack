/**
 * Clean-room E2E (DESIGN.md §8.4 — E2E 北极星判据 ②): with the REAL dsh CLI,
 * pack a profile from a clean DSH_HOME, install the pack into a second clean
 * DSH_HOME, and prove `dsh --profile web --dump-config` composes the same tree
 * on both machines (modulo the home paths), plus the Portable configHash
 * recomputed on the install side equals the manifest's.
 *
 * Requires: the built dsh CLI (apps/cli/lib/bin.js) and pnpm on PATH.
 * Run: PATH=<pnpm-shim-dir>:$PATH node scripts/clean-room-e2e.mjs
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { DefaultPackager } from '../lib/service.js'
import { loadProfileDir, resolveInstallAnchor } from '../lib/profile-reader.js'
import { buildSnapshot } from '../lib/config-snapshot.js'
import { resolveDependencies } from '../lib/dependency-resolver.js'
import { bundleIdentities, computeConfigHash } from '../lib/manifest.js'

const execFileAsync = promisify(execFile)
const DSH_CLI = new URL('../../deepseek-harness/apps/cli/lib/bin.js', import.meta.url).pathname
const DSH_VERSION = '0.1.0-rc.5'

const PROFILE_PATCH = `# web profile (clean-room E2E)
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
- insert:
    - id: timeout-policy
      timeoutMs: 30000
`

async function dumpConfig(home) {
  const { stdout } = await execFileAsync(process.execPath, [DSH_CLI, '--profile', 'web', '--dump-config'], {
    env: { ...process.env, DSH_HOME: home },
    timeout: 60_000,
  })
  return stdout
}

/** Normalize machine-specific home paths out of dump output for comparison. */
function normalize(text, homeA, homeB) {
  return text.replaceAll(homeA, '$HOME').replaceAll(homeB, '$HOME')
}

async function main() {
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-cleanroom-'))
  const homeA = join(root, 'homeA')
  const homeB = join(root, 'homeB')
  for (const home of [homeA, homeB]) mkdirSync(join(home, 'profiles'), { recursive: true })
  try {
    // --- machine A: a runnable profile ---
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
    await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 60_000 })

    // --- pack on A ---
    const packagerA = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION })
    const outcome = await packagerA.pack({ profile: 'web', outDir: root })
    console.log(`✓ pack: ${outcome.file}`)

    // --- install into B ---
    const packagerB = new DefaultPackager({ home: homeB, installedDshVersion: DSH_VERSION })
    const installed = await packagerB.install(outcome.file, {})
    console.log(`✓ install: ${installed.profile} -> ${installed.dir}`)

    // --- clean-room dump-config comparison (criterion ②) ---
    const dumpA = await dumpConfig(homeA)
    const dumpB = await dumpConfig(homeB)
    const normA = normalize(dumpA, homeA, homeB)
    const normB = normalize(dumpB, homeA, homeB)
    const dumpOk = normA === normB

    // --- portable configHash recompute on the install side (criterion ①) ---
    const loaded = loadProfileDir('web', homeB)
    const anchor = resolveInstallAnchor()
    const snapshot = buildSnapshot(loaded, homeB, anchor.anchor)
    const depTree = resolveDependencies(loaded.dir, loaded.manifest.dependencies ?? {}, [])
    const recomputed = computeConfigHash(snapshot.composition, bundleIdentities([], depTree), depTree.closure)
    const manifest = JSON.parse(readFileSync(join(installed.dir, '.dshpack', 'manifest.json'), 'utf8'))
    const hashOk = recomputed === manifest.configHash

    console.log(`✓ dump-config identical (normalized): ${dumpOk}`)
    console.log(`✓ install-side configHash == manifest.configHash: ${hashOk}`)
    if (!dumpOk) {
      const linesA = normA.split('\n')
      const linesB = normB.split('\n')
      for (let i = 0; i < Math.max(linesA.length, linesB.length); i++) {
        if (linesA[i] !== linesB[i]) console.log(`  diff@${i} A=${JSON.stringify(linesA[i])} B=${JSON.stringify(linesB[i])}`)
      }
    }
    if (!dumpOk || !hashOk) {
      console.error('✗ CLEAN-ROOM E2E FAILED')
      process.exitCode = 1
      return
    }
    console.log('✔ CLEAN-ROOM E2E PASSED')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
