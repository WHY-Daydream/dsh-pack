/**
 * Profile discovery and reading (DESIGN.md §4, §5): locate `$DSH_HOME` and the
 * profile directory, parse its package.json, and read the raw patch layers.
 * The composed tree itself is built by config-snapshot via the official
 * `@deepseek-ai/dsh-app-boot` engine (D5).
 * @module @why-daydream/dsh-pack/profile-reader
 */

import { existsSync, readFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { resolveDshHome } from '@deepseek-ai/dsh-home-paths'
import { PROFILE_PATCH_FILENAME } from '@deepseek-ai/dsh-app-boot'

/** Directory under the Harness home holding every profile. */
const PROFILES_DIR = 'profiles'

export { resolveDshHome }

/**
 * Validate + resolve a profile directory under the home, mirroring the
 * official `resolveProfileDir` guard (name must be a single path segment).
 * @param name - the profile name.
 * @param home - the Harness home (defaults to the resolved $DSH_HOME).
 */
export function resolveProfileDir(name: string, home: string = resolveDshHome()): string {
  if (name === '' || name.includes('/') || name.includes('\\') || name === '.' || name === '..'
    || name === 'node_modules') {
    throw new Error(`dsh-pack: invalid profile name ${JSON.stringify(name)}`)
  }
  return join(home, PROFILES_DIR, name)
}

export interface LoadedProfile {
  name: string
  dir: string
  manifest: {
    name?: string
    dependencies?: Record<string, string>
    dsh?: { profile?: { bundles?: string[] } }
  }
  /** Raw `cordis.patch.yml` text (profile layer), undefined when absent. */
  patchText: string | undefined
  /** Raw `$DSH_HOME/cordis.patch.yml` text (home layer), undefined when absent. */
  homePatchText: string | undefined
}

/**
 * Read a profile directory. Fails loud when the profile does not exist
 * (no template auto-init — packing must never mutate state).
 */
export function loadProfileDir(name: string, home: string = resolveDshHome()): LoadedProfile {
  const dir = resolveProfileDir(name, home)
  const pkgFile = join(dir, 'package.json')
  if (!existsSync(pkgFile)) {
    throw new Error(`dsh-pack: profile ${JSON.stringify(name)} does not exist (${dir})`)
  }
  let manifest: LoadedProfile['manifest']
  try {
    manifest = JSON.parse(readFileSync(pkgFile, 'utf8'))
  } catch (error) {
    throw new Error(`dsh-pack: profile ${JSON.stringify(name)} has an unreadable package.json: ${String(error)}`)
  }
  const patchFile = join(dir, PROFILE_PATCH_FILENAME)
  const homePatchFile = join(home, PROFILE_PATCH_FILENAME)
  return {
    name,
    dir,
    manifest,
    patchText: existsSync(patchFile) ? readFileSync(patchFile, 'utf8') : undefined,
    homePatchText: existsSync(homePatchFile) ? readFileSync(homePatchFile, 'utf8') : undefined,
  }
}

export interface InstallAnchor {
  /** Absolute path of the dsh installation package.json (`@deepseek-ai/dsh`). */
  anchor: string
  /** `'dsh'` when the real installation was found, `'fallback'` otherwise. */
  source: 'dsh' | 'fallback'
}

/**
 * Locate the dsh installation anchor used by `loadProfile` for in-box bundle
 * resolution. Walks up from the resolved `@deepseek-ai/dsh-app-boot` package
 * to the nearest `@deepseek-ai/dsh` package.json; falls back to app-boot's
 * own package.json (in-box resolution then degrades to the profile's
 * node_modules, which profiles normally satisfy anyway).
 */
export function resolveInstallAnchor(): InstallAnchor {
  const require = createRequire(import.meta.url)
  let appBootDir: string
  try {
    appBootDir = dirname(require.resolve('@deepseek-ai/dsh-app-boot/package.json'))
  } catch {
    throw new Error('dsh-pack: cannot resolve @deepseek-ai/dsh-app-boot; install dsh-pack inside a DSH profile')
  }
  let dir: string = appBootDir
  for (let depth = 0; depth < 8; depth++) {
    const pkgFile = join(dir, 'package.json')
    if (existsSync(pkgFile)) {
      try {
        const pkg = JSON.parse(readFileSync(pkgFile, 'utf8')) as { name?: string }
        if (pkg.name === '@deepseek-ai/dsh') return { anchor: pkgFile, source: 'dsh' }
      } catch {
        // unreadable manifest — keep walking
      }
    }
    const parent = dirname(dir)
    if (parent === dir) break
    dir = parent
  }
  return { anchor: join(appBootDir, 'package.json'), source: 'fallback' }
}
