/**
 * Install pipeline (DESIGN.md §8.4, frozen v0.1): verify → safe extract to a
 * staging dir → materialize the profile → `pnpm install --frozen-lockfile`
 * (MUST-1) → bundle reconcile → atomic swap (MUST-3). Refuses non-installable
 * packs and mismatched DSH versions (D15); never restores secrets (D9).
 * @module @why-daydream/dsh-pack/install
 */

import { execFile } from 'node:child_process'
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { PROFILE_PATCH_FILENAME } from '@deepseek-ai/dsh-app-boot'
import { validateManifest } from './manifest.ts'
import { extractTarGz } from './pack-builder.ts'
import { prettyJson } from './canonical.ts'
import { PROFILE_ROOT_CONFIG } from './config-snapshot.ts'
import { resolveProfileDir } from './profile-reader.ts'
import type { InstallOptions, InstallResult, Manifest } from './types.ts'

const execFileAsync = promisify(execFile)

export interface InstallContext {
  home: string
  installedDshVersion: string
  /** Where the temporary staging root lives (default: `<home>/profiles`). */
}

export interface InstallOutcome {
  result: InstallResult
  /** Staging root that must be cleaned up by the caller when an error occurred. */
  staging: string
}

/**
 * Install a verified `.dshpack` buffer into `$DSH_HOME/profiles/<name>`.
 * On failure the existing profile (if any) is left untouched (MUST-3).
 */
export async function installPack(
  buffer: Buffer,
  opts: InstallOptions,
  context: InstallContext,
): Promise<InstallOutcome> {
  // 1. safe extraction to a staging root under profiles/
  const profilesDir = join(context.home, 'profiles')
  mkdirSync(profilesDir, { recursive: true })
  const staging = join(profilesDir, `.dsh-pack-staging-${randomUUID()}`)
  try {
    await extractTarGz(buffer, staging)

    // 2. manifest validation
    const manifestPath = join(staging, 'manifest.json')
    if (!existsSync(manifestPath)) throw new Error('dsh-pack: archive has no manifest.json')
    const parsed = validateManifest(JSON.parse(readFileSync(manifestPath, 'utf8')))
    if (!parsed.ok) {
      throw new Error(`dsh-pack: invalid manifest: ${parsed.errors.join('; ')}`)
    }
    const manifest = parsed.manifest

    // 3. entry gates (D7 / D15)
    if (manifest.installable === false) {
      throw new Error(
        'dsh-pack: this pack is NOT installable (it contains non-portable file:/link: directory dependencies). '
        + 'Repack with v0.2 --portable, or create it with --allow-nonportable only for inspection.',
      )
    }
    if (!opts.ignoreRuntimeVersion && manifest.runtime.dshVersion !== context.installedDshVersion) {
      throw new Error(
        `dsh-pack: pack was built for dsh ${manifest.runtime.dshVersion}, installed is ${context.installedDshVersion}. `
        + 'Pass --ignore-runtime-version to override (DSH is Developer Preview; exact match is the v0.1 default).',
      )
    }

    // 4. target profile
    const name = opts.profile ?? manifest.profile.name
    const target = resolveProfileDir(name, context.home)
    const backup = join(profilesDir, `.dsh-pack-backup-${randomUUID()}`)
    const replaced = existsSync(target)
    if (replaced && !opts.force) {
      throw new Error(`dsh-pack: profile ${JSON.stringify(name)} already exists (${target}); pass --force to replace it`)
    }

    // 5. materialize the profile inside staging
    const profileDir = join(staging, name)
    mkdirSync(profileDir, { recursive: true })
    copyPackProfile(staging, profileDir, manifest)
    // receipt: manifest + resolved/ for later diff/debugging
    const receipt = join(profileDir, '.dshpack')
    mkdirSync(receipt, { recursive: true })
    copyFileSync(manifestPath, join(receipt, 'manifest.json'))
    copyTree(join(staging, 'resolved'), receipt)

    // 6. pnpm install --frozen-lockfile (MUST-1)
    await frozenInstall(profileDir)

    // 7. bundle reconcile (official algorithm: installed deps declaring dsh.bundle)
    reconcileBundles(profileDir, manifest)

    // 8. atomic swap (MUST-3)
    if (replaced) {
      try {
        renameSync(target, backup)
      } catch (error) {
        throw new Error(`dsh-pack: cannot back up existing profile: ${String(error)}`)
      }
    }
    try {
      renameSync(profileDir, target)
    } catch (error) {
      if (replaced && existsSync(backup)) renameSync(backup, target)
      throw new Error(`dsh-pack: cannot move staged profile into place: ${String(error)}`)
    }
    if (replaced && existsSync(backup)) rmSync(backup, { recursive: true, force: true })

    return { result: { profile: name, dir: target }, staging }
  } catch (error) {
    rmSync(staging, { recursive: true, force: true })
    throw error
  }
}

/** Copy profile/ + env/ + vendor artifacts from the pack into the profile dir. */
function copyPackProfile(staging: string, profileDir: string, manifest: Manifest): void {
  // profile/package.json with vendored tarball specs rewritten (MUST-2)
  const srcPackage = join(staging, 'profile/package.json')
  const pkg = JSON.parse(readFileSync(srcPackage, 'utf8')) as {
    dependencies?: Record<string, string>
    dsh?: { profile?: { bundles?: string[] } }
  }
  writeFileSync(join(profileDir, 'package.json'), prettyJson(pkg))

  // profile/cordis.patch.yml (raw, as packed)
  const patch = join(staging, 'profile/cordis.patch.yml')
  if (existsSync(patch)) {
    writeFileSync(join(profileDir, PROFILE_PATCH_FILENAME), readFileSync(patch, 'utf8'))
  }

  // profile/cordis.yml (fixed empty root)
  writeFileSync(join(profileDir, 'cordis.yml'), PROFILE_ROOT_CONFIG)

  // profile/pnpm-lock.yaml — required by pnpm install --frozen-lockfile (MUST-1)
  const lockfile = join(staging, 'profile/pnpm-lock.yaml')
  if (existsSync(lockfile)) {
    writeFileSync(join(profileDir, 'pnpm-lock.yaml'), readFileSync(lockfile, 'utf8'))
  }

  // env/.env.example — hint only, never applied (D9)
  const env = join(staging, 'env/.env.example')
  if (existsSync(env)) {
    writeFileSync(join(profileDir, '.env.example'), readFileSync(env, 'utf8'))
  }

  // vendor/ — packages/*.tgz copied and specs rewritten to file:vendor/<name>
  const packagesDir = join(staging, 'packages')
  if (existsSync(packagesDir)) {
    const vendorDir = join(profileDir, 'vendor')
    mkdirSync(vendorDir, { recursive: true })
    const rewritten: Record<string, string> = { ...(pkg.dependencies ?? {}) }
    for (const tgz of readdirSync(packagesDir)) {
      if (!tgz.endsWith('.tgz')) continue
      copyFileSync(join(packagesDir, tgz), join(vendorDir, tgz))
      const spec = `file:vendor/${tgz}`
      for (const [dep, original] of Object.entries(rewritten)) {
        if (original === `file:./packages/${tgz}` || original === `file:packages/${tgz}`) {
          rewritten[dep] = spec
        }
      }
    }
    if (JSON.stringify(rewritten) !== JSON.stringify(pkg.dependencies)) {
      pkg.dependencies = rewritten
      writeFileSync(join(profileDir, 'package.json'), prettyJson(pkg))
    }
  }
  void manifest
}

/** Run `pnpm install --frozen-lockfile` in the profile dir (MUST-1). */
async function frozenInstall(profileDir: string): Promise<void> {
  const { stdout, stderr } = await execFileAsync('pnpm', ['install', '--frozen-lockfile'], {
    cwd: profileDir,
    env: { ...process.env },
  }).catch((error: NodeJS.ErrnoException & { stdout?: string; stderr?: string }) => {
    throw new Error(
      `dsh-pack: pnpm install --frozen-lockfile failed in ${profileDir} (lock mismatch or resolution error). `
      + `stdout: ${String(error.stdout ?? '')} stderr: ${String(error.stderr ?? error.message)}`,
    )
  })
  void stdout
  void stderr
}

/**
 * Bundle reconcile — mirrors the official CLI algorithm (apps/cli/src/plugin.ts):
 * an installed dependency that declares `dsh.bundle.patch` joins the layer
 * stack, in dependency declaration order.
 */
function reconcileBundles(profileDir: string, manifest: Manifest): void {
  const pkgPath = join(profileDir, 'package.json')
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as {
    dependencies?: Record<string, string>
    dsh?: { profile?: { bundles?: string[] } }
  }
  const bundles: string[] = []
  for (const name of Object.keys(pkg.dependencies ?? {})) {
    const depPkg = join(profileDir, 'node_modules', name, 'package.json')
    if (!existsSync(depPkg)) continue
    try {
      const dep = JSON.parse(readFileSync(depPkg, 'utf8')) as { dsh?: { bundle?: { patch?: string } } }
      if (dep.dsh?.bundle?.patch !== undefined && !bundles.includes(name)) bundles.push(name)
    } catch {
      // unreadable installed manifest — skip
    }
  }
  const before = pkg.dsh?.profile?.bundles ?? []
  if (JSON.stringify(bundles) !== JSON.stringify(before)) {
    pkg.dsh = { ...(pkg.dsh ?? {}), profile: { ...(pkg.dsh?.profile ?? {}), bundles } }
    writeFileSync(pkgPath, prettyJson(pkg))
  }
  void manifest
}

/** Recursively copy a directory tree (files only). */
function copyTree(source: string, dest: string): void {
  if (!existsSync(source)) return
  for (const name of readdirSync(source)) {
    const from = join(source, name)
    const to = join(dest, name)
    if (statSync(from).isDirectory()) {
      mkdirSync(to, { recursive: true })
      copyTree(from, to)
    } else {
      copyFileSync(from, to)
    }
  }
}
