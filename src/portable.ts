/**
 * v0.2 --portable (DESIGN.md v0.2, §5.2): vendors the local dependency graph
 * so a profile with `file:`/`link:` directory deps becomes fully portable.
 *
 * Pipeline (empirically validated against pnpm v11 lockfile v9, 2026-08-29):
 *   1. DFS the local closure — every `file:`/`link:` DIRECTORY dep of the
 *      profile and of each local package (transitively), with cycle detection.
 *   2. Rewrite each local package's package.json local specs to
 *      `file:vendor/<name>-<version>.tgz` (resolved relative to the project
 *      root at install time) and build a deterministic tgz with the npm
 *      `package/` entry prefix.
 *   3. Rewrite the staged lockfile: importer entries, `packages:` keys and
 *      `snapshots:` dependency values go from directory form
 *      (`name@file:../x` + `resolution: {directory: ...}`) to tarball form
 *      (`name@file:vendor/x.tgz` + `resolution: {integrity, tarball}`) — the
 *      exact shape `pnpm install` produces, so `--frozen-lockfile` passes.
 *
 * Integrity = `sha512-` + base64(sha512(tgzBytes)), matching pnpm's own
 * computation (verified byte-for-byte; tampered tgzs are rejected by frozen
 * install).
 * @module @why-daydream/dsh-pack/portable
 */

import { createHash, randomUUID } from 'node:crypto'
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, statSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, isAbsolute, join, relative, resolve } from 'node:path'
import * as tar from 'tar'
import { parseYaml, stringifyYaml } from './canonical.ts'
import { classifySpec, specPath } from './dependency-resolver.ts'
import { PackError } from './service.ts'

/** One vendored local package in the closure. */
export interface VendoredPackage {
  name: string
  /** version from its own package.json (never a machine path). */
  version: string
  /** Source directory on the pack machine (diagnostics only). */
  dir: string
  /**
   * Project-relative POSIX path from the profile dir to `dir`. pnpm lockfiles
   * address file:/link: deps by PROJECT-relative path, which differs from the
   * declared spec for transitive deps — both forms must be rewritten.
   */
  relPath: string
  /** The spec that introduced it, e.g. `file:../a-tool` / `link:../x`. */
  entrySpec: string
  kind: 'directory' | 'tarball'
  /** Vendored tgz file name, `file:vendor/<tgz>` on the install side. */
  tgz: string
  /** Original specs of its LOCAL deps (file:/link:/tarball) → rewritten later. */
  localSpecs: Record<string, string>
}

/** The full portable plan produced at pack time. */
export interface PortablePlan {
  /** Post-order local closure (dependencies before dependents), deduped. */
  packages: VendoredPackage[]
  /** tgz file name → tgz bytes (written into the pack's `packages/`). */
  tgzs: Record<string, Buffer>
  /** Original local spec string → `file:vendor/<tgz>` (for tgz package.json rewrites). */
  specRewrites: Record<string, string>
  /** Staged direct dependency map (local specs → `file:./packages/<tgz>`). */
  stagedDeps: Record<string, string>
  /** Staged lockfile text (directory form → tarball form), undefined if none. */
  lockfile: string | undefined
}

/** Discover the local closure: every file:/link: directory dep, transitively. */
export function collectLocalClosure(
  profileDir: string,
  directDeps: Record<string, string>,
): VendoredPackage[] {
  const visited = new Map<string, VendoredPackage>()
  const visiting = new Set<string>()
  const order: VendoredPackage[] = []

  const visit = (name: string, spec: string, fromDir: string): void => {
    const kind = classifySpec(spec)
    if (kind === 'tarball') {
      // Transitive tarball deps are vendored byte-for-byte (no repack).
      const pathPart = specPath(spec)
      const resolved = isAbsolute(pathPart) ? pathPart : resolve(fromDir, pathPart)
      const tgz = basename(resolved)
      if (!visited.has(resolved)) {
        const pkg: VendoredPackage = {
          name, version: '', dir: resolved,
          relPath: toPosix(relative(profileDir, resolved)),
          entrySpec: spec, kind: 'tarball',
          tgz, localSpecs: {},
        }
        visited.set(resolved, pkg)
        order.push(pkg)
      }
      return
    }
    if (kind !== 'file' && kind !== 'link') return // npm / github: registry-resolved

    const pathPart = specPath(spec)
    const dir = isAbsolute(pathPart) ? pathPart : resolve(fromDir, pathPart)
    if (visiting.has(dir)) {
      throw new PackError(`Local dependency cycle detected: ${dir} (via ${spec})`, 1)
    }
    if (visited.has(dir)) return
    visiting.add(dir)

    const pkgFile = join(dir, 'package.json')
    if (!existsSync(pkgFile)) {
      visiting.delete(dir)
      throw new PackError(`Local dependency ${name} missing package.json: ${dir}`, 1)
    }
    let pkg: { name?: string; version?: string; dependencies?: Record<string, string> }
    try {
      pkg = JSON.parse(readFileSync(pkgFile, 'utf8'))
    } catch (error) {
      visiting.delete(dir)
      throw new PackError(`Local dependency ${name} has an unreadable package.json: ${String(error)}`, 1)
    }
    const localSpecs: Record<string, string> = {}
    for (const [depName, depSpec] of Object.entries(pkg.dependencies ?? {})) {
      const depKind = classifySpec(depSpec)
      if (depKind === 'file' || depKind === 'link' || depKind === 'tarball') {
        localSpecs[depName] = depSpec
        visit(depName, depSpec, dir)
      }
    }
    visiting.delete(dir)

    const version = typeof pkg.version === 'string' && pkg.version !== '' ? pkg.version : '0.0.0'
    const entry: VendoredPackage = {
      name, version, dir,
      relPath: toPosix(relative(profileDir, dir)),
      entrySpec: spec, kind: 'directory',
      tgz: `${name.replace(/^@/, '').replaceAll('/', '-')}-${version}.tgz`,
      localSpecs,
    }
    visited.set(dir, entry)
    order.push(entry)
  }

  for (const [name, spec] of Object.entries(directDeps)) visit(name, spec, profileDir)
  return order
}

/** Compute pnpm-style integrity for a tgz: `sha512-` + base64(sha512(bytes)). */
export function tgzIntegrity(tgzBytes: Buffer): string {
  return `sha512-${createHash('sha512').update(tgzBytes).digest('base64')}`
}

/**
 * Build the portable plan for a profile: closure + vendored tgzs + staged
 * package.json/lockfile. Mutates nothing on disk outside temp dirs.
 */
export async function buildPortablePlan(
  profileDir: string,
  directDeps: Record<string, string>,
): Promise<PortablePlan> {
  const packages = collectLocalClosure(profileDir, directDeps)
  const tgzs: Record<string, Buffer> = {}
  const specRewrites: Record<string, string> = {}
  const stagedDeps: Record<string, string> = { ...directDeps }
  const byTgz = new Map<string, VendoredPackage>()

  for (const pkg of packages) {
    if (pkg.kind === 'directory') {
      const tgzBytes = await buildVendoredTgz(pkg, specRewrites)
      tgzs[pkg.tgz] = tgzBytes
    } else {
      if (!existsSync(pkg.dir)) {
        throw new PackError(`tarball dependency ${pkg.name} missing: ${pkg.dir}`, 1)
      }
      tgzs[pkg.tgz] = readFileSync(pkg.dir)
    }
    byTgz.set(pkg.tgz, pkg)
    const vendorSpec = `file:vendor/${pkg.tgz}`
    specRewrites[pkg.entrySpec] = vendorSpec
    // Direct deps are staged with the pack-relative form (MUST-2); install
    // rewrites them to `file:vendor/...` to match the lockfile.
    if (directDeps[pkg.name] === pkg.entrySpec) stagedDeps[pkg.name] = `file:./packages/${pkg.tgz}`
  }

  // Rewrite transitive local specs inside each vendored tgz's package.json
  // (done inside buildVendoredTgz). Tarball packages' bytes are copied
  // verbatim — their internal specs cannot be rewritten.
  const lockfile = rewriteLockfileForPortable(profileDir, packages, tgzs)
  return { packages, tgzs, specRewrites, stagedDeps, lockfile }
}

/** Normalize a path to forward slashes (lockfile convention). */
function toPosix(path: string): string {
  return path.replaceAll('\\', '/')
}

/**
 * Rewrite the staged lockfile from directory form to the vendored tarball form
 * (validated shape: `name@file:vendor/<tgz>` + `resolution: {integrity,
 * tarball}` + `version`, and `snapshots:` values rewritten to the same
 * vendor specs). Frozen install then passes without re-resolving anything
 * (D6): the registry part of the lockfile is untouched.
 *
 * pnpm lockfiles address file:/link: deps by PROJECT-relative path (not the
 * declared spec), so every closure member is matched by BOTH the declared spec
 * and its project-relative form (with `file:` and `link:` prefixes).
 * @returns the staged lockfile text, or `undefined` when the profile has none.
 */
export function rewriteLockfileForPortable(
  profileDir: string,
  packages: readonly VendoredPackage[],
  tgzs: Record<string, Buffer>,
): string | undefined {
  const lockPath = join(profileDir, 'pnpm-lock.yaml')
  if (!existsSync(lockPath)) return undefined
  const raw = readFileSync(lockPath, 'utf8')
  try {
    const lock = parseYaml(raw) as Record<string, unknown>
    const importers = lock.importers as
      | { '.'?: { dependencies?: Record<string, { specifier?: string; version?: string }> } }
      | undefined
    const deps = importers?.['.']?.dependencies
    const pkgMap = lock.packages as Record<string, unknown> | undefined
    const snapshots = lock.snapshots as Record<string, unknown> | undefined
    if (deps === undefined && pkgMap === undefined) return raw

    // entrySpec / project-relative spec → `file:vendor/<tgz>` (importer +
    // snapshot values + packages keys), for `file:` and `link:` prefixes.
    const specRewrites: Record<string, string> = {}
    const keyRewrites: Record<string, string> = {}
    // old packages key → owning closure member (for the packages-map rewrite).
    const keyOwners: Record<string, VendoredPackage> = {}
    for (const pkg of packages) {
      const vendorSpec = `file:vendor/${pkg.tgz}`
      const forms = new Set<string>([
        pkg.entrySpec,
        `file:${pkg.relPath}`,
        `link:${pkg.relPath}`,
      ])
      for (const form of forms) {
        specRewrites[form] = vendorSpec
        const oldKey = `${pkg.name}@${form}`
        const newKey = `${pkg.name}@${vendorSpec}`
        keyRewrites[oldKey] = newKey
        keyRewrites[`/${oldKey}`] = `/${newKey}`
        keyOwners[oldKey] = pkg
        keyOwners[`/${oldKey}`] = pkg
      }
    }

    let changed = false

    // importer: direct local deps → vendor spec
    if (deps !== undefined) {
      for (const entry of Object.values(deps)) {
        const rewritten = specRewrites[entry.version ?? ''] ?? specRewrites[entry.specifier ?? '']
        if (rewritten !== undefined && entry.version !== rewritten) {
          entry.version = rewritten
          if (entry.specifier !== undefined) entry.specifier = rewritten
          changed = true
        }
      }
    }

    // packages map: directory entries → tarball entries (integrity + version)
    if (pkgMap !== undefined) {
      for (const [key, entry] of Object.entries(pkgMap)) {
        const pkg = keyOwners[key]
        if (pkg === undefined) continue
        const newKey = keyRewrites[key]
        if (newKey === undefined) continue
        const tgzBytes = tgzs[pkg.tgz]
        if (tgzBytes === undefined) continue
        const vendorSpec = `file:vendor/${pkg.tgz}`
        const record = entry as Record<string, unknown>
        record.resolution = { integrity: tgzIntegrity(tgzBytes), tarball: vendorSpec }
        if (pkg.kind === 'directory') record.version = pkg.version
        delete pkgMap[key]
        pkgMap[newKey] = record
        changed = true
      }
    }

    // snapshots: rename keys + rewrite dependency values
    if (snapshots !== undefined) {
      for (const [key, snapshot] of Object.entries(snapshots)) {
        const newKey = keyRewrites[key]
        if (newKey !== undefined) {
          snapshots[newKey] = snapshot
          delete snapshots[key]
          changed = true
        }
        const depsOf = (snapshot as { dependencies?: Record<string, string> }).dependencies
        if (depsOf !== undefined) {
          for (const [depName, spec] of Object.entries(depsOf)) {
            const rewritten = specRewrites[spec]
            if (rewritten !== undefined && rewritten !== spec) {
              depsOf[depName] = rewritten
              changed = true
            }
          }
        }
      }
    }

    if (!changed) return raw
    return stringifyYaml(lock)
  } catch {
    // Unparseable lockfile: pass the original through; frozen install fails loud.
    return raw
  }
}

/**
 * Build a deterministic tgz for one local directory package: stage a temp copy
 * with the rewritten package.json (local specs → `file:vendor/<tgz>`), then
 * tar with the npm `package/` entry prefix, sorted entries and mtime=0.
 */
async function buildVendoredTgz(
  pkg: VendoredPackage,
  specRewrites: Record<string, string>,
): Promise<Buffer> {
  const staging = mkdtempSync(join(tmpdir(), `dsh-pack-vendor-${randomUUID()}-`))
  try {
    const pkgFile = join(pkg.dir, 'package.json')
    const manifest = JSON.parse(readFileSync(pkgFile, 'utf8')) as {
      dependencies?: Record<string, string>
    }
    const rewritten = { ...(manifest.dependencies ?? {}) }
    for (const [depName, spec] of Object.entries(rewritten)) {
      const replacement = specRewrites[spec]
      if (replacement !== undefined) rewritten[depName] = replacement
    }
    const outManifest = { ...manifest, dependencies: rewritten }
    // npm/pnpm convention: every archive entry lives under `package/`.
    const packageDir = join(staging, 'package')
    mkdirSync(packageDir, { recursive: true })
    // Copy the tree FIRST, then write the rewritten package.json LAST so the
    // copy step cannot clobber it with the original from pkg.dir.
    copyTreeExcluding(pkg.dir, packageDir, ['node_modules', '.git'])
    writeFileSync(join(packageDir, 'package.json'), `${JSON.stringify(outManifest, null, 2)}\n`)
    // MUST await: without it the `finally` below deletes the staging dir while
    // tar.c is still asynchronously reading files (ENOENT race).
    return await createPackageTgz(staging)
  } finally {
    rmSync(staging, { recursive: true, force: true })
  }
}

/** Copy a directory tree, skipping the given top-level names. */
function copyTreeExcluding(source: string, dest: string, skip: readonly string[]): void {
  for (const name of readdirSync(source)) {
    if (skip.includes(name)) continue
    const from = join(source, name)
    const to = join(dest, name)
    const stat = statSync(from)
    if (stat.isDirectory()) {
      mkdirSync(to, { recursive: true })
      copyTreeExcluding(from, to, skip)
    } else if (stat.isFile()) {
      copyFileSync(from, to)
    }
  }
}

/** Deterministic tgz of a staged root whose entries already carry `package/`. */
async function createPackageTgz(packageRoot: string): Promise<Buffer> {
  const fileList = collectFilesRecursive(packageRoot).sort()
  const chunks: Buffer[] = []
  await new Promise<void>((resolvePromise, reject) => {
    const stream = tar.c({ cwd: packageRoot, gzip: true, portable: true, mtime: new Date(0) }, fileList)
    stream.on('data', (chunk: Buffer) => chunks.push(chunk))
    stream.on('end', resolvePromise)
    stream.on('error', reject)
  })
  return Buffer.concat(chunks)
}

/** Recursively collect relative file paths under a root. */
function collectFilesRecursive(root: string): string[] {
  const out: string[] = []
  const walk = (dir: string, prefix: string): void => {
    for (const name of readdirSync(dir)) {
      const absolute = join(dir, name)
      const rel = prefix === '' ? name : `${prefix}/${name}`
      if (statSync(absolute).isDirectory()) walk(absolute, rel)
      else out.push(rel)
    }
  }
  walk(root, '')
  return out
}
