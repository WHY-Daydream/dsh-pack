/**
 * Dependency resolution (DESIGN.md §5): source of truth is the profile
 * directory's `pnpm-lock.yaml`. Builds the full closure (name → locked
 * version), classifies every direct spec (npm/github/tarball/file/link), and
 * flags non-portable local deps (D7) — never re-resolves versions.
 * @module @why-daydream/dsh-pack/dependency-resolver
 */

import { existsSync, readFileSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import type { DependencyTree, LocalDep, SpecKind } from './types.ts'
import { parseYaml, stringifyYaml } from './canonical.ts'

const LOCKFILE_NAME = 'pnpm-lock.yaml'

/** Classify one dependency spec (DESIGN.md §5.2). */
export function classifySpec(spec: string): SpecKind {
  const trimmed = spec.trim()
  if (trimmed.startsWith('link:')) return 'link'
  if (trimmed.startsWith('file:')) {
    return /\.tgz$/i.test(trimmed.slice(5)) ? 'tarball' : 'file'
  }
  if (trimmed.startsWith('github:') || trimmed.startsWith('git+') || trimmed.includes('github.com/')) {
    return 'github'
  }
  return 'npm'
}

/** Whether a github spec is pinned to a commit (floating branches are not reproducible). */
export function isFloatingGithubSpec(spec: string): boolean {
  const trimmed = spec.trim()
  if (trimmed.startsWith('github:')) return !trimmed.includes('#')
  return /github\.com\/[^#\s]+$/.test(trimmed)
}

/** Strip a spec prefix, returning the path part for file:/link:. */
export function specPath(spec: string): string {
  const trimmed = spec.trim()
  for (const prefix of ['link:', 'file:']) {
    if (trimmed.startsWith(prefix)) return trimmed.slice(prefix.length)
  }
  return trimmed
}

/** Parse a pnpm v9 `packages` key like `foo@1.2.3` / `/@scope/x@1.0.0` / `foo@1.0.0(peer@2)`. */
export function parsePackageKey(key: string): { name: string; version: string } | undefined {
  let k = key.trim()
  if (k.startsWith('/')) k = k.slice(1)
  const suffixStart = k.indexOf('(')
  if (suffixStart !== -1) k = k.slice(0, suffixStart).trim()
  const at = k.lastIndexOf('@')
  if (at <= 0 || at === k.length - 1) return undefined
  return { name: k.slice(0, at), version: k.slice(at + 1) }
}

/**
 * Resolve dependencies for a profile directory. When the lockfile is missing
 * the closure degrades to the declared specs with an `unverified closure`
 * warning (verify reports it; install requires a lockfile via frozen install).
 */
export function resolveDependencies(
  profileDir: string,
  direct: Record<string, string>,
  bundles: readonly string[],
): DependencyTree {
  const warnings: string[] = []
  const lockPath = join(profileDir, LOCKFILE_NAME)
  const directEntries = Object.fromEntries(Object.entries(direct)) as Record<string, string>
  // Ordered bundle names first is not required here — direct deps carry specs.

  const localDeps: LocalDep[] = []
  for (const [name, spec] of Object.entries(directEntries)) {
    const kind = classifySpec(spec)
    if (kind === 'file' || kind === 'link' || kind === 'tarball') {
      const pathPart = specPath(spec)
      const resolved = isAbsolute(pathPart) ? pathPart : resolve(profileDir, pathPart)
      // tarballs are vendored (MUST-2); directory deps start non-portable
      // until --portable vendors them (D7).
      localDeps.push({ name, spec, kind, resolved, portable: kind === 'tarball' })
    }
    if (kind === 'github' && isFloatingGithubSpec(spec)) {
      warnings.push(`${name}: github spec without a #commit anchor is not reproducible (floating branch)`)
    }
  }

  let closure: Record<string, string> = {}
  let lockfileLabel = 'MISSING'
  if (!existsSync(lockPath)) {
    warnings.push('pnpm-lock.yaml missing; dependency closure is unverified')
    closure = { ...directEntries }
    for (const name of bundles) {
      if (closure[name] === undefined && directEntries[name] !== undefined) {
        closure[name] = directEntries[name]
      }
    }
    return { lockfile: lockfileLabel, direct: directEntries, closure, localDeps, warnings }
  }

  const raw = readFileSync(lockPath, 'utf8')
  let lock: Record<string, unknown>
  try {
    lock = parseYaml(raw) as Record<string, unknown>
  } catch (error) {
    warnings.push(`pnpm-lock.yaml unparseable: ${String(error)}`)
    return { lockfile: lockfileLabel, direct: directEntries, closure: { ...directEntries }, localDeps, warnings }
  }

  const lockfileVersion = String((lock.lockfileVersion as string | number | undefined) ?? '?')
  lockfileLabel = `pnpm-lock.yaml (lockfileVersion ${lockfileVersion})`

  // Direct locked versions from importers['.'].dependencies.<name>.version.
  const importers = lock.importers as { '.'?: { dependencies?: Record<string, { version?: string }> } } | undefined
  const importerDeps = importers?.['.']?.dependencies ?? {}
  for (const [name, spec] of Object.entries(directEntries)) {
    const entry = importerDeps[name]
    if (entry?.version !== undefined && entry.version !== '' && !entry.version.startsWith('link:')
      && !entry.version.startsWith('file:')) {
      closure[name] = entry.version
    }
  }

  // Full transitive closure from the `packages` map.
  const packages = lock.packages as Record<string, unknown> | undefined
  if (packages !== undefined) {
    const sortedKeys = Object.keys(packages).sort()
    for (const key of sortedKeys) {
      const parsed = parsePackageKey(key)
      if (parsed !== undefined) {
        // Tarball-form entries (e.g. vendored `file:vendor/x.tgz`) carry a
        // real `version:` field — use it so the closure identity is the
        // version, not the spec string (configHash reproducibility, v0.2).
        const entry = packages[key] as { version?: string } | undefined
        const version = typeof entry?.version === 'string' && entry.version !== ''
          ? entry.version
          : parsed.version
        if (closure[parsed.name] === undefined) closure[parsed.name] = version
      }
    }
  }

  // Direct deps still missing from the lock → keep their declared spec but warn.
  for (const [name, spec] of Object.entries(directEntries)) {
    if (closure[name] === undefined) {
      closure[name] = spec
      warnings.push(`${name}: not found in pnpm-lock.yaml; using declared spec`)
    }
  }

  return { lockfile: lockfileLabel, direct: directEntries, closure, localDeps, warnings }
}

/**
 * Produce the staged lockfile that ships inside the pack (MUST-1 + MUST-2):
 * the original `pnpm-lock.yaml` with importer entries AND their `packages:`
 * resolution keys rewritten for vendored tarballs. The lockfile must describe
 * the INSTALL-side final state, because the restored profile runs
 * `pnpm install --frozen-lockfile` after `copyPackProfile` rewrites specs to
 * `file:vendor/<tgz>` — so importer `specifier` + `version` and the packages
 * map key (`<name>@file:../x.tgz` → `<name>@file:vendor/x.tgz`) all have to
 * agree with that spec, or frozen install fails the lockfile check.
 * @returns the staged lockfile text, or `undefined` when the profile has none.
 */
export function rewriteLockfileForStaging(
  profileDir: string,
  stagedDeps: Record<string, string>,
): string | undefined {
  const lockPath = join(profileDir, LOCKFILE_NAME)
  if (!existsSync(lockPath)) return undefined
  const raw = readFileSync(lockPath, 'utf8')
  try {
    const lock = parseYaml(raw) as Record<string, unknown>
    const importers = lock.importers as
      | { '.'?: { dependencies?: Record<string, { specifier?: string; version?: string }> } }
      | undefined
    const deps = importers?.['.']?.dependencies
    const packages = lock.packages as Record<string, unknown> | undefined
    if (deps === undefined) return raw

    const rewrittenKeys: Record<string, string> = {}
    let changed = false
    for (const [name, spec] of Object.entries(stagedDeps)) {
      if (!spec.startsWith('file:./packages/')) continue
      const entry = deps[name]
      if (entry === undefined) continue
      // Install-side final spec: `file:vendor/<name>.tgz` (copyPackProfile).
      const tgz = spec.slice('file:./packages/'.length)
      const vendorSpec = `file:vendor/${tgz}`
      const oldVersion = entry.version ?? entry.specifier
      if (entry.version !== vendorSpec) {
        entry.version = vendorSpec
        changed = true
      }
      if (entry.specifier !== undefined && entry.specifier !== vendorSpec) {
        entry.specifier = vendorSpec
        changed = true
      }
      // Rewrite the matching `packages:` resolution key so frozen install can
      // resolve the vendored tarball (key format: `<name>@<oldVersion>`; scoped
      // names get a leading `/` in pnpm v9 lockfiles — try both variants).
      if (packages !== undefined && oldVersion !== undefined) {
        const oldKey = `${name}@${oldVersion}`
        const newKey = `${name}@${vendorSpec}`
        const candidates = [oldKey, `/${oldKey}`]
        for (const candidate of candidates) {
          if (packages[candidate] !== undefined) {
            const slashStyle = candidate.startsWith('/') ? '/' : ''
            const rewritten = `${slashStyle}${newKey}`
            packages[rewritten] = packages[candidate]
            delete packages[candidate]
            rewrittenKeys[candidate] = rewritten
            changed = true
            break
          }
        }
      }
    }
    if (!changed) return raw
    // Keep the `packages:` map sorted for determinism (YAML stringify would
    // otherwise preserve insertion order of the rewritten keys).
    if (packages !== undefined) {
      const sorted: Record<string, unknown> = {}
      for (const key of Object.keys(packages).sort()) sorted[key] = packages[key]
      lock.packages = sorted
    }
    return stringifyYaml(lock)
  } catch {
    // Unparseable lockfile: pass the original through; frozen install will fail loud.
    return raw
  }
}
