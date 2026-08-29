/**
 * Manifest generation, validation, and the frozen configHash algorithm
 * (DESIGN.md §3.3, §7.3). configHash is the **Portable Profile Configuration
 * Hash**: inputs are the canonical composition (bundles + profile patch),
 * ordered bundle identities, and the full dependency closure — never
 * createdAt, paths, home/--patch layers, mtimes, or secret values.
 * @module @why-daydream/dsh-pack/manifest
 */

import type { DependencyTree, Manifest } from './types.ts'
import type { SnapshotResult } from './config-snapshot.ts'
import { canonicalJson, sha256Hex } from './canonical.ts'

export const PACK_FORMAT = 'dshpack'
export const SCHEMA_VERSION = 1
export const CONFIG_HASH_PREFIX = 'sha256:'
const CONFIG_HASH_RE = /^sha256:[0-9a-f]{64}$/

/** One ordered bundle identity used as hash input (§7.3). */
export interface BundleIdentity {
  name: string
  version: string
}

/**
 * Derive bundle identities in `dsh.profile.bundles` order. Versions come from
 * the lockfile closure (fallback: the declared spec). Never machine paths.
 */
export function bundleIdentities(
  bundles: readonly string[],
  depTree: DependencyTree,
): BundleIdentity[] {
  return bundles.map((name) => ({
    name,
    version: depTree.closure[name] ?? depTree.direct[name] ?? 'unknown',
  }))
}

/** The frozen configHash formula (DESIGN.md §7.3). */
export function computeConfigHash(
  composition: { rows: Record<string, unknown>[] },
  identities: readonly BundleIdentity[],
  closure: Record<string, string>,
): string {
  const blob = [
    'dshpack-config-v1\0',
    canonicalJson(composition),
    '\0',
    canonicalJson(identities),
    '\0',
    canonicalJson(closure),
  ].join('')
  return `${CONFIG_HASH_PREFIX}${sha256Hex(blob)}`
}

export interface BuildManifestInput {
  profileName: string
  excludedLayersPresent: boolean
  dshVersion: string
  nodeVersion: string
  pnpmVersion: string
  platform: string
  bundles: string[]
  dependencies: Record<string, string>
  redacted: number
  configHash: string
  installable: boolean
  portable: boolean
  /** v0.2 --portable: vendored tgz file names. */
  packages?: string[]
  packagerVersion: string
  createdAt: string
}

/** Build a schema-v1 manifest (all required fields present). */
export function buildManifest(input: BuildManifestInput): Manifest {
  const manifest: Manifest = {
    format: PACK_FORMAT,
    schemaVersion: SCHEMA_VERSION,
    profile: { name: input.profileName },
    snapshot: { scope: 'profile', excludedLayersPresent: input.excludedLayersPresent },
    runtime: {
      dshVersion: input.dshVersion,
      nodeVersion: input.nodeVersion,
      pnpmVersion: input.pnpmVersion,
      platform: input.platform,
    },
    installable: input.installable,
    portable: input.portable,
    bundles: [...input.bundles],
    dependencies: { ...input.dependencies },
    configHash: input.configHash,
    createdAt: input.createdAt,
    packager: { name: '@why-daydream/dsh-pack', version: input.packagerVersion },
  }
  if (input.redacted > 0) manifest.secrets = { redacted: input.redacted }
  if (input.packages !== undefined && input.packages.length > 0) manifest.packages = [...input.packages]
  return manifest
}

/** Validate an unknown manifest value against schema v1 (§3.4: reject unknown major). */
export function validateManifest(value: unknown): { ok: true; manifest: Manifest } | { ok: false; errors: string[] } {
  const errors: string[] = []
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['manifest is not an object'] }
  const m = value as Record<string, unknown>

  if (m.format !== PACK_FORMAT) errors.push(`format must be "${PACK_FORMAT}"`)
  if (m.schemaVersion !== SCHEMA_VERSION) errors.push(`schemaVersion must be ${SCHEMA_VERSION} (got ${String(m.schemaVersion)})`)

  const profile = m.profile as Record<string, unknown> | undefined
  if (profile === undefined || typeof profile.name !== 'string' || profile.name === '') {
    errors.push('profile.name must be a non-empty string')
  }

  const runtime = m.runtime as Record<string, unknown> | undefined
  for (const key of ['dshVersion', 'nodeVersion', 'pnpmVersion', 'platform']) {
    if (runtime === undefined || typeof runtime[key] !== 'string') errors.push(`runtime.${key} must be a string`)
  }

  const snapshot = m.snapshot as Record<string, unknown> | undefined
  if (snapshot === undefined || snapshot.scope !== 'profile') errors.push('snapshot.scope must be "profile"')
  if (snapshot === undefined || typeof snapshot.excludedLayersPresent !== 'boolean') {
    errors.push('snapshot.excludedLayersPresent must be a boolean')
  }

  if (typeof m.installable !== 'boolean') errors.push('installable must be a boolean')
  if (typeof m.portable !== 'boolean') errors.push('portable must be a boolean')

  if (!Array.isArray(m.bundles) || m.bundles.some((b) => typeof b !== 'string')) {
    errors.push('bundles must be an array of strings')
  }
  const dependencies = m.dependencies as Record<string, unknown> | undefined
  if (dependencies === undefined || Object.entries(dependencies).some(([, v]) => typeof v !== 'string')) {
    errors.push('dependencies must be an object of strings')
  }
  // Optional v0.2 field (schema minor addition, §3.4): vendored tgz list.
  if (m.packages !== undefined && (!Array.isArray(m.packages) || m.packages.some((p) => typeof p !== 'string'))) {
    errors.push('packages must be an array of strings when present')
  }

  if (typeof m.configHash !== 'string' || !CONFIG_HASH_RE.test(m.configHash)) {
    errors.push('configHash must match sha256:<64 hex>')
  }
  if (typeof m.createdAt !== 'string') errors.push('createdAt must be a string')

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, manifest: m as unknown as Manifest }
}
