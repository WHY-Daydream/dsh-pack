/**
 * Portable Profile composition snapshot (DESIGN.md §4): uses the official
 * `@deepseek-ai/dsh-app-boot` engine (loadProfile + composeEntries — D5) to
 * compose bundle layers + the profile patch, records every observed layer
 * (including excluded machine-local home / invocation-local --patch), and
 * derives the canonical composition object configHash is computed from.
 * @module @why-daydream/dsh-pack/config-snapshot
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  composeEntries,
  loadOptionalPatches,
  loadProfile,
  PROFILE_PATCH_FILENAME,
} from '@deepseek-ai/dsh-app-boot'
import type { PatchOptions } from '@deepseek-ai/cordis-plugin-include'
import type { LoadedProfile } from './profile-reader.ts'
import { stringifyYaml } from './canonical.ts'

/** One observed layer (DESIGN.md §4.3). */
export interface SnapshotLayer {
  type: 'bundle' | 'profile' | 'home' | 'cli-overlay'
  /** Logical identifier, never a filesystem path. */
  id: string
  included: boolean
  rows: number
  reason?: 'machine-local' | 'invocation-local'
}

/** Portable Profile Scope snapshot (DESIGN.md §4.2/§4.4). */
export interface SnapshotResult {
  layers: SnapshotLayer[]
  /** Whether any excluded layer (home/--patch) was present at pack time. */
  excludedLayersPresent: boolean
  /** Composed rows as plain JSON (bundles + profile patch only). */
  rows: Record<string, unknown>[]
  /** Human-readable effective config. */
  effectiveYaml: string
  /** Canonical composition object — the exact configHash input (§7.3). */
  composition: { rows: Record<string, unknown>[] }
  /** row id → source layer logical id, for secret-source annotation. */
  rowSources: Record<string, string>
}

/** The empty root config every profile tree patches over (official text). */
export const PROFILE_ROOT_CONFIG = `# dsh profile root — an empty entry list. The tree is composed as patches:
# each bundle in package.json's dsh.profile.bundles, then cordis.patch.yml, then any
# --patch overlays. Edit cordis.patch.yml, not this file.
[]
`

/** Collect the entry ids a patch list would insert (for row → layer mapping). */
function insertedIds(patches: readonly PatchOptions[]): string[] {
  const ids: string[] = []
  for (const patch of patches) {
    const insert = (patch as { insert?: { id?: string }[] }).insert
    if (insert !== undefined) {
      for (const row of insert) if (typeof row.id === 'string') ids.push(row.id)
    }
  }
  return ids
}

/**
 * Compose the Portable Profile Scope for `profile`. Layers below the profile
 * layer are bundle layers in `dsh.profile.bundles` order; the home layer and
 * any `--patch` overlays are observed but excluded (D3).
 * @param profile - the loaded profile directory.
 * @param home - the Harness home.
 * @param installAnchor - dsh installation package.json (in-box bundle anchor).
 * @param binName - diagnostic name for app-boot errors.
 */
export function buildSnapshot(
  profile: LoadedProfile,
  home: string,
  installAnchor: string,
  binName = 'dsh-pack',
): SnapshotResult {
  const loaded = loadProfile(binName, profile.name, installAnchor, home)

  const layers: SnapshotLayer[] = []
  const bundlePatchLayers: PatchOptions[][] = []
  const rowSources: Record<string, string> = {}

  for (const layer of loaded.layers) {
    layers.push({ type: 'bundle', id: layer.packageName, included: true, rows: layer.patches.length })
    bundlePatchLayers.push(layer.patches)
    for (const id of insertedIds(layer.patches)) rowSources[id] = `bundle:${layer.packageName}`
  }

  layers.push({ type: 'profile', id: 'profile:cordis.patch.yml', included: true, rows: loaded.patches.length })
  for (const id of insertedIds(loaded.patches)) rowSources[id] = 'profile:cordis.patch.yml'

  let excludedLayersPresent = false
  const homePatchFile = join(home, PROFILE_PATCH_FILENAME)
  const homePatches = loadOptionalPatches(binName, homePatchFile)
  if (homePatches !== undefined) {
    excludedLayersPresent = true
    layers.push({
      type: 'home',
      id: 'home:cordis.patch.yml',
      included: false,
      reason: 'machine-local',
      rows: homePatches.length,
    })
  }

  const rows = composeEntries([...bundlePatchLayers, loaded.patches]) as unknown as Record<string, unknown>[]
  const composition = { rows }
  const effectiveYaml = renderEffective(rows, layers)
  return { layers, excludedLayersPresent, rows, effectiveYaml, composition, rowSources }
}

/** Human-readable effective config with a source-comment header. */
function renderEffective(rows: Record<string, unknown>[], layers: SnapshotLayer[]): string {
  const header = layers
    .map((layer) => `# ${layer.included ? '' : '[excluded] '}${layer.id} (${layer.rows} rows)`)
    .join('\n')
  return `# dsh-pack effective config (Portable Profile Scope)\n${header}\n${stringifyYaml(rows)}`
}

/** Read the raw profile patch text (unchanged bytes go into the pack). */
export function readPatchFile(path: string): string {
  if (!existsSync(path)) return ''
  return readFileSync(path, 'utf8')
}
