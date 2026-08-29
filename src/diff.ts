/**
 * Pack diff (DESIGN.md v0.2 `/pack diff`): compares two `.dshpack` archives
 * across four domains — Manifest fields, Bundles (ordered, with locked
 * versions), Config (leaf-level drift inside the composed tree) and
 * Dependencies (direct specs + locked closure versions) — plus the configHash
 * verdict. Both archives are opened with the safe extractor (MUST-4).
 * @module @why-daydream/dsh-pack/diff
 */

import { existsSync, readFileSync, rmSync } from 'node:fs'
import { join } from 'node:path'
import { openPack } from './pack-builder.ts'
import { bundleIdentities, validateManifest } from './manifest.ts'
import type {
  BundleChange, ConfigChange, DependencyChange, DependencyTree, Manifest, ManifestChange, PackDiff,
} from './types.ts'

/** Diff result before the caller stamps the two file paths. */
export type DiffPayload = Omit<PackDiff, 'fileA' | 'fileB'>

/** Diff two `.dshpack` buffers. Extraction roots are cleaned up here. */
export async function diffPacks(bufferA: Buffer, bufferB: Buffer): Promise<DiffPayload> {
  const packA = await openPack(bufferA)
  const packB = await openPack(bufferB)
  try {
    const manifestA = validateManifest(packA.manifest)
    const manifestB = validateManifest(packB.manifest)
    if (!manifestA.ok) throw new Error(`dsh-pack: manifest.json is invalid: ${manifestA.errors.join('; ')}`)
    if (!manifestB.ok) throw new Error(`dsh-pack: manifest.json is invalid: ${manifestB.errors.join('; ')}`)
    const mA = manifestA.manifest
    const mB = manifestB.manifest

    const depTreeA = readDepTree(packA.root)
    const depTreeB = readDepTree(packB.root)

    return {
      manifest: diffManifest(mA, mB),
      bundles: diffBundles(mA.bundles, mB.bundles, depTreeA, depTreeB),
      config: diffConfig(packA.root, packB.root),
      dependencies: diffDependencies(mA.dependencies, mB.dependencies, depTreeA, depTreeB),
      configHashA: mA.configHash,
      configHashB: mB.configHash,
      configHashEqual: mA.configHash === mB.configHash,
    }
  } finally {
    rmSync(packA.root, { recursive: true, force: true })
    rmSync(packB.root, { recursive: true, force: true })
  }
}

/** Compare the reported manifest fields (null-secret = 0 redactions omitted). */
function diffManifest(mA: Manifest, mB: Manifest): ManifestChange[] {
  const changes: ManifestChange[] = []
  const fields: [string, unknown, unknown][] = [
    ['profile.name', mA.profile.name, mB.profile.name],
    ['schemaVersion', mA.schemaVersion, mB.schemaVersion],
    ['installable', mA.installable, mB.installable],
    ['portable', mA.portable, mB.portable],
    ['runtime.dshVersion', mA.runtime.dshVersion, mB.runtime.dshVersion],
    ['runtime.nodeVersion', mA.runtime.nodeVersion, mB.runtime.nodeVersion],
    ['runtime.pnpmVersion', mA.runtime.pnpmVersion, mB.runtime.pnpmVersion],
    ['runtime.platform', mA.runtime.platform, mB.runtime.platform],
    ['secrets.redacted', mA.secrets?.redacted, mB.secrets?.redacted],
    ['createdAt', mA.createdAt, mB.createdAt],
    ['packager.version', mA.packager.version, mB.packager.version],
  ]
  for (const [field, before, after] of fields) {
    if (JSON.stringify(before) !== JSON.stringify(after)) changes.push({ field, before, after })
  }
  return changes
}

/** Compare ordered bundle lists, resolving each side's locked versions. */
function diffBundles(
  bundlesA: readonly string[],
  bundlesB: readonly string[],
  depTreeA: DependencyTree,
  depTreeB: DependencyTree,
): BundleChange[] {
  const changes: BundleChange[] = []
  const byName = new Map<string, { a?: boolean; b?: boolean }>()
  for (const name of bundlesA) byName.set(name, { a: true, ...(byName.get(name) ?? {}) })
  for (const name of bundlesB) byName.set(name, { b: true, ...(byName.get(name) ?? {}) })

  const idA = new Map(bundleIdentities(bundlesA, depTreeA).map((i) => [i.name, i.version]))
  const idB = new Map(bundleIdentities(bundlesB, depTreeB).map((i) => [i.name, i.version]))

  for (const [name, sides] of byName) {
    if (sides.b === undefined) {
      changes.push({ name, kind: 'removed', before: idA.get(name) ?? 'unknown' })
    } else if (sides.a === undefined) {
      changes.push({ name, kind: 'added', after: idB.get(name) ?? 'unknown' })
    } else {
      const before = idA.get(name)
      const after = idB.get(name)
      if (before !== after) {
        const change: BundleChange = { name, kind: 'changed' }
        if (before !== undefined) change.before = before
        if (after !== undefined) change.after = after
        changes.push(change)
      }
    }
  }
  return changes
}

/** Compare the composed trees at leaf granularity (row id + dotted path). */
function diffConfig(rootA: string, rootB: string): ConfigChange[] {
  const leavesA = readCompositionLeaves(rootA)
  const leavesB = readCompositionLeaves(rootB)
  const changes: ConfigChange[] = []
  const paths = new Set([...Object.keys(leavesA), ...Object.keys(leavesB)])
  for (const path of [...paths].sort()) {
    const before = leavesA[path]
    const after = leavesB[path]
    if (before === undefined && after !== undefined) changes.push({ path, kind: 'added', after })
    else if (before !== undefined && after === undefined) changes.push({ path, kind: 'removed', before })
    else if (JSON.stringify(before) !== JSON.stringify(after)) {
      changes.push({ path, kind: 'changed', before, after })
    }
  }
  return changes
}

/** Compare direct specs and locked closure versions. */
function diffDependencies(
  depsA: Record<string, string>,
  depsB: Record<string, string>,
  depTreeA: DependencyTree,
  depTreeB: DependencyTree,
): DependencyChange[] {
  const changes: DependencyChange[] = []
  const names = new Set([
    ...Object.keys(depsA), ...Object.keys(depsB),
    ...Object.keys(depTreeA.closure), ...Object.keys(depTreeB.closure),
  ])
  for (const name of [...names].sort()) {
    const specBefore = depsA[name]
    const specAfter = depsB[name]
    const versionBefore = depTreeA.closure[name]
    const versionAfter = depTreeB.closure[name]
    if (specBefore === specAfter && versionBefore === versionAfter) continue
    const change: DependencyChange = { name }
    if (specBefore !== specAfter) {
      if (specBefore !== undefined) change.specBefore = specBefore
      if (specAfter !== undefined) change.specAfter = specAfter
    }
    if (versionBefore !== versionAfter) {
      if (versionBefore !== undefined) change.versionBefore = versionBefore
      if (versionAfter !== undefined) change.versionAfter = versionAfter
    }
    changes.push(change)
  }
  return changes
}

/** Read `resolved/dependency-tree.json` from an extracted pack root. */
function readDepTree(root: string): DependencyTree {
  const path = join(root, 'resolved/dependency-tree.json')
  if (!existsSync(path)) throw new Error(`dsh-pack: ${path} missing — not a complete .dshpack`)
  return JSON.parse(readFileSync(path, 'utf8')) as DependencyTree
}

/** Flatten `resolved/composition.json` rows into a path → leaf map. */
function readCompositionLeaves(root: string): Record<string, unknown> {
  const path = join(root, 'resolved/composition.json')
  if (!existsSync(path)) throw new Error(`dsh-pack: ${path} missing — not a complete .dshpack`)
  const composition = JSON.parse(readFileSync(path, 'utf8')) as { rows?: Record<string, unknown>[] }
  const leaves: Record<string, unknown> = {}
  for (const row of composition.rows ?? []) {
    const rowId = typeof row.id === 'string' ? row.id : '?'
    walkLeaves(row, rowId, (leafPath, value) => { leaves[leafPath] = value })
  }
  return leaves
}

type LeafVisitor = (path: string, value: unknown) => void

/** Depth-first leaf walk building a dotted path (display only). */
function walkLeaves(value: unknown, path: string, visit: LeafVisitor): void {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) walkLeaves(value[i], `${path}.${i}`, visit)
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) walkLeaves(v, `${path}.${k}`, visit)
    return
  }
  visit(path, value)
}
