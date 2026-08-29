/**
 * Verify pipeline (DESIGN.md §7.5): recomputes checksums, contentHash and the
 * Portable configHash from packed sources, validates the manifest schema, and
 * checks the exact DSH runtime version (D15). Every section is FAIL/WARN/ok.
 * @module @why-daydream/dsh-pack/verify
 */

import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { computeContentHash, extractTarGz } from './pack-builder.ts'
import { bundleIdentities, computeConfigHash, validateManifest } from './manifest.ts'
import { sha256Hex } from './canonical.ts'
import type { DependencyTree, Manifest, VerificationReport, VerificationSection } from './types.ts'

export interface VerifyContext {
  /** The installed dsh version (for the DSH Version section). */
  installedDshVersion: string
  /** Skip the exact runtime version match (D15). */
  ignoreRuntimeVersion?: boolean
}

export interface VerifyOutcome {
  report: VerificationReport
  /** Temp extraction root — caller must clean up (rmSync recursive). */
  root: string
}

/**
 * Verify a `.dshpack` buffer. Extraction is safe (MUST-4) and lands in a temp
 * dir the caller must clean up.
 */
export async function verifyPack(buffer: Buffer, context: VerifyContext): Promise<VerifyOutcome> {
  const sections: VerificationSection[] = []
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-verify-'))
  const fail = (name: string, detail: string): void => {
    sections.push({ name, status: 'fail', detail })
  }
  const ok = (name: string, detail?: string): void => {
    sections.push(detail === undefined ? { name, status: 'ok' } : { name, status: 'ok', detail })
  }

  // --- extract (safe) ---
  try {
    await extractTarGz(buffer, root)
  } catch (error) {
    fail('Archive', `cannot extract: ${String(error)}`)
    return { report: { ok: false, sections }, root }
  }

  // --- manifest schema ---
  const manifestPath = join(root, 'manifest.json')
  if (!existsSync(manifestPath)) {
    fail('Manifest', 'manifest.json missing')
    return { report: { ok: false, sections }, root }
  }
  const parsed = validateManifest(JSON.parse(readFileSync(manifestPath, 'utf8')))
  if (!parsed.ok) {
    fail('Manifest', parsed.errors.join('; '))
    return { report: { ok: false, sections }, root }
  }
  ok('Manifest', `format=dshpack schemaVersion=${parsed.manifest.schemaVersion}`)

  // --- checksums ---
  const checksumsPath = join(root, 'metadata/checksums.json')
  const warningsPath = join(root, 'metadata/warnings.json')
  if (!existsSync(checksumsPath) || !existsSync(warningsPath)) {
    fail('Checksums', 'metadata/checksums.json or metadata/warnings.json missing')
  } else {
    const checksums = JSON.parse(readFileSync(checksumsPath, 'utf8')) as {
      contentHash?: string
      files?: Record<string, string>
    }
    const mismatch: string[] = []
    for (const [path, expected] of Object.entries(checksums.files ?? {})) {
      const actualFile = join(root, path)
      if (!existsSync(actualFile)) {
        mismatch.push(`${path}: missing`)
        continue
      }
      const actual = sha256Hex(readFileSync(actualFile))
      if (actual !== expected) mismatch.push(`${path}: checksum mismatch`)
    }
    const recomputed = computeContentHash(checksums.files ?? {})
    if (recomputed !== checksums.contentHash) mismatch.push('contentHash mismatch')
    if (mismatch.length > 0) fail('Checksums', mismatch.join('; '))
    else ok('Checksums', `${Object.keys(checksums.files ?? {}).length} files, contentHash verified`)

    // --- configHash (recompute from packed sources) ---
    const config = verifyConfigHash(root, parsed.manifest)
    if (config.ok) ok('Config', `configHash ${parsed.manifest.configHash}`)
    else fail('Config', config.error)

    // --- packages (v0.2 --portable: vendored tgzs; per-file integrity is
    // already covered by the Checksums section) ---
    const packagesDir = join(root, 'packages')
    if (existsSync(packagesDir)) {
      const expected = parsed.manifest.packages ?? []
      const actual = readdirSync(packagesDir).filter((f) => f.endsWith('.tgz')).sort()
      const missing = expected.filter((f) => !existsSync(join(packagesDir, f)))
      if (missing.length > 0) {
        fail('Packages', `missing vendored tgz: ${missing.join(', ')}`)
      } else if (JSON.stringify(actual) !== JSON.stringify([...expected].sort())) {
        fail('Packages', `packages/ contents do not match manifest.packages (${actual.join(', ')})`)
      } else {
        ok('Packages', `${actual.length} vendored packages, integrity covered by checksums`)
      }
    } else if ((parsed.manifest.packages ?? []).length > 0) {
      fail('Packages', 'manifest.packages set but packages/ directory is missing')
    } else {
      ok('Packages', 'no vendored packages (light pack)')
    }

    // --- DSH version (exact match, D15) ---
    if (context.ignoreRuntimeVersion) {
      sections.push({
        name: 'DSH Version',
        status: 'warn',
        detail: `skipped (--ignore-runtime-version); pack built for dsh ${parsed.manifest.runtime.dshVersion}`,
      })
    } else if (parsed.manifest.runtime.dshVersion !== context.installedDshVersion) {
      fail('DSH Version', `pack built for dsh ${parsed.manifest.runtime.dshVersion}, installed is ${context.installedDshVersion}`)
    } else {
      ok('DSH Version', `dsh ${parsed.manifest.runtime.dshVersion} exact match`)
    }
  }

  const failed = sections.some((section) => section.status === 'fail')
  return { report: { ok: !failed, sections }, root }
}

function verifyConfigHash(root: string, manifest: Manifest): { ok: true } | { ok: false; error: string } {
  const compositionPath = join(root, 'resolved/composition.json')
  const depTreePath = join(root, 'resolved/dependency-tree.json')
  if (!existsSync(compositionPath) || !existsSync(depTreePath)) {
    return { ok: false, error: 'resolved/composition.json or resolved/dependency-tree.json missing' }
  }
  const composition = JSON.parse(readFileSync(compositionPath, 'utf8')) as { rows: Record<string, unknown>[] }
  const depTree = JSON.parse(readFileSync(depTreePath, 'utf8')) as DependencyTree
  const identities = bundleIdentities(manifest.bundles, depTree)
  const recomputed = computeConfigHash(composition, identities, depTree.closure)
  if (recomputed !== manifest.configHash) {
    return { ok: false, error: `configHash mismatch: manifest=${manifest.configHash} recomputed=${recomputed}` }
  }
  return { ok: true }
}
