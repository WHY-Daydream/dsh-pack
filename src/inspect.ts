/**
 * Inspection (DESIGN.md §8.1 / §8.3): renders a human-readable summary of a
 * `.dshpack` from its manifest and metadata without installing anything.
 * @module @why-daydream/dsh-pack/inspect
 */

import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { collectFiles, extractTarGz } from './pack-builder.ts'
import { validateManifest } from './manifest.ts'
import type { PackInspection, Warning } from './types.ts'

/** Open a `.dshpack` and summarize it. Extraction lands in a caller-cleaned temp dir. */
export async function inspectPack(buffer: Buffer): Promise<PackInspection> {
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-inspect-'))
  try {
    await extractTarGz(buffer, root)
    const files = collectFiles(root)
    const manifestPath = join(root, 'manifest.json')
    if (!existsSync(manifestPath)) {
      throw new Error('dsh-pack: archive has no manifest.json — not a .dshpack')
    }
    const parsed = validateManifest(JSON.parse(readFileSync(manifestPath, 'utf8')))
    if (!parsed.ok) {
      throw new Error(`dsh-pack: invalid manifest: ${parsed.errors.join('; ')}`)
    }
    const warningsPath = join(root, 'metadata/warnings.json')
    const warnings: Warning[] = existsSync(warningsPath)
      ? (JSON.parse(readFileSync(warningsPath, 'utf8')) as { warnings: Warning[] }).warnings ?? []
      : []
    const entries = files.map((path) => ({ path, size: statSync(join(root, path)).size }))
    return { file: '', manifest: parsed.manifest, warnings, entries }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}
