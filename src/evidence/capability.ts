/**
 * v0.5 alpha.4 Declared Capability Manifest (DESIGN-v0.5.0.md §8, D81–D88):
 * a pure artifact-inspection view of what the artifact DECLARES it can do —
 * never what the runtime actually does (D83, observed belongs to beta.1).
 *
 * Static source (research, §8.1): the harness profile schema only declares
 * `dsh.profile.bundles`; providers/services ARE statically discoverable from
 * the composed patch rows (`insert: [{ id, provider, config }]`) inside the
 * artifact; tools/skills are registered by plugin code at RUNTIME, so they are
 * recorded as UNKNOWN + reason (D86/C10) — we never execute plugin code and
 * never guess from names (a tool called `fetch` is not `network=true`).
 *
 * Deterministic canonical bytes (D88), subject bound to the actual artifact
 * contentHash (D82), capability = stable id + kind + declaredBy (D84/D85),
 * and NO allow/deny judgment (D87).
 * @module @why-daydream/dsh-pack/evidence/capability
 */

import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { canonicalJson, parseYaml, sha256Hex } from '../canonical.ts'
import { extractTarGz } from '../pack-builder.ts'

export const CAPABILITY_EVIDENCE_TYPE = 'capability'
export const CAPABILITY_FORMAT = 'dsh-capability'
export const CAPABILITY_SCHEMA_VERSION = 1
/** D86/C10: statically undiscoverable — recorded as a fact, never guessed. */
export const CAPABILITY_UNKNOWN_REASON = 'requires runtime registration (no cold boot, D86)'
const PROFILE_PATCH_LAYER = 'profile:cordis.patch.yml'
const BUNDLE_LAYER = 'bundle'
const CONTENT_HASH_RE = /^sha256:[0-9a-f]{64}$/

/** One declared capability: stable id + kind + traceable source (D84/D85). */
export interface DeclaredCapability {
  /** Stable identity — the composed row id, never a display name. */
  id: string
  kind: 'provider' | 'service'
  declaredBy: { layer: string }
}

/** The frozen declared-capability manifest (DESIGN-v0.5.0.md §8.2). */
export interface CapabilityManifest {
  schemaVersion: 1
  /** D82: bound to the ACTUAL artifact contentHash. */
  subject: { contentHash: string }
  declared: {
    providers: DeclaredCapability[]
    services: DeclaredCapability[]
    /** Statically undiscoverable — always empty here (D83/D86). */
    tools: never[]
    skills: never[]
  }
  /** Why the empty categories are empty (C10) — never a guess. */
  undiscoverable: {
    tools: { reason: string }
    skills: { reason: string }
  }
}

/** Artifact-internal inputs (D74-style: only what the .dshpack contains). */
export interface CapabilityBuildInput {
  /** The artifact anchor computed by the service layer (D82). */
  contentHash: string
  /** Composed rows from `resolved/composition.json`. */
  compositionRows: Record<string, unknown>[]
  /** Packed `profile/cordis.patch.yml` text — id-level layer attribution (D85). */
  profilePatchText?: string
}

/** Deterministic digest over the EXACT document bytes (D88) — C7 anchor. */
export function capabilityDocumentDigest(document: string): string {
  return `sha256:${sha256Hex(document)}`
}

/**
 * Build the declared capability manifest from artifact-internal data.
 * Classification: rows with a `provider` field → provider; other id-bearing
 * rows → service. Layer attribution: id declared by the profile patch →
 * `profile:cordis.patch.yml`, otherwise `bundle` (per-bundle attribution is not
 * in the artifact — recorded as-is, never guessed, D86). Deterministic: sorted
 * by id then layer (D88); identical (id, kind, layer) entries are merged.
 */
export function buildCapabilityManifest(input: CapabilityBuildInput): CapabilityManifest {
  if (!CONTENT_HASH_RE.test(input.contentHash)) {
    throw new Error(`capability manifest subject contentHash must be sha256:<64 hex> (got ${JSON.stringify(input.contentHash)})`)
  }
  const profileIds = new Set(profilePatchIds(input.profilePatchText))
  const providers: DeclaredCapability[] = []
  const services: DeclaredCapability[] = []
  const seen = new Set<string>()
  for (const row of input.compositionRows) {
    const id = typeof row.id === 'string' && row.id !== '' ? row.id : undefined
    if (id === undefined) continue // not an addressable declared instance
    const kind = typeof row.provider === 'string' && row.provider !== ''
      ? 'provider' as const
      : 'service' as const
    const layer = profileIds.has(id) ? PROFILE_PATCH_LAYER : BUNDLE_LAYER
    const key = `${id}\u0000${kind}\u0000${layer}`
    if (seen.has(key)) continue
    seen.add(key)
    const entry: DeclaredCapability = { id, kind, declaredBy: { layer } }
    if (kind === 'provider') providers.push(entry)
    else services.push(entry)
  }
  const byIdThenLayer = (a: DeclaredCapability, b: DeclaredCapability): number =>
    a.id.localeCompare(b.id) || a.declaredBy.layer.localeCompare(b.declaredBy.layer)
  providers.sort(byIdThenLayer)
  services.sort(byIdThenLayer)

  return {
    schemaVersion: CAPABILITY_SCHEMA_VERSION,
    subject: { contentHash: input.contentHash },
    declared: {
      providers,
      services,
      tools: [],
      skills: [],
    },
    undiscoverable: {
      tools: { reason: CAPABILITY_UNKNOWN_REASON },
      skills: { reason: CAPABILITY_UNKNOWN_REASON },
    },
  }
}

/**
 * Generate the deterministic declared capability manifest for a `.dshpack`
 * buffer: extracts the archive and consumes ONLY artifact-internal materials
 * (composed rows + the packed profile patch). Pure inspection — no cold boot.
 */
export async function generateCapabilityManifestFromPack(
  packBuffer: Buffer,
  contentHash: string,
): Promise<{ document: string; digest: string; manifest: CapabilityManifest }> {
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-cap-'))
  try {
    await extractTarGz(packBuffer, root)
    const compositionPath = join(root, 'resolved', 'composition.json')
    if (!existsSync(compositionPath)) {
      throw new Error('dsh-pack: pack has no resolved/composition.json — cannot build capability manifest')
    }
    const composition = JSON.parse(readFileSync(compositionPath, 'utf8')) as { rows?: Record<string, unknown>[] }
    const patchPath = join(root, 'profile', 'cordis.patch.yml')
    const profilePatchText = existsSync(patchPath) ? readFileSync(patchPath, 'utf8') : undefined
    const manifest = buildCapabilityManifest({
      contentHash,
      compositionRows: composition.rows ?? [],
      ...(profilePatchText !== undefined ? { profilePatchText } : {}),
    })
    const document = canonicalJson(manifest)
    return { document, digest: capabilityDocumentDigest(document), manifest }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

/** Ids declared by the packed profile patch (`- insert: [{ id }]` rows). */
function profilePatchIds(patchText: string | undefined): string[] {
  if (patchText === undefined) return []
  try {
    const parsed = parseYaml(patchText)
    if (!Array.isArray(parsed)) return []
    const ids: string[] = []
    for (const patch of parsed) {
      if (patch === null || typeof patch !== 'object') continue
      const insert = (patch as Record<string, unknown>).insert
      if (!Array.isArray(insert)) continue
      for (const row of insert) {
        if (row !== null && typeof row === 'object') {
          const id = (row as Record<string, unknown>).id
          if (typeof id === 'string' && id !== '') ids.push(id)
        }
      }
    }
    return ids
  } catch {
    return []
  }
}
