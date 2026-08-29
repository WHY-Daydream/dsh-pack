/**
 * Secret detection and redaction (DESIGN.md §6): scans the composed tree
 * (final values — a secret may enter from any layer), redacts high-confidence
 * hits to `${VAR}` placeholders, and generates `env/.env.example`. Low
 * confidence hits only warn; install never restores secrets.
 * @module @why-daydream/dsh-pack/secret-scanner
 */

import type { Warning } from './types.ts'
import type { SnapshotLayer } from './config-snapshot.ts'
import { parseYaml, stringifyYaml } from './canonical.ts'

/** High-confidence key-name signals. */
const KEY_PATTERN = /(api[_-]?key|access[_-]?key|private[_-]?key|token|secret|passwd|password|authorization|cookie|credential)/i

/** High-confidence value signals. */
const VALUE_PATTERNS: RegExp[] = [
  /^sk-[A-Za-z0-9_-]{8,}$/, // OpenAI-style
  /^ghp_[A-Za-z0-9]{20,}$/, // GitHub PAT
  /^xox[baprs]-[A-Za-z0-9-]{10,}$/, // Slack
  /^AKIA[0-9A-Z]{16}$/, // AWS access key id
  /^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\./, // JWT
]

/** Known sensitive env-var prefixes (value or key signals). */
const ENV_PREFIX_PATTERN = /^(DEEPSEEK|OPENAI|ANTHROPIC|GEMINI|DATABASE|AWS|AZURE|GOOGLE|GITHUB|SLACK|STRIPE|TWILIO)_/i
const KNOWN_ENV_SUFFIX = ['API_KEY', 'ACCESS_TOKEN', 'SECRET', 'SECRET_KEY', 'PASSWORD', 'TOKEN', 'PRIVATE_KEY']

/** One detected secret. */
export interface SecretHit {
  /** Row + field path for display, e.g. `llm-deepseek.config.apiKey`. */
  path: string
  /** Exact traversal segments (dot-safe), e.g. `['llm-deepseek','config','apiKey']`. */
  segments: string[]
  /** Redacted environment variable name, e.g. `LLM_DEEPSEEK_API_KEY`. */
  var: string
  confidence: 'high' | 'low'
  /** Source layer logical id when known (from rowSources). */
  source?: string
}

export interface ScanResult {
  hits: SecretHit[]
  /** High-confidence hits that were redacted. */
  redacted: number
  /** `env/.env.example` content (empty when nothing was redacted). */
  envExample: string
  warnings: Warning[]
}

/** Derive an env var name from a field key (camelCase-aware). */
export function envVarFor(key: string): string {
  const camel = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2')
  const base = camel.replace(/[^A-Za-z0-9]+/g, '_').replace(/^_+|_+$/g, '').toUpperCase()
  return base === '' ? 'SECRET_VALUE' : base
}

function isEnvNameMatch(key: string, value: string): string | undefined {
  const upper = key.toUpperCase()
  if (ENV_PREFIX_PATTERN.test(upper)) {
    const suffix = upper.split('_').slice(1).join('_')
    if (KNOWN_ENV_SUFFIX.includes(suffix)) return upper
  }
  if (KNOWN_ENV_SUFFIX.includes(upper)) return upper
  if (/^\$\{[A-Z][A-Z0-9_]*\}$/.test(value.trim())) {
    // Reference-style value: keep the referenced var as the redaction target.
    return value.trim().slice(2, -1)
  }
  return undefined
}

function detect(segments: string[], key: string, value: unknown, rowId: string): SecretHit | undefined {
  const path = segments.join('.')
  if (typeof value !== 'string') return undefined
  const trimmed = value.trim()
  if (trimmed === '') return undefined

  const envName = isEnvNameMatch(key, trimmed)
  const keyMatch = KEY_PATTERN.test(key)
  const valueMatch = VALUE_PATTERNS.some((pattern) => pattern.test(trimmed))
  // Credential-shaped: a known value pattern, or 16+ chars of token material.
  const credentialShaped = valueMatch
    || (trimmed.length >= 16 && trimmed.length <= 512 && /[A-Za-z0-9_-]{16,}/.test(trimmed))

  if (envName !== undefined && credentialShaped) {
    return { path, segments, var: envName, confidence: 'high' }
  }
  if (keyMatch) {
    // Sensitive key name: high only when the value looks credential-shaped,
    // otherwise low-confidence (no false-positive redaction).
    return { path, segments, var: envVarFor(`${rowId}_${key}`), confidence: credentialShaped ? 'high' : 'low' }
  }
  return undefined
}

/**
 * Walk the composed rows and redact high-confidence hits in place.
 * @param rows - the composed Portable Profile Scope rows (mutated).
 * @param rowSources - row id → source layer (for annotation).
 */
export function scanAndRedact(
  rows: Record<string, unknown>[],
  rowSources: Record<string, string>,
): ScanResult {
  const hits: SecretHit[] = []
  const warnings: Warning[] = []

  for (const row of rows) {
    const rowId = typeof row.id === 'string' ? row.id : '?'
    const source = rowSources[rowId]
    walk(row, `${rowId}`, [rowId], (path, segments, key, value) => {
      const hit = detect(segments, key, value, rowId)
      if (hit === undefined) return
      if (source !== undefined) hit.source = source
      hits.push(hit)
    })
  }

  const high = hits.filter((hit) => hit.confidence === 'high')
  const redacted = high.length

  const envLines: string[] = ['# dsh-pack redacted secrets — set these before starting the restored profile.', '']
  for (const hit of high) {
    const comment = `# ${hit.path}${hit.source !== undefined ? ` (source: ${hit.source})` : ''}`
    envLines.push(comment, `${hit.var}=`, '')
    // Redact the value in place using the exact traversal segments.
    redactAt(rows, hit.segments, `\${${hit.var}}`)
  }
  for (const hit of hits.filter((h) => h.confidence === 'low')) {
    warnings.push({ code: 'secret-suspected', message: `${hit.path}: low-confidence secret-like value (not redacted)` })
  }

  return {
    hits,
    redacted,
    envExample: redacted > 0 ? `${envLines.join('\n')}` : '',
    warnings,
  }
}

type Visitor = (path: string, segments: string[], key: string, value: unknown) => void

/** Depth-first walk over a row's fields, invoking the visitor for every leaf value. */
function walk(value: unknown, path: string, segments: string[], visit: Visitor, key = ''): void {
  if (Array.isArray(value)) {
    for (let i = 0; i < value.length; i++) walk(value[i], `${path}.${i}`, [...segments, String(i)], visit, key)
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walk(v, `${path}.${k}`, [...segments, k], visit, k)
    }
    return
  }
  visit(path, segments, key, value)
}

/** Replace the leaf value at the given traversal segments inside the rows. */
function redactAt(rows: Record<string, unknown>[], segments: readonly string[], replacement: string): void {
  const rowId = segments[0]
  if (rowId === undefined) return
  const row = rows.find((candidate) => candidate.id === rowId)
  if (row === undefined) return
  let current: unknown = row
  for (let i = 1; i < segments.length - 1; i++) {
    const segment = segments[i]
    if (segment === undefined) return
    if (current !== null && typeof current === 'object') {
      current = (current as Record<string, unknown>)[segment]
    } else {
      return
    }
  }
  const last = segments[segments.length - 1]
  if (last === undefined) return
  if (current !== null && typeof current === 'object') {
    (current as Record<string, unknown>)[last] = replacement
  }
}

/**
 * Redact profile-layer hits inside the packed `cordis.patch.yml` text (D9):
 * the composed-tree redaction alone would still ship the plaintext secret in
 * the archive, so every profile-layer hit is also rewritten in the packed
 * patch bytes. Bundle-layer hits cannot be rewritten (bundle patches are not
 * packed) and surface as warnings instead.
 * @returns the patched text plus how many values were rewritten.
 */
export function redactPatchText(patchText: string, hits: readonly SecretHit[]): { text: string; redacted: number } {
  const profileHits = hits.filter((hit) => hit.source === 'profile:cordis.patch.yml')
  if (profileHits.length === 0) return { text: patchText, redacted: 0 }
  let ops: unknown
  try {
    ops = parseYaml(patchText)
  } catch {
    return { text: patchText, redacted: 0 }
  }
  if (!Array.isArray(ops)) return { text: patchText, redacted: 0 }
  let redacted = 0
  for (const hit of profileHits) {
    const rowId = hit.segments[0]
    if (rowId === undefined) continue
    const row = findInsertRow(ops, rowId)
    if (row !== undefined && setAt(row, hit.segments.slice(1), `\${${hit.var}}`)) redacted++
  }
  return { text: stringifyYaml(ops), redacted }
}

/** Find the insert row with the given id inside a patch-list. */
function findInsertRow(ops: unknown[], rowId: string): Record<string, unknown> | undefined {
  for (const op of ops) {
    const insert = (op as { insert?: unknown }).insert
    if (Array.isArray(insert)) {
      const row = insert.find((candidate) => (candidate as { id?: unknown }).id === rowId)
      if (row !== undefined && typeof row === 'object') return row as Record<string, unknown>
    }
  }
  return undefined
}

/** Set a leaf value along segments inside an object; reports whether it changed. */
function setAt(target: Record<string, unknown>, segments: string[], value: string): boolean {
  let current: unknown = target
  for (let i = 0; i < segments.length - 1; i++) {
    const segment = segments[i]
    if (segment === undefined) return false
    if (current !== null && typeof current === 'object') {
      current = (current as Record<string, unknown>)[segment]
    } else {
      return false
    }
  }
  const last = segments[segments.length - 1]
  if (last === undefined || current === null || typeof current !== 'object') return false
  const before = (current as Record<string, unknown>)[last]
  if (typeof before === 'string' && before !== value) {
    (current as Record<string, unknown>)[last] = value
    return true
  }
  return false
}
