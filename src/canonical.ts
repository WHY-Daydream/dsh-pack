/**
 * Canonicalization primitives (DESIGN.md §7.2): stable JSON, sha256, and
 * deterministic YAML rendering. Every hash in dsh-pack flows through here so
 * identical inputs always produce identical bytes.
 * @module @why-daydream/dsh-pack/canonical
 */

import { createHash } from 'node:crypto'
import YAML from 'yaml'

/** sha256 hex digest of a string or buffer. */
export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex')
}

/**
 * Stable compact JSON: object keys sorted recursively, no trailing whitespace.
 * This is the ONLY serialization used as hash input.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value))
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue)
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) out[key] = sortValue(record[key])
    return out
  }
  return value
}

/** Pretty JSON with sorted keys (for files inside the pack). */
export function prettyJson(value: unknown): string {
  return `${JSON.stringify(sortValue(value), null, 2)}\n`
}

/** Parse YAML text. */
export function parseYaml(text: string): unknown {
  return YAML.parse(text)
}

/** Deterministic human-readable YAML (sorted map keys, no line folding). */
export function stringifyYaml(value: unknown): string {
  return YAML.stringify(value, { sortMapEntries: true, lineWidth: 0 })
}

/** Current UTC timestamp in the manifest's ISO 8601 format. */
export function utcNowIso(): string {
  return new Date().toISOString()
}

/** `YYYYMMDD` for the pack file name. */
export function todayStamp(): string {
  return new Date().toISOString().slice(0, 10).replaceAll('-', '')
}
