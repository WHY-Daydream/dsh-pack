/**
 * Secret scanner unit tests (DESIGN.md §6): high-confidence hits are redacted
 * in both the composed rows and the packed profile patch text (D9); low
 * confidence hits only warn.
 */
import { describe, expect, it } from 'vitest'
import { parseYaml, stringifyYaml } from '../src/canonical.js'
import { redactPatchText, scanAndRedact } from '../src/secret-scanner.js'

const PROFILE_PATCH = `# web profile
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        apiKey: sk-1234567890abcdef1234
        temperature: 0.3
- insert:
    - id: timeout-policy
      timeoutMs: 30000
`

/** Composed-row structure (what buildSnapshot produces), not patch ops. */
const ROWS: Record<string, unknown>[] = [
  { id: 'llm-deepseek', provider: 'deepseek', config: { apiKey: 'sk-1234567890abcdef1234', temperature: 0.3 } },
  { id: 'timeout-policy', timeoutMs: 30000 },
]

describe('scanAndRedact', () => {
  it('redacts a high-confidence apiKey to ${VAR} and records the env var', () => {
    const rows = structuredClone(ROWS)
    const result = scanAndRedact(rows, { 'llm-deepseek': 'profile:cordis.patch.yml' })
    expect(result.redacted).toBe(1)
    expect(result.hits[0]?.confidence).toBe('high')
    expect(result.envExample).toContain('LLM_DEEPSEEK_API_KEY=')
    // composed rows no longer contain the plaintext
    expect(stringifyYaml(rows)).not.toContain('sk-1234567890abcdef1234')
    expect(stringifyYaml(rows)).toContain('${LLM_DEEPSEEK_API_KEY}')
  })

  it('treats env-var-named keys as high confidence', () => {
    const rows = [{ id: 'gateway', config: { DEEPSEEK_API_KEY: 'sk-abcdefghijklmnop' } }]
    const result = scanAndRedact(rows, { gateway: 'profile:cordis.patch.yml' })
    expect(result.redacted).toBe(1)
    expect(result.hits[0]?.var).toBe('DEEPSEEK_API_KEY')
  })

  it('keeps low-confidence hits as warnings only', () => {
    const rows = [{ id: 'svc', token: 'abc' }]
    const result = scanAndRedact(rows, { svc: 'profile:cordis.patch.yml' })
    expect(result.redacted).toBe(0)
    expect(result.warnings.some((w) => w.code === 'secret-suspected')).toBe(true)
  })

  it('does not flag ordinary config values', () => {
    const rows = [{ id: 'llm', temperature: 0.3, model: 'deepseek-chat' }]
    const result = scanAndRedact(rows, { llm: 'profile:cordis.patch.yml' })
    expect(result.redacted).toBe(0)
    expect(result.warnings).toHaveLength(0)
  })

  it('redacts values under dot-containing keys (segment-safe traversal, F4)', () => {
    const rows = [{ id: 'gateway', config: { 'auth.apiKey': 'sk-abcdefghijklmnop123' } }]
    const result = scanAndRedact(rows, { gateway: 'profile:cordis.patch.yml' })
    expect(result.redacted).toBe(1)
    expect(rows[0]).toEqual({ id: 'gateway', config: { 'auth.apiKey': '${GATEWAY_AUTH_API_KEY}' } })
    expect(result.envExample).toContain('GATEWAY_AUTH_API_KEY=')
  })
})

describe('redactPatchText', () => {
  it('rewrites profile-layer hits in the packed patch text', () => {
    const scan = scanAndRedact(structuredClone(ROWS), { 'llm-deepseek': 'profile:cordis.patch.yml' })
    const packed = redactPatchText(PROFILE_PATCH, scan.hits)
    expect(packed.redacted).toBe(1)
    expect(packed.text).not.toContain('sk-1234567890abcdef1234')
    expect(packed.text).toContain('${LLM_DEEPSEEK_API_KEY}')
    // non-secret rows survive
    expect(packed.text).toContain('timeoutMs')
  })

  it('leaves text untouched when there are no profile-layer hits', () => {
    const scan = scanAndRedact(structuredClone(ROWS), { 'llm-deepseek': 'bundle:some-bundle' })
    const packed = redactPatchText(PROFILE_PATCH, scan.hits)
    expect(packed.redacted).toBe(0)
    expect(packed.text).toBe(PROFILE_PATCH)
  })

  it('round-trips as valid YAML', () => {
    const scan = scanAndRedact(structuredClone(ROWS), { 'llm-deepseek': 'profile:cordis.patch.yml' })
    const packed = redactPatchText(PROFILE_PATCH, scan.hits)
    expect(parseYaml(packed.text)).toEqual([
      { insert: [{ id: 'llm-deepseek', provider: 'deepseek', config: { apiKey: '${LLM_DEEPSEEK_API_KEY}', temperature: 0.3 } }] },
      { insert: [{ id: 'timeout-policy', timeoutMs: 30000 }] },
    ])
  })
})
