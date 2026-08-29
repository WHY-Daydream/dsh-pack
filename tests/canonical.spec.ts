/**
 * Canonicalization unit tests (DESIGN.md §7.2): hash inputs must be stable,
 * order-independent and machine-independent.
 */
import { describe, expect, it } from 'vitest'
import { canonicalJson, sha256Hex } from '../src/canonical.js'
import { computeContentHash } from '../src/pack-builder.js'

describe('canonicalJson', () => {
  it('sorts object keys recursively', () => {
    expect(canonicalJson({ b: 1, a: { d: 4, c: 3 } })).toBe('{"a":{"c":3,"d":4},"b":1}')
  })

  it('is stable for equal objects', () => {
    expect(canonicalJson({ x: [2, 1], y: 'v' })).toBe(canonicalJson({ y: 'v', x: [2, 1] }))
  })
})

describe('sha256Hex', () => {
  it('matches the empty-string known vector', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })
})

describe('computeContentHash', () => {
  it('is independent of insertion order', () => {
    const a = computeContentHash({ b: 'h1', a: 'h2' })
    const b = computeContentHash({ a: 'h2', b: 'h1' })
    expect(a).toBe(b)
  })

  it('changes when a file hash changes', () => {
    expect(computeContentHash({ a: 'h1' })).not.toBe(computeContentHash({ a: 'h2' }))
  })
})
