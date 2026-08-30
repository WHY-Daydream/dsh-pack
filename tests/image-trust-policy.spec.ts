/**
 * v0.4.2 trust-policy engine unit tests (DESIGN-v0.4.2.md §11, D51–D55):
 * repository pattern matching, most-specific-match wins, CLI can only tighten,
 * schema validation, and the policy-level trustedKeys fingerprint check.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { VerificationSection } from '../src/types.js'
import { applyTrustPolicy } from '../src/image/trust.js'
import {
  TRUST_POLICY_FILE, loadTrustPolicy, mergeCliTightening, patternMatches, resolveTrustPolicy, validateTrustPolicy,
} from '../src/image/trust-policy.js'

const FP_A = 'a'.repeat(64)
const FP_B = 'b'.repeat(64)
const tempDirs: string[] = []
function tempRoot(): string {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-pack-trust-'))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('patternMatches (D51)', () => {
  it('`*` crosses segments and must match the WHOLE repository', () => {
    expect(patternMatches('ghcr.io/company/*', 'ghcr.io/company/prod-agent')).toBe(true)
    expect(patternMatches('ghcr.io/*', 'ghcr.io/company/prod-agent')).toBe(true)
    expect(patternMatches('localhost:5000/*', 'localhost:5000/dev/foo')).toBe(true)
    expect(patternMatches('ghcr.io/company/prod-*', 'ghcr.io/company/prod-agent')).toBe(true)
    expect(patternMatches('ghcr.io/company/prod-*', 'ghcr.io/company/dev-agent')).toBe(false)
    expect(patternMatches('ghcr.io/company/*', 'other.io/company/x')).toBe(false)
    expect(patternMatches('ghcr.io/*', 'other.io/company/x')).toBe(false)
  })
})

describe('resolveTrustPolicy (D52/D53)', () => {
  it('no policy file / no matching rule → permissive v0.4.1 defaults', () => {
    expect(resolveTrustPolicy(undefined, 'ghcr.io/x/y')).toEqual({ requireSignature: false, requireTrusted: false })
    const policy = { version: 1 as const, registries: { 'ghcr.io/company/*': { requireSignature: true } } }
    expect(resolveTrustPolicy(policy, 'ghcr.io/other/x')).toEqual({ requireSignature: false, requireTrusted: false })
  })

  it('most-specific-match wins (longest pattern; lexicographic tiebreak, order-independent)', () => {
    const policy = {
      version: 1 as const,
      registries: {
        'ghcr.io/*': { requireSignature: false },
        'ghcr.io/company/*': { requireSignature: true },
        'ghcr.io/company/prod-*': { requireTrusted: true, trustedKeys: [`SHA256:${FP_A}`] },
      },
    }
    const decision = resolveTrustPolicy(policy, 'ghcr.io/company/prod-agent')
    expect(decision.matchedRule).toBe('ghcr.io/company/prod-*')
    expect(decision.requireTrusted).toBe(true)
    expect(decision.requireSignature).toBe(false) // the most-specific rule doesn't set it
    expect(decision.trustedKeys).toEqual([`SHA256:${FP_A}`])
  })
})

describe('mergeCliTightening (D54)', () => {
  it('CLI can only TIGHTEN, never weaken', () => {
    // policy false + CLI true → effective true
    const tightened = mergeCliTightening({ requireSignature: false, requireTrusted: false }, { requireSignature: true })
    expect(tightened.requireSignature).toBe(true)
    expect(tightened.requireTrusted).toBe(false)
    // policy true + CLI false → CLI false IGNORED (still true)
    const base = { requireSignature: false, requireTrusted: true, trustedKeys: [`SHA256:${FP_A}`] }
    expect(mergeCliTightening(base, { requireTrusted: false }).requireTrusted).toBe(true)
    expect(mergeCliTightening(base, {}).trustedKeys).toEqual([`SHA256:${FP_A}`])
  })
})

describe('validateTrustPolicy / loadTrustPolicy', () => {
  it('validates the frozen schema', () => {
    expect(validateTrustPolicy({
      version: 1, registries: { 'x/*': { requireSignature: true, trustedKeys: [`SHA256:${FP_A}`] } },
    }).ok).toBe(true)
    expect(validateTrustPolicy({ version: 2, registries: {} }).ok).toBe(false)
    expect(validateTrustPolicy({ version: 1, registries: { 'x/*': { requireSignature: 'yes' } } }).ok).toBe(false)
    expect(validateTrustPolicy({ version: 1, registries: { 'x/*': { trustedKeys: 'nope' } } }).ok).toBe(false)
    expect(validateTrustPolicy({ version: 1, registries: 'nope' }).ok).toBe(false)
  })

  it('loads $DSH_HOME/trust.yaml; missing → undefined; broken → loud FAIL', () => {
    const root = tempRoot()
    expect(loadTrustPolicy(root)).toBeUndefined() // D53
    writeFileSync(join(root, TRUST_POLICY_FILE), 'version: 1\nregistries:\n  "x/*":\n    requireSignature: true\n')
    expect(loadTrustPolicy(root)?.registries['x/*']).toEqual({ requireSignature: true })
    writeFileSync(join(root, TRUST_POLICY_FILE), 'version: 99\nregistries: {}\n')
    expect(() => loadTrustPolicy(root)).toThrow(/version/)
    writeFileSync(join(root, TRUST_POLICY_FILE), 'version: [broken\n')
    expect(() => loadTrustPolicy(root)).toThrow(/not parseable/)
  })
})

describe('applyTrustPolicy trustedKeys (D55, fingerprint NOT signer label)', () => {
  const section = (status: VerificationSection['status'], detail = ''): VerificationSection =>
    ({ name: 'Signature', status, detail })
  const detailWithFp = `VALID (ed25519, Key SHA256:${FP_A}, Trust: N/A (no whitelist))`

  it('fingerprint in policy keys → VERIFIED even without the env whitelist', () => {
    const verdict = applyTrustPolicy(section('ok', detailWithFp), {
      requireTrusted: true, trustedKeys: [`SHA256:${FP_A}`],
    })
    expect(verdict.ok).toBe(true)
    expect(verdict.trust).toBe('VERIFIED')
  })

  it('fingerprint NOT in policy keys → UNTRUSTED (signer label is irrelevant)', () => {
    const verdict = applyTrustPolicy(section('ok', detailWithFp), {
      requireTrusted: true, trustedKeys: [`SHA256:${FP_B}`],
    })
    expect(verdict.ok).toBe(false)
    expect(verdict.trust).toBe('UNTRUSTED')
  })

  it('no fingerprint in the detail → not trusted', () => {
    const verdict = applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: N/A)'), {
      requireTrusted: true, trustedKeys: [`SHA256:${FP_A}`],
    })
    expect(verdict.ok).toBe(false)
    expect(verdict.trust).toBe('UNTRUSTED')
  })
})
