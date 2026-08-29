/**
 * v0.4.2 trust policy engine (DESIGN-v0.4.2.md §11, D50–D56): the LOCAL
 * Remote Image Execution Policy at `$DSH_HOME/trust.yaml`. This engine only
 * RESOLVES policy — repository pattern match (D51), most-specific wins (D52),
 * no-match → v0.4.1 semantics (D53), CLI can only tighten (D54). Signature /
 * trust VERIFICATION stays in the existing v0.3/v0.4 machinery (trust.ts +
 * verify.ts); the policy's trustedKeys are keyId fingerprints (D55) consumed
 * there. The policy is host/environment policy, never artifact policy (D50).
 * @module @why-daydream/dsh-pack/image/trust-policy
 */

import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import YAML from 'yaml'

export const TRUST_POLICY_VERSION = 1
export const TRUST_POLICY_FILE = 'trust.yaml'

/** One repository-pattern rule (DESIGN-v0.4.2.md §11 schema). */
export interface TrustPolicyRule {
  requireSignature?: boolean
  requireTrusted?: boolean
  /** keyId fingerprints (`SHA256:<64 hex>`) — the ONLY trusted identity (D55). */
  trustedKeys?: string[]
}

export interface TrustPolicyFile {
  version: 1
  /** key = remote repository pattern, e.g. `ghcr.io/company/prod-*` (D51). */
  registries: Record<string, TrustPolicyRule>
}

/** The resolved decision for one remote repository. */
export interface TrustPolicyDecision {
  requireSignature: boolean
  requireTrusted: boolean
  trustedKeys?: string[]
  /** the matched pattern (most-specific, D52); undefined when nothing matched. */
  matchedRule?: string
}

/** Load `$DSH_HOME/trust.yaml`; missing file → undefined (D53). */
export function loadTrustPolicy(home: string): TrustPolicyFile | undefined {
  const file = join(home, TRUST_POLICY_FILE)
  if (!existsSync(file)) return undefined
  let parsed: unknown
  try {
    parsed = YAML.parse(readFileSync(file, 'utf8'))
  } catch {
    throw new Error(`invalid trust.yaml: not parseable YAML`)
  }
  const result = validateTrustPolicy(parsed)
  if (!result.ok) throw new Error(`invalid trust.yaml: ${result.errors.join('; ')}`)
  return result.policy
}

/** Validate an unknown value as the frozen trust.yaml schema. */
export function validateTrustPolicy(
  value: unknown,
): { ok: true; policy: TrustPolicyFile } | { ok: false; errors: string[] } {
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['trust.yaml is not an object'] }
  const v = value as Record<string, unknown>
  const errors: string[] = []

  if (v.version !== TRUST_POLICY_VERSION) errors.push(`version must be ${TRUST_POLICY_VERSION}`)
  if (v.registries === null || typeof v.registries !== 'object') {
    errors.push('registries must be an object')
  } else {
    for (const [pattern, rawRule] of Object.entries(v.registries as Record<string, unknown>)) {
      const rule = rawRule as Record<string, unknown> | undefined
      if (rule === null || typeof rule !== 'object') {
        errors.push(`rule ${JSON.stringify(pattern)} must be an object`)
        continue
      }
      if (rule.requireSignature !== undefined && typeof rule.requireSignature !== 'boolean') {
        errors.push(`rule ${JSON.stringify(pattern)}: requireSignature must be boolean`)
      }
      if (rule.requireTrusted !== undefined && typeof rule.requireTrusted !== 'boolean') {
        errors.push(`rule ${JSON.stringify(pattern)}: requireTrusted must be boolean`)
      }
      if (rule.trustedKeys !== undefined) {
        if (!Array.isArray(rule.trustedKeys) || rule.trustedKeys.some((k) => typeof k !== 'string')) {
          errors.push(`rule ${JSON.stringify(pattern)}: trustedKeys must be an array of strings`)
        }
      }
    }
  }

  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, policy: value as unknown as TrustPolicyFile }
}

/** Glob: `*` matches ANY sequence (including `/`); the pattern must match the WHOLE repository. */
export function patternMatches(pattern: string, repository: string): boolean {
  const regex = new RegExp(`^${escapeRegExp(pattern).replaceAll('\\*', '.*')}$`)
  return regex.test(repository)
}

function escapeRegExp(input: string): string {
  // escape every regex metachar INCLUDING '*' — the wildcard is restored by
  // replaceAll('\\*', '.*') afterwards (a bare '*' would act as a quantifier)
  return input.replace(/[.+?^${}()|[\]\\*]/g, '\\$&')
}

/**
 * D52: most-specific-match wins — the LONGEST matching pattern; ties break by
 * lexicographic pattern order (deterministic, independent of file line order).
 * D53: no match → the v0.4.1 permissive defaults.
 */
export function resolveTrustPolicy(
  policy: TrustPolicyFile | undefined,
  remoteRepository: string,
): TrustPolicyDecision {
  if (policy === undefined) return { requireSignature: false, requireTrusted: false }
  const matches: { pattern: string; rule: TrustPolicyRule }[] = []
  for (const [pattern, rule] of Object.entries(policy.registries)) {
    if (patternMatches(pattern, remoteRepository)) matches.push({ pattern, rule })
  }
  if (matches.length === 0) return { requireSignature: false, requireTrusted: false } // D53

  matches.sort((a, b) => b.pattern.length - a.pattern.length || a.pattern.localeCompare(b.pattern))
  const best = matches[0]!.rule
  return {
    requireSignature: best.requireSignature === true,
    requireTrusted: best.requireTrusted === true,
    ...(best.trustedKeys !== undefined && best.trustedKeys.length > 0 ? { trustedKeys: [...best.trustedKeys] } : {}),
    matchedRule: matches[0]!.pattern,
  }
}

/**
 * D54: CLI can only TIGHTEN policy — the effective decision is
 * `policy OR CLI`; a CLI `false` is ignored and can never weaken an
 * administrator-set requirement.
 */
export function mergeCliTightening(
  decision: TrustPolicyDecision,
  cli: { requireSignature?: boolean; requireTrusted?: boolean },
): TrustPolicyDecision {
  return {
    requireSignature: decision.requireSignature || cli.requireSignature === true,
    requireTrusted: decision.requireTrusted || cli.requireTrusted === true,
    ...(decision.trustedKeys !== undefined ? { trustedKeys: [...decision.trustedKeys] } : {}),
    ...(decision.matchedRule !== undefined ? { matchedRule: decision.matchedRule } : {}),
  }
}
