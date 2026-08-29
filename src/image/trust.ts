/**
 * v0.4 trust bridge (DESIGN-v0.4.md §11, D29): applies the run-time trust
 * policy ON TOP of the v0.3 Signature verify section — no re-implementation
 * of verification. VALID ≠ TRUSTED (D19) is preserved: the section status
 * proves the signature, the `Trust:` marker in its detail reflects the keyId
 * whitelist (`DSH_PACK_TRUSTED_KEYS`, SHA256: prefix normalized upstream).
 * @module @why-daydream/dsh-pack/image/trust
 */

import type { VerificationSection } from '../types.ts'

export interface TrustPolicy {
  /** unsigned/invalid signature → FAIL (v0.4.0: `--require-signature`). */
  requireSignature?: boolean
  /** signer fingerprint not in the whitelist → FAIL (`--require-trusted`). */
  requireTrusted?: boolean
}

export interface TrustVerdict {
  ok: boolean
  signature: 'VALID' | 'INVALID' | 'MISSING'
  trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A'
  error?: string
}

/** Apply the trust policy to a v0.3 Signature section (pure, testable). */
export function applyTrustPolicy(
  signature: VerificationSection | undefined,
  policy: TrustPolicy,
): TrustVerdict {
  const detail = String(signature?.detail ?? '')

  let signatureState: TrustVerdict['signature']
  if (signature === undefined || signature.status === 'warn') signatureState = 'MISSING'
  else if (signature.status === 'fail') signatureState = 'INVALID'
  else signatureState = 'VALID'

  let trust: TrustVerdict['trust'] = 'N/A'
  if (detail.includes('Trust: VERIFIED')) trust = 'VERIFIED'
  else if (detail.includes('Trust: UNTRUSTED')) trust = 'UNTRUSTED'

  if (policy.requireSignature === true && signatureState !== 'VALID') {
    return {
      ok: false,
      signature: signatureState,
      trust,
      error: `signature required but ${signatureState === 'MISSING' ? 'missing' : 'invalid'}`,
    }
  }
  if (policy.requireTrusted === true && trust !== 'VERIFIED') {
    return {
      ok: false,
      signature: signatureState,
      trust,
      error: trust === 'N/A'
        ? 'trusted key required but no DSH_PACK_TRUSTED_KEYS whitelist configured'
        : 'trusted key required but signer is not in the whitelist',
    }
  }
  return { ok: true, signature: signatureState, trust }
}
