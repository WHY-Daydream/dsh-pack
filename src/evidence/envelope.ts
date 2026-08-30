/**
 * v0.5 Signed Evidence Envelope (DESIGN-v0.5.0.md §3, D64–D67): a standalone,
 * self-authenticating statement ABOUT an immutable artifact.
 *
 * The envelope is the v0.5 Evidence Foundation's one primitive:
 *
 *   subject.contentHash   — the immutable DSH artifact anchor this evidence is
 *                           ABOUT (D64); evidence never joins the artifact, it
 *                           points at it.
 *   statementDigest       — sha256 over canonicalJson(statement), so the payload
 *                           is anchored without the envelope trusting its own
 *                           raw JSON bytes.
 *   signing.signature     — ed25519 over the domain-separated canonical object
 *                           `{domain, schemaVersion, type, subject, statementDigest}`
 *                           (D66). NOT over the envelope file: any field-level
 *                           tampering, subject substitution or statement edit
 *                           invalidates the signature.
 *
 * Domain separation (v0.5 protocol hardening): the signing input carries the
 * fixed `domain: "dsh-pack:evidence:v1"` + schemaVersion, so the same Ed25519
 * key can later sign OTHER protocol objects (Artifact Signature, Runtime
 * Attestation, OCI Attestation) without cross-protocol replay/ambiguity —
 * each protocol gets its own domain. An Artifact Signature (v0.3) covers the
 * bare contentHash string; an Evidence Signature covers this domain-tagged
 * canonical object; they can never collide.
 *
 * Artifact signature vs Evidence signature stay separate: the v0.3 Artifact
 * Signature covers the contentHash anchor; this module authenticates EVIDENCE
 * about that artifact (D65 — evidence never enters the artifact contentHash and
 * never touches the existing Artifact Signature anchor).
 *
 * Trust (which signer is acceptable) is NOT decided here — that is policy
 * (D67, trust.yaml v2 in a later phase). This module only answers "is this
 * evidence genuine, intact, and bound to this artifact?". The keyId it returns
 * is ALWAYS recomputed from the embedded verification public key — never a
 * claimed value — so policy consumes only verifiedKeyId.
 * @module @why-daydream/dsh-pack/evidence/envelope
 */

import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { canonicalJson, sha256Hex, utcNowIso } from '../canonical.ts'
import { PackError } from '../service.ts'
import type { EvidenceEnvelope, EvidenceSignInput } from '../types.ts'

export const EVIDENCE_ENVELOPE_SCHEMA_VERSION = 1
export const EVIDENCE_SIGNING_ALGORITHM = 'ed25519'
/**
 * The evidence protocol's fixed domain (v0.5 hardening). Every evidence
 * signature covers an object carrying this domain + schemaVersion, so an
 * evidence signature can never be replayed as / confused with another signing
 * protocol (artifact signature, future attestations) under the same key.
 */
export const EVIDENCE_DOMAIN = 'dsh-pack:evidence:v1'
const CONTENT_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/

/** A verify verdict: ok + verified signer fingerprint, or one precise failure reason. */
export type EvidenceVerdict = { ok: true; keyId: string } | { ok: false; error: string }

/**
 * The ONLY signing input an evidence signature covers (D66, domain-separated):
 * canonical JSON of the fixed-domain object
 * `{domain, schemaVersion, type, subject.contentHash, statementDigest}`.
 * Any change to the protocol domain, the evidence class, the bound artifact,
 * or the statement anchor changes these bytes and invalidates the signature.
 */
export function evidenceSigningInput(type: string, subjectContentHash: string, statementDigest: string): string {
  const digest = parseSha256Digest(statementDigest)
  return canonicalJson({
    domain: EVIDENCE_DOMAIN,
    schemaVersion: EVIDENCE_ENVELOPE_SCHEMA_VERSION,
    type,
    subject: { contentHash: subjectContentHash },
    statementDigest: { algorithm: digest.algorithm, value: digest.value },
  })
}

/** Split a `sha256:<64 hex>` digest into `{algorithm, value}` (strict). */
function parseSha256Digest(digest: string): { algorithm: 'sha256'; value: string } {
  const match = /^sha256:([0-9a-f]{64})$/.exec(digest)
  if (match === null) {
    throw new PackError(`digest must be sha256:<64 hex> (got ${JSON.stringify(digest)})`, 1)
  }
  return { algorithm: 'sha256', value: match[1] as string }
}

/** `sha256:` + hex over the canonical JSON of the statement payload. */
export function statementDigestOf(statement: unknown): string {
  return `sha256:${sha256Hex(canonicalJson(statement))}`
}

/** Sign an evidence envelope (D64–D66). Subject is the immutable artifact anchor. */
export function signEvidence(input: EvidenceSignInput): EvidenceEnvelope {
  if (input.type === '') throw new PackError('evidence type must be a non-empty string', 1)
  if (!CONTENT_HASH_PATTERN.test(input.subjectContentHash)) {
    throw new PackError(
      `evidence subject contentHash must be sha256:<64 hex> (got ${JSON.stringify(input.subjectContentHash)})`,
      1,
    )
  }
  if (!existsSync(input.keyPath)) throw new PackError(`private key not found: ${input.keyPath}`, 1)
  let privateKey
  try {
    privateKey = createPrivateKey(readFileSync(input.keyPath, 'utf8'))
  } catch (error) {
    throw new PackError(`cannot read private key ${input.keyPath}: ${String(error)}`, 1)
  }

  const statementDigest = statementDigestOf(input.statement)
  const signedBytes = Buffer.from(
    evidenceSigningInput(input.type, input.subjectContentHash, statementDigest),
    'utf8',
  )
  const signatureBytes = sign(null, signedBytes, privateKey)
  // spki export is only valid on a PUBLIC key object.
  const publicKey = createPublicKey(privateKey)
  const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
  const keyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))

  return {
    schemaVersion: EVIDENCE_ENVELOPE_SCHEMA_VERSION,
    type: input.type,
    subject: { contentHash: input.subjectContentHash },
    statement: input.statement,
    statementDigest,
    signing: {
      algorithm: EVIDENCE_SIGNING_ALGORITHM,
      keyId,
      publicKey: publicPem,
      signature: signatureBytes.toString('base64'),
      createdAt: utcNowIso(),
    },
  }
}

/**
 * Verify the envelope's OWN authenticity (D66): schema, statement→digest
 * binding, keyId↔publicKey consistency, and the ed25519 signature over the
 * canonical triple. This is the "is this evidence genuine and intact" gate —
 * it does NOT decide whether the signer is trusted (that is policy, D67).
 */
export function verifyEvidenceEnvelope(value: unknown): EvidenceVerdict {
  if (value === null || typeof value !== 'object') return { ok: false, error: 'evidence envelope is not an object' }
  const env = value as Record<string, unknown>
  if (env.schemaVersion !== EVIDENCE_ENVELOPE_SCHEMA_VERSION) {
    return { ok: false, error: `evidence schemaVersion must be ${EVIDENCE_ENVELOPE_SCHEMA_VERSION} (got ${String(env.schemaVersion)})` }
  }
  if (typeof env.type !== 'string' || env.type === '') {
    return { ok: false, error: 'evidence type must be a non-empty string' }
  }
  const subject = env.subject as Record<string, unknown> | undefined
  if (subject === null || typeof subject !== 'object' || typeof subject.contentHash !== 'string') {
    return { ok: false, error: 'evidence subject must be an object with contentHash' }
  }
  if (!CONTENT_HASH_PATTERN.test(subject.contentHash)) {
    return { ok: false, error: `evidence subject.contentHash must be sha256:<64 hex> (got ${JSON.stringify(subject.contentHash)})` }
  }
  if (typeof env.statementDigest !== 'string' || !CONTENT_HASH_PATTERN.test(env.statementDigest)) {
    return { ok: false, error: `evidence statementDigest must be sha256:<64 hex> (got ${JSON.stringify(env.statementDigest)})` }
  }
  const signing = env.signing as Record<string, unknown> | undefined
  if (signing === null || typeof signing !== 'object') {
    return { ok: false, error: 'evidence signing must be an object' }
  }
  if (signing.algorithm !== EVIDENCE_SIGNING_ALGORITHM) {
    return { ok: false, error: `unsupported evidence signature algorithm: ${String(signing.algorithm)}` }
  }
  if (typeof signing.keyId !== 'string' || !/^[0-9a-f]{64}$/.test(signing.keyId)) {
    return { ok: false, error: 'evidence signing.keyId must be 64 hex chars' }
  }
  if (typeof signing.publicKey !== 'string') {
    return { ok: false, error: 'evidence signing.publicKey must be a PEM string' }
  }
  if (typeof signing.signature !== 'string' || signing.signature === '') {
    return { ok: false, error: 'evidence signing.signature must be a base64 string' }
  }

  // statement → statementDigest binding: the payload must hash to the anchor
  // (tamper detection independent of the signature).
  const recomputed = statementDigestOf(env.statement)
  if (recomputed !== env.statementDigest) {
    return { ok: false, error: `statementDigest mismatch: envelope=${env.statementDigest} recomputed=${recomputed}` }
  }

  // keyId ↔ publicKey consistency: the fingerprint must be the hash of the
  // embedded public key, so an attacker cannot pair a trusted keyId with an
  // unrelated key.
  let publicKey
  try {
    publicKey = createPublicKey(signing.publicKey)
  } catch {
    return { ok: false, error: 'evidence signing.publicKey is not a valid PEM key' }
  }
  const actualKeyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))
  if (actualKeyId !== signing.keyId) {
    return { ok: false, error: `signing.keyId does not match the embedded public key (keyId=${signing.keyId} actual=${actualKeyId})` }
  }

  // signature over canonical(type + subject.contentHash + statementDigest):
  // subject substitution and type edits change these bytes → FAIL.
  const signedInput = evidenceSigningInput(env.type, subject.contentHash, env.statementDigest)
  let signatureBytes: Buffer
  try {
    signatureBytes = Buffer.from(signing.signature, 'base64')
  } catch {
    return { ok: false, error: 'evidence signing.signature is not valid base64' }
  }
  const valid = verify(null, Buffer.from(signedInput, 'utf8'), publicKey, signatureBytes)
  if (!valid) return { ok: false, error: 'evidence ed25519 signature verification FAILED' }
  return { ok: true, keyId: signing.keyId }
}

/**
 * D64 binding check: the evidence must be ABOUT exactly one immutable artifact.
 * `expectedContentHash` is the artifact's recomputed anchor (never a declared
 * value). Mismatch ⇒ stale/substituted evidence.
 */
export function verifyEvidenceSubject(envelope: EvidenceEnvelope, expectedContentHash: string): EvidenceVerdict {
  if (envelope.subject.contentHash !== expectedContentHash) {
    return {
      ok: false,
      error: `evidence subject is ${envelope.subject.contentHash}, artifact contentHash is ${expectedContentHash}`,
    }
  }
  return { ok: true, keyId: envelope.signing.keyId }
}

/**
 * D67 prelude: the envelope's signer fingerprint must match the expected
 * identity (policy-provided keyId). A VALID envelope from the WRONG signer
 * must be rejected by policy — VALID ≠ TRUSTED (mirrors v0.3).
 */
export function verifyEvidenceSigner(envelope: EvidenceEnvelope, expectedKeyId: string): EvidenceVerdict {
  if (envelope.signing.keyId !== expectedKeyId) {
    return {
      ok: false,
      error: `evidence signed by SHA256:${envelope.signing.keyId}, policy expects SHA256:${expectedKeyId}`,
    }
  }
  return { ok: true, keyId: envelope.signing.keyId }
}
