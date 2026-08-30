/**
 * v0.5 Evidence service seam (DESIGN-v0.5.0.md §3): signs Signed Evidence
 * Envelope files for an existing `.dshpack` and verifies evidence JSON files.
 *
 * The subject is ALWAYS the pack's recomputed immutable contentHash (D64) —
 * never a caller-declared value. Evidence is written into an **Evidence
 * Collection** directory (v0.5 hardening) and NEVER embedded into the artifact:
 *
 *   <name>.dshpack.evidence/
 *     <type>/
 *       <statementDigest hex>.json
 *
 * One artifact may carry N independent evidence files of M different types
 * (build-provenance / sbom / runtime-attestation/linux-x64 / …). The
 * statementDigest-hex filename makes collisions impossible: the same statement
 * maps to the same file (idempotent re-sign), a different statement is a new
 * file — **existing evidence is never overwritten** (D65 + collection rules).
 *
 * The `.dshpack` bytes and its own v0.3 Artifact Signature anchor are untouched.
 * Verification returns ordered failure reasons; trust of the signer (which
 * keyId is acceptable) stays with policy (D67) — this service only proves the
 * evidence is genuine, intact, and bound to the artifact.
 * @module @why-daydream/dsh-pack/evidence/service
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { computePackContentHash } from '../pack-builder.ts'
import { prettyJson } from '../canonical.ts'
import { PackError } from '../service.ts'
import { signEvidence, verifyEvidenceEnvelope, verifyEvidenceSigner, verifyEvidenceSubject } from './envelope.ts'
import type {
  EvidenceEnvelope, EvidenceSignOptions, EvidenceSignResult, EvidenceVerifyResult,
} from '../types.ts'

export interface EvidenceVerifyOptions {
  /** Recompute the artifact's contentHash and require the envelope's subject to match (D64). */
  against?: string
  /** Require the envelope's signer fingerprint to equal this keyId (D67 prelude). */
  keyId?: string
}

/** v0.5 evidence service seam (provided as `ctx.evidence`). */
export interface EvidenceService {
  /** Sign an evidence envelope for a `.dshpack`, writing it into the evidence collection. */
  sign(file: string, opts: EvidenceSignOptions): Promise<EvidenceSignResult>
  /** Verify an evidence file (self-integrity + optional artifact/signer binding). */
  verify(file: string, opts?: EvidenceVerifyOptions): Promise<EvidenceVerifyResult>
}

/** Default evidence service: pack contentHash is the immutable subject (D64). */
export class DefaultEvidenceService implements EvidenceService {
  async sign(file: string, opts: EvidenceSignOptions): Promise<EvidenceSignResult> {
    if (!existsSync(file)) throw new PackError(`pack file not found: ${file}`, 1)
    const contentHash = await computePackContentHash(readFileSync(file))
    const envelope = signEvidence({
      type: opts.type,
      subjectContentHash: contentHash,
      statement: opts.statement,
      keyPath: opts.key,
      ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
    })
    const outDir = opts.outDir ?? dirname(file)
    const collectionRoot = join(outDir, `${basename(file, '.dshpack')}.dshpack.evidence`)
    // type is a filesystem segment — never let it escape the collection root.
    const typeSegment = opts.type.replace(/[^a-zA-Z0-9._-]/g, '_')
    const out = join(collectionRoot, typeSegment, `${envelope.statementDigest.slice('sha256:'.length)}.json`)
    mkdirSync(dirname(out), { recursive: true })
    const incoming = prettyJson(envelope)
    if (existsSync(out)) {
      // Collection rule: existing evidence is NEVER overwritten. Idempotency is
      // judged by the SIGNED BINDING, not the raw bytes (the envelope carries a
      // fresh createdAt, so re-signing the same statement yields different
      // bytes): a VALID envelope with the same statementDigest + subject +
      // signer is the same evidence — keep the existing file. Anything else
      // (tampered file, different statement, different signer) is refused.
      const existingRaw = readFileSync(out, 'utf8')
      let existing: unknown
      try {
        existing = JSON.parse(existingRaw)
      } catch {
        throw new PackError(`evidence already exists (refusing to overwrite): ${out}`, 1)
      }
      const existingVerdict = verifyEvidenceEnvelope(existing)
      const existingEnvelope = existing as EvidenceEnvelope
      const sameBinding = existingVerdict.ok
        && existingEnvelope.statementDigest === envelope.statementDigest
        && existingEnvelope.subject.contentHash === envelope.subject.contentHash
        && existingEnvelope.signing.keyId === envelope.signing.keyId
      if (!sameBinding) {
        throw new PackError(`evidence already exists (refusing to overwrite): ${out}`, 1)
      }
    } else {
      writeFileSync(out, incoming)
    }
    return {
      file: out,
      keyId: envelope.signing.keyId,
      contentHash,
      type: envelope.type,
      statementDigest: envelope.statementDigest,
      ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
    }
  }

  async verify(file: string, opts: EvidenceVerifyOptions = {}): Promise<EvidenceVerifyResult> {
    if (!existsSync(file)) throw new PackError(`evidence file not found: ${file}`, 1)
    let envelope: unknown
    try {
      envelope = JSON.parse(readFileSync(file, 'utf8'))
    } catch {
      return emptyResult(false, 'evidence file is not valid JSON')
    }
    const verdict = verifyEvidenceEnvelope(envelope)
    if (!verdict.ok) return emptyResult(false, verdict.error)
    const ev = envelope as EvidenceEnvelope

    const errors: string[] = []
    if (opts.against !== undefined) {
      if (!existsSync(opts.against)) throw new PackError(`pack file not found: ${opts.against}`, 1)
      const actual = await computePackContentHash(readFileSync(opts.against))
      const binding = verifyEvidenceSubject(ev, actual)
      if (!binding.ok) errors.push(binding.error)
    }
    if (opts.keyId !== undefined) {
      const signer = verifyEvidenceSigner(ev, opts.keyId)
      if (!signer.ok) errors.push(signer.error)
    }
    return {
      ok: errors.length === 0,
      keyId: ev.signing.keyId,
      type: ev.type,
      subject: ev.subject.contentHash,
      statementDigest: ev.statementDigest,
      errors,
    }
  }
}

function emptyResult(ok: boolean, error: string): EvidenceVerifyResult {
  return { ok, keyId: '', type: '', subject: '', statementDigest: '', errors: [error] }
}
