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
import { buildReceiptPath, validateBuildRecord } from './build-record.ts'
import {
  generateSbomFromPack, SBOM_EVIDENCE_TYPE, SBOM_FORMAT, SBOM_MEDIA_TYPE, SBOM_SPEC_VERSION,
} from './sbom.ts'
import {
  CAPABILITY_EVIDENCE_TYPE, CAPABILITY_FORMAT, CAPABILITY_SCHEMA_VERSION,
  generateCapabilityManifestFromPack,
} from './capability.ts'
import type {
  CapabilitySignOptions, CapabilitySignResult,
  EvidenceEnvelope, EvidenceSignOptions, EvidenceSignResult, EvidenceVerifyResult,
  ProvenanceSignOptions, ProvenanceSignResult, SbomSignOptions, SbomSignResult,
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
  /**
   * Sign a `build-provenance` Evidence from the pack's BUILD-TIME receipt
   * (D68): consumes only what `/pack` recorded — never the current git HEAD.
   */
  provenance(file: string, opts: ProvenanceSignOptions): Promise<ProvenanceSignResult>
  /**
   * Generate a CycloneDX 1.7 SBOM from the artifact's own materials (D74),
   * write the standalone document, and sign the `sbom` Evidence (D75).
   */
  sbom(file: string, opts: SbomSignOptions): Promise<SbomSignResult>
  /**
   * Generate a Declared Capability Manifest by PURE artifact inspection
   * (D81–D88, no cold boot), write the standalone document, and sign the
   * `capability` Evidence bound to the actual contentHash (D82).
   */
  capability(file: string, opts: CapabilitySignOptions): Promise<CapabilitySignResult>
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

  /**
   * Sign `build-provenance` Evidence from the pack's build receipt (D68):
   * the receipt was captured at `/pack` time and records the actual inputs.
   * This command NEVER re-reads the current git state — and it refuses a
   * receipt whose subject does not match the artifact's recomputed anchor
   * (a swapped/edited receipt cannot be laundered into provenance).
   */
  async provenance(file: string, opts: ProvenanceSignOptions): Promise<ProvenanceSignResult> {
    if (!existsSync(file)) throw new PackError(`pack file not found: ${file}`, 1)
    const receiptPath = buildReceiptPath(file)
    if (!existsSync(receiptPath)) {
      throw new PackError(
        `no build receipt at ${receiptPath} — pack the artifact with /pack to record build-time inputs (D68)`,
        1,
      )
    }
    let raw: unknown
    try {
      raw = JSON.parse(readFileSync(receiptPath, 'utf8'))
    } catch {
      throw new PackError(`build receipt ${receiptPath} is not valid JSON`, 1)
    }
    const validated = validateBuildRecord(raw)
    if (!validated.ok) throw new PackError(`invalid build receipt: ${validated.errors.join('; ')}`, 1)
    const receipt = validated.record

    // receipt anti-tamper: subject must equal the ACTUAL artifact anchor
    const actual = await computePackContentHash(readFileSync(file))
    if (receipt.subject.contentHash !== actual) {
      throw new PackError(
        `build receipt subject is ${receipt.subject.contentHash}, artifact contentHash is ${actual}`,
        1,
      )
    }

    // D68: a dirty build tree must not claim a commit that does not describe
    // the actual inputs — default FAIL; --allow-dirty signs with the recorded
    // sourceTreeDigest instead.
    if (receipt.source.dirty && opts.allowDirty !== true) {
      throw new PackError(
        'provenance FAIL: the build tree was dirty at pack time; use --allow-dirty to sign with the recorded sourceTreeDigest (D68)',
        1,
      )
    }

    // D72 trust boundary: this is a POST-BUILD signing of an UNSIGNED build
    // receipt — the receipt could have been edited after the build, so the
    // signed statement is explicitly marked `post-build-receipt` and can never
    // claim to be a cryptographic attestation of the unmodified build moment.
    // (Only `/pack --evidence-key` signs AT the build site as `build-time`.)
    const result = await this.sign(file, {
      type: 'build-provenance',
      statement: { ...receipt, capture: { mode: 'post-build-receipt' } },
      key: opts.key,
      ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
      ...(opts.outDir !== undefined ? { outDir: opts.outDir } : {}),
    })
    return {
      ...result,
      ...(receipt.source.gitCommit !== undefined ? { gitCommit: receipt.source.gitCommit } : {}),
      dirty: receipt.source.dirty,
      ...(receipt.source.sourceTreeDigest !== undefined ? { sourceTreeDigest: receipt.source.sourceTreeDigest } : {}),
      captureMode: 'post-build-receipt' as const,
    }
  }

  /**
   * Generate the CycloneDX 1.7 SBOM from the artifact's OWN materials (D74 —
   * never the current node_modules / workspace), write the standalone
   * document to `documents/<sbomDigest>.cdx.json` (D73/D75), and sign the
   * `sbom` Evidence: subject = actual contentHash, statement carries
   * format/specVersion/mediaType + sbomDigest (D75).
   */
  async sbom(file: string, opts: SbomSignOptions): Promise<SbomSignResult> {
    if (!existsSync(file)) throw new PackError(`pack file not found: ${file}`, 1)
    const contentHash = await computePackContentHash(readFileSync(file))
    const { document, digest, bom } = await generateSbomFromPack(readFileSync(file))
    const digestHex = digest.slice('sha256:'.length)

    // standalone document for standard SBOM tooling (D73/D75)
    const outDir = opts.outDir ?? dirname(file)
    const collectionRoot = join(outDir, `${basename(file, '.dshpack')}.dshpack.evidence`)
    const documentFile = join(collectionRoot, 'documents', `${digestHex}.cdx.json`)
    mkdirSync(dirname(documentFile), { recursive: true })
    if (existsSync(documentFile)) {
      const existing = readFileSync(documentFile, 'utf8')
      if (existing !== document) {
        throw new PackError(`sbom document already exists (refusing to overwrite): ${documentFile}`, 1)
      }
    } else {
      writeFileSync(documentFile, document)
    }

    // signed Evidence envelope bound to the artifact (D75)
    const result = await this.sign(file, {
      type: SBOM_EVIDENCE_TYPE,
      statement: {
        format: SBOM_FORMAT,
        specVersion: SBOM_SPEC_VERSION,
        mediaType: SBOM_MEDIA_TYPE,
        sbomDigest: { algorithm: 'sha256', value: digestHex },
      },
      key: opts.key,
      ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
      ...(opts.outDir !== undefined ? { outDir: opts.outDir } : {}),
    })
    return {
      ...result,
      documentFile,
      sbomDigest: digest,
      componentCount: bom.components.length,
    }
  }

  /**
   * Generate the Declared Capability Manifest by PURE artifact inspection
   * (D81–D88): composed rows + the packed profile patch only — never a cold
   * boot, never plugin execution. Write the standalone document to
   * `documents/<capabilityDigest>.capability.json`, then sign the `capability`
   * Evidence: subject = actual contentHash (D82), statement carries
   * format/schemaVersion + capabilityDigest (D88).
   */
  async capability(file: string, opts: CapabilitySignOptions): Promise<CapabilitySignResult> {
    if (!existsSync(file)) throw new PackError(`pack file not found: ${file}`, 1)
    const contentHash = await computePackContentHash(readFileSync(file))
    const { document, digest, manifest } = await generateCapabilityManifestFromPack(readFileSync(file), contentHash)
    const digestHex = digest.slice('sha256:'.length)

    // standalone document (D81: separate evidence domain from SBOM)
    const outDir = opts.outDir ?? dirname(file)
    const collectionRoot = join(outDir, `${basename(file, '.dshpack')}.dshpack.evidence`)
    const documentFile = join(collectionRoot, 'documents', `${digestHex}.capability.json`)
    mkdirSync(dirname(documentFile), { recursive: true })
    if (existsSync(documentFile)) {
      const existing = readFileSync(documentFile, 'utf8')
      if (existing !== document) {
        throw new PackError(`capability document already exists (refusing to overwrite): ${documentFile}`, 1)
      }
    } else {
      writeFileSync(documentFile, document)
    }

    // signed Evidence envelope bound to the artifact (D82)
    const result = await this.sign(file, {
      type: CAPABILITY_EVIDENCE_TYPE,
      statement: {
        format: CAPABILITY_FORMAT,
        schemaVersion: CAPABILITY_SCHEMA_VERSION,
        capabilityDigest: { algorithm: 'sha256', value: digestHex },
      },
      key: opts.key,
      ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
      ...(opts.outDir !== undefined ? { outDir: opts.outDir } : {}),
    })
    return {
      ...result,
      documentFile,
      capabilityDigest: digest,
      capabilityCount: manifest.declared.providers.length + manifest.declared.services.length,
    }
  }
}

function emptyResult(ok: boolean, error: string): EvidenceVerifyResult {
  return { ok, keyId: '', type: '', subject: '', statementDigest: '', errors: [error] }
}
