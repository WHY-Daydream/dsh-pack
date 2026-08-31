/**
 * v0.6.0-alpha.1 OCI Evidence carrier parsing (DESIGN-v0.6.0.md §2/§6, D159):
 * a STRICT validator, never a finder. Exactly one Signed Evidence Envelope
 * layer; an external document layer is governed by the VERIFIED Evidence
 * statement — a required document must exist exactly once and pass BOTH OCI
 * descriptor integrity (digest + size) and DSH document-digest verification.
 * Duplicate / ambiguous / unknown payloads are INVALID_CARRIER — no
 * `.find()` / first-layer-wins anywhere (this must not reopen the N4/D120
 * SBOM substitution gap).
 * @module @why-daydream/dsh-pack/evidence/remote/carrier
 */

import { sha256Hex } from '../../canonical.ts'
import { RegistryClient } from '../../image/registry/client.ts'
import { verifyEvidenceEnvelope } from '../envelope.ts'
import type { EvidenceEnvelope } from '../../types.ts'
import {
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
  type RemoteEvidenceDiscoveryError,
} from './types.ts'

/** The verified carrier payloads: an envelope, plus an optional document. */
export interface EvidenceCarrier {
  envelopeBytes: Buffer
  envelope: EvidenceEnvelope
  document?: { mediaType: string; digest: string; bytes: Buffer }
}

interface LayerDescriptor {
  mediaType?: unknown
  digest?: unknown
  size?: unknown
}

interface OciEvidenceManifest {
  schemaVersion?: unknown
  mediaType?: unknown
  subject?: { digest?: unknown } | null
  config?: { mediaType?: unknown } | null
  layers?: unknown
}

const OCI_IMAGE_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
const OCI_EMPTY_CONFIG_MEDIA_TYPE = 'application/vnd.oci.empty.v1+json'

function invalidCarrier(message: string): RemoteEvidenceDiscoveryError {
  return { kind: 'INVALID_CARRIER', message }
}

/**
 * D159 — the DSH document digest a verified Evidence statement REQUIRES
 * (sbomDigest / attestationDigest / capabilityDigest), if any. The presence of
 * this field in the verified statement governs whether the carrier MUST carry
 * exactly one external document.
 */
function statementDocumentDigest(envelope: EvidenceEnvelope): string | undefined {
  const statement = envelope.statement as Record<string, unknown> | null
  if (statement === null || typeof statement !== 'object') return undefined
  for (const key of ['sbomDigest', 'attestationDigest', 'capabilityDigest'] as const) {
    const field = statement[key] as { value?: unknown } | null | undefined
    if (field !== null && typeof field === 'object' && typeof field.value === 'string' && /^[0-9a-f]{64}$/.test(field.value)) {
      return `sha256:${field.value}`
    }
  }
  return undefined
}

/**
 * Parse + fully verify one OCI Evidence carrier:
 *   1. manifest structure (schemaVersion 2, subject descriptor present)
 *   2. `manifest.subject.digest == expectedSubjectDigest` (D150 — foreign subject rejected)
 *   3. strict layer classification + cardinality (D159 — exactly one envelope;
 *      document governed by the verified statement)
 *   4. OCI descriptor verification for every consumed layer (digest + size)
 *   5. DSH envelope verification + document digest verification
 * Returns `{ carrier }` or `{ error: INVALID_CARRIER }`.
 */
export async function parseEvidenceCarrier(
  client: RegistryClient,
  manifestBytes: Buffer,
  expectedSubjectDigest: string,
): Promise<{ carrier: EvidenceCarrier } | { error: RemoteEvidenceDiscoveryError }> {
  let parsed: unknown
  try {
    parsed = JSON.parse(manifestBytes.toString('utf8'))
  } catch {
    return { error: invalidCarrier('evidence manifest is not valid JSON') }
  }
  if (parsed === null || typeof parsed !== 'object') {
    return { error: invalidCarrier('evidence manifest is not an object') }
  }
  const manifest = parsed as OciEvidenceManifest
  if (manifest.schemaVersion !== 2) {
    return { error: invalidCarrier(`evidence manifest schemaVersion must be 2 (got ${String(manifest.schemaVersion)})`) }
  }
  if (typeof manifest.mediaType === 'string' && manifest.mediaType !== OCI_IMAGE_MANIFEST_MEDIA_TYPE) {
    return { error: invalidCarrier(`evidence manifest mediaType must be ${OCI_IMAGE_MANIFEST_MEDIA_TYPE} (got ${JSON.stringify(manifest.mediaType)})`) }
  }
  if (typeof manifest.config?.mediaType === 'string' && manifest.config.mediaType !== OCI_EMPTY_CONFIG_MEDIA_TYPE) {
    return { error: invalidCarrier(`evidence carrier config must be the OCI empty descriptor (got ${JSON.stringify(manifest.config.mediaType)})`) }
  }
  const subject = manifest.subject
  if (subject === null || typeof subject !== 'object' || typeof subject.digest !== 'string') {
    return { error: invalidCarrier('evidence manifest is missing the subject descriptor') }
  }
  if (subject.digest !== expectedSubjectDigest) {
    return { error: invalidCarrier(`evidence manifest subject is ${subject.digest}, expected ${expectedSubjectDigest} (foreign subject, D150)`) }
  }
  if (!Array.isArray(manifest.layers)) {
    return { error: invalidCarrier('evidence manifest layers must be an array') }
  }

  // D159 — classify by counting, never by finding
  const envelopes: LayerDescriptor[] = []
  const documents: LayerDescriptor[] = []
  for (const raw of manifest.layers as unknown[]) {
    const layer = raw as LayerDescriptor | null
    if (layer === null || typeof layer !== 'object') {
      return { error: invalidCarrier('evidence layer descriptor is not an object') }
    }
    if (layer.mediaType === EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE) envelopes.push(layer)
    else if (layer.mediaType === EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE) documents.push(layer)
    else return { error: invalidCarrier(`unexpected evidence layer mediaType ${JSON.stringify(layer.mediaType)}`) }
  }

  if (envelopes.length !== 1) {
    return { error: invalidCarrier(`evidence carrier must contain exactly one envelope layer (got ${envelopes.length})`) }
  }
  const envelopeDescriptor = envelopes[0]!
  if (typeof envelopeDescriptor.digest !== 'string' || typeof envelopeDescriptor.size !== 'number') {
    return { error: invalidCarrier('envelope layer descriptor must carry digest + size') }
  }

  // fetch + OCI descriptor verification (digest + size)
  let envelopeBytes: Buffer
  try {
    envelopeBytes = await client.getBlob(envelopeDescriptor.digest)
  } catch (error) {
    return { error: invalidCarrier(`envelope blob fetch failed: ${String(error)}`) }
  }
  try {
    client.verifyDescriptor('evidence envelope layer', { digest: envelopeDescriptor.digest, size: envelopeDescriptor.size }, envelopeBytes)
  } catch (error) {
    return { error: invalidCarrier(String(error)) }
  }

  // DSH envelope verification (self-integrity + signature)
  let envelope: EvidenceEnvelope
  try {
    envelope = JSON.parse(envelopeBytes.toString('utf8')) as EvidenceEnvelope
  } catch {
    return { error: invalidCarrier('envelope layer is not valid JSON') }
  }
  const envelopeVerdict = verifyEvidenceEnvelope(envelope)
  if (!envelopeVerdict.ok) {
    return { error: invalidCarrier(`evidence envelope verification failed: ${envelopeVerdict.error}`) }
  }

  // document cardinality governed by the VERIFIED statement (D159)
  const requiredDigest = statementDocumentDigest(envelope)
  if (requiredDigest !== undefined) {
    if (documents.length !== 1) {
      return { error: invalidCarrier(`statement requires exactly one document layer (got ${documents.length})`) }
    }
    const documentDescriptor = documents[0]!
    if (typeof documentDescriptor.digest !== 'string' || typeof documentDescriptor.size !== 'number') {
      return { error: invalidCarrier('document layer descriptor must carry digest + size') }
    }
    let documentBytes: Buffer
    try {
      documentBytes = await client.getBlob(documentDescriptor.digest)
    } catch (error) {
      return { error: invalidCarrier(`document blob fetch failed: ${String(error)}`) }
    }
    try {
      client.verifyDescriptor('evidence document layer', { digest: documentDescriptor.digest, size: documentDescriptor.size }, documentBytes)
    } catch (error) {
      return { error: invalidCarrier(String(error)) }
    }
    const actual = `sha256:${sha256Hex(documentBytes)}`
    if (actual !== requiredDigest) {
      return { error: invalidCarrier(`document digest mismatch: statement requires ${requiredDigest}, actual ${actual}`) }
    }
    return {
      carrier: {
        envelopeBytes,
        envelope,
        document: { mediaType: String(documentDescriptor.mediaType), digest: documentDescriptor.digest, bytes: documentBytes },
      },
    }
  }

  if (documents.length > 0) {
    return { error: invalidCarrier('statement does not reference a document but the carrier carries one (ambiguous payload)') }
  }
  return { carrier: { envelopeBytes, envelope } }
}
