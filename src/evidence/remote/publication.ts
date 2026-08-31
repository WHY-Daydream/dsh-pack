/**
 * v0.6.0-alpha.2 Evidence Publication orchestration (DESIGN-v0.6.0.md,
 * D160–D165): publish an already-validated DSH Evidence object as an OCI
 * referrer of an Agent Image.
 *
 *   validate evidence (D159 write-side twin)
 *     → build OCI carrier (subject = full descriptor)
 *     → upload blobs FIRST: empty config, envelope, required document (D161)
 *     → PUT Evidence manifest LAST (the subject may point to a
 *       not-yet-existing manifest — D160, no existence preflight)
 *     → OCI-Subject: exact M ⇒ native referrers; absent ⇒ standard
 *       referrers-tag fallback; present but wrong ⇒ FAIL LOUD (D162)
 *     → fallback: append-with-dedup + conditional push when supported (D163/D164)
 *
 * Publication ONLY adds an Evidence Set: the subject's OCI manifestDigest M
 * and DSH contentHash C never change (D165), and nothing is materialized or
 * executed. Distribution-layer only — no cache, no trust verdicts.
 * @module @why-daydream/dsh-pack/evidence/remote/publication
 */

import { sha256Hex } from '../../canonical.ts'
import { RegistryClient } from '../../image/registry/client.ts'
import type { RegistryCredentials } from '../../image/registry/auth.ts'
import { parseRemoteReference, registryBaseUrl, repoPath } from '../../image/registry/reference.ts'
import type { EvidenceEnvelope } from '../../types.ts'
import { buildEvidenceCarrier, validateEvidenceForCarrier } from './carrier.ts'
import { updateReferrersTag } from './referrers.ts'
import type { EvidencePublicationResult, RemoteSubjectDescriptor } from './types.ts'

/** The standard OCI empty JSON blob (image-spec DescriptorEmptyJSON, size 2). */
const OCI_EMPTY_BLOB = Buffer.from('{}', 'utf8')
const OCI_EMPTY_BLOB_DIGEST = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'

export interface EvidencePublicationOptions {
  /** Fully-qualified remote image reference, e.g. `ghcr.io/company/agent:prod`. */
  reference: string
  /** D160 — the FULL subject descriptor (digest === M; the subject manifest may not exist yet). */
  subjectDescriptor: RemoteSubjectDescriptor
  /** The signed Evidence envelope bytes (validated here against the strict D159 write-side contract). */
  envelopeBytes: Buffer
  /** Required external document bytes — ONLY when the verified statement demands one (D159). */
  documentBytes?: Buffer
  /** OCI artifactType (untrusted discovery hint; Envelope.type stays authoritative). */
  artifactType: string
  credentials?: RegistryCredentials
}

/**
 * Publish one validated Evidence object as an OCI referrer (D160–D165).
 * Throws on any protocol failure — including an OCI-Subject value that does
 * not exactly equal M (D162: never "guess unsupported and fall back").
 */
export async function publishRemoteEvidence(opts: EvidencePublicationOptions): Promise<EvidencePublicationResult> {
  const ref = parseRemoteReference(opts.reference)
  const base = registryBaseUrl(ref.registry)
  const repository = repoPath(ref)
  const clientOptions: ConstructorParameters<typeof RegistryClient>[0] = { baseUrl: base, repo: repository }
  if (opts.credentials !== undefined) clientOptions.credentials = opts.credentials
  const client = new RegistryClient(clientOptions)

  // D159 write-side twin: the envelope must be valid and the document presence
  // must exactly match the verified statement — publication never relaxes this.
  let envelope: EvidenceEnvelope
  try {
    envelope = JSON.parse(opts.envelopeBytes.toString('utf8')) as EvidenceEnvelope
  } catch {
    throw new Error('evidence envelope is not valid JSON (D159)')
  }
  const validated = validateEvidenceForCarrier(envelope, opts.documentBytes)
  if (!validated.ok) throw new Error(`refusing to publish invalid evidence: ${validated.error}`)

  // Build the carrier (exactly-one envelope layer, statement-governed document).
  const carrier = buildEvidenceCarrier({
    subjectDescriptor: opts.subjectDescriptor,
    artifactType: opts.artifactType,
    envelopeBytes: opts.envelopeBytes,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
  })

  // D161 — blobs FIRST, manifest LAST. Any payload failure aborts before a
  // dangling carrier can exist; uploadBlob is idempotent (digest-addressed).
  await client.uploadBlob(OCI_EMPTY_BLOB_DIGEST, OCI_EMPTY_BLOB)
  await client.uploadBlob(carrier.layers[0]!.digest, opts.envelopeBytes)
  if (carrier.layers.length > 1 && opts.documentBytes !== undefined) {
    await client.uploadBlob(carrier.layers[1]!.digest, opts.documentBytes)
  }

  // PUT the Evidence manifest by ITS DIGEST (digest-addressable). The subject
  // is a forward reference — D160 forbids existence preflight.
  const evidenceManifestDigest = `sha256:${sha256Hex(carrier.manifest)}`
  const put = await client.putManifestRaw(evidenceManifestDigest, carrier.manifest)
  if (put.status !== 200 && put.status !== 201) {
    throw new Error(`evidence manifest PUT failed (status ${put.status})`)
  }
  const reported = put.headers['docker-content-digest']
  if (reported !== undefined && reported !== evidenceManifestDigest) {
    throw new Error(`Docker-Content-Digest mismatch: registry reported ${reported}, expected ${evidenceManifestDigest}`)
  }

  // D162 — OCI-Subject is authoritative only as an EXACT push acknowledgement.
  const ociSubject = put.headers['oci-subject']
  if (ociSubject === undefined) {
    const fallback = await updateReferrersTag(
      client,
      { registry: ref.registry, repository, subjectManifestDigest: opts.subjectDescriptor.digest },
      { digest: evidenceManifestDigest, size: carrier.manifest.length, ...(opts.artifactType !== undefined ? { artifactType: opts.artifactType } : {}) },
    )
    return {
      repository,
      subjectManifestDigest: opts.subjectDescriptor.digest,
      evidenceManifestDigest,
      mode: 'tag-fallback',
      fallback,
    }
  }
  if (ociSubject !== opts.subjectDescriptor.digest) {
    throw new Error(`OCI-Subject mismatch: registry acknowledged ${ociSubject}, expected ${opts.subjectDescriptor.digest} (D162 — fail loud, no fallback)`)
  }
  return {
    repository,
    subjectManifestDigest: opts.subjectDescriptor.digest,
    evidenceManifestDigest,
    mode: 'native-referrers',
  }
}
