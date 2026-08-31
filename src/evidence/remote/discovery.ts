/**
 * v0.6.0-alpha.1 Remote Evidence Discovery orchestration (DESIGN-v0.6.0.md
 * §4.1/§8, D149/D150/D152/D153/D157/D158): the alpha.1 read path.
 *
 *   remote image ref → resolve mutable tag → immutable M → discover ALL
 *   referrers (native + pagination + standard fallback) → fetch each evidence
 *   manifest → OCI integrity + subject == M → strict carrier → DSH Evidence
 *   verification → subject.contentHash == independently-known C → candidates.
 *
 * Distinguishes a REJECTED single object (discovery still complete) from an
 * INCOMPLETE enumeration (D158 — partial results are never returned as a
 * complete set). No trust verdicts: VALID ≠ TRUSTED, and nothing here
 * consults trust.yaml or policy.
 * @module @why-daydream/dsh-pack/evidence/remote/discovery
 */

import { RegistryClient } from '../../image/registry/client.ts'
import type { RegistryCredentials } from '../../image/registry/auth.ts'
import { digestOf } from '../../image/registry/descriptor.ts'
import { parseRemoteReference, registryBaseUrl, repoPath } from '../../image/registry/reference.ts'
import { verifyEvidenceSubject } from '../envelope.ts'
import { parseEvidenceCarrier } from './carrier.ts'
import { discoverReferrers } from './referrers.ts'
import type {
  ReferrerDescriptor,
  RemoteEvidenceCandidate,
  RemoteEvidenceDiscoveryError,
  RemoteEvidenceDiscoveryResult,
  RemoteEvidenceLocator,
  RejectedRemoteEvidence,
} from './types.ts'

export interface DiscoverRemoteEvidenceOptions {
  /** Fully-qualified remote image reference, e.g. `ghcr.io/company/agent:prod` or `...@sha256:M`. */
  reference: string
  /** The INDEPENDENTLY verified artifact contentHash C (D150 — never read from evidence itself). */
  actualContentHash: string
  /** Discovery hint only (D152): passed to the Referrers API when exactly one; never a trust input. */
  artifactTypes?: string[]
  credentials?: RegistryCredentials
}

/**
 * The alpha.1 entry point: discover + verify ALL remote Evidence attached to
 * the artifact referenced by `opts.reference`.
 *
 *  - mutable tag is resolved exactly once to immutable M (D149); everything
 *    after is anchored to (registry, repository, M) (D157).
 *  - referrers enumeration is fully consumed before any result is formed
 *    (D158); enumeration failures surface as `complete: false`.
 *  - each candidate passes OCI integrity → subject == M → strict carrier
 *    (D159) → DSH envelope verification → subject.contentHash == C (D150).
 *  - the candidate's evidenceType is always the verified Envelope.type;
 *    declared OCI artifactType is diagnostic only (D152).
 */
export async function discoverRemoteEvidence(opts: DiscoverRemoteEvidenceOptions): Promise<RemoteEvidenceDiscoveryResult> {
  let locator: RemoteEvidenceLocator
  let client: RegistryClient
  try {
    const ref = parseRemoteReference(opts.reference)
    const base = registryBaseUrl(ref.registry)
    const repo = repoPath(ref)
    const clientOptions: ConstructorParameters<typeof RegistryClient>[0] = { baseUrl: base, repo }
    if (opts.credentials !== undefined) clientOptions.credentials = opts.credentials
    client = new RegistryClient(clientOptions)

    // D149 — resolve the mutable tag EXACTLY ONCE to immutable M; a digest
    // reference needs no resolution. Everything after anchors on M.
    let manifestDigest: string
    if (ref.digest !== undefined) {
      manifestDigest = ref.digest
    } else {
      const resolved = await client.getManifest(ref.tag ?? 'latest')
      manifestDigest = resolved.digest
    }
    locator = { registry: ref.registry, repository: repo, subjectManifestDigest: manifestDigest }
  } catch (error) {
    const message = `cannot resolve remote reference: ${String(error)}`
    return { complete: false, error: referenceOrRegistryError(message, error) }
  }

  return discoverForLocator(client, locator, opts)
}

/** Map a resolution error to REFERENCE_ERROR or REGISTRY_ERROR. */
function referenceOrRegistryError(message: string, error: unknown): RemoteEvidenceDiscoveryError {
  const status = (error as { status?: unknown } | null)?.status
  if (typeof status === 'number') return { kind: 'REGISTRY_ERROR', status, message }
  return { kind: 'REFERENCE_ERROR', message }
}

/** Discovery anchored at an immutable (registry, repository, M) locator (D157). */
async function discoverForLocator(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  opts: DiscoverRemoteEvidenceOptions,
): Promise<RemoteEvidenceDiscoveryResult> {
  const filter = opts.artifactTypes !== undefined && opts.artifactTypes.length === 1 ? opts.artifactTypes[0] : undefined

  // enumeration — MUST complete in full (D158) or the whole result is incomplete
  let enumeration: Awaited<ReturnType<typeof discoverReferrers>>
  try {
    enumeration = await discoverReferrers(client, locator, filter)
  } catch (error) {
    const e = error as RemoteEvidenceDiscoveryError
    return { complete: false, error: e }
  }

  const candidates: RemoteEvidenceCandidate[] = []
  const rejected: RejectedRemoteEvidence[] = []

  for (const descriptor of enumeration.descriptors) {
    const outcome = await verifyOneReferrer(client, locator, enumeration.source, descriptor, opts.actualContentHash)
    if (outcome.kind === 'candidate') candidates.push(outcome.candidate)
    else rejected.push(outcome.rejected)
  }

  return { complete: true, candidates, rejected }
}

/** Fetch + verify ONE referrer object (untrusted enumeration metadata → candidate). */
async function verifyOneReferrer(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  source: 'referrers-api' | 'tag-fallback',
  descriptor: ReferrerDescriptor,
  actualContentHash: string,
): Promise<{ kind: 'candidate'; candidate: RemoteEvidenceCandidate } | { kind: 'rejected'; rejected: RejectedRemoteEvidence }> {
  const reject = (reason: string): { kind: 'rejected'; rejected: RejectedRemoteEvidence } => ({
    kind: 'rejected',
    rejected: { referrerManifestDigest: descriptor.digest, reason, ...(descriptor.artifactType !== undefined ? { declaredArtifactType: descriptor.artifactType } : {}) },
  })

  // 1. fetch the evidence manifest RAW by digest + verify OCI digest/size.
  //    Evidence carriers are OCI ARTIFACT manifests (empty config) — the DSH
  //    agent-envelope validator must NOT be applied here; carrier structure is
  //    validated by parseEvidenceCarrier (D152/D159).
  let raw: Awaited<ReturnType<RegistryClient['getManifestRaw']>>
  try {
    raw = await client.getManifestRaw(descriptor.digest)
  } catch (error) {
    return reject(`evidence manifest fetch failed: ${String(error)}`)
  }
  if (raw.status !== 200 || raw.body === undefined) {
    return reject(`evidence manifest fetch failed (status ${raw.status})`)
  }
  const manifestBytes = raw.body
  const actualDigest = digestOf(manifestBytes)
  if (actualDigest !== descriptor.digest) {
    return reject(`evidence manifest digest mismatch: descriptor=${descriptor.digest} actual=${actualDigest}`)
  }
  if (manifestBytes.length !== descriptor.size) {
    return reject(`evidence manifest size mismatch: descriptor=${descriptor.size} actual=${manifestBytes.length}`)
  }

  // 2. strict carrier: subject == M, exactly-one envelope, statement-governed document (D150/D159)
  const carrierOutcome = await parseEvidenceCarrier(client, manifestBytes, locator.subjectManifestDigest)
  if (!('carrier' in carrierOutcome)) {
    return reject(carrierOutcome.error.message)
  }
  const { carrier } = carrierOutcome

  // 3. D150 — semantic binding: Evidence subject.contentHash == independently known C
  const binding = verifyEvidenceSubject(carrier.envelope, actualContentHash)
  if (!binding.ok) {
    return reject(binding.error)
  }

  // 4. D152 — evidenceType is the VERIFIED Envelope.type; the OCI declaration is diagnostic
  return {
    kind: 'candidate',
    candidate: {
      source,
      subject: {
        registry: locator.registry,
        repository: locator.repository,
        manifestDigest: locator.subjectManifestDigest,
        contentHash: actualContentHash,
      },
      referrerManifestDigest: descriptor.digest,
      ...(descriptor.artifactType !== undefined ? { declaredArtifactType: descriptor.artifactType } : {}),
      evidenceType: carrier.envelope.type,
      envelope: carrier.envelope,
      ...(carrier.document !== undefined
        ? { document: { mediaType: carrier.document.mediaType, digest: carrier.document.digest, bytes: carrier.document.bytes } }
        : {}),
    },
  }
}
