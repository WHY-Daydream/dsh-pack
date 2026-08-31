/**
 * v0.6.0 Remote Evidence Discovery (DESIGN-v0.6.0.md §4/§8):
 *
 * alpha.1 read path (D149/D150/D152/D153/D157/D158):
 *   remote image ref → resolve mutable tag ONCE → immutable M → discover ALL
 *   referrers (native + pagination + standard fallback) → fetch each evidence
 *   manifest → OCI integrity + subject == M → strict carrier → DSH Evidence
 *   verification → subject.contentHash == independently-known C → candidates.
 *
 * alpha.3 cache layer (D166–D174):
 *   - online: REMOTE enumeration is always authoritative (a snapshot never
 *     shadows newer referrers, D169/D174); CAS only skips immutable object
 *     downloads (D167); complete enumerations are snapshot-captured
 *     atomically (D171); corrupt CAS objects fail loud and, online, are
 *     deleted + re-fetched (D172).
 *   - offline: EXPLICIT mode only — a complete snapshot + complete CAS
 *     reconstructs candidates (source = cached-snapshot); anything partial
 *     fails OFFLINE_CACHE_INCOMPLETE, never partial (D170).
 *
 * The cache is a BYTES store (D166): no trust verdicts, no TTL, no GC,
 * no code execution (D148/D165).
 * @module @why-daydream/dsh-pack/evidence/remote/discovery
 */

import { RegistryClient } from '../../image/registry/client.ts'
import type { RegistryCredentials } from '../../image/registry/auth.ts'
import { digestOf } from '../../image/registry/descriptor.ts'
import { parseRemoteReference, registryBaseUrl, repoPath, type RemoteReference } from '../../image/registry/reference.ts'
import { verifyEvidenceSubject } from '../envelope.ts'
import { parseEvidenceCarrier } from './carrier.ts'
import { CacheCorruptionError, RemoteEvidenceCache } from './cache.ts'
import { discoverReferrers } from './referrers.ts'
import { OfflineCacheGapError } from './types.ts'
import type {
  EvidenceCacheMode,
  EvidenceCacheStats,
  OfflineCacheError,
  ReferrerDescriptor,
  RemoteEvidenceCandidate,
  RemoteEvidenceDiscoveryError,
  RemoteEvidenceDiscoveryResult,
  RemoteEvidenceDiscoveryResultCached,
  RemoteEvidenceDiscoverySnapshot,
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
 * the artifact referenced by `opts.reference`. Cache-free — identical
 * behavior to alpha.1 (offline-mode callers must use discoverRemoteEvidenceCached).
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
  const cached = await discoverRemoteEvidenceCached({ ...opts, mode: 'online' })
  if (cached.complete) {
    return { complete: true, candidates: cached.candidates, rejected: cached.rejected }
  }
  return { complete: false, error: toDiscoveryError(cached.error) }
}

/** alpha.3 — discovery with explicit cache participation (D166–D174). */
export interface DiscoverRemoteEvidenceCachedOptions extends DiscoverRemoteEvidenceOptions {
  /** D174 — `online` keeps remote enumeration authoritative; `offline` is EXPLICIT. */
  mode?: EvidenceCacheMode
  /** The content-addressed object + snapshot cache (D166). Omitted = no caching. */
  cache?: RemoteEvidenceCache
}

export async function discoverRemoteEvidenceCached(
  opts: DiscoverRemoteEvidenceCachedOptions,
): Promise<RemoteEvidenceDiscoveryResultCached> {
  const mode: EvidenceCacheMode = opts.mode ?? 'online'
  const cache = opts.cache
  const stats: EvidenceCacheStats = {
    mode,
    objectCacheHits: 0,
    objectCacheMisses: 0,
    snapshotHit: false,
    snapshotStored: false,
    corruptionRepaired: false,
  }

  let ref: RemoteReference
  try {
    ref = parseRemoteReference(opts.reference)
  } catch (error) {
    return {
      complete: false,
      error: { kind: 'REFERENCE_ERROR', message: String(error) },
      cache: stats,
    }
  }

  // D174 — offline is EXPLICIT and never reached by an online failure. The
  // offline path performs NO remote calls, so the reference must already be
  // digest-anchored (M is given; no tag resolution is possible).
  if (mode === 'offline') {
    if (ref.digest === undefined) {
      return {
        complete: false,
        error: { kind: 'REFERENCE_ERROR', message: 'offline discovery requires a digest-anchored reference (registry/repo@sha256:M)' },
        cache: stats,
      }
    }
    if (cache === undefined) {
      return {
        complete: false,
        error: { kind: 'REFERENCE_ERROR', message: 'offline discovery requires a cache' },
        cache: stats,
      }
    }
    return offlineReconstruct(cache, stats, {
      registry: ref.registry,
      repository: repoPath(ref),
      subjectManifestDigest: ref.digest,
    }, opts)
  }

  // online
  const base = registryBaseUrl(ref.registry)
  const clientOptions: ConstructorParameters<typeof RegistryClient>[0] = { baseUrl: base, repo: repoPath(ref) }
  if (opts.credentials !== undefined) clientOptions.credentials = opts.credentials
  const client = new RegistryClient(clientOptions)

  let locator: RemoteEvidenceLocator
  try {
    // D149 — resolve the mutable tag EXACTLY ONCE to immutable M.
    const manifestDigest = ref.digest ?? (await client.getManifest(ref.tag ?? 'latest')).digest
    locator = { registry: ref.registry, repository: repoPath(ref), subjectManifestDigest: manifestDigest }
  } catch (error) {
    const status = (error as { status?: unknown } | null)?.status
    const message = `cannot resolve remote reference: ${String(error)}`
    return {
      complete: false,
      error: typeof status === 'number' ? { kind: 'REGISTRY_ERROR', status, message } : { kind: 'REFERENCE_ERROR', message },
      cache: stats,
    }
  }

  // D169 — online enumeration is ALWAYS remote: the snapshot cache never
  // participates in deciding WHICH referrers exist.
  const filter = opts.artifactTypes !== undefined && opts.artifactTypes.length === 1 ? opts.artifactTypes[0] : undefined
  let enumeration: Awaited<ReturnType<typeof discoverReferrers>>
  try {
    enumeration = await discoverReferrers(client, locator, filter)
  } catch (error) {
    return { complete: false, error: error as RemoteEvidenceDiscoveryError, cache: stats }
  }

  const candidates: RemoteEvidenceCandidate[] = []
  const rejected: RejectedRemoteEvidence[] = []
  for (const descriptor of enumeration.descriptors) {
    const outcome = await verifyOneReferrer(client, locator, enumeration.source, descriptor, opts.actualContentHash, {
      ...(cache !== undefined ? { cache } : {}),
      stats,
      offline: false,
    })
    if (outcome.kind === 'candidate') candidates.push(outcome.candidate)
    else if (outcome.kind === 'rejected') rejected.push(outcome.rejected)
    // online never produces 'offline-incomplete' (that would be an internal bug — fail loud)
  }

  // D171 — only a COMPLETE enumeration is ever snapshotted (all-or-nothing);
  // an incomplete one can never create or overwrite a known-complete one.
  if (cache !== undefined) {
    const snapshot: RemoteEvidenceDiscoverySnapshot = {
      registry: locator.registry,
      repository: locator.repository,
      subjectManifestDigest: locator.subjectManifestDigest,
      source: enumeration.source,
      complete: true,
      descriptors: enumeration.descriptors,
      capturedAt: new Date().toISOString(),
    }
    cache.putDiscoverySnapshot(snapshot)
    stats.snapshotStored = true
  }

  return { complete: true, candidates, rejected, source: 'remote', mode: enumeration.source, cache: stats }
}

/** Map an offline failure into the (frozen) discovery error union for the cache-free entry. */
function toDiscoveryError(error: RemoteEvidenceDiscoveryError | OfflineCacheError): RemoteEvidenceDiscoveryError {
  if (error.kind === 'OFFLINE_CACHE_INCOMPLETE') {
    return { kind: 'REGISTRY_ERROR', status: 599, message: `offline cache incomplete: ${error.reason} — ${error.message}` }
  }
  return error
}

/** D170 — offline reconstruction from a complete snapshot + complete CAS only. */
async function offlineReconstruct(
  cache: RemoteEvidenceCache,
  stats: EvidenceCacheStats,
  locator: RemoteEvidenceLocator,
  opts: DiscoverRemoteEvidenceCachedOptions,
): Promise<RemoteEvidenceDiscoveryResultCached> {
  let snapshot: RemoteEvidenceDiscoverySnapshot | undefined
  try {
    snapshot = cache.getDiscoverySnapshot(locator)
  } catch {
    return {
      complete: false,
      error: { kind: 'OFFLINE_CACHE_INCOMPLETE', reason: 'corrupt-object', message: 'discovery snapshot cache is corrupt' },
      cache: stats,
    }
  }
  if (snapshot === undefined) {
    return {
      complete: false,
      error: { kind: 'OFFLINE_CACHE_INCOMPLETE', reason: 'no-snapshot', message: 'no complete discovery snapshot cached for this locator' },
      cache: stats,
    }
  }
  stats.snapshotHit = true

  // Offline makes NO remote calls, so there is no RegistryClient — the only
  // client method the verification chain needs is the PURE descriptor
  // validator (digest + size), which is reimplemented here byte-for-byte
  // (same messages as RegistryClient.verifyDescriptor) so the offline path
  // can never accidentally perform network I/O (D148/D165).
  const offlineClient = {
    verifyDescriptor: (what: string, descriptor: { digest: string; size: number }, bytes: Buffer): void => {
      const actualDigest = digestOf(bytes)
      if (bytes.length !== descriptor.size) {
        throw new Error(`${what} size mismatch: expected ${descriptor.size}, actual ${bytes.length} (transport integrity failure)`)
      }
      if (actualDigest !== descriptor.digest) {
        throw new Error(`${what} digest mismatch: expected ${descriptor.digest}, actual ${actualDigest} (transport integrity failure)`)
      }
    },
  } as unknown as RegistryClient

  const candidates: RemoteEvidenceCandidate[] = []
  const rejected: RejectedRemoteEvidence[] = []
  for (const descriptor of snapshot.descriptors) {
    const outcome = await verifyOneReferrer(offlineClient, locator, snapshot.source, descriptor, opts.actualContentHash, {
      cache,
      stats,
      offline: true,
    })
    if (outcome.kind === 'candidate') candidates.push(outcome.candidate)
    else {
      if (outcome.kind === 'offline-incomplete') {
        // D170 — NEVER a partial Evidence Set: fail loud, keep nothing
        return { complete: false, error: outcome.error, cache: stats }
      }
      rejected.push(outcome.rejected)
    }
  }

  return { complete: true, candidates, rejected, source: 'cached-snapshot', mode: snapshot.source, cache: stats }
}

type ReferrerOutcome =
  | { kind: 'candidate'; candidate: RemoteEvidenceCandidate }
  | { kind: 'rejected'; rejected: RejectedRemoteEvidence }
  | { kind: 'offline-incomplete'; error: OfflineCacheError }

interface ReferrerVerifyOptions {
  cache?: RemoteEvidenceCache
  stats: EvidenceCacheStats
  offline: boolean
}

/** Fetch + verify ONE referrer object (untrusted enumeration metadata → candidate). */
async function verifyOneReferrer(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  source: 'referrers-api' | 'tag-fallback',
  descriptor: ReferrerDescriptor,
  actualContentHash: string,
  opts: ReferrerVerifyOptions,
): Promise<ReferrerOutcome> {
  const { cache, stats, offline } = opts
  const reject = (reason: string): ReferrerOutcome => ({
    kind: 'rejected',
    rejected: { referrerManifestDigest: descriptor.digest, reason, ...(descriptor.artifactType !== undefined ? { declaredArtifactType: descriptor.artifactType } : {}) },
  })

  const offlineFail = (reason: 'missing-object' | 'corrupt-object', what: string): ReferrerOutcome => ({
    kind: 'offline-incomplete',
    error: { kind: 'OFFLINE_CACHE_INCOMPLETE', reason, message: `${what} not fully cached (offline)` },
  })

  // D166/D167 — fetch by digest with CAS (hit → digest REVALIDATED, miss →
  // remote + store). The path is content-addressed: bytes never trusted.
  const fetchObject = async (
    kind: 'manifests' | 'blobs',
    digest: string,
    remote: () => Promise<Buffer>,
    what: string,
  ): Promise<{ bytes: Buffer } | { offline: true; reason: 'missing-object' | 'corrupt-object' } | { failed: string }> => {
    if (cache !== undefined) {
      try {
        const hit = cache.getOciObject(kind, digest)
        if (hit !== undefined) {
          stats.objectCacheHits += 1
          return { bytes: hit }
        }
      } catch (error) {
        if (error instanceof CacheCorruptionError) {
          if (offline) {
            // D172 offline — no trusted re-fetch source: FAIL
            return { offline: true, reason: 'corrupt-object' }
          }
          // D172 online — detected, deleted, re-fetched by the SAME immutable digest
          cache.deleteCorruptObject(kind, digest)
          stats.corruptionRepaired = true
        } else {
          throw error
        }
      }
    }
    stats.objectCacheMisses += 1
    if (offline) return { offline: true, reason: 'missing-object' }
    try {
      const bytes = await remote()
      if (cache !== undefined) cache.putOciObject(kind, digest, bytes)
      return { bytes }
    } catch (error) {
      return { failed: what === 'evidence manifest' ? `evidence manifest fetch failed: ${String(error)}` : String(error) }
    }
  }

  // 1. fetch the evidence manifest RAW by digest + verify OCI digest/size.
  //    Evidence carriers are OCI ARTIFACT manifests (empty config) — the DSH
  //    agent-envelope validator must NOT be applied here; carrier structure is
  //    validated by parseEvidenceCarrier (D152/D159).
  const manifestFetch = await fetchObject('manifests', descriptor.digest, () => (async () => {
    const raw = await client.getManifestRaw(descriptor.digest)
    if (raw.status !== 200 || raw.body === undefined) throw new Error(`evidence manifest fetch failed (status ${raw.status})`)
    return raw.body
  })(), 'evidence manifest')
  if ('offline' in manifestFetch) return offlineFail(manifestFetch.reason, 'evidence manifest')
  if ('failed' in manifestFetch) return reject(manifestFetch.failed)
  const manifestBytes = manifestFetch.bytes
  const actualDigest = digestOf(manifestBytes)
  if (actualDigest !== descriptor.digest) {
    return reject(`evidence manifest digest mismatch: descriptor=${descriptor.digest} actual=${actualDigest}`)
  }
  if (manifestBytes.length !== descriptor.size) {
    return reject(`evidence manifest size mismatch: descriptor=${descriptor.size} actual=${manifestBytes.length}`)
  }

  // 2. strict carrier: subject == M, exactly-one envelope, statement-governed
  //    document (D150/D159). Layer blobs go through the same CAS path.
  let carrierOutcome: Awaited<ReturnType<typeof parseEvidenceCarrier>>
  try {
    carrierOutcome = await parseEvidenceCarrier(
      client,
      manifestBytes,
      locator.subjectManifestDigest,
      async (digest) => {
        const fetched = await fetchObject('blobs', digest, async () => client.getBlob(digest), 'evidence layer blob')
        if ('offline' in fetched) throw new OfflineCacheGapError(fetched.reason, 'evidence layer blob')
        if ('failed' in fetched) throw new Error(fetched.failed)
        return fetched.bytes
      },
    )
  } catch (error) {
    // D170 — an offline availability gap is NOT a carrier defect: fail loud
    // as OFFLINE_CACHE_INCOMPLETE (never INVALID_CARRIER, never partial).
    if (error instanceof OfflineCacheGapError) {
      return offlineFail(error.reason, error.what)
    }
    throw error
  }
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
