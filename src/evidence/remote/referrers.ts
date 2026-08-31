/**
 * v0.6.0-alpha.1 OCI Referrers discovery (DESIGN-v0.6.0.md §4.1/§5, D151/D158):
 * native Referrers API with FULL `Link rel=next` pagination consumption, and
 * the OCI 1.1 standard referrers-tag fallback — ONLY on a 404. There is no
 * DSH-private discovery scheme; 401/403/5xx/timeout are errors, never
 * "registry does not support Referrers" signals (D151 note).
 *
 * `OCI-Filters-Applied: artifactType` on the first response is the ONLY way
 * server-side artifactType filtering is assumed (D152 note); otherwise the
 * enumeration is treated as unfiltered.
 * @module @why-daydream/dsh-pack/evidence/remote/referrers
 */

import { RegistryClient } from '../../image/registry/client.ts'
import { referrersEndpoint, registryBaseUrl } from '../../image/registry/reference.ts'
import type { ReferrerDescriptor, RemoteEvidenceLocator, RemoteEvidenceDiscoveryError } from './types.ts'

/** OCI image index media type — the referrers response / fallback tag payload. */
export const OCI_IMAGE_INDEX_MEDIA_TYPE = 'application/vnd.oci.image.index.v1+json'

/**
 * OCI referrers-tag schema (distribution-spec §Referrers Tag Schema): the tag
 * for a subject digest is `<truncated-algorithm>-<truncated-encoded>` (e.g.
 * `sha256-<64 hex>`), containing an OCI IMAGE INDEX of the referrers.
 */
export function referrersTagFor(subjectDigest: string): string {
  const match = /^([A-Za-z0-9+.-]+):([A-Za-z0-9=_-]+)$/.exec(subjectDigest)
  if (match === null) throw new Error(`invalid OCI digest for referrers tag: ${JSON.stringify(subjectDigest)}`)
  const algorithm = match[1]!.slice(0, 32)
  const encoded = match[2]!.replace(/[^A-Za-z0-9_]/g, '-').slice(0, 64)
  return `${algorithm}-${encoded}`
}

/** A COMPLETE referrers enumeration (D158: all pages consumed, or nothing). */
export interface ReferrersEnumeration {
  source: 'referrers-api' | 'tag-fallback'
  /** `OCI-Filters-Applied: artifactType` present on the first response (D152 note). */
  filtersApplied: boolean
  /** Untrusted enumeration metadata — never directly a candidate (D152/D153). */
  descriptors: ReferrerDescriptor[]
}

interface OciImageIndex {
  schemaVersion?: unknown
  mediaType?: unknown
  manifests?: unknown
}

/** Parse raw bytes as an OCI image index; undefined if invalid. */
function parseImageIndex(body: Buffer): OciImageIndex | undefined {
  let parsed: unknown
  try {
    parsed = JSON.parse(body.toString('utf8'))
  } catch {
    return undefined
  }
  if (parsed === null || typeof parsed !== 'object') return undefined
  const index = parsed as Record<string, unknown>
  if (index.schemaVersion !== 2) return undefined
  if (typeof index.mediaType === 'string' && index.mediaType !== OCI_IMAGE_INDEX_MEDIA_TYPE) return undefined
  if (!Array.isArray(index.manifests)) return undefined
  return index as unknown as OciImageIndex
}

/** Extract untrusted referrer descriptors (digest/size only) from an index body. */
function descriptorsFromIndex(body: Buffer): ReferrerDescriptor[] {
  const index = parseImageIndex(body)
  if (index === undefined || !Array.isArray(index.manifests)) return []
  const out: ReferrerDescriptor[] = []
  for (const entry of index.manifests as unknown[]) {
    const item = entry as Record<string, unknown> | null
    if (item === null || typeof item !== 'object') continue
    if (typeof item.digest !== 'string' || typeof item.size !== 'number') continue
    out.push({
      digest: item.digest,
      size: item.size,
      ...(typeof item.artifactType === 'string' ? { artifactType: item.artifactType } : {}),
      ...(item.annotations !== null && typeof item.annotations === 'object'
        ? { annotations: item.annotations as Record<string, string> }
        : {}),
    })
  }
  return out
}

/** The `Link: <url>; rel="next"` URL from a response header (RFC 5988). */
function nextPageUrl(linkHeader: string | undefined): string | undefined {
  if (linkHeader === undefined) return undefined
  for (const part of linkHeader.split(',')) {
    const match = /<([^>]+)>\s*;\s*rel="?next"?/.exec(part.trim())
    if (match !== null) return match[1]
  }
  return undefined
}

/** RegistryError without a status (transport failure) → REGISTRY_ERROR status 0. */
function registryError(message: string): RemoteEvidenceDiscoveryError {
  return { kind: 'REGISTRY_ERROR', status: 0, message }
}

/**
 * D158 — discover ALL referrers of `locator.subjectManifestDigest`:
 *   - native Referrers API (200): follow every `Link rel=next` page to EOF;
 *     any page failure makes the whole enumeration DISCOVERY_INCOMPLETE.
 *   - 404: standard referrers-tag fallback (D151); fallback 404 / non-index
 *     payload ⇒ assume no referrers (spec); fallback transport/5xx ⇒ incomplete.
 *   - anything else (401/403/5xx/timeout): REGISTRY_ERROR, NEVER fallback.
 */
export async function discoverReferrers(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  artifactType?: string,
): Promise<ReferrersEnumeration> {
  const base = registryBaseUrl(locator.registry)
  const firstUrl = referrersEndpoint(base, locator.repository, locator.subjectManifestDigest)

  let first: Awaited<ReturnType<RegistryClient['getReferrers']>>
  try {
    first = await client.getReferrers(locator.subjectManifestDigest, artifactType)
  } catch (error) {
    throw registryError(`referrers request failed (${firstUrl}): ${String(error)}`)
  }

  if (first.status === 200) {
    const descriptors = await collectReferrersPages(client, locator, firstUrl, first)
    const filtersApplied = first.headers['oci-filters-applied'] === 'artifactType'
    return { source: 'referrers-api', filtersApplied, descriptors }
  }

  if (first.status === 404) {
    return discoverViaFallbackTag(client, locator)
  }

  throw { kind: 'REGISTRY_ERROR', status: first.status, message: `referrers request returned status ${first.status} (no fallback)` } as RemoteEvidenceDiscoveryError
}

/** Native path: consume the first page + ALL Link rel=next pages (D158). */
async function collectReferrersPages(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  firstUrl: string,
  first: Awaited<ReturnType<RegistryClient['getReferrers']>>,
): Promise<ReferrerDescriptor[]> {
  // rc.1 Review (RI-21) — the FIRST page must be a valid OCI image index too:
  // a garbage first page must not masquerade as "no referrers" (consistent
  // with the mid-chain page check below, D158). The tag-fallback spec tolerance
  // (D151: non-index tag ⇒ assume none) is fallback-only and unchanged.
  if (first.body !== undefined && parseImageIndex(first.body) === undefined) {
    throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers first page is not a valid OCI image index (${firstUrl})` } as RemoteEvidenceDiscoveryError
  }
  const descriptors: ReferrerDescriptor[] = []
  if (first.body !== undefined) descriptors.push(...descriptorsFromIndex(first.body))

  // rc.1 (D193) — pagination is a TRUST BOUNDARY: the enumeration is only
  // complete when every page was consumed from the SAME registry origin and
  // the link chain terminates. A cross-origin or looping `Link rel=next` is
  // NEVER followed — both fail closed as DISCOVERY_INCOMPLETE.
  const firstOrigin = new URL(firstUrl).origin
  const visited = new Set<string>([firstUrl])

  let next = nextPageUrl(first.headers['link'])
  while (next !== undefined) {
    let resolved: URL
    try {
      resolved = new URL(next, firstUrl)
    } catch {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `invalid referrers next link ${JSON.stringify(next)} (D193)` } as RemoteEvidenceDiscoveryError
    }
    // D193 — a next link pointing OUTSIDE the registry origin is rejected
    // WITHOUT a request: following it would (a) leak the registry credentials
    // to an arbitrary host and (b) let a foreign enumeration smuggle itself
    // into this repository's Evidence Set (D191/D197).
    if (resolved.origin !== firstOrigin) {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers page ${resolved} is outside the registry origin ${firstOrigin} (cross-origin next link rejected, D193)` } as RemoteEvidenceDiscoveryError
    }
    // D193 — a pagination loop (next pointing back to an already-consumed
    // page) must never be mistaken for completeness: fail closed instead of
    // looping forever.
    if (visited.has(resolved.toString())) {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers pagination loop detected at ${resolved} (D193)` } as RemoteEvidenceDiscoveryError
    }
    visited.add(resolved.toString())
    let page: Awaited<ReturnType<RegistryClient['requestAbsolute']>>
    try {
      page = await client.requestAbsolute('GET', resolved.toString(), {
        Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json',
      })
    } catch (error) {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers page fetch failed (${resolved}): ${String(error)}` } as RemoteEvidenceDiscoveryError
    }
    if (page.status !== 200 || page.body === undefined) {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers page ${resolved} returned status ${page.status}` } as RemoteEvidenceDiscoveryError
    }
    // a page that is not a valid image index mid-chain must never silently drop
    // referrers — partial enumeration must not masquerade as complete (D158)
    if (parseImageIndex(page.body) === undefined) {
      throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers page ${resolved} is not a valid OCI image index` } as RemoteEvidenceDiscoveryError
    }
    descriptors.push(...descriptorsFromIndex(page.body))
    next = nextPageUrl(page.headers['link'])
  }
  return descriptors
}

/** D151 fallback: the standard `<algorithm>-<hex>` tag holding the image index. */
async function discoverViaFallbackTag(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
): Promise<ReferrersEnumeration> {
  const tag = referrersTagFor(locator.subjectManifestDigest)
  let fallback: Awaited<ReturnType<RegistryClient['getManifestRaw']>>
  try {
    fallback = await client.getManifestRaw(tag)
  } catch (error) {
    throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers-tag fallback fetch failed (${tag}): ${String(error)}` } as RemoteEvidenceDiscoveryError
  }
  if (fallback.status === 404) {
    // spec: fallback tag absent ⇒ assume there are no referrers (fail-closed at policy time)
    return { source: 'tag-fallback', filtersApplied: false, descriptors: [] }
  }
  if (fallback.status !== 200 || fallback.body === undefined) {
    throw { kind: 'DISCOVERY_INCOMPLETE', message: `referrers-tag fallback (${tag}) returned status ${fallback.status}` } as RemoteEvidenceDiscoveryError
  }
  if (parseImageIndex(fallback.body) === undefined) {
    // spec: tag does not return a valid image index ⇒ assume no referrers
    return { source: 'tag-fallback', filtersApplied: false, descriptors: [] }
  }
  return { source: 'tag-fallback', filtersApplied: false, descriptors: descriptorsFromIndex(fallback.body) }
}

// ============================================================================
// alpha.2 — referrers-tag index update (publication side, D163/D164)
// ============================================================================

/** D164 — bounded retry budget for conditional fallback conflicts. */
export const FALLBACK_RETRY_LIMIT = 3

/** The transport facts of one fallback index update. */
export interface FallbackUpdateResult {
  tag: string
  concurrencyProtection: 'conditional' | 'none'
  retries: number
}

/**
 * D163 — pull the standard referrers-tag image index:
 *   - 404 → start from an EMPTY index
 *   - 200 + valid image index → the current entries (+ ETag when present)
 *   - 200 + NOT an image index → FAIL (never guess)
 *   - any other status → FAIL
 */
function fallbackEntriesFrom(read: Awaited<ReturnType<RegistryClient['getManifestRaw']>>): ReferrerDescriptor[] {
  if (read.status === 404) return []
  if (read.status !== 200 || read.body === undefined) {
    throw new Error(`referrers-tag read failed (status ${read.status})`)
  }
  if (parseImageIndex(read.body) === undefined) {
    throw new Error('referrers-tag does not hold a valid OCI image index (D163)')
  }
  return descriptorsFromIndex(read.body)
}

/** Build the image index bytes for a referrers-tag (D163 append semantics). */
function buildFallbackIndex(entries: ReferrerDescriptor[]): Buffer {
  return Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: OCI_IMAGE_INDEX_MEDIA_TYPE,
    manifests: entries.map((e) => ({
      digest: e.digest,
      size: e.size,
      ...(e.artifactType !== undefined ? { artifactType: e.artifactType } : {}),
      ...(e.annotations !== undefined ? { annotations: e.annotations } : {}),
    })),
  }), 'utf8')
}

/**
 * D163/D164 — append `descriptor` to the subject's standard referrers-tag
 * index:
 *   - existing descriptor → idempotent (no duplicate added)
 *   - otherwise append, PRESERVING all existing entries
 *   - conditional push (If-Match with the observed ETag) when the registry
 *     supports conditional requests; a 412 conflict → re-read → merge → retry
 *     (bounded by FALLBACK_RETRY_LIMIT)
 *   - without an ETag, concurrencyProtection is honestly 'none' — the client
 *     never claims linearizable fallback publication it cannot provide
 */
export async function updateReferrersTag(
  client: RegistryClient,
  locator: RemoteEvidenceLocator,
  descriptor: ReferrerDescriptor,
): Promise<FallbackUpdateResult> {
  const tag = referrersTagFor(locator.subjectManifestDigest)
  let read = await client.getManifestRaw(tag)
  let entries = fallbackEntriesFrom(read)
  let etag = read.headers['etag']

  if (entries.some((e) => e.digest === descriptor.digest)) {
    return { tag, concurrencyProtection: etag !== undefined ? 'conditional' : 'none', retries: 0 }
  }

  let retries = 0
  for (;;) {
    const merged = [...entries, descriptor]
    const indexBytes = buildFallbackIndex(merged)
    const put = await client.putManifestRaw(tag, indexBytes, etag !== undefined ? { ifMatch: etag } : undefined)
    if (put.status === 200 || put.status === 201) {
      return { tag, concurrencyProtection: etag !== undefined ? 'conditional' : 'none', retries }
    }
    if (put.status === 412 && etag !== undefined && retries < FALLBACK_RETRY_LIMIT) {
      // conflict: re-read → merge → retry (D164, bounded)
      retries += 1
      read = await client.getManifestRaw(tag)
      entries = fallbackEntriesFrom(read)
      etag = read.headers['etag']
      if (entries.some((e) => e.digest === descriptor.digest)) {
        return { tag, concurrencyProtection: 'conditional', retries }
      }
      continue
    }
    throw new Error(`referrers-tag fallback push failed (status ${put.status})`)
  }
}
