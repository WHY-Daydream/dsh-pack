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
  const descriptors: ReferrerDescriptor[] = []
  if (first.body !== undefined) descriptors.push(...descriptorsFromIndex(first.body))

  let next = nextPageUrl(first.headers['link'])
  while (next !== undefined) {
    const resolved = new URL(next, firstUrl)
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
