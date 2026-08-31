/**
 * v0.4.1 OCI Registry client (DESIGN-v0.4.1.md §5/§8, D38/D40): the HTTP
 * primitive layer — GET/PUT/HEAD blob, GET/PUT manifest, anonymous +
 * username/token (Basic) + Bearer challenge with a single retry round, and
 * Docker-Content-Digest verification on manifest PUT. Transport digests are
 * always recomputed from actual bytes; headers are never trusted for identity.
 * @module @why-daydream/dsh-pack/image/registry/client
 */

import { basicAuthHeader, loadRegistryCredentials, parseWwwAuthenticate, type AuthChallenge, type RegistryCredentials } from './auth.ts'
import { digestOf, manifestDigestOf } from './descriptor.ts'
import { validateOciManifest, OCI_IMAGE_MANIFEST_MEDIA_TYPE, type OciImageManifest } from './manifest.ts'
import { blobEndpoint, manifestEndpoint, referrersEndpoint, uploadsEndpoint } from './reference.ts'
import type { OciBlobDigest, OciManifestDigest } from './types.ts'

export interface RegistryFetchResult {
  status: number
  headers: Record<string, string>
  body?: Buffer
}

export interface RegistryClientOptions {
  /** `https://<registry>` (http for localhost). */
  baseUrl: string
  /** `namespace/name`. */
  repo: string
  credentials?: RegistryCredentials
}

export class RegistryError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message)
    this.name = 'RegistryError'
  }
}

/** Minimal OCI Distribution client (v0.4.1 subset). */
export class RegistryClient {
  private readonly credentials: RegistryCredentials

  constructor(private readonly options: RegistryClientOptions) {
    this.credentials = options.credentials ?? loadRegistryCredentials(options.baseUrl.replace(/^https?:\/\//, ''))
  }

  private async raw(method: string, url: string, headers: Record<string, string>, body?: Buffer): Promise<RegistryFetchResult> {
    let response: Response
    try {
      response = await fetch(url, {
        method,
        headers,
        ...(body !== undefined ? { body: body as Uint8Array } : {}),
        redirect: 'follow',
      })
    } catch (error) {
      throw new Error(`registry request failed (${method} ${url}): ${String(error)}`)
    }
    const outHeaders: Record<string, string> = {}
    response.headers.forEach((value, key) => { outHeaders[key] = value })
    const content = Buffer.from(await response.arrayBuffer())
    return { status: response.status, headers: outHeaders, ...(content.byteLength > 0 ? { body: content } : {}) }
  }

  /** One auth round: initial attempt → 401 → Bearer token fetch / Basic → retry once. */
  private async request(method: string, url: string, headers: Record<string, string> = {}, body?: Buffer): Promise<RegistryFetchResult> {
    const initial: Record<string, string> = { ...headers }
    if (this.credentials.token !== undefined) initial['Authorization'] = `Bearer ${this.credentials.token}`
    else if (this.credentials.username !== undefined && this.credentials.password !== undefined) {
      initial['Authorization'] = basicAuthHeader(this.credentials.username, this.credentials.password)
    }

    let result = await this.raw(method, url, initial, body)
    if (result.status !== 401) return result

    const challenge = parseWwwAuthenticate(result.headers['www-authenticate'])
    if (challenge === undefined) return result

    if (challenge.scheme === 'bearer') {
      const token = await this.fetchBearerToken(challenge)
      if (token === undefined) return result
      result = await this.raw(method, url, { ...headers, Authorization: `Bearer ${token}` }, body)
    } else if (challenge.scheme === 'basic' && this.credentials.username !== undefined && this.credentials.password !== undefined) {
      result = await this.raw(method, url, {
        ...headers,
        Authorization: basicAuthHeader(this.credentials.username, this.credentials.password),
      }, body)
    }
    return result
  }

  /** Bearer token fetch: GET realm?service&scope (Basic if we have creds). */
  private async fetchBearerToken(challenge: Extract<AuthChallenge, { scheme: 'bearer' }>): Promise<string | undefined> {
    const url = new URL(challenge.realm)
    // rc.1 Review (RI-28/D198) — the realm comes from the UNTRUSTED 401
    // challenge (D191: registry input is never trusted). It must live on the
    // SAME origin as the registry: otherwise the Basic credentials would be
    // shipped to an arbitrary host controlled by the challenger. A foreign
    // realm is refused WITHOUT a request — the 401 result then stands and the
    // caller fails closed.
    if (url.origin !== new URL(this.options.baseUrl).origin) {
      return undefined
    }
    if (challenge.service !== undefined) url.searchParams.set('service', challenge.service)
    if (challenge.scope !== undefined) url.searchParams.set('scope', challenge.scope)
    const headers: Record<string, string> = {}
    if (this.credentials.username !== undefined && this.credentials.password !== undefined) {
      headers['Authorization'] = basicAuthHeader(this.credentials.username, this.credentials.password)
    }
    const result = await this.raw('GET', url.toString(), headers)
    if (result.status !== 200 || result.body === undefined) return undefined
    try {
      const parsed = JSON.parse(result.body.toString('utf8')) as { token?: string; access_token?: string }
      return parsed.token ?? parsed.access_token
    } catch {
      return undefined
    }
  }

  /** HEAD blob: 200 → exists, 404 → missing, else error. */
  async blobExists(digest: OciBlobDigest): Promise<boolean> {
    const result = await this.request('HEAD', blobEndpoint(this.options.baseUrl, this.options.repo, digest))
    if (result.status === 200) return true
    if (result.status === 404) return false
    throw new RegistryError(result.status, `blob HEAD failed (status ${result.status})`)
  }

  /** Monolithic blob upload: POST uploads/ → PUT <location>?digest=. */
  async uploadBlob(digest: OciBlobDigest, bytes: Buffer): Promise<void> {
    if (await this.blobExists(digest)) return // idempotent
    const start = await this.request('POST', uploadsEndpoint(this.options.baseUrl, this.options.repo), { 'Content-Length': '0' })
    if (start.status !== 202) {
      throw new RegistryError(start.status, `blob upload start failed (status ${start.status})`)
    }
    const location = start.headers['location']
    if (location === undefined) throw new Error('registry upload response missing Location header')
    const uploadUrl = new URL(location, this.options.baseUrl)
    uploadUrl.searchParams.set('digest', digest)
    const put = await this.request('PUT', uploadUrl.toString(), {
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(bytes.length),
    }, bytes)
    if (put.status !== 201) {
      throw new RegistryError(put.status, `blob upload PUT failed (status ${put.status})`)
    }
  }

  /** GET a blob by digest; the caller verifies digest/size from actual bytes. */
  async getBlob(digest: OciBlobDigest): Promise<Buffer> {
    const result = await this.request('GET', blobEndpoint(this.options.baseUrl, this.options.repo, digest))
    if (result.status !== 200 || result.body === undefined) {
      throw new RegistryError(result.status, `blob GET failed (status ${result.status})`)
    }
    return result.body
  }

  /** GET manifest by tag or digest; transport digest recomputed from bytes. */
  async getManifest(tagOrDigest: string): Promise<{ bytes: Buffer; digest: OciManifestDigest; manifest: OciImageManifest }> {
    const result = await this.request('GET', manifestEndpoint(this.options.baseUrl, this.options.repo, tagOrDigest), {
      Accept: OCI_IMAGE_MANIFEST_MEDIA_TYPE,
    })
    if (result.status !== 200 || result.body === undefined) {
      throw new RegistryError(result.status, `manifest GET failed (status ${result.status})`)
    }
    const bytes = result.body
    let parsed: ReturnType<typeof validateOciManifest>
    try {
      parsed = validateOciManifest(JSON.parse(bytes.toString('utf8')))
    } catch {
      throw new Error('registry returned an unparseable manifest')
    }
    if (!parsed.ok) {
      throw new Error(`registry returned an invalid OCI envelope: ${parsed.errors.join('; ')}`)
    }
    return { bytes, digest: manifestDigestOf(bytes.toString('utf8')), manifest: parsed.manifest }
  }

  /** GET manifest bytes WITHOUT image-manifest validation — e.g. the referrers-tag IMAGE INDEX (D151 fallback). */
  async getManifestRaw(tagOrDigest: string): Promise<RegistryFetchResult> {
    return this.request('GET', manifestEndpoint(this.options.baseUrl, this.options.repo, tagOrDigest), {
      Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json',
    })
  }

  /** GET `/v2/<repo>/referrers/<digest>` — distribution-spec 1.1 Referrers API (end-12a/12b). Raw result; callers own status semantics. */
  async getReferrers(subjectDigest: string, artifactType?: string): Promise<RegistryFetchResult> {
    const url = new URL(referrersEndpoint(this.options.baseUrl, this.options.repo, subjectDigest))
    if (artifactType !== undefined) url.searchParams.set('artifactType', artifactType)
    return this.request('GET', url.toString(), {
      Accept: 'application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json',
    })
  }

  /** Raw authenticated request to an absolute URL (referrers pagination `Link rel=next`). */
  async requestAbsolute(method: string, url: string, headers: Record<string, string> = {}, body?: Buffer): Promise<RegistryFetchResult> {
    return this.request(method, url, headers, body)
  }

  /** PUT manifest; verifies the returned Docker-Content-Digest when present. */
  async putManifest(tagOrDigest: string, manifestBytes: Buffer): Promise<OciManifestDigest> {
    const expected = manifestDigestOf(manifestBytes.toString('utf8'))
    const result = await this.request('PUT', manifestEndpoint(this.options.baseUrl, this.options.repo, tagOrDigest), {
      'Content-Type': OCI_IMAGE_MANIFEST_MEDIA_TYPE,
      'Content-Length': String(manifestBytes.length),
    }, manifestBytes)
    if (result.status !== 201 && result.status !== 200) {
      throw new RegistryError(result.status, `manifest PUT failed (status ${result.status})`)
    }
    const reported = result.headers['docker-content-digest']
    if (reported !== undefined && reported !== expected) {
      throw new Error(`Docker-Content-Digest mismatch: registry reported ${reported}, expected ${expected}`)
    }
    return expected
  }

  /**
   * PUT manifest with OPTIONAL If-Match (D164 conditional fallback push) and
   * RAW result — callers read status (412 conflict) and headers (OCI-Subject,
   * Docker-Content-Digest). The strict putManifest is unchanged.
   */
  async putManifestRaw(tagOrDigest: string, manifestBytes: Buffer, opts?: { ifMatch?: string }): Promise<RegistryFetchResult> {
    const headers: Record<string, string> = {
      'Content-Type': OCI_IMAGE_MANIFEST_MEDIA_TYPE,
      'Content-Length': String(manifestBytes.length),
    }
    if (opts?.ifMatch !== undefined) headers['If-Match'] = opts.ifMatch
    return this.request('PUT', manifestEndpoint(this.options.baseUrl, this.options.repo, tagOrDigest), headers, manifestBytes)
  }

  /** Verify actual bytes against a descriptor (digest + size). */
  verifyDescriptor(what: string, descriptor: { digest: string; size: number }, bytes: Buffer): void {
    const actualDigest = digestOf(bytes)
    if (bytes.length !== descriptor.size) {
      throw new Error(`${what} size mismatch: expected ${descriptor.size}, actual ${bytes.length} (transport integrity failure)`)
    }
    if (actualDigest !== descriptor.digest) {
      throw new Error(`${what} digest mismatch: expected ${descriptor.digest}, actual ${actualDigest} (transport integrity failure)`)
    }
  }
}
