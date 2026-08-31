/**
 * Test-only OCI mock registry (v0.4.1 E2E vehicle): an in-process HTTP server
 * implementing the SAME Distribution protocol subset as GHCR that the
 * RegistryClient speaks — HEAD/GET blob, POST uploads/ + PUT blob, GET/PUT
 * manifest (tags AND digests addressable), optional Bearer challenge, and
 * injectable tamper modes for the North-Star criteria:
 *   - `tamper.blobDigest`: serve CORRUPTED bytes for that blob (criterion 4 →
 *     OCI transport integrity failure, DSH verify must not run)
 *   - `tamper.configContentHash`: at manifest PUT, replace the config blob
 *     with a DSH Image Manifest whose artifact.digest is overridden
 *     (criterion 5 → DSH artifact integrity failure after transport passed)
 */
import { createHash, randomUUID } from 'node:crypto'
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'

export interface MockRegistryTamper {
  /** Serve corrupted bytes for this blob digest. */
  blobDigest?: string
  /** Override the DSH contentHash inside the stored config blob. */
  configContentHash?: string
  /** Serve ANOTHER manifest's bytes under this digest (malicious registry). */
  manifestSwap?: { forDigest: string; serveTag: string }
  /** Force the FIRST `GET referrers` response status (e.g. 404/401/403/500). */
  referrersStatus?: number
  /** Force paginated (page 2+) referrers responses to this status. */
  referrersPageStatus?: number
  /** Respond with `OCI-Filters-Applied: artifactType` on the first page (D152 note). */
  referrersFiltersApplied?: boolean
  /** Override the OCI-Subject header value on manifest PUT (D162 wrong-value test). */
  ociSubject?: string
  /** Omit the OCI-Subject header on manifest PUT (D162 fallback-trigger test). */
  ociSubjectOmit?: boolean
  /** Fail the blob upload PUT for this digest (D161 blobs-first test). */
  uploadFailDigest?: string
  /** rc.1 (D194) — force the GET manifest status for ONE ref (fallback 5xx attacks). */
  manifestGetStatus?: { forRef: string; status: number }
  /** rc.1 (D197/D198) — redirect ONE path to an arbitrary location (302). */
  redirect?: { from: string; to: string }
  /** rc.1 Review (RI-21) — serve a NON-index body for the referrers FIRST page. */
  referrersGarbageBody?: boolean
  /** rc.1 Review (RI-28/D198) — foreign Bearer realm in the 401 challenge. */
  wwwAuthenticateRealm?: string
}

/**
 * beta.2 (D183) — registry interoperability profiles. Capability is decided by
 * PROTOCOL BEHAVIOR, never by vendor name: these profiles simulate distinct
 * real-world registries by their observable OCI responses.
 *   - 'native': PUT acknowledges `OCI-Subject: M` (native Referrers 1.1);
 *     GET /referrers/M → 200 OCI index (+ pagination when referrersPageSize).
 *   - 'fallback-only': PUT never echoes OCI-Subject; GET /referrers/M → 404;
 *     discovery falls back to the standard `<algorithm>-<hex>` referrers tag.
 */
export type MockRegistryProfile = 'native' | 'fallback-only'

export interface MockRegistryOptions {
  tamper?: MockRegistryTamper
  /** 401 + Bearer challenge on unauthenticated requests. */
  requireAuth?: boolean
  /** beta.2 (D183): the simulated registry profile (default 'native'). */
  profile?: MockRegistryProfile
}

interface ManifestEntry {
  bytes: Buffer
  digest: string
}

/** A referrer descriptor entry (untrusted enumeration metadata, D152). */
export interface MockReferrerEntry {
  digest: string
  size: number
  artifactType?: string
  annotations?: Record<string, string>
}

export class MockRegistry {
  readonly blobs = new Map<string, Buffer>()
  readonly manifests = new Map<string, ManifestEntry>()
  /** Referrers index: subjectDigest → descriptors (publication order). */
  readonly referrers = new Map<string, MockReferrerEntry[]>()
  /**
   * rc.1 (D192) — repository-scoped referrers: `repo|subjectDigest` → entries.
   * A native registry indexes referrers PER REPOSITORY — the same manifest
   * digest M in repo-A and repo-B can carry DIFFERENT Evidence sets. Lookups
   * prefer this map and fall back to `referrers` (legacy default-repo tests).
   */
  readonly referrersByRepo = new Map<string, MockReferrerEntry[]>()
  /** > 0 → paginate referrers responses with `Link rel=next` (D158 tests). */
  referrersPageSize = 0
  /** rc.1 (D194) — simulate a registry WITHOUT conditional-request support. */
  etagEnabled = true
  /**
   * rc.1 (D193) — adversarial pagination hook: return the RAW `Link rel=next`
   * URL to inject (loop / cross-origin / invalid links), or undefined for the
   * default page-NEXT behavior. `isNextPage` is true for page-2+ requests.
   */
  referrersNextLink?: (isNextPage: boolean) => string | undefined
  /**
   * Test hook fired on manifest PUTs (before the conditional check) — used to
   * inject a competing fallback-tag write for the D164 concurrent-update race
   * (P10). Return `true` to consume (clear) the hook; `false` keeps it for the
   * next PUT (so non-target refs do not consume it).
   */
  beforeManifestPut?: (ref: string, bytes: Buffer) => boolean
  /** Request log in arrival order (D161 blobs-before-manifest test). */
  readonly requests: Array<{ method: string; path: string }> = []
  tamper: MockRegistryTamper
  /** beta.2 (D183) — the simulated registry profile (default 'native'). */
  readonly profile: MockRegistryProfile
  private readonly server: Server
  port = 0
  baseUrl = ''

  constructor(options: MockRegistryOptions = {}) {
    this.tamper = options.tamper ?? {}
    this.profile = options.profile ?? 'native'
    this.server = createServer((req, res) => {
      void this.handle(req, res, options.requireAuth === true)
    })
  }

  /** Register the referrers descriptors for a subject digest (legacy default repo). */
  setReferrers(subjectDigest: string, entries: MockReferrerEntry[]): void {
    this.referrers.set(subjectDigest, entries)
  }

  /** rc.1 (D192) — register referrers for an EXPLICIT repository (repo-scoped isolation). */
  setReferrersForRepo(repo: string, subjectDigest: string, entries: MockReferrerEntry[]): void {
    this.referrersByRepo.set(`${repo}|${subjectDigest}`, entries)
  }

  /** rc.1 (D192) — the referrers of ONE repository: repo-scoped index first, legacy default fallback. */
  referrersOf(repo: string, subjectDigest: string): MockReferrerEntry[] {
    return this.referrersByRepo.get(`${repo}|${subjectDigest}`) ?? this.referrers.get(subjectDigest) ?? []
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, '127.0.0.1', resolve))
    const address = this.server.address()
    if (address === null || typeof address === 'string') throw new Error('mock registry failed to bind')
    this.port = address.port
    this.baseUrl = `http://127.0.0.1:${this.port}`
  }

  async stop(): Promise<void> {
    await new Promise<void>((resolve, reject) => this.server.close((error) => (error === undefined ? resolve() : reject(error))))
  }

  private unauthorized(res: ServerResponse): void {
    res.statusCode = 401
    // rc.1 Review (RI-28/D198) — a registry MAY challenge with a FOREIGN realm
    // (credential-exfiltration attempt); the client must refuse it.
    const realm = this.tamper.wwwAuthenticateRealm ?? `${this.baseUrl}/token`
    res.setHeader('WWW-Authenticate', `Bearer realm="${realm}",service="mock",scope="repository:pull,push"`)
    res.end('{"errors":[{"code":"UNAUTHORIZED"}]}')
  }

  private async handle(req: IncomingMessage, res: ServerResponse, requireAuth: boolean): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const path = url.pathname
    this.requests.push({ method: req.method ?? '', path })

    // rc.1 (D197/D198) — a redirecting registry: 302 to an ARBITRARY origin.
    // The client must not forward Authorization across origins, and the
    // resulting failure must stay credential-free.
    if (this.tamper.redirect !== undefined && path === this.tamper.redirect.from) {
      res.statusCode = 302
      res.setHeader('Location', this.tamper.redirect.to)
      res.end()
      return
    }

    // token endpoint for the Bearer challenge
    if (path === '/token' && req.method === 'GET') {
      // beta.2 (I7/D185) — with auth required, the token endpoint only issues
      // tokens to clients presenting Basic credentials (anonymous clients must
      // NOT be able to authenticate). The challenge → token → retry flow stays.
      if (requireAuth) {
        const authHeader = req.headers['authorization']
        if (authHeader === undefined || !authHeader.startsWith('Basic ')) {
          res.statusCode = 401
          res.setHeader('WWW-Authenticate', 'Basic realm="mock"')
          res.end('{"errors":[{"code":"UNAUTHORIZED"}]}')
          return
        }
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/json')
      res.end(JSON.stringify({ token: 'mock-bearer-token' }))
      return
    }

    if (path === '/v2/') {
      res.statusCode = 200
      res.end('{}')
      return
    }

    const authenticated = req.headers['authorization'] === 'Bearer mock-bearer-token'
    if (requireAuth && !authenticated) {
      this.unauthorized(res)
      return
    }

    const blobMatch = path.match(/^\/v2\/(.+?)\/blobs\/(.+)$/)
    if (blobMatch !== null && (req.method === 'HEAD' || req.method === 'GET')) {
      // the client URL-encodes the digest ('sha256%3Aabc') — decode it back
      const digest = decodeURIComponent(blobMatch[2] as string)
      const stored = this.blobs.get(digest)
      if (stored === undefined) {
        res.statusCode = 404
        res.end()
        return
      }
      let served = stored
      if (this.tamper.blobDigest === digest) served = Buffer.from('# TAMPERED BLOB BYTES\n')
      res.statusCode = 200
      res.setHeader('Content-Length', String(served.length))
      res.setHeader('Docker-Content-Digest', digest)
      res.end(served)
      return
    }

    const referrersMatch = path.match(/^\/v2\/(.+?)\/referrers\/(.+)$/)
    if (referrersMatch !== null && req.method === 'GET') {
      const repoPathMatch = referrersMatch[1] as string
      const subjectDigest = decodeURIComponent(referrersMatch[2] as string)
      // pagination marker: the mock's own Link URLs carry `last=`; an
      // `artifactType` filter param alone is NOT a page-2 request
      const isNextPage = url.searchParams.has('last')
      if (isNextPage && this.tamper.referrersPageStatus !== undefined) {
        res.statusCode = this.tamper.referrersPageStatus
        res.end('{}')
        return
      }
      if (!isNextPage && this.tamper.referrersStatus !== undefined) {
        res.statusCode = this.tamper.referrersStatus
        res.end('{}')
        return
      }
      // beta.2 (D183) — fallback-only profile: the native Referrers endpoint
      // does not exist; discovery must use the standard referrers tag.
      if (this.profile === 'fallback-only') {
        res.statusCode = 404
        res.end('{}')
        return
      }
      // beta.2 (D186) — artifactType filtering. A registry that SUPPORTS
      // server-side filtering (and confirms it via OCI-Filters-Applied)
      // returns only matching referrers; a registry that ignores the query
      // returns the FULL enumeration — the client then treats it as
      // unfiltered (alpha.1 D152 note) and verifies every candidate.
      // rc.1 (D192) — the enumeration is REPOSITORY-SCOPED: the same subject
      // digest in different repositories is a different referrers index.
      let entries = this.referrersOf(repoPathMatch, subjectDigest)
      const artifactTypeFilter = url.searchParams.get('artifactType')
      if (this.tamper.referrersFiltersApplied === true && artifactTypeFilter !== null) {
        entries = entries.filter((e) => e.artifactType === artifactTypeFilter)
      }
      const pageSize = this.referrersPageSize > 0 ? this.referrersPageSize : entries.length
      const page = isNextPage ? entries.slice(pageSize) : entries.slice(0, pageSize)
      const hasMore = !isNextPage && entries.length > pageSize
      const index = {
        schemaVersion: 2,
        mediaType: 'application/vnd.oci.image.index.v1+json',
        manifests: page.map((e) => ({
          digest: e.digest,
          size: e.size,
          ...(e.artifactType !== undefined ? { artifactType: e.artifactType } : {}),
          ...(e.annotations !== undefined ? { annotations: e.annotations } : {}),
        })),
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/vnd.oci.image.index.v1+json')
      if (!isNextPage && this.tamper.referrersFiltersApplied === true) res.setHeader('OCI-Filters-Applied', 'artifactType')
      // rc.1 Review (RI-21) — a registry serving garbage for the FIRST page:
      // a client must treat it as INCOMPLETE, never as "no referrers".
      if (!isNextPage && this.tamper.referrersGarbageBody === true) {
        res.end(JSON.stringify({ not: 'an index' }))
        return
      }
      // rc.1 (D193) — adversarial Link injection: the hook overrides the next
      // page URL (loop / cross-origin / invalid); otherwise the default
      // page-NEXT link applies when more pages exist.
      let linkValue: string | undefined
      const injected = this.referrersNextLink?.(isNextPage)
      if (injected !== undefined) {
        linkValue = `<${injected}>; rel="next"`
      } else if (!isNextPage && entries.length > pageSize) {
        linkValue = `<${`/v2/${repoPathMatch}/referrers/${encodeURIComponent(subjectDigest)}?n=${pageSize}&last=x`}>; rel="next"`
      }
      if (linkValue !== undefined) res.setHeader('Link', linkValue)
      res.end(JSON.stringify(index))
      return
    }

    const uploadStart = path.match(/^\/v2\/(.+?)\/blobs\/uploads\/$/)
    if (uploadStart !== null && req.method === 'POST') {
      res.statusCode = 202
      res.setHeader('Location', `/v2/repo/blobs/uploads/${randomUUID()}`)
      res.end()
      return
    }

    const uploadPut = path.match(/^\/v2\/(.+?)\/blobs\/uploads\/[0-9a-f-]+$/)
    if (uploadPut !== null && req.method === 'PUT') {
      const digest = url.searchParams.get('digest')
      if (digest === null) {
        res.statusCode = 400
        res.end()
        return
      }
      if (this.tamper.uploadFailDigest === digest) {
        res.statusCode = 500
        res.end('{}')
        return
      }
      const bytes = await readBody(req)
      this.blobs.set(digest, bytes)
      res.statusCode = 201
      res.setHeader('Location', `/v2/repo/blobs/${digest}`)
      res.setHeader('Docker-Content-Digest', digest)
      res.end()
      return
    }

    const manifestMatch = path.match(/^\/v2\/(.+?)\/manifests\/(.+)$/)
    if (manifestMatch !== null && req.method === 'PUT') {
      // group 1 = repo path, group 2 = tag-or-digest (multi-segment repo regex)
      const ref = decodeURIComponent(manifestMatch[2] as string)
      const bytes = await readBody(req)
      const digest = `sha256:${createHash('sha256').update(bytes).digest('hex')}`
      const entry: ManifestEntry = { bytes, digest }

      // D164 test hook: inject a competing fallback-tag write before the
      // conditional check (concurrent-update race, P10)
      if (this.beforeManifestPut !== undefined) {
        const done = this.beforeManifestPut(ref, bytes)
        if (done) this.beforeManifestPut = undefined
      }

      // ETag conditional push (D164): If-Match must equal the CURRENT ref digest
      const ifMatch = req.headers['if-match']
      if (ifMatch !== undefined) {
        const expected = ifMatch.replace(/^"|"$/g, '')
        const current = this.manifests.get(ref)
        if (current === undefined || current.digest !== expected) {
          res.statusCode = 412
          res.end('{}')
          return
        }
      }

      this.manifests.set(ref, entry)
      this.manifests.set(digest, entry) // digest-addressable (criterion 3)
      if (this.tamper.configContentHash !== undefined) {
        this.tamperConfig(ref, bytes, this.tamper.configContentHash)
      }
      res.statusCode = 201
      res.setHeader('Docker-Content-Digest', digest)
      if (this.etagEnabled) res.setHeader('ETag', `"${digest}"`)
      // D162 — OCI-Subject acknowledgement (a native Referrers registry echoes
      // the manifest's subject digest on PUT; tests can omit or override it)
      let subjectDigest: string | undefined
      let artifactType: string | undefined
      try {
        const parsed = JSON.parse(bytes.toString('utf8')) as { subject?: { digest?: unknown }; artifactType?: unknown }
        subjectDigest = typeof parsed.subject?.digest === 'string' ? parsed.subject.digest : undefined
        artifactType = typeof parsed.artifactType === 'string' ? parsed.artifactType : undefined
      } catch {
        // not a manifest with a subject — no header
      }
      // beta.2 (D183) — a NATIVE registry automatically indexes referrers: a
      // manifest carrying a subject descriptor becomes discoverable via
      // GET /referrers/<subject> (real OCI 1.1 registry behavior). The
      // fallback-only profile never maintains this index — discovery there
      // MUST go through the standard referrers tag instead.
      // rc.1 (D192) — the index is REPOSITORY-SCOPED (repo|subjectDigest):
      // the same digest in repo-A and repo-B has independent Evidence sets.
      if (this.profile !== 'fallback-only' && subjectDigest !== undefined) {
        const repoPath = manifestMatch[1] as string
        const existing = this.referrersByRepo.get(`${repoPath}|${subjectDigest}`) ?? []
        if (!existing.some((e) => e.digest === digest)) {
          this.referrersByRepo.set(`${repoPath}|${subjectDigest}`, [
            ...existing,
            { digest, size: bytes.length, ...(artifactType !== undefined ? { artifactType } : {}) },
          ])
        }
      }
      if (!this.tamper.ociSubjectOmit && this.profile !== 'fallback-only' && subjectDigest !== undefined) {
        res.setHeader('OCI-Subject', this.tamper.ociSubject ?? subjectDigest)
      }
      res.end('{}')
      return
    }

    if (manifestMatch !== null && req.method === 'GET') {
      // group 1 = repo path, group 2 = tag-or-digest (multi-segment repo regex)
      const ref = decodeURIComponent(manifestMatch[2] as string)
      // tamper: serve a DIFFERENT manifest's bytes under the requested digest
      // (a malicious registry — the client's digest-form check must FAIL)
      const serveRef = this.tamper.manifestSwap !== undefined && this.tamper.manifestSwap.forDigest === ref
        ? this.tamper.manifestSwap.serveTag
        : ref
      const entry = this.manifests.get(serveRef)
      if (entry === undefined) {
        res.statusCode = 404
        res.end('{}')
        return
      }
      if (this.tamper.manifestGetStatus !== undefined && this.tamper.manifestGetStatus.forRef === ref) {
        res.statusCode = this.tamper.manifestGetStatus.status
        res.end('{}')
        return
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/vnd.oci.image.manifest.v1+json')
      res.setHeader('Docker-Content-Digest', entry.digest)
      if (this.etagEnabled) res.setHeader('ETag', `"${entry.digest}"`)
      res.end(entry.bytes)
      return
    }

    res.statusCode = 404
    res.end('{}')
  }

  /** Criterion 5: replace the config blob with one declaring a bogus contentHash. */
  private tamperConfig(tag: string, manifestBytes: Buffer, bogusContentHash: string): void {
    try {
      const manifest = JSON.parse(manifestBytes.toString('utf8')) as {
        config?: { digest?: string; size?: number }
      }
      const configDigest = manifest.config?.digest
      if (configDigest === undefined) return
      const configBytes = this.blobs.get(configDigest)
      if (configBytes === undefined) return
      const dsh = JSON.parse(configBytes.toString('utf8')) as { artifact?: { digest?: string } }
      if (dsh.artifact !== undefined) dsh.artifact.digest = bogusContentHash
      const tamperedConfig = Buffer.from(JSON.stringify(dsh), 'utf8')
      const newDigest = `sha256:${createHash('sha256').update(tamperedConfig).digest('hex')}`
      this.blobs.set(newDigest, tamperedConfig)
      if (manifest.config !== undefined) {
        manifest.config.digest = newDigest
        manifest.config.size = tamperedConfig.length
      }
      const newManifest = Buffer.from(JSON.stringify(manifest), 'utf8')
      this.manifests.set(tag, { bytes: newManifest, digest: `sha256:${createHash('sha256').update(newManifest).digest('hex')}` })
    } catch {
      // leave the registry unchanged on any parse failure (test would fail later)
    }
  }
}

async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = []
  for await (const chunk of req) chunks.push(chunk as Buffer)
  return Buffer.concat(chunks)
}
