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
}

export interface MockRegistryOptions {
  tamper?: MockRegistryTamper
  /** 401 + Bearer challenge on unauthenticated requests. */
  requireAuth?: boolean
}

interface ManifestEntry {
  bytes: Buffer
  digest: string
}

export class MockRegistry {
  readonly blobs = new Map<string, Buffer>()
  readonly manifests = new Map<string, ManifestEntry>()
  tamper: MockRegistryTamper
  private readonly server: Server
  port = 0
  baseUrl = ''

  constructor(options: MockRegistryOptions = {}) {
    this.tamper = options.tamper ?? {}
    this.server = createServer((req, res) => {
      void this.handle(req, res, options.requireAuth === true)
    })
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
    res.setHeader('WWW-Authenticate', `Bearer realm="${this.baseUrl}/token",service="mock",scope="repository:pull,push"`)
    res.end('{"errors":[{"code":"UNAUTHORIZED"}]}')
  }

  private async handle(req: IncomingMessage, res: ServerResponse, requireAuth: boolean): Promise<void> {
    const url = new URL(req.url ?? '/', 'http://localhost')
    const path = url.pathname

    // token endpoint for the Bearer challenge
    if (path === '/token' && req.method === 'GET') {
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
      this.manifests.set(ref, entry)
      this.manifests.set(digest, entry) // digest-addressable (criterion 3)
      if (this.tamper.configContentHash !== undefined) {
        this.tamperConfig(ref, bytes, this.tamper.configContentHash)
      }
      res.statusCode = 201
      res.setHeader('Docker-Content-Digest', digest)
      res.end('{}')
      return
    }

    if (manifestMatch !== null && req.method === 'GET') {
      // group 1 = repo path, group 2 = tag-or-digest (multi-segment repo regex)
      const ref = decodeURIComponent(manifestMatch[2] as string)
      const entry = this.manifests.get(ref)
      if (entry === undefined) {
        res.statusCode = 404
        res.end('{}')
        return
      }
      res.statusCode = 200
      res.setHeader('Content-Type', 'application/vnd.oci.image.manifest.v1+json')
      res.setHeader('Docker-Content-Digest', entry.digest)
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
