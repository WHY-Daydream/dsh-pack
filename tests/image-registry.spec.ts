/**
 * v0.4.1 registry module unit tests (DESIGN-v0.4.1.md §2/§3/§8, D32/D34–D37):
 * WWW-Authenticate parsing, credential loading (env → auth file), the OCI
 * envelope build/validate rules and digest/size verification over raw bytes.
 */
import { afterEach, describe, expect, it } from 'vitest'
import { loadRegistryCredentials, parseWwwAuthenticate } from '../src/image/registry/auth.js'
import { digestOf, verifyDescriptorBytes } from '../src/image/registry/descriptor.js'
import {
  buildOciManifest, DSH_AGENT_ARTIFACT_TYPE, DSH_PACK_LAYER_MEDIA_TYPE,
  OCI_IMAGE_MANIFEST_MEDIA_TYPE, validateOciManifest,
} from '../src/image/registry/manifest.js'
import { IMAGE_MANIFEST_MEDIA_TYPE as DSH_IMAGE_MANIFEST_MEDIA_TYPE } from '../src/image/manifest.js'
import { sha256Hex } from '../src/canonical.js'

const BLOB_DIGEST = 'sha256:' + 'a'.repeat(64)
const CONFIG_DIGEST = 'sha256:' + 'b'.repeat(64)

afterEach(() => {
  delete process.env['DSH_REGISTRY_USERNAME']
  delete process.env['DSH_REGISTRY_TOKEN']
})

describe('parseWwwAuthenticate', () => {
  it('parses Bearer challenges (realm/service/scope) and Basic', () => {
    expect(parseWwwAuthenticate('Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:org/agent:pull,push"'))
      .toEqual({
        scheme: 'bearer',
        realm: 'https://ghcr.io/token',
        service: 'ghcr.io',
        scope: 'repository:org/agent:pull,push',
      })
    expect(parseWwwAuthenticate('Basic realm="registry"')).toEqual({ scheme: 'basic' })
  })

  it('returns undefined for unknown/absent challenges', () => {
    expect(parseWwwAuthenticate(undefined)).toBeUndefined()
    expect(parseWwwAuthenticate('')).toBeUndefined()
    expect(parseWwwAuthenticate('Digest realm="x"')).toBeUndefined()
    expect(parseWwwAuthenticate('Bearer error="no realm"')).toBeUndefined()
  })
})

describe('loadRegistryCredentials', () => {
  it('prefers DSH_REGISTRY_USERNAME/TOKEN over the auth file', () => {
    process.env['DSH_REGISTRY_USERNAME'] = 'pat-user'
    process.env['DSH_REGISTRY_TOKEN'] = 'secret-pat'
    expect(loadRegistryCredentials('ghcr.io')).toEqual({ username: 'pat-user', password: 'secret-pat' })
  })

  it('returns empty credentials when nothing is configured', () => {
    expect(loadRegistryCredentials('ghcr.io')).toEqual({})
  })
})

describe('OCI envelope (D34–D37)', () => {
  it('builds the standard envelope: config = DSH manifest, one layer = .dshpack', () => {
    const manifest = buildOciManifest(
      { mediaType: DSH_IMAGE_MANIFEST_MEDIA_TYPE, digest: CONFIG_DIGEST, size: 100 },
      { mediaType: DSH_PACK_LAYER_MEDIA_TYPE, digest: BLOB_DIGEST, size: 1000 },
    )
    expect(manifest.schemaVersion).toBe(2)
    expect(manifest.mediaType).toBe(OCI_IMAGE_MANIFEST_MEDIA_TYPE)
    expect(manifest.artifactType).toBe(DSH_AGENT_ARTIFACT_TYPE)
    expect(manifest.layers).toHaveLength(1)
    expect(validateOciManifest(manifest).ok).toBe(true)
  })

  it('rejects wrong envelope shapes loudly', () => {
    const good = buildOciManifest(
      { mediaType: DSH_IMAGE_MANIFEST_MEDIA_TYPE, digest: CONFIG_DIGEST, size: 100 },
      { mediaType: DSH_PACK_LAYER_MEDIA_TYPE, digest: BLOB_DIGEST, size: 1000 },
    )
    expect(validateOciManifest({ ...good, schemaVersion: 1 }).ok).toBe(false)
    expect(validateOciManifest({ ...good, mediaType: 'application/vnd.oci.image.manifest.v2+json' }).ok).toBe(false)
    expect(validateOciManifest({ ...good, artifactType: 'application/vnd.other' }).ok).toBe(false)
    expect(validateOciManifest({ ...good, layers: [good.layers[0], good.layers[0]] }).ok).toBe(false)
    expect(validateOciManifest({ ...good, layers: [] }).ok).toBe(false)
    expect(validateOciManifest({ ...good, config: { ...good.config, digest: 'md5:abc' } }).ok).toBe(false)
    expect(validateOciManifest({ ...good, layers: [{ ...good.layers[0], digest: 'sha256:zzz' }] }).ok).toBe(false)
  })
})

describe('descriptor verification (D32/D38)', () => {
  it('recomputes digests over actual bytes and fails on mismatch', () => {
    const bytes = Buffer.from('raw artifact bytes')
    const digest = `sha256:${sha256Hex(bytes)}`
    expect(digestOf(bytes)).toBe(digest)
    verifyDescriptorBytes('pack blob', { digest, size: bytes.length }, bytes)
    expect(() => verifyDescriptorBytes('pack blob', { digest, size: bytes.length + 1 }, bytes)).toThrow(/size mismatch/)
    expect(() => verifyDescriptorBytes('pack blob', { digest: 'sha256:' + 'f'.repeat(64), size: bytes.length }, bytes))
      .toThrow(/digest mismatch/)
  })
})
