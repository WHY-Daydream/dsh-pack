/**
 * v0.4 image core unit tests (DESIGN-v0.4.md): reference grammar (D21/D22),
 * image manifest digest/validation (D24), content-addressed local store (D25)
 * with atomic/tag semantics, resolution (tag/digest → manifest) and the
 * trust bridge on top of v0.3 signature sections (D29, VALID ≠ TRUSTED).
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.js'
import { ImageReferenceError, digestReference, formatReference, parseReference, repository } from '../src/image/reference.js'
import { buildImageManifest, imageManifestDigest, validateImageManifest } from '../src/image/manifest.js'
import { LocalImageStore } from '../src/image/local-store.js'
import { ImageResolveError, resolveImage } from '../src/image/resolver.js'
import { applyTrustPolicy } from '../src/image/trust.js'
import type { VerificationSection } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-img-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

describe('parseReference (D21/D22 grammar)', () => {
  it('parses name / namespace / registry forms', () => {
    expect(parseReference('agent')).toEqual({ namespace: '', name: 'agent' })
    expect(parseReference('why-daydream/agent')).toEqual({ namespace: 'why-daydream', name: 'agent' })
    expect(parseReference('ghcr.io/why-daydream/procurement-agent')).toEqual({
      registry: 'ghcr.io', namespace: 'why-daydream', name: 'procurement-agent',
    })
    expect(parseReference('localhost:5000/agent')).toEqual({ registry: 'localhost:5000', namespace: '', name: 'agent' })
  })

  it('parses tag and digest (mutable vs immutable)', () => {
    expect(parseReference('agent:v1.0')).toEqual({ namespace: '', name: 'agent', tag: 'v1.0' })
    const digest = 'sha256:' + 'a'.repeat(64)
    expect(parseReference(`agent@${digest}`)).toEqual({ namespace: '', name: 'agent', digest })
    expect(parseReference(`ghcr.io/x/agent:v1@${digest}`)).toEqual({
      registry: 'ghcr.io', namespace: 'x', name: 'agent', tag: 'v1', digest,
    })
  })

  it('rejects invalid references loudly', () => {
    expect(() => parseReference('')).toThrow(ImageReferenceError)
    expect(() => parseReference('agent@sha256:abc')).toThrow(/digest/)
    expect(() => parseReference('Agent')).toThrow(/name/)
    expect(() => parseReference('agent:bad tag!')).toThrow(/tag/)
    expect(() => parseReference('agent@sha256:' + 'A'.repeat(64))).toThrow(/digest/)
  })

  it('formats canonically and exposes the immutable digest form', () => {
    const ref = parseReference('ghcr.io/why-daydream/agent:v1')
    expect(repository(ref)).toBe('ghcr.io/why-daydream/agent')
    expect(formatReference(ref)).toBe('ghcr.io/why-daydream/agent:v1')
    const withDigest = parseReference(`agent@sha256:${'b'.repeat(64)}`)
    expect(digestReference(withDigest)).toBe(`agent@sha256:${'b'.repeat(64)}`)
  })
})

describe('image manifest (D24)', () => {
  const base = {
    artifactDigest: 'sha256:' + 'a'.repeat(64),
    artifactSize: 1024,
    configHash: 'sha256:' + 'b'.repeat(64),
    dshVersion: DSH_VERSION,
    annotations: { 'org.opencontainers.image.title': 'agent' },
  }

  it('builds a v1 manifest with a stable digest', () => {
    const manifest = buildImageManifest(base)
    expect(manifest.mediaType).toBe('application/vnd.dsh.image.manifest.v1+json')
    expect(manifest.artifact.mediaType).toBe('application/vnd.dsh.pack.v1+gzip')
    expect(imageManifestDigest(manifest)).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(imageManifestDigest(manifest)).toBe(imageManifestDigest(buildImageManifest(base)))
  })

  it('validates a well-formed manifest and rejects broken ones', () => {
    const manifest = buildImageManifest(base)
    expect(validateImageManifest(manifest).ok).toBe(true)
    expect(validateImageManifest({ ...manifest, mediaType: 'x' }).ok).toBe(false)
    expect(validateImageManifest({ ...manifest, artifact: { ...manifest.artifact, digest: 'md5:abc' } }).ok).toBe(false)
    expect(validateImageManifest({ ...manifest, configHash: 'nope' }).ok).toBe(false)
  })
})

describe('LocalImageStore (D25)', () => {
  it('round-trips blobs, manifests and tags with atomic semantics', async () => {
    const store = new LocalImageStore(join(tempRoot('store'), 'images'))
    const bytes = Buffer.from('pack-bytes')
    const blobDigest = `sha256:${sha256Hex(bytes)}`
    const manifest = buildImageManifest({
      artifactDigest: blobDigest, artifactSize: bytes.length, configHash: 'sha256:' + 'c'.repeat(64), dshVersion: DSH_VERSION,
    })
    const manifestDigest = imageManifestDigest(manifest)

    await store.putBlob(blobDigest, bytes)
    expect(await store.hasBlob(blobDigest)).toBe(true)
    expect((await store.getBlob(blobDigest))?.equals(bytes)).toBe(true)

    await store.putManifest(manifestDigest, manifest)
    expect((await store.getManifest(manifestDigest))?.artifact.digest).toBe(blobDigest)

    // tag is mutable: same tag can move to a new digest
    await store.setTag('why-daydream/agent', 'v1', manifestDigest)
    expect(await store.getTag('why-daydream/agent', 'v1')).toBe(manifestDigest)
    await store.setTag('why-daydream/agent', 'latest', manifestDigest)
    expect(await store.listRefs()).toEqual([
      { repo: 'why-daydream/agent', tag: 'latest', manifestDigest },
      { repo: 'why-daydream/agent', tag: 'v1', manifestDigest },
    ])
    await store.removeTag('why-daydream/agent', 'v1')
    expect(await store.getTag('why-daydream/agent', 'v1')).toBeUndefined()

    await store.removeBlob(blobDigest)
    expect(await store.hasBlob(blobDigest)).toBe(false)
  })

  it('enforces the content-addressing invariant (format + same-digest consistency)', async () => {
    const store = new LocalImageStore(join(tempRoot('invariant'), 'images'))
    await expect(store.putBlob('not-a-digest', Buffer.from('x'))).rejects.toThrow(/invalid blob digest/)
    const bytes = Buffer.from('same-bytes')
    const digest = `sha256:${sha256Hex(bytes)}`
    await store.putBlob(digest, bytes)
    await store.putBlob(digest, bytes) // idempotent
    // different bytes under the same digest → FAIL (collision guard)
    await expect(store.putBlob(digest, Buffer.from('other-bytes'))).rejects.toThrow(/already exists/)
  })
})

describe('resolveImage', () => {
  it('resolves by tag and by digest; fails loudly when anything is missing', async () => {
    const store = new LocalImageStore(join(tempRoot('resolve'), 'images'))
    const bytes = Buffer.from('artifact')
    const blobDigest = `sha256:${sha256Hex(bytes)}`
    const manifest = buildImageManifest({
      artifactDigest: blobDigest, artifactSize: bytes.length, configHash: 'sha256:' + 'd'.repeat(64), dshVersion: DSH_VERSION,
    })
    const manifestDigest = imageManifestDigest(manifest)
    await store.putBlob(blobDigest, bytes)
    await store.putManifest(manifestDigest, manifest)
    await store.setTag('org/agent', 'v1', manifestDigest)

    const byTag = await resolveImage(store, parseReference('org/agent:v1'))
    expect(byTag.manifestDigest).toBe(manifestDigest)
    expect(byTag.artifactDigest).toBe(blobDigest)

    const byDigest = await resolveImage(store, parseReference(`org/agent@${manifestDigest}`))
    expect(byDigest.artifactDigest).toBe(blobDigest)

    await expect(resolveImage(store, parseReference('org/agent:missing'))).rejects.toThrow(/not found/)
    await expect(resolveImage(store, parseReference('org/agent'))).rejects.toThrow(/tag or a digest/)
    await expect(resolveImage(store, parseReference(`org/agent@sha256:${'f'.repeat(64)}`))).rejects.toThrow(/not found/)

    // manifest present but blob missing → resolve FAILS (run fails before boot)
    const manifest2 = buildImageManifest({
      artifactDigest: 'sha256:' + 'e'.repeat(64), artifactSize: 1, configHash: 'sha256:' + 'd'.repeat(64), dshVersion: DSH_VERSION,
    })
    await store.putManifest(imageManifestDigest(manifest2), manifest2)
    await store.setTag('org/agent', 'v2', imageManifestDigest(manifest2))
    await expect(resolveImage(store, parseReference('org/agent:v2'))).rejects.toThrow(/blob .* missing/)
  })
})

describe('applyTrustPolicy (D29, VALID ≠ TRUSTED)', () => {
  const section = (status: VerificationSection['status'], detail = ''): VerificationSection => ({ name: 'Signature', status, detail })

  it('maps section status to VALID/INVALID/MISSING and trust markers', () => {
    expect(applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: VERIFIED)'), {}))
      .toEqual({ ok: true, signature: 'VALID', trust: 'VERIFIED' })
    expect(applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: UNTRUSTED)'), {}))
      .toEqual({ ok: true, signature: 'VALID', trust: 'UNTRUSTED' })
    expect(applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: N/A)'), {}))
      .toEqual({ ok: true, signature: 'VALID', trust: 'N/A' })
    expect(applyTrustPolicy(section('warn', 'unsigned pack'), {}).signature).toBe('MISSING')
    expect(applyTrustPolicy(section('fail', 'ed25519 verification FAILED'), {}).signature).toBe('INVALID')
  })

  it('enforces requireSignature and requireTrusted', () => {
    const verified = applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: VERIFIED)'), { requireSignature: true, requireTrusted: true })
    expect(verified.ok).toBe(true)

    const missing = applyTrustPolicy(section('warn', 'unsigned pack'), { requireSignature: true })
    expect(missing.ok).toBe(false)
    expect(missing.error).toContain('signature required')

    // VALID but not trusted → requireTrusted FAILS (VALID ≠ TRUSTED)
    const untrusted = applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: UNTRUSTED)'), { requireTrusted: true })
    expect(untrusted.ok).toBe(false)
    expect(untrusted.signature).toBe('VALID')

    const noWhitelist = applyTrustPolicy(section('ok', 'VALID (ed25519, Trust: N/A)'), { requireTrusted: true })
    expect(noWhitelist.ok).toBe(false)
    expect(noWhitelist.error).toContain('no DSH_PACK_TRUSTED_KEYS')
  })
})
