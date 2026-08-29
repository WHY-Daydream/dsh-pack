/**
 * v0.3 signing unit tests (DESIGN.md v0.3): keygen roundtrip, embedded
 * signature over the contentHash anchor, tamper detection (crypto + anchor),
 * the unsigned Signature section, and the service-level sign → verify flow.
 */
import { createPublicKey, createHash } from 'node:crypto'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { DefaultPackager } from '../src/service.js'
import { buildTarGz, openPack, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackBuffer, verifySignatureValue } from '../src/sign.js'
import { verifyPack } from '../src/verify.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import type { SignatureInfo } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-sign-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** Minimal valid pack (manifest + checksums + warnings + resolved). */
async function makePack(root: string): Promise<Buffer> {
  const rows = [{ id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.3 } }]
  const manifest = {
    format: 'dshpack',
    schemaVersion: 1,
    profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true,
    portable: true,
    bundles: [],
    dependencies: {},
    // real anchor so the verify Config section recomputes it identically
    configHash: computeConfigHash({ rows }, [], {}),
    createdAt: '2026-08-28T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.3.0' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: 'web-profile', private: true, dependencies: {} }) },
    { path: 'resolved/composition.json', content: prettyJson({ rows }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson({ lockfile: 'pnpm-lock.yaml', direct: {}, closure: {}, localDeps: [], warnings: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
    { path: 'README.md', content: '# web snapshot\n' },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

describe('keygen', () => {
  it('generates an ed25519 keypair with a consistent fingerprint', () => {
    const root = tempRoot('keygen')
    const { privateKey, publicKey, keyId } = generateKeypair(root)
    expect(existsSync(privateKey)).toBe(true)
    expect(existsSync(publicKey)).toBe(true)
    expect(statSync(privateKey).mode & 0o777).toBe(0o600)

    const pubPem = readFileSync(publicKey, 'utf8')
    const der = createPublicKey(pubPem).export({ type: 'spki', format: 'der' })
    expect(keyId).toBe(sha256Hex(der))
    expect(keyId).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe('sign + verify', () => {
  it('embeds signature + provenance and verifies against the contentHash anchor', async () => {
    const root = tempRoot('sign')
    const pack = await makePack(root)
    const key = generateKeypair(root)
    const { buffer, signature } = await signPackBuffer(pack, { keyPath: key.privateKey, signer: 'why-daydream' })

    const opened = await openPack(buffer)
    try {
      expect(opened.files).toContain('metadata/signature.json')
      expect(opened.files).toContain('metadata/provenance.json')
      const info = JSON.parse(readFileSync(join(opened.root, 'metadata/signature.json'), 'utf8')) as SignatureInfo
      expect(info.algorithm).toBe('ed25519')
      expect(info.keyId).toBe(key.keyId)
      expect(info.contentHash).toMatch(/^sha256:[0-9a-f]{64}$/)
      const provenance = JSON.parse(readFileSync(join(opened.root, 'metadata/provenance.json'), 'utf8')) as { signer: string }
      expect(provenance.signer).toBe('why-daydream')

      // the anchor must be unchanged by signing (signature files are excluded)
      expect(info.contentHash).toBe(signature.contentHash)
      const verdict = verifySignatureValue(info, info.contentHash)
      expect(verdict.ok).toBe(true)
    } finally {
      rmSync(opened.root, { recursive: true, force: true })
    }
  })

  it('rejects tampered signatures, wrong anchors and bad keys', async () => {
    const root = tempRoot('tamper')
    const pack = await makePack(root)
    const key = generateKeypair(root)
    const { buffer } = await signPackBuffer(pack, { keyPath: key.privateKey })

    const opened = await openPack(buffer)
    let info: SignatureInfo
    try {
      info = JSON.parse(readFileSync(join(opened.root, 'metadata/signature.json'), 'utf8')) as SignatureInfo
    } finally {
      rmSync(opened.root, { recursive: true, force: true })
    }

    // flipped signature byte
    const sigBytes = Buffer.from(info.signature, 'base64')
    sigBytes[0] = (sigBytes[0] ?? 0) ^ 0xff
    const tampered = { ...info, signature: sigBytes.toString('base64') }
    expect(verifySignatureValue(tampered, info.contentHash).ok).toBe(false)

    // anchor mismatch (content changed after signing)
    expect(verifySignatureValue(info, 'sha256:' + 'b'.repeat(64)).ok).toBe(false)

    // bogus public key
    expect(verifySignatureValue({ ...info, publicKey: 'not a pem' }, info.contentHash).ok).toBe(false)
  })
})

describe('verifyPack Signature section', () => {
  it('reports unsigned packs as warn, and FAILS with --require-signature', async () => {
    const root = tempRoot('unsigned')
    const pack = await makePack(root)
    const context = { installedDshVersion: DSH_VERSION }
    const unsigned = await verifyPack(pack, context)
    const section = unsigned.report.sections.find((s) => s.name === 'Signature')
    expect(section?.status).toBe('warn')
    expect(unsigned.report.ok).toBe(true)

    const required = await verifyPack(pack, { ...context, requireSignature: true })
    const requiredSection = required.report.sections.find((s) => s.name === 'Signature')
    expect(requiredSection?.status).toBe('fail')
    expect(required.report.ok).toBe(false)
    rmSync(unsigned.root, { recursive: true, force: true })
    rmSync(required.root, { recursive: true, force: true })
  })

  it('detects content tampering via the Signature section', async () => {
    const root = tempRoot('tamper-verify')
    const pack = await makePack(root)
    const key = generateKeypair(root)
    const { buffer } = await signPackBuffer(pack, { keyPath: key.privateKey })

    // tamper a REAL content file, then rebuild the archive byte-for-byte
    // except README.md (checksums.json left stale on purpose — both the
    // Checksums and Signature sections must fail).
    const opened = await openPack(buffer)
    let tampered: Buffer
    try {
      writeFileSync(join(opened.root, 'README.md'), '# TAMPERED\n')
      const entries: PackFileEntry[] = []
      for (const file of opened.files) {
        entries.push({ path: file, content: readFileSync(join(opened.root, file)) })
      }
      const rebuilt = await buildTarGz(entries)
      tampered = rebuilt.buffer
    } finally {
      rmSync(opened.root, { recursive: true, force: true })
    }

    const report = await verifyPack(tampered, { installedDshVersion: DSH_VERSION })
    const signatureSection = report.report.sections.find((s) => s.name === 'Signature')
    expect(signatureSection?.status).toBe('fail')
    expect(String(signatureSection?.detail)).toContain('contentHash')
    rmSync(report.root, { recursive: true, force: true })
  })
})

describe('service-level sign → verify', () => {
  it('signs a real pack and verifies it with a VALID Signature section', async () => {
    const home = tempRoot('svc')
    mkdirSync(join(home, 'profiles', 'web'), { recursive: true })
    writeFileSync(join(home, 'profiles', 'web', 'package.json'), JSON.stringify({
      name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
    }, null, 2))
    writeFileSync(join(home, 'profiles', 'web', 'cordis.patch.yml'), '- insert:\n    - id: llm-deepseek\n      provider: deepseek\n      config:\n        temperature: 0.3\n')

    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: '0.3.0' })
    const packed = await packager.pack({ profile: 'web', outDir: home })

    const key = await packager.keygen({ outDir: home })
    expect(key.keyId).toMatch(/^[0-9a-f]{64}$/)

    const signed = await packager.sign(packed.file, { key: key.privateKey, signer: 'why-daydream' })
    expect(existsSync(signed.file)).toBe(true)
    expect(signed.file).toMatch(/\.signed\.dshpack$/)

    const report = await packager.verify(signed.file)
    expect(report.ok).toBe(true)
    const section = report.sections.find((s) => s.name === 'Signature')
    expect(section?.status).toBe('ok')
    expect(String(section?.detail)).toContain('VALID')
    expect(String(section?.detail)).toContain('why-daydream')
  })
})
