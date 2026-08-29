/**
 * v0.3 embedded ed25519 signing (DESIGN.md v0.3): `/pack keygen` generates an
 * ed25519 keypair, `/pack sign` embeds `metadata/signature.json` +
 * `metadata/provenance.json` into a deterministic rebuild of the `.dshpack`,
 * and the Signature verify section validates the signature over the contentHash
 * anchor.
 *
 * Why sign the contentHash string, not the archive bytes: contentHash is the
 * integrity anchor over every real entry, and — like checksums.json (D17) —
 * the signing files are derived metadata EXCLUDED from the anchor, so adding a
 * signature never changes the signed value (sign-then-embed stays valid).
 * @module @why-daydream/dsh-pack/sign
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, verify, sign } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { buildTarGz, checksumsJson, computeContentHash, openPack, type PackFileEntry } from './pack-builder.ts'
import { prettyJson, sha256Hex, utcNowIso } from './canonical.ts'
import { PackError } from './service.ts'
import type { KeygenResult, SignatureInfo, SignOptions, SignResult } from './types.ts'

/** ed25519 keypair files + fingerprint. */
export interface GeneratedKeypair {
  privateKey: string
  publicKey: string
  keyId: string
}

/** Generate an ed25519 keypair into `outDir` (private key chmod 0600). */
export function generateKeypair(outDir: string): GeneratedKeypair {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519')
  const publicDer = publicKey.export({ type: 'spki', format: 'der' })
  const keyId = sha256Hex(publicDer)
  mkdirSync(outDir, { recursive: true })
  const privatePath = join(outDir, 'dsh-pack-private.pem')
  const publicPath = join(outDir, 'dsh-pack-public.pem')
  writeFileSync(privatePath, privateKey.export({ type: 'pkcs8', format: 'pem' }))
  chmodSync(privatePath, 0o600)
  writeFileSync(publicPath, publicKey.export({ type: 'spki', format: 'pem' }))
  return { privateKey: privatePath, publicKey: publicPath, keyId }
}

/** Validate + verify an embedded signature against a recomputed contentHash. */
export function verifySignatureValue(
  value: unknown,
  contentHash: string,
): { ok: true; keyId: string } | { ok: false; error: string } {
  if (value === null || typeof value !== 'object') return { ok: false, error: 'signature.json is not an object' }
  const info = value as Record<string, unknown>
  if (info.schemaVersion !== 1) return { ok: false, error: `signature.json schemaVersion must be 1 (got ${String(info.schemaVersion)})` }
  if (info.algorithm !== 'ed25519') return { ok: false, error: `unsupported signature algorithm: ${String(info.algorithm)}` }
  if (typeof info.keyId !== 'string' || !/^[0-9a-f]{64}$/.test(info.keyId)) {
    return { ok: false, error: 'signature.json keyId must be 64 hex chars' }
  }
  if (typeof info.publicKey !== 'string') return { ok: false, error: 'signature.json publicKey must be a PEM string' }
  if (typeof info.signature !== 'string' || info.signature === '') return { ok: false, error: 'signature.json signature must be a base64 string' }
  if (info.contentHash !== contentHash) {
    return { ok: false, error: `signature covers ${String(info.contentHash)}, pack contentHash is ${contentHash}` }
  }

  let publicKey
  try {
    publicKey = createPublicKey(info.publicKey)
  } catch {
    return { ok: false, error: 'signature.json publicKey is not a valid PEM key' }
  }
  let signatureBytes: Buffer
  try {
    signatureBytes = Buffer.from(info.signature, 'base64')
  } catch {
    return { ok: false, error: 'signature.json signature is not valid base64' }
  }
  const valid = verify(null, Buffer.from(contentHash, 'utf8'), publicKey, signatureBytes)
  if (!valid) return { ok: false, error: 'ed25519 signature verification FAILED' }
  return { ok: true, keyId: info.keyId }
}

/**
 * Sign a `.dshpack` buffer: verify it opens, recompute the contentHash anchor,
 * sign it, and rebuild a deterministic archive with `metadata/signature.json` +
 * `metadata/provenance.json` embedded (checksums.json regenerated; the anchor
 * is unchanged because the signing files are excluded from contentHash).
 */
export async function signPackBuffer(
  buffer: Buffer,
  opts: { keyPath: string; signer?: string; packagerVersion?: string; force?: boolean },
): Promise<{ buffer: Buffer; signature: SignatureInfo }> {
  const pack = await openPack(buffer)
  try {
    // Re-sign guard: replacing an existing signature is destructive, so it is
    // refused unless --force is explicit (mirrors install --force, D13).
    if (pack.files.includes('metadata/signature.json') && !opts.force) {
      throw new PackError(
        'this pack is already signed; use --force to replace the existing signature (explicit destructive behavior)',
        1,
      )
    }
    // Per-entry hashes for the anchor (checksums.json is excluded by buildTarGz).
    const entryHashes: Record<string, string> = {}
    for (const file of pack.files) {
      if (file === 'metadata/checksums.json') continue
      entryHashes[file] = sha256Hex(readFileSync(join(pack.root, file)))
    }
    const contentHash = computeContentHash(entryHashes)

    const keyPath = opts.keyPath
    if (!existsSync(keyPath)) throw new PackError(`private key not found: ${keyPath}`, 1)
    let privateKey
    try {
      privateKey = createPrivateKey(readFileSync(keyPath, 'utf8'))
    } catch (error) {
      throw new PackError(`cannot read private key ${keyPath}: ${String(error)}`, 1)
    }
    const signatureBytes = sign(null, Buffer.from(contentHash, 'utf8'), privateKey)
    // spki export is only valid on a PUBLIC key object.
    const publicKey = createPublicKey(privateKey)
    const publicPem = publicKey.export({ type: 'spki', format: 'pem' }).toString()
    const keyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))

    const createdAt = utcNowIso()
    const signatureInfo: SignatureInfo = {
      schemaVersion: 1,
      algorithm: 'ed25519',
      keyId,
      publicKey: publicPem,
      contentHash,
      signature: signatureBytes.toString('base64'),
      createdAt,
    }
    // Lightweight provenance (v0.3 frozen, DESIGN.md Appendix E): links
    // Artifact → Build → Signer. `--signer` is display metadata only — the
    // cryptographic identity is keyId (sha256 of the public key DER).
    const runtime = (pack.manifest as { runtime?: Record<string, unknown> } | undefined)?.runtime
    const provenance = {
      schemaVersion: 1,
      artifact: { contentHash },
      signing: {
        algorithm: 'ed25519',
        keyId,
        signer: opts.signer ?? 'unknown',
      },
      build: {
        dshPackVersion: opts.packagerVersion ?? '0.3.0',
        dshVersion: typeof runtime?.dshVersion === 'string' ? runtime.dshVersion : 'unknown',
        nodeVersion: typeof runtime?.nodeVersion === 'string' ? runtime.nodeVersion : process.versions.node,
        pnpmVersion: typeof runtime?.pnpmVersion === 'string' ? runtime.pnpmVersion : 'unknown',
      },
      createdAt,
    }

    // Rebuild: original entries (except checksums.json) + signing files.
    const entries: PackFileEntry[] = []
    for (const file of pack.files) {
      if (file === 'metadata/checksums.json') continue
      entries.push({ path: file, content: readFileSync(join(pack.root, file)) })
    }
    entries.push({ path: 'metadata/signature.json', content: prettyJson(signatureInfo) })
    entries.push({ path: 'metadata/provenance.json', content: prettyJson(provenance) })
    const built = await buildTarGz(entries)
    const finalEntries: PackFileEntry[] = [
      ...entries,
      { path: 'metadata/checksums.json', content: checksumsJson(built.contentHash, built.files) },
    ]
    const final = await buildTarGz(finalEntries)
    return { buffer: final.buffer, signature: signatureInfo }
  } finally {
    rmSync(pack.root, { recursive: true, force: true })
  }
}

/** Sign an existing `.dshpack` file, writing `<name>.signed.dshpack`. */
export async function signPackFile(file: string, opts: SignOptions): Promise<SignResult> {
  const buffer = readFileSync(file)
  const { buffer: signedBuffer, signature } = await signPackBuffer(buffer, {
    keyPath: opts.key,
    ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
    ...(opts.force === true ? { force: true } : {}),
  })
  const outDir = opts.outDir ?? dirname(file)
  mkdirSync(outDir, { recursive: true })
  const out = join(outDir, `${basename(file, '.dshpack')}.signed.dshpack`)
  writeFileSync(out, signedBuffer)
  return {
    file: out,
    keyId: signature.keyId,
    contentHash: signature.contentHash,
    ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
  }
}
