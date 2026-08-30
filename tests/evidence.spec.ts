/**
 * v0.5 Evidence Foundation unit tests (DESIGN-v0.5.0.md §3, D64–D67): the
 * Signed Evidence Envelope is self-authenticating — canonical statement digest
 * + ed25519 over `canonical(type + subject.contentHash + statementDigest)` —
 * bound to the immutable artifact contentHash (D64), and NEVER part of the
 * artifact or its Signature anchor (D65). Negative matrix: tamper / subject
 * substitution / wrong signer / stale evidence.
 */
import { createPrivateKey, createPublicKey, sign as cryptoSign } from 'node:crypto'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, openPack, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackBuffer, verifySignatureValue } from '../src/sign.js'
import { canonicalJson, prettyJson, sha256Hex } from '../src/canonical.js'
import { parseCommand } from '../src/commands.js'
import {
  EVIDENCE_DOMAIN, evidenceSigningInput, signEvidence, statementDigestOf,
  verifyEvidenceEnvelope, verifyEvidenceSigner, verifyEvidenceSubject,
} from '../src/evidence/envelope.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import type { EvidenceEnvelope } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-evidence-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

/** Minimal valid pack (manifest + a content file + metadata). */
async function makePack(root: string, content = '# web snapshot\n'): Promise<Buffer> {
  const entries: PackFileEntry[] = [
    {
      path: 'manifest.json',
      content: prettyJson({
        format: 'dshpack',
        schemaVersion: 1,
        profile: { name: 'web' },
        snapshot: { scope: 'profile', excludedLayersPresent: false },
        runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
        installable: true,
        portable: true,
        bundles: [],
        dependencies: {},
        configHash: 'sha256:' + 'a'.repeat(64),
        createdAt: '2026-08-30T00:00:00Z',
        packager: { name: '@why-daydream/dsh-pack', version: '0.5.0' },
      }),
    },
    { path: 'README.md', content },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

/** A build-provenance-like payload — the envelope treats statements as opaque. */
function buildStatement(): Record<string, unknown> {
  return {
    source: { gitCommit: 'f'.repeat(40), repository: 'github.com/company/app' },
    build: { dshPackVersion: '0.5.0', nodeVersion: '24.6.0', platform: { os: 'linux', arch: 'x64' } },
  }
}

describe('Signed Evidence Envelope (D64–D66)', () => {
  it('signs and verifies: canonical triple signature, statement digest, keyId', () => {
    const root = tempRoot('roundtrip')
    const key = generateKeypair(root)
    const contentHash = 'sha256:' + 'c'.repeat(64)
    const statement = buildStatement()
    const envelope = signEvidence({
      type: 'build-provenance', subjectContentHash: contentHash, statement, keyPath: key.privateKey,
    })

    expect(envelope.schemaVersion).toBe(1)
    expect(envelope.type).toBe('build-provenance')
    expect(envelope.subject.contentHash).toBe(contentHash)
    expect(envelope.statementDigest).toBe(statementDigestOf(statement))
    expect(envelope.signing.algorithm).toBe('ed25519')
    expect(envelope.signing.keyId).toBe(key.keyId)

    const verdict = verifyEvidenceEnvelope(envelope)
    expect(verdict.ok).toBe(true)
    if (verdict.ok) expect(verdict.keyId).toBe(key.keyId)
    // verifiedKeyId: ALWAYS recomputed from the embedded verification public
    // key — never a claimed value (protocol hardening #2)
    const der = createPublicKey(envelope.signing.publicKey).export({ type: 'spki', format: 'der' })
    expect(sha256Hex(der)).toBe(envelope.signing.keyId)
    expect(verifyEvidenceSubject(envelope, contentHash).ok).toBe(true)
    expect(verifyEvidenceSigner(envelope, key.keyId).ok).toBe(true)
  })

  it('canonical signing input is domain-separated and covers the full triple', () => {
    const input = evidenceSigningInput('build-provenance', 'sha256:' + 'c'.repeat(64), 'sha256:' + 'd'.repeat(64))
    expect(input).toBe(evidenceSigningInput('build-provenance', 'sha256:' + 'c'.repeat(64), 'sha256:' + 'd'.repeat(64)))
    // fixed protocol domain + schemaVersion (protocol hardening #1): an evidence
    // signature is tagged so it can never collide with other signing protocols
    const parsed = JSON.parse(input) as {
      domain?: unknown
      schemaVersion?: unknown
      type?: unknown
      subject?: { contentHash?: unknown }
      statementDigest?: { algorithm?: unknown; value?: unknown }
    }
    expect(parsed.domain).toBe(EVIDENCE_DOMAIN)
    expect(parsed.schemaVersion).toBe(1)
    expect(parsed.statementDigest).toEqual({ algorithm: 'sha256', value: 'd'.repeat(64) })
    // any component change ⇒ different bytes ⇒ different signature
    expect(input).not.toBe(evidenceSigningInput('sbom', 'sha256:' + 'c'.repeat(64), 'sha256:' + 'd'.repeat(64)))
    expect(input).not.toBe(evidenceSigningInput('build-provenance', 'sha256:' + 'e'.repeat(64), 'sha256:' + 'd'.repeat(64)))
    expect(input).not.toBe(evidenceSigningInput('build-provenance', 'sha256:' + 'c'.repeat(64), 'sha256:' + 'f'.repeat(64)))
  })

  it('rejects tampered statements and flipped signature bytes', () => {
    const root = tempRoot('tamper')
    const key = generateKeypair(root)
    const envelope = signEvidence({
      type: 'build-provenance', subjectContentHash: 'sha256:' + 'c'.repeat(64),
      statement: buildStatement(), keyPath: key.privateKey,
    })

    // statement edited (e.g. gitCommit rewritten) → statementDigest mismatch
    const tamperedStatement: EvidenceEnvelope = {
      ...envelope,
      statement: { ...buildStatement(), source: { gitCommit: '0'.repeat(40) } },
    }
    const verdict = verifyEvidenceEnvelope(tamperedStatement)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('statementDigest mismatch')

    // signature byte flipped
    const sig = Buffer.from(envelope.signing.signature, 'base64')
    sig[0] = (sig[0] ?? 0) ^ 0xff
    const tamperedSig: EvidenceEnvelope = { ...envelope, signing: { ...envelope.signing, signature: sig.toString('base64') } }
    const verdictSig = verifyEvidenceEnvelope(tamperedSig)
    expect(verdictSig.ok).toBe(false)
    if (!verdictSig.ok) expect(verdictSig.error).toContain('FAILED')
  })

  it('rejects subject substitution (signature covers subject.contentHash)', () => {
    const root = tempRoot('substitution')
    const key = generateKeypair(root)
    const subjectA = 'sha256:' + 'a'.repeat(64)
    const subjectB = 'sha256:' + 'b'.repeat(64)
    const envelope = signEvidence({
      type: 'build-provenance', subjectContentHash: subjectA, statement: buildStatement(), keyPath: key.privateKey,
    })

    // attacker rewrites subject → the signed triple no longer matches
    const substituted: EvidenceEnvelope = { ...envelope, subject: { contentHash: subjectB } }
    const verdict = verifyEvidenceEnvelope(substituted)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('FAILED')

    // binding check against a real artifact hash
    expect(verifyEvidenceSubject(envelope, subjectA).ok).toBe(true)
    const binding = verifyEvidenceSubject(envelope, subjectB)
    expect(binding.ok).toBe(false)
    if (!binding.ok) expect(binding.error).toContain('evidence subject is')
  })

  it('rejects the wrong signer and forged keyId/publicKey pairs', () => {
    const root = tempRoot('wrong-signer')
    const keyA = generateKeypair(root)
    const keyB = generateKeypair(root)
    const envelope = signEvidence({
      type: 'build-provenance', subjectContentHash: 'sha256:' + 'c'.repeat(64),
      statement: buildStatement(), keyPath: keyB.privateKey,
    })

    // VALID ≠ TRUSTED: the envelope is genuine but from the wrong key
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
    expect(verifyEvidenceSigner(envelope, keyB.keyId).ok).toBe(true)
    const wrong = verifyEvidenceSigner(envelope, keyA.keyId)
    expect(wrong.ok).toBe(false)
    if (!wrong.ok) expect(wrong.error).toContain('policy expects')

    // attacker pairs keyA's trusted keyId with keyB's public key/signature
    const forged: EvidenceEnvelope = { ...envelope, signing: { ...envelope.signing, keyId: keyA.keyId } }
    const verdict = verifyEvidenceEnvelope(forged)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('keyId does not match')
  })
})

describe('protocol domain separation (v0.5 hardening)', () => {
  it('a non-domain signature (other protocol, same key) is NOT valid evidence', () => {
    const root = tempRoot('domain')
    const key = generateKeypair(root)
    const contentHash = 'sha256:' + 'c'.repeat(64)
    const statement = buildStatement()
    const digest = statementDigestOf(statement)

    // What another signing protocol would cover: the BARE triple without the
    // `domain`/`schemaVersion` tag (e.g. an old-style or attestation protocol).
    // Signed with the SAME Ed25519 key — but evidence verification signs the
    // domain-separated input, so the replay must FAIL.
    const foreignInput = canonicalJson({ type: 'build-provenance', subject: { contentHash }, statementDigest: digest })
    const privateKey = createPrivateKey(readFileSync(key.privateKey, 'utf8'))
    const foreignSignature = cryptoSign(null, Buffer.from(foreignInput, 'utf8'), privateKey).toString('base64')
    const forged: EvidenceEnvelope = {
      schemaVersion: 1,
      type: 'build-provenance',
      subject: { contentHash },
      statement,
      statementDigest: digest,
      signing: {
        algorithm: 'ed25519',
        keyId: key.keyId,
        publicKey: readFileSync(key.publicKey, 'utf8'),
        signature: foreignSignature,
        createdAt: '2026-08-30T00:00:00Z',
      },
    }
    const verdict = verifyEvidenceEnvelope(forged)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('FAILED')
  })
})

describe('Evidence service (D64 subject binding + D65 separation)', () => {
  it('signs a sidecar bound to the pack contentHash; verify --against roundtrip', async () => {
    const root = tempRoot('service')
    const packFile = join(root, 'app.dshpack')
    const pack = await makePack(root)
    writeFileSync(packFile, pack)
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const anchorBefore = await computePackContentHash(pack)
    const result = await evidence.sign(packFile, {
      type: 'build-provenance', statement: buildStatement(), key: key.privateKey, signer: 'why-daydream',
    })
    // collection layout: <name>.dshpack.evidence/<type>/<statementDigest hex>.json
    const digestHex = statementDigestOf(buildStatement()).slice('sha256:'.length)
    expect(result.file).toBe(join(root, 'app.dshpack.evidence', 'build-provenance', `${digestHex}.json`))
    expect(existsSync(result.file)).toBe(true)
    expect(result.contentHash).toBe(anchorBefore)
    expect(result.statementDigest).toMatch(/^sha256:[0-9a-f]{64}$/)

    // the pack file on disk is untouched — evidence is a sidecar (D65)
    expect(readFileSync(packFile).equals(pack)).toBe(true)
    expect(await computePackContentHash(readFileSync(packFile))).toBe(anchorBefore)

    // the sidecar parses as a valid envelope bound to the same anchor
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
    expect(envelope.subject.contentHash).toBe(anchorBefore)

    const ok = await evidence.verify(result.file, { against: packFile })
    expect(ok).toMatchObject({ ok: true, type: 'build-provenance', subject: anchorBefore })
    expect(ok.errors).toEqual([])
  })

  it('stale evidence: a rebuilt artifact with a different contentHash FAILS --against', async () => {
    const root = tempRoot('stale')
    const v1File = join(root, 'v1.dshpack')
    const v2File = join(root, 'v2.dshpack')
    writeFileSync(v1File, await makePack(root, '# v1\n'))
    writeFileSync(v2File, await makePack(root, '# v2 — code changed\n'))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const result = await evidence.sign(v1File, {
      type: 'runtime-attestation', statement: { checks: { coldBoot: 'PASS' } }, key: key.privateKey,
    })
    const v1Anchor = await computePackContentHash(readFileSync(v1File))
    expect(result.contentHash).toBe(v1Anchor)

    expect((await evidence.verify(result.file, { against: v1File })).ok).toBe(true)

    // same evidence, NEW artifact → stale → FAIL (D64); envelope stays genuine
    const stale = await evidence.verify(result.file, { against: v2File })
    expect(stale.ok).toBe(false)
    expect(stale.subject).toBe(v1Anchor)
    expect(stale.errors.join('; ')).toContain('evidence subject is')
    expect(verifyEvidenceEnvelope(JSON.parse(readFileSync(result.file, 'utf8'))).ok).toBe(true)
  })

  it('D65: evidence does not enter the artifact contentHash nor the Artifact Signature anchor', async () => {
    const root = tempRoot('d65')
    const packFile = join(root, 'signed.dshpack')
    const pack = await makePack(root)
    const key = generateKeypair(root)

    // 1) artifact signed (v0.3) — the signature covers the contentHash anchor
    const { buffer: signedPack, signature } = await signPackBuffer(pack, { keyPath: key.privateKey, signer: 'why-daydream' })
    writeFileSync(packFile, signedPack)
    const anchorBefore = await computePackContentHash(signedPack)
    expect(signature.contentHash).toBe(anchorBefore)

    // 2) evidence sidecar for the same artifact
    const evidence = new DefaultEvidenceService()
    await evidence.sign(packFile, { type: 'build-provenance', statement: buildStatement(), key: key.privateKey })

    // 3) the anchor is unchanged by evidence creation, and the v0.3 signature
    //    still validates against it — evidence never touched the artifact
    expect(await computePackContentHash(readFileSync(packFile))).toBe(anchorBefore)
    const opened = await openPack(readFileSync(packFile))
    try {
      // no evidence file is embedded inside the archive
      expect(opened.files.some((f) => f.includes('evidence'))).toBe(false)
      const info = JSON.parse(readFileSync(join(opened.root, 'metadata/signature.json'), 'utf8')) as {
        contentHash: string
      }
      expect(verifySignatureValue(info, anchorBefore).ok).toBe(true)
    } finally {
      rmSync(opened.root, { recursive: true, force: true })
    }
  })

  it('verify reports precise failure reasons (bad JSON, wrong --key-id)', async () => {
    const root = tempRoot('verify-failures')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack(root))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const result = await evidence.sign(packFile, {
      type: 'build-provenance', statement: buildStatement(), key: key.privateKey,
    })

    // non-JSON evidence file
    const garbage = join(root, 'garbage.json')
    writeFileSync(garbage, 'not json')
    expect((await evidence.verify(garbage)).errors[0]).toContain('not valid JSON')

    // valid envelope + wrong expected signer → FAIL with the policy expectation
    const wrong = await evidence.verify(result.file, { keyId: 'f'.repeat(64) })
    expect(wrong.ok).toBe(false)
    expect(wrong.errors.join('; ')).toContain('policy expects')

    // valid envelope + right signer + right artifact → ok
    const ok = await evidence.verify(result.file, { against: packFile, keyId: key.keyId })
    expect(ok.ok).toBe(true)
  })
})

describe('Evidence Collection (multi-evidence, no overwrite)', () => {
  it('same statement re-sign is idempotent; different statements/types coexist', async () => {
    const root = tempRoot('collection')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack(root))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const first = await evidence.sign(packFile, { type: 'build-provenance', statement: buildStatement(), key: key.privateKey })
    // idempotent re-sign: same statement ⇒ same digest ⇒ same file, untouched
    const second = await evidence.sign(packFile, { type: 'build-provenance', statement: buildStatement(), key: key.privateKey })
    expect(second.file).toBe(first.file)
    expect(readFileSync(first.file, 'utf8')).toBe(readFileSync(second.file, 'utf8'))

    // a DIFFERENT statement of the SAME type ⇒ a NEW file — both coexist
    const other = await evidence.sign(packFile, {
      type: 'build-provenance', statement: { source: { gitCommit: '0'.repeat(40) } }, key: key.privateKey,
    })
    expect(other.file).not.toBe(first.file)
    expect(existsSync(first.file)).toBe(true)
    expect(existsSync(other.file)).toBe(true)

    // a DIFFERENT type ⇒ separate type directory — all three coexist (one
    // artifact, N independent evidence files — SBOM must never overwrite
    // provenance)
    const sbom = await evidence.sign(packFile, { type: 'sbom', statement: { packages: [] }, key: key.privateKey })
    expect(sbom.file).toContain(join('app.dshpack.evidence', 'sbom'))
    expect(existsSync(sbom.file)).toBe(true)
    expect(existsSync(first.file)).toBe(true)
    expect(existsSync(other.file)).toBe(true)
  })

  it('refuses to overwrite an existing evidence file that was modified', async () => {
    const root = tempRoot('no-overwrite')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack(root))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const result = await evidence.sign(packFile, { type: 'build-provenance', statement: buildStatement(), key: key.privateKey })
    // someone modified the existing evidence (e.g. a tampered statement)
    const edited = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    edited.statement = { ...buildStatement(), source: { gitCommit: '1'.repeat(40) } }
    writeFileSync(result.file, prettyJson(edited))

    await expect(
      evidence.sign(packFile, { type: 'build-provenance', statement: buildStatement(), key: key.privateKey }),
    ).rejects.toThrow(/refusing to overwrite/)
  })
})

describe('CLI surface', () => {
  it('recognizes /pack evidence sign|verify', () => {
    expect(parseCommand('evidence sign app.dshpack --type build-provenance --statement-file s.json --key k.pem').sub).toBe('evidence')
    const parsed = parseCommand('evidence verify app.dshpack.evidence.json --against app.dshpack --key-id ' + 'f'.repeat(64))
    expect(parsed.sub).toBe('evidence')
    expect(parsed.positionals).toEqual(['verify', 'app.dshpack.evidence.json'])
    expect(parsed.flags['against']).toBe('app.dshpack')
    expect(parsed.flags['key-id']).toBe('f'.repeat(64))
  })
})
