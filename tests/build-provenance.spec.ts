/**
 * v0.5 Build Provenance v2 test matrix (DESIGN-v0.5.0.md alpha.2, D68–D71):
 * provenance is captured AT BUILD TIME from the build site — never inferred
 * afterwards from the current repo state. P0–P10:
 *   P0 clean repo pack → provenance PASS
 *   P1 subject.contentHash == actual recomputed artifact anchor
 *   P2 git commit is a full SHA
 *   P3 dirty repo → provenance FAIL by default
 *   P4 --allow-dirty → dirty=true + sourceTreeDigest
 *   P5 pack, then switch git commit → provenance still records the build-time commit
 *   P6 lockfile change → lockfileDigest changes
 *   P7 file:/link: dependency content change → dependencyClosureDigest changes
 *   P8 same configHash, different code → contentHash/provenance differ
 *   P9 modified provenance statement → Evidence signature FAIL
 *   P10 subject swapped to another artifact → signature FAIL
 */
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, openPack, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair } from '../src/sign.js'
import { prettyJson } from '../src/canonical.js'
import { DefaultPackager } from '../src/service.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { verifyEvidenceEnvelope } from '../src/evidence/envelope.js'
import {
  buildReceiptPath, captureGitSource, computeDependencyClosureDigest, validateBuildRecord,
} from '../src/evidence/build-record.js'
import type { BuildRecord } from '../src/evidence/build-record.js'
import type { EvidenceEnvelope } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const PACKAGER_VERSION = '0.5.0-alpha.2'
const execFileAsync = promisify(execFile)

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-provenance-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// --- git helpers (temporary build sites) ---

async function git(dir: string, args: string[]): Promise<string> {
  const { stdout } = await execFileAsync('git', args, { cwd: dir, timeout: 10_000 })
  return stdout.trim()
}

async function initGitRepo(dir: string): Promise<string> {
  mkdirSync(dir, { recursive: true })
  await git(dir, ['init'])
  await git(dir, ['config', 'user.name', 'dsh-pack-test'])
  await git(dir, ['config', 'user.email', 'dsh-pack-test@example.com'])
  await git(dir, ['config', 'commit.gpgsign', 'false'])
  writeFileSync(join(dir, 'README.md'), '# build site\n')
  await git(dir, ['add', '-A'])
  await git(dir, ['commit', '-m', 'init'])
  return git(dir, ['rev-parse', 'HEAD'])
}

// --- profile / pack helpers ---

const PROFILE_PACKAGE_JSON = prettyJson({
  name: 'web-profile', private: true, version: '0.0.0',
  dependencies: { foo: '^1.0.0' },
  dsh: { profile: { bundles: [] } },
})

const PROFILE_PATCH = `# web
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
`

function lockfileFixture(fooVersion = '1.2.3'): string {
  return [
    "lockfileVersion: '9.0'",
    "importers:",
    "  '.':",
    "    dependencies:",
    "      foo:",
    "        specifier: ^1.0.0",
    `        version: ${fooVersion}`,
    "packages:",
    `  /foo@${fooVersion}:`,
    "    resolution:",
    "      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==",
    `      tarball: https://registry.npmjs.org/foo/-/foo-${fooVersion}.tgz`,
    `    version: ${fooVersion}`,
    '',
  ].join('\n')
}

/** Create $DSH_HOME/profiles/web with a lockfile (P0/P6 fixtures). */
function makeProfileHome(home: string, opts: { lockfile?: string } = {}): void {
  const profile = join(home, 'profiles', 'web')
  mkdirSync(profile, { recursive: true })
  writeFileSync(join(profile, 'package.json'), PROFILE_PACKAGE_JSON)
  writeFileSync(join(profile, 'cordis.patch.yml'), PROFILE_PATCH)
  if (opts.lockfile !== undefined) writeFileSync(join(profile, 'pnpm-lock.yaml'), opts.lockfile)
}

interface PackProfileOptions {
  home: string
  outDir: string
  buildCwd?: string
  evidenceKey?: string
  allowDirty?: boolean
  signer?: string
}

/** Pack the web profile via the real pipeline (captures build-time inputs, D68). */
async function packProfile(opts: PackProfileOptions): Promise<{ packFile: string; receipt: BuildRecord }> {
  mkdirSync(opts.outDir, { recursive: true }) // pack() writes into outDir, it must exist
  const packager = new DefaultPackager({
    home: opts.home,
    installedDshVersion: DSH_VERSION,
    packagerVersion: PACKAGER_VERSION,
    ...(opts.buildCwd !== undefined ? { buildCwd: opts.buildCwd } : {}),
  })
  const result = await packager.pack({
    profile: 'web',
    outDir: opts.outDir,
    portable: true,
    provenance: true,
    ...(opts.evidenceKey !== undefined ? { evidenceKey: opts.evidenceKey } : {}),
    ...(opts.allowDirty === true ? { allowDirty: true } : {}),
    ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
  })
  expect(result.receipt).toBe(buildReceiptPath(result.file))
  const receipt = JSON.parse(readFileSync(result.receipt as string, 'utf8')) as BuildRecord
  return { packFile: result.file, receipt }
}

// --- P6/P7 unit-level digest tests ---

describe('P6/P7: materials digests (D69)', () => {
  it('P6: lockfile content change ⇒ sourceLockfileDigest / closure digest change', () => {
    const digestA = computeDependencyClosureDigest(lockfileFixture('1.2.3'), [])
    const digestB = computeDependencyClosureDigest(lockfileFixture('1.2.4'), [])
    expect(digestA).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(digestB).not.toBe(digestA)
  })

  it('P7: file:/link: dependency content change ⇒ dependencyClosureDigest changes (not the path)', () => {
    const root = tempRoot('p7')
    const localDir = join(root, 'local-plugin')
    mkdirSync(localDir, { recursive: true })
    writeFileSync(join(localDir, 'index.js'), 'module.exports = 1\n')
    const dep = { name: 'local-plugin', spec: 'file:../local-plugin', kind: 'file' as const, resolved: localDir }

    const digestV1 = computeDependencyClosureDigest(undefined, [dep])
    // content changed, PATH unchanged ⇒ digest MUST change (a path-only closure
    // would silently miss the code change)
    writeFileSync(join(localDir, 'index.js'), 'module.exports = 2\n')
    const digestV2 = computeDependencyClosureDigest(undefined, [dep])
    expect(digestV2).not.toBe(digestV1)

    // content identical, different path ⇒ digest is content-based, unchanged
    const otherDir = join(root, 'elsewhere')
    mkdirSync(otherDir, { recursive: true })
    writeFileSync(join(otherDir, 'index.js'), 'module.exports = 2\n')
    const digestSameContent = computeDependencyClosureDigest(undefined, [{ ...dep, resolved: otherDir }])
    expect(digestSameContent).toBe(digestV2)
  })

  it('captureGitSource: clean repo → full SHA + dirty=false; non-git dir → no source claim', async () => {
    const root = tempRoot('git-source')
    const repo = join(root, 'repo')
    const commit = await initGitRepo(repo)
    const clean = await captureGitSource(repo)
    expect(clean.gitCommit).toBe(commit)
    expect(clean.gitCommit).toMatch(/^[0-9a-f]{40}$/)
    expect(clean.dirty).toBe(false)

    const nonGit = await captureGitSource(join(root, 'plain'))
    expect(nonGit.gitCommit).toBeUndefined()
    expect(nonGit.dirty).toBe(false)
  })
})

// --- P0–P5: build-time capture via the real pack pipeline ---

describe('P0–P5: build-time capture (D68)', () => {
  it('P0+P1+P2: clean repo pack → provenance PASS, subject == actual anchor, full commit SHA', async () => {
    const root = tempRoot('p0')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    const commit = await initGitRepo(repo)

    const { packFile, receipt } = await packProfile({ home, outDir, buildCwd: repo })
    const validated = validateBuildRecord(receipt)
    expect(validated.ok).toBe(true)
    // P1: subject == actual recomputed artifact anchor (never declared)
    expect(receipt.subject.contentHash).toBe(await computePackContentHash(readFileSync(packFile)))
    // P2: full commit SHA from the build site
    expect(receipt.source.gitCommit).toBe(commit)
    expect(receipt.source.dirty).toBe(false)
    // materials + environment captured at build time (D69/D71)
    expect(receipt.materials.sourceLockfileDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(receipt.materials.artifactLockfileDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(receipt.materials.profileManifestDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(receipt.environment.dshPack).toBe(PACKAGER_VERSION)
    expect(receipt.environment.os).toBe(process.platform)
  })

  it('P3: dirty repo → provenance FAIL by default (pack with --evidence-key)', async () => {
    const root = tempRoot('p3')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)
    writeFileSync(join(repo, 'README.md'), '# build site — dirty\n') // uncommitted change

    const key = generateKeypair(join(root, 'keys'))
    const packager = new DefaultPackager({
      home, installedDshVersion: DSH_VERSION, packagerVersion: PACKAGER_VERSION, buildCwd: repo,
    })
    mkdirSync(outDir, { recursive: true }) // pack() writes into outDir, it must exist
    await expect(packager.pack({
      profile: 'web', outDir, portable: true, provenance: true, evidenceKey: key.privateKey,
    })).rejects.toThrow(/dirty/)

    // without signing, a dirty pack still succeeds and records dirty=true
    const { receipt } = await packProfile({ home, outDir: join(root, 'out2'), buildCwd: repo })
    expect(receipt.source.dirty).toBe(true)
    expect(receipt.source.sourceTreeDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('P4: --allow-dirty → dirty=true + sourceTreeDigest, evidence signed at build time', async () => {
    const root = tempRoot('p4')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)
    writeFileSync(join(repo, 'README.md'), '# build site — dirty\n')

    const key = generateKeypair(join(root, 'keys'))
    const packager = new DefaultPackager({
      home, installedDshVersion: DSH_VERSION, packagerVersion: PACKAGER_VERSION, buildCwd: repo,
    })
    mkdirSync(outDir, { recursive: true }) // pack() writes into outDir, it must exist
    const result = await packager.pack({
      profile: 'web', outDir, portable: true, provenance: true, evidenceKey: key.privateKey, allowDirty: true,
    })
    expect(result.evidence).toBeDefined()
    const receipt = JSON.parse(readFileSync(result.receipt as string, 'utf8')) as BuildRecord
    expect(receipt.source.dirty).toBe(true)
    expect(receipt.source.sourceTreeDigest).toMatch(/^sha256:[0-9a-f]{64}$/)

    // the build-time signed evidence is genuine and carries the dirty record
    const envelope = JSON.parse(readFileSync(result.evidence as string, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
    const statement = envelope.statement as BuildRecord
    expect(statement.source.dirty).toBe(true)
    expect(statement.source.sourceTreeDigest).toBe(receipt.source.sourceTreeDigest)
  })

  it('P5: pack then switch git commit → provenance still records the BUILD-TIME commit', async () => {
    const root = tempRoot('p5')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    const commitA = await initGitRepo(repo)

    const { packFile } = await packProfile({ home, outDir, buildCwd: repo })

    // the repo moves on — HEAD is now a DIFFERENT commit
    await git(repo, ['commit', '--allow-empty', '-m', 'second commit'])
    const commitB = await git(repo, ['rev-parse', 'HEAD'])
    expect(commitB).not.toBe(commitA)

    // provenance signing consumes ONLY the receipt — it must record commit A,
    // never the current HEAD B (post-hoc inference would be forgery, D68)
    const key = generateKeypair(join(root, 'keys'))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.provenance(packFile, { key: key.privateKey })
    expect(result.gitCommit).toBe(commitA)
    expect(result.gitCommit).not.toBe(commitB)
    expect(result.dirty).toBe(false)
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect((envelope.statement as BuildRecord).source.gitCommit).toBe(commitA)
  })
})

// --- P8–P10 + receipt anti-tamper ---

describe('P8–P10: identity separation and tamper resistance', () => {
  it('P8: same configHash, different artifact → contentHash/provenance differ (configHash ≠ code identity)', async () => {
    const root = tempRoot('p8')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)

    const { packFile: packA, receipt: receiptA } = await packProfile({ home, outDir: join(root, 'outA'), buildCwd: repo })
    const { packFile: packB, receipt: receiptB } = await packProfile({ home, outDir: join(root, 'outB'), buildCwd: repo })

    // configHash is deterministic for the same configuration…
    const openedA = await openPack(readFileSync(packA))
    const openedB = await openPack(readFileSync(packB))
    try {
      const configHashA = (openedA.manifest as { configHash?: string }).configHash
      const configHashB = (openedB.manifest as { configHash?: string }).configHash
      expect(configHashA).toBe(configHashB)
    } finally {
      rmSync(openedA.root, { recursive: true, force: true })
      rmSync(openedB.root, { recursive: true, force: true })
    }

    // …but the artifact identity (contentHash + provenance subject) differs:
    // configHash can NEVER substitute source/code identity (D70)
    expect(receiptA.subject.contentHash).not.toBe(receiptB.subject.contentHash)
    expect(await computePackContentHash(readFileSync(packA))).not.toBe(await computePackContentHash(readFileSync(packB)))
    // both bind their own artifact (P1 holds for each)
    expect(receiptA.subject.contentHash).toBe(await computePackContentHash(readFileSync(packA)))
    expect(receiptB.subject.contentHash).toBe(await computePackContentHash(readFileSync(packB)))
  })

  it('P9: modified provenance statement → Evidence signature FAIL', async () => {
    const root = tempRoot('p9')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)

    const { packFile } = await packProfile({ home, outDir, buildCwd: repo })
    const key = generateKeypair(join(root, 'keys'))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.provenance(packFile, { key: key.privateKey })

    const original = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(original).ok).toBe(true)
    expect((await evidence.verify(result.file, { against: packFile })).ok).toBe(true)

    // attacker rewrites the provenance payload (e.g. fakes the closure digest)
    const tampered = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    tampered.statement = { ...(tampered.statement as BuildRecord), materials: { ...(tampered.statement as BuildRecord).materials, dependencyClosureDigest: 'sha256:' + 'e'.repeat(64) } }
    writeFileSync(result.file, prettyJson(tampered))
    const verdict = verifyEvidenceEnvelope(tampered)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('statementDigest mismatch')
    expect((await evidence.verify(result.file)).ok).toBe(false)
  })

  it('P10: Artifact A provenance, subject swapped to Artifact B → signature FAIL', async () => {
    const root = tempRoot('p10')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)

    const { packFile: packA, receipt: receiptA } = await packProfile({ home, outDir: join(root, 'outA'), buildCwd: repo })
    const { packFile: packB } = await packProfile({ home, outDir: join(root, 'outB'), buildCwd: repo })
    const key = generateKeypair(join(root, 'keys'))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.provenance(packA, { key: key.privateKey })

    // envelope-level: swapping subject.contentHash breaks the signed triple
    const swapped = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(swapped.subject.contentHash).toBe(receiptA.subject.contentHash)
    swapped.subject = { contentHash: await computePackContentHash(readFileSync(packB)) }
    const verdict = verifyEvidenceEnvelope(swapped)
    expect(verdict.ok).toBe(false)
    if (!verdict.ok) expect(verdict.error).toContain('FAILED')

    // service-level: --against B fails the D64 subject binding
    const binding = await evidence.verify(result.file, { against: packB })
    expect(binding.ok).toBe(false)
    expect(binding.errors.join('; ')).toContain('evidence subject is')
  })

  it('receipt anti-tamper: edited receipt subject is refused; missing receipt errors', async () => {
    const root = tempRoot('receipt-guard')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)
    const key = generateKeypair(join(root, 'keys'))
    const evidence = new DefaultEvidenceService()

    const { packFile, receipt } = await packProfile({ home, outDir, buildCwd: repo })
    const receiptPath = buildReceiptPath(packFile)
    const forged = { ...receipt, subject: { contentHash: 'sha256:' + 'f'.repeat(64) } }
    writeFileSync(receiptPath, prettyJson(forged))
    await expect(evidence.provenance(packFile, { key: key.privateKey })).rejects.toThrow(/build receipt subject/)

    // a pack with no receipt (built outside the pipeline) has nothing to consume
    const bare = await buildTarGz([{ path: 'manifest.json', content: prettyJson({ format: 'dshpack', schemaVersion: 1 }) }])
    const bareFile = join(root, 'bare.dshpack')
    writeFileSync(bareFile, bare.buffer)
    await expect(evidence.provenance(bareFile, { key: key.privateKey })).rejects.toThrow(/no build receipt/)
  })
})

describe('P11/P12: D72 trust boundary — build-time attestation vs post-build endorsement', () => {
  it('P11: a modified receipt can only be signed as post-build-receipt — never build-time', async () => {
    const root = tempRoot('p11')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)

    // pack WITHOUT --evidence-key: only the UNSIGNED receipt exists
    const { packFile, receipt } = await packProfile({ home, outDir, buildCwd: repo })
    const receiptPath = buildReceiptPath(packFile)
    expect(receipt.capture.mode).toBe('build-time')

    // the unsigned receipt is edited after the build (gitCommit rewritten;
    // subject kept valid so the artifact binding still holds)
    const edited = { ...receipt, source: { ...receipt.source, gitCommit: 'b'.repeat(40) } }
    writeFileSync(receiptPath, prettyJson(edited))

    // post-build provenance MAY still be generated — but only as an
    // ENDORSEMENT: origin must be post-build-receipt, NEVER build-time (D72)
    const key = generateKeypair(join(root, 'keys'))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.provenance(packFile, { key: key.privateKey })
    expect(result.captureMode).toBe('post-build-receipt')
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    const statement = envelope.statement as BuildRecord
    expect(statement.capture.mode).toBe('post-build-receipt')
    // the modified input is honestly recorded under the endorsement origin…
    expect(statement.source.gitCommit).toBe('b'.repeat(40))
    // …and the signed statement is genuine (but post-build)
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
  })

  it('P12: build-time attestation survives later receipt modification (signed at the build moment)', async () => {
    const root = tempRoot('p12')
    const home = join(root, 'home')
    const repo = join(root, 'repo')
    const outDir = join(root, 'out')
    makeProfileHome(home, { lockfile: lockfileFixture() })
    await initGitRepo(repo)

    // build-time attestation: signed AT the build site by /pack --evidence-key
    const key = generateKeypair(join(root, 'keys'))
    const packager = new DefaultPackager({
      home, installedDshVersion: DSH_VERSION, packagerVersion: PACKAGER_VERSION, buildCwd: repo,
    })
    mkdirSync(outDir, { recursive: true })
    const result = await packager.pack({
      profile: 'web', outDir, portable: true, provenance: true, evidenceKey: key.privateKey,
    })
    expect(result.evidence).toBeDefined()
    const attestation = JSON.parse(readFileSync(result.evidence as string, 'utf8')) as EvidenceEnvelope
    const statementBefore = attestation.statement as BuildRecord
    expect(statementBefore.capture.mode).toBe('build-time')
    const subjectBefore = attestation.subject.contentHash
    const gitCommitBefore = statementBefore.source.gitCommit

    // the UNSIGNED receipt is modified afterwards — the build-time
    // attestation must remain untouched and VALID (its statement + signature
    // were fixed at the build moment)
    const receiptPath = buildReceiptPath(result.file)
    const receipt = JSON.parse(readFileSync(receiptPath, 'utf8')) as BuildRecord
    writeFileSync(receiptPath, prettyJson({ ...receipt, source: { ...receipt.source, gitCommit: 'c'.repeat(40) } }))

    expect(verifyEvidenceEnvelope(attestation).ok).toBe(true)
    expect(attestation.subject.contentHash).toBe(subjectBefore)
    expect((attestation.statement as BuildRecord).capture.mode).toBe('build-time')
    expect((attestation.statement as BuildRecord).source.gitCommit).toBe(gitCommitBefore)
    // the attestation still binds the artifact
    const evidence = new DefaultEvidenceService()
    expect((await evidence.verify(result.evidence as string, { against: result.file })).ok).toBe(true)
  })
})
