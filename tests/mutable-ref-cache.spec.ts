/**
 * v0.5.0-rc.1 — N1 Mutable Ref / Cache regression matrix (D112/D113/D129):
 *
 * D112 — Mutable refs never override immutable lock identity: a locked run
 *        executes the LOCKED manifest digest, never a re-resolved tag.
 * D113 — Cache hit never bypasses integrity / evidence / trust / policy
 *        verification: cached bytes are re-verified at every run.
 * D129 (frozen this round) — Authorization verdicts are never cacheable as
 *        artifact identity: ALLOW is a function of artifact + evidence +
 *        CURRENT trust.yaml + CURRENT execution target, so a cached artifact is
 *        re-decided on every run. Cache stores bytes, not decisions.
 *
 * RC-N1 North-Star: tag prod → A, lock → manifest A, A cached, prod → malicious
 * B, trust policy also changes ⇒ locked run → A with CURRENT policy re-applied;
 * mutable run → B with verify/policy; NEVER cached-A bypassing current policy,
 * NEVER locked-A-missing falling back to B.
 *
 * N1 does NOT add cache TTL / new lock selectors / registry pinning (rc.1
 * scope guard) — adversarial tests + minimal fixes only.
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { LocalImageStore } from '../src/image/local-store.js'
import { DefaultImageService } from '../src/image/service.js'
import { DefaultPackager } from '../src/service.js'
import { MockRegistry } from './helpers/mock-registry.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n1-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

async function pnpmAvailable(): Promise<boolean> {
  try {
    await execFileAsync('pnpm', ['--version'], { timeout: 10_000 })
    return true
  } catch {
    return false
  }
}
const hasPnpm = await pnpmAvailable()

/** Machine A: a signed, runnable profile → .dshpack (temperature is the knob). */
async function makeSignedPack(root: string, outDir: string, temperature = 0.3): Promise<{ file: string; keyId: string }> {
  const homeA = join(root, 'homeA')
  mkdirSync(join(homeA, 'profiles', 'web'), { recursive: true })
  const profileA = join(homeA, 'profiles', 'web')
  writeFileSync(join(profileA, 'package.json'), JSON.stringify({
    name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
  }, null, 2))
  writeFileSync(join(profileA, 'cordis.patch.yml'), `# web
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: ${temperature}
`)
  await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 60_000 })

  const packager = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.1' })
  const packed = await packager.pack({ profile: 'web', outDir, portable: true })
  const key = await packager.keygen({ outDir: mkdtempSync(join(outDir, 'keys-')) })
  const signed = await packager.sign(packed.file, { key: key.privateKey, signer: 'why-daydream' })
  return { file: signed.file, keyId: key.keyId }
}

/** Machine B: fresh home + local image store. */
function makeImageEnv(root: string): { images: DefaultImageService; home: string } {
  const home = join(root, 'homeB')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
    home,
    installedDshVersion: DSH_VERSION,
  })
  return { images, home }
}

const remoteRefOf = (mock: MockRegistry, repo: string, ref: string): string => `127.0.0.1:${mock.port}/${repo}:${ref}`
const remoteDigestRefOf = (mock: MockRegistry, repo: string, digest: string): string => `127.0.0.1:${mock.port}/${repo}@${digest}`

/** Push artifact A to `prod`, lock `prod` → manifest A, then drift `prod` → B. */
async function pushProdThenDrift(
  mock: MockRegistry, images: DefaultImageService, root: string,
): Promise<{ contentHashA: string; contentHashB: string; lockFile: string; lockedResolved: string }> {
  const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
  const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
  await images.import(a.file, { tag: 'org/agent:v1' })
  const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

  // lock prod WHILE it still points at A (D48)
  const lockFile = join(root, 'dsh-lock.json')
  const locked = await images.lock(remoteRefOf(mock, 'org/agent', 'prod'), { file: lockFile })
  expect(locked.resolved).toBe(remoteDigestRefOf(mock, 'org/agent', pushedA.ociManifestDigest))

  // tag drift: prod → B, so the lock point is now stale
  await images.import(b.file, { tag: 'org/agent:v2' })
  const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))
  expect(pushedB.ociManifestDigest).not.toBe(pushedA.ociManifestDigest)

  return {
    contentHashA: pushedA.contentHash, contentHashB: pushedB.contentHash,
    lockFile, lockedResolved: locked.resolved,
  }
}

// ============================================================
// N1.1 — tag drift after lock (D112): locked identity is immutable
// ============================================================

describe('N1.1: tag drift after lock — locked run executes A, never re-resolves :prod', () => {
  it('lock prod → A, drift prod → B, run locked ref → A', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n11')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { images } = makeImageEnv(root)
      const { contentHashA, contentHashB, lockedResolved } = await pushProdThenDrift(mock, images, root)

      // fresh machine executes the LOCKED identity — the full OCI → DSH →
      // signature → trust chain still runs (D49), but the identity is A.
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const ran = await imagesB.run(lockedResolved)
      expect(ran.digest).toBe(contentHashA)
      expect(ran.digest).not.toBe(contentHashB) // :prod → B must NOT be followed
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.2 — cache hit after tag drift (D113): cached A is re-verified, never substituted
// ============================================================

describe('N1.2: cache hit after tag drift — cached artifact is re-verified, never substituted', () => {
  it('A cached locally + prod → B ⇒ locked run @A still verifies and runs A', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n12')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))
      const lockFile = join(root, 'dsh-lock.json')
      const locked = await images.lock(remoteRefOf(mock, 'org/agent', 'prod'), { file: lockFile })

      // machine B pulls prod WHILE it still points at A → A is cached (+ local tag mirror)
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pulled.contentHash).toBe(pushedA.contentHash)

      // now drift prod → B on the registry; the locked digest @A is a LOCAL cache hit
      await images.import(b.file, { tag: 'org/agent:v2' })
      const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pushedB.ociManifestDigest).not.toBe(pushedA.ociManifestDigest)

      const ran = await imagesB.run(locked.resolved)
      // cache hit must still run the FULL verify chain and return A — never B
      expect(ran.digest).toBe(pushedA.contentHash)
      expect(ran.digest).not.toBe(pushedB.contentHash)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.3 — cached artifact + trust policy change (D129):
// cache stores bytes, not authorization decisions
// ============================================================

describe('N1.3: cached artifact is re-decided against the CURRENT trust policy', () => {
  it('Key-A trusted → run ALLOW; remove Key-A from trust.yaml → same cached A → DENY', { timeout: 120_000 }, async () => {
    const root = tempRoot('n13')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const { file, keyId } = await makeSignedPack(root, root)
      const { images } = makeImageEnv(root)
      await images.import(file, { tag: 'org/agent:v1' })
      await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

      // machine B: pull → A cached; trust.yaml trusts Key-A
      const { images: imagesB, home } = makeImageEnv(join(root, 'fresh'))
      await imagesB.pull(remoteRefOf(mock, 'org/agent', 'prod'))
      const trustFile = join(home, 'trust.yaml')
      const policy = (trusted: string): string => `version: 1
registries:
  "127.0.0.1:${mock.port}/org/agent":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${trusted}"
`
      writeFileSync(trustFile, policy(keyId))
      const first = await imagesB.run(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(first.trust).toBe('VERIFIED')

      // policy change: Key-A REMOVED — artifact/cache bytes are untouched
      writeFileSync(trustFile, policy('f'.repeat(64)))
      const second = await imagesB.run(remoteRefOf(mock, 'org/agent', 'prod')).catch((error: Error) => error)
      expect(second).toBeInstanceOf(Error)
      expect((second as Error).message).toMatch(/trust policy rejected/)
      // nothing new was materialized for the rejected run
      expect(readdirSync(join(home, 'profiles')).filter((p) => p.startsWith('.run-')).length).toBe(1)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.4 — cached Evidence trust change (D129, evidence dimension):
// same artifact + same evidence bytes + changed policy ⇒ verdict flips
// ============================================================
// The image run path (v0.4.1) enforces SIGNATURE trust only — the v0.5
// evidence chain lives in packager.policy(). N1.4 pins D129 where evidence is
// actually consumed: policy() re-derives the verdict from the CURRENT
// trust.yaml on every evaluation; ALLOW is never cached alongside the
// artifact/evidence bytes.

import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { canonicalJson, prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import type { DependencyTree } from '../src/types.js'

const MINIMAL_DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: {}, closure: {}, localDeps: [], warnings: [],
}

async function n1MakePack(): Promise<Buffer> {
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: {},
    configHash: computeConfigHash({ rows: [] }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: 'web-profile', version: '1.0.0', private: true, dependencies: {} }) },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
    { path: 'resolved/composition.json', content: prettyJson({ rows: [] }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson(MINIMAL_DEP_TREE) },
    { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

interface N1Artifact {
  packFile: string
  keyId: string
  collectionRoot: string
}

/** Deterministic attestation document — same semantics + same run metadata ⇒ same bytes. */
function n1AttDoc(providers: string[], runId: string): string {
  const normalized = {
    declaredCapabilityDigest: 'sha256:' + 'd'.repeat(64),
    observation: { coverage: 'complete', reasons: [] },
    coldBoot: { status: 'PASS' },
    observed: { tools: [], skills: [], services: [], providers },
    comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
  }
  const resultDigest = 'sha256:' + sha256Hex(canonicalJson(normalized))
  return JSON.stringify({
    schemaVersion: 1, subject: { contentHash: 'ignored' },
    metadata: { observedAt: '2026-08-30T00:00:00Z', runId },
    ...normalized,
    resultDigest,
  })
}

async function n1BuildArtifact(root: string, label: string): Promise<N1Artifact> {
  const dir = join(root, label)
  mkdirSync(dir, { recursive: true })
  const packFile = join(dir, 'app.dshpack')
  writeFileSync(packFile, await n1MakePack())
  const key = generateKeypair(join(dir, 'release'))
  const signed = await signPackFile(packFile, { key: key.privateKey })
  const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
  return { packFile: signed.file, keyId: key.keyId, collectionRoot }
}

async function n1SignAttestation(artifact: N1Artifact, docText: string, key: string): Promise<void> {
  const evidence = new DefaultEvidenceService()
  const docHex = sha256Hex(docText)
  const docFile = join(artifact.collectionRoot, 'documents', `${docHex}.attestation.json`)
  mkdirSync(dirname(docFile), { recursive: true })
  writeFileSync(docFile, docText)
  await evidence.sign(artifact.packFile, {
    type: 'attestation',
    statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
    key,
  })
}

async function n1Evaluate(
  artifact: N1Artifact, policyYaml: string,
): Promise<Awaited<ReturnType<DefaultPackager['policy']>>> {
  const home = join(dirname(artifact.packFile), 'policy-home')
  mkdirSync(home, { recursive: true })
  writeFileSync(join(home, 'trust.yaml'), policyYaml)
  const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
  return packager.policy(artifact.packFile, {
    repository: 'ghcr.io/company/prod-app',
    collectionDir: artifact.collectionRoot,
    executionTarget: { os: 'linux', arch: 'x64' },
  })
}

const n1V2Policy = (releaseKeyId: string, evidenceKeyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKeyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${evidenceKeyId}"
`

describe('N1.4: evidence trust change re-decides — verdict is never cached with the bytes', () => {
  it('Attestor-X trusted → ALLOW; remove Attestor-X → same artifact+evidence bytes → DENY', async () => {
    const root = tempRoot('n14')
    const artifact = await n1BuildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const attestor = generateKeypair(join(root, 'attestor'))

    const doc = n1AttDoc(['process.exec'], 'n14')
    await n1SignAttestation(artifact, doc, attestor.privateKey)

    // snapshot the exact bytes the SECOND evaluation reuses — only the policy
    // file changes between the two calls
    const packBytes = readFileSync(artifact.packFile)

    const first = await n1Evaluate(artifact, n1V2Policy(artifact.keyId, attestor.keyId))
    expect(first.verdict.decision).toBe('ALLOW')
    expect(first.verdict.evidenceTrust.attestation).toBe('VERIFIED')

    // policy change: Attestor-X removed — NOTHING else changes
    const second = await n1Evaluate(artifact, n1V2Policy(artifact.keyId, 'f'.repeat(64)))
    expect(second.verdict.decision).toBe('DENY')
    expect(second.verdict.evidenceTrust.attestation).toBe('UNTRUSTED')
    expect(second.verdict.errors.join('; ')).toContain('UNTRUSTED_EVIDENCE_ISSUER')

    // prove the artifact + evidence bytes are byte-identical across both runs
    expect(readFileSync(artifact.packFile).equals(packBytes)).toBe(true)
    const docDir = join(artifact.collectionRoot, 'documents')
    const docNames = readdirSync(docDir)
    expect(docNames.length).toBe(1)
    expect(readFileSync(join(docDir, docNames[0]!), 'utf8')).toBe(doc)
  })
})

// ============================================================
// N1.5 — mutable ref follows the CURRENT registry identity; locked stays A
// ============================================================

describe('N1.5: registry tag moves to malicious B while cache holds trusted A', () => {
  it('mutable :prod → resolves B → DENY (untrusted); locked @A still runs A', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n15')
    const mock = new MockRegistry()
    await mock.start()
    try {
      // A signed by keyA (the only trusted key); B signed by its own key (untrusted)
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))
      const lockFile = join(root, 'dsh-lock.json')
      const locked = await images.lock(remoteRefOf(mock, 'org/agent', 'prod'), { file: lockFile })

      // machine B: cache A while prod → A; trust.yaml trusts ONLY keyA
      const { images: imagesB, home } = makeImageEnv(join(root, 'fresh'))
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pulled.contentHash).toBe(pushedA.contentHash)
      writeFileSync(join(home, 'trust.yaml'), `version: 1
registries:
  "127.0.0.1:${mock.port}/org/agent":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${a.keyId}"
`)

      // registry: prod → malicious B (different signer, not trusted)
      await images.import(b.file, { tag: 'org/agent:v2' })
      const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pushedB.ociManifestDigest).not.toBe(pushedA.ociManifestDigest)

      // MUTABLE: must resolve the CURRENT manifest B → untrusted → DENY.
      // It must NEVER silently run the cached trusted A.
      const mutable = await imagesB.run(remoteRefOf(mock, 'org/agent', 'prod')).catch((error: Error) => error)
      expect(mutable).toBeInstanceOf(Error)
      expect((mutable as Error).message).toMatch(/trust policy rejected/)

      // LOCKED: immutable identity still runs A — never follows prod → B
      const lockedRun = await imagesB.run(locked.resolved)
      expect(lockedRun.digest).toBe(pushedA.contentHash)
      expect(lockedRun.digest).not.toBe(pushedB.contentHash)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.6 — same tag: a stale local mapping never shadows an explicit remote ref
// ============================================================

describe('N1.6: stale local mapping must not hijack an explicit remote ref', () => {
  it('local prod → A (from an earlier pull), registry prod → B ⇒ remote run resolves B', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n16')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

      // machine B: pull :prod → the LOCAL store now maps prod → A
      const { images: imagesB } = makeImageEnv(join(root, 'fresh'))
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pulled.contentHash).toBe(pushedA.contentHash)
      // the local tag mirror exists
      await expect(imagesB.resolve(remoteRefOf(mock, 'org/agent', 'prod'))).resolves.toMatchObject({
        artifactDigest: pushedA.contentHash,
      })

      // registry: prod → B
      await images.import(b.file, { tag: 'org/agent:v2' })
      const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pushedB.ociManifestDigest).not.toBe(pushedA.ociManifestDigest)

      // an EXPLICIT remote ref must resolve the registry's CURRENT identity (B),
      // not the stale local mapping (A)
      const ran = await imagesB.run(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(ran.digest).toBe(pushedB.contentHash)
      expect(ran.digest).not.toBe(pushedA.contentHash)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.7 — locked digest unavailable ⇒ FAIL, never a tag fallback
// ============================================================

describe('N1.7: locked digest 404 — lock miss never falls back to the tag', () => {
  it('lock points at a digest the registry no longer has → run FAILS, prod → B is NOT used', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n17')
    const mock = new MockRegistry()
    await mock.start()
    try {
      // registry only has prod → B; the LOCK pins prod → A (gone / never existed)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(b.file, { tag: 'org/agent:v2' })
      const pushedB = await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'prod'))

      const goneDigest = 'sha256:' + 'a'.repeat(64)
      const lockFile = join(root, 'dsh-lock.json')
      const { addLockEntry, emptyLockfile, saveLockfile, loadLockfile } = await import('../src/image/lockfile.js')
      saveLockfile(lockFile, addLockEntry(
        emptyLockfile(), remoteRefOf(mock, 'org/agent', 'prod'), goneDigest as never,
        remoteDigestRefOf(mock, 'org/agent', goneDigest),
      ))
      const locked = loadLockfile(lockFile).images[remoteRefOf(mock, 'org/agent', 'prod')]!

      // run the LOCKED identity: digest A is missing (404) and not cached
      const { images: imagesB, home } = makeImageEnv(join(root, 'fresh'))
      const attempt = await imagesB.run(locked.resolved).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/manifest GET failed|not found|404/i)
      // NOTHING was imported, nothing was booted, and prod → B was never followed
      expect((await imagesB.list()).length).toBe(0)
      expect(readdirSync(join(home, 'profiles')).filter((p) => p.startsWith('.run-')).length).toBe(0)
      expect(pushedB.contentHash).toMatch(/^sha256:/) // B exists remotely — but must not be used
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.8 — registry violates a locked manifest digest ⇒ full-chain FAIL
// ============================================================

describe('N1.8: registry returns bytes that do not hash to the locked digest', () => {
  it('locked run against a digest-swapping registry → transport integrity FAIL, nothing imported/booted', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n18')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
      const b = await makeSignedPack(root, mkdtempSync(join(root, 'out-b-')), 0.7)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))
      await images.import(b.file, { tag: 'org/agent:v2' })
      await images.push('org/agent:v2', remoteRefOf(mock, 'org/agent', 'dev'))

      // malicious registry: serve dev's manifest bytes under A's locked digest
      mock.tamper = { manifestSwap: { forDigest: pushedA.ociManifestDigest, serveTag: 'dev' } }
      const { images: imagesB, home } = makeImageEnv(join(root, 'fresh'))
      const attempt = await imagesB.run(
        remoteDigestRefOf(mock, 'org/agent', pushedA.ociManifestDigest),
      ).catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/manifest digest mismatch.*transport integrity failure/)
      // nothing imported, no cache mutation, no profile boot
      expect((await imagesB.list()).length).toBe(0)
      expect(readdirSync(join(home, 'profiles')).filter((p) => p.startsWith('.run-')).length).toBe(0)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.9 — cached raw artifact tamper: CAS path is not proof
// ============================================================

describe('N1.9: a tampered cached blob fails integrity on the cache-hit run', () => {
  it('contentHash key = A but blob bytes modified → run recomputes contentHash → FAIL, nothing boots', { timeout: 120_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n19')
    const mock = new MockRegistry()
    await mock.start()
    try {
      const a = await makeSignedPack(root, mkdtempSync(join(root, 'out-a-')), 0.3)
      const { images } = makeImageEnv(root)
      await images.import(a.file, { tag: 'org/agent:v1' })
      const pushedA = await images.push('org/agent:v1', remoteRefOf(mock, 'org/agent', 'prod'))

      // machine B: pull → blob cached under the contentHash
      const { images: imagesB, home } = makeImageEnv(join(root, 'fresh'))
      const pulled = await imagesB.pull(remoteRefOf(mock, 'org/agent', 'prod'))
      expect(pulled.contentHash).toBe(pushedA.contentHash)

      // manual tamper: flip a byte inside the CAS blob (ref still → A)
      const blobPath = join(root, 'fresh', 'store', 'blobs', 'sha256', pushedA.contentHash.slice('sha256:'.length))
      const bytes = readFileSync(blobPath)
      const flipped = Buffer.from(bytes)
      flipped[0] = (flipped[0]! ^ 0xff) as number
      writeFileSync(blobPath, flipped)

      // cache-hit run: the LOCAL dsh-manifest ref resolves without touching the
      // registry — the tampered bytes must fail the recomputed contentHash
      const attempt = await imagesB.run(`local@${pulled.dshManifestDigest}`)
        .catch((error: Error) => error)
      expect(attempt).toBeInstanceOf(Error)
      expect((attempt as Error).message).toMatch(/verification failed|integrity|contentHash/i)
      expect(readdirSync(join(home, 'profiles')).filter((p) => p.startsWith('.run-')).length).toBe(0)
    } finally {
      await mock.stop()
    }
  })
})

// ============================================================
// N1.10 — cached Evidence tamper: the document digest is re-verified
// ============================================================
// The image run path (v0.4.1) enforces SIGNATURE trust only — N1.10 pins the
// property where the v0.5 evidence chain is consumed (packager.policy()): a
// tampered cached attestation DOCUMENT is re-verified at the next evaluation
// (sha256(document) === envelope attestationDigest, D100) and the verdict must
// flip to DENY. EvidenceTrust=VERIFIED is never cached.

describe('N1.10: a tampered cached evidence document flips the verdict to DENY', () => {
  it('ALLOW → modify the cached attestation document bytes → same artifact/policy → DENY', async () => {
    const root = tempRoot('n110')
    const artifact = await n1BuildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const attestor = generateKeypair(join(root, 'attestor'))

    const doc = n1AttDoc(['process.exec'], 'n110')
    await n1SignAttestation(artifact, doc, attestor.privateKey)
    const packBytes = readFileSync(artifact.packFile)

    const first = await n1Evaluate(artifact, n1V2Policy(artifact.keyId, attestor.keyId))
    expect(first.verdict.decision).toBe('ALLOW')
    expect(first.verdict.evidenceTrust.attestation).toBe('VERIFIED')

    // tamper ONLY the cached evidence document (artifact + policy unchanged)
    const docDir = join(artifact.collectionRoot, 'documents')
    const docFile = join(docDir, readdirSync(docDir)[0]!)
    writeFileSync(docFile, `${doc.slice(0, -1)} "tampered":true}`)

    const second = await n1Evaluate(artifact, n1V2Policy(artifact.keyId, attestor.keyId))
    expect(second.verdict.decision).toBe('DENY')
    expect(second.verdict.evidenceTrust.attestation).not.toBe('VERIFIED')
    expect(second.verdict.errors.join('; ')).toMatch(/attestation-signature failed|no attestation candidate passed|UNTRUSTED|unverified/i)

    // the artifact bytes are untouched — only the evidence document changed
    expect(readFileSync(artifact.packFile).equals(packBytes)).toBe(true)
  })
})
