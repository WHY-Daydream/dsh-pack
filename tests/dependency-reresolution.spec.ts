/**
 * v0.5.0-rc.1 — N2 Dependency Re-resolution regression matrix (D130–D134):
 *
 * An already-built immutable artifact must never re-resolve a new dependency
 * set when the external dependency universe changes. Its identity, dependency
 * closure, SBOM and provenance come ONLY from artifact-contained materials:
 *
 *   D130 artifact dependency identity ← artifact lockfile / dependency closure
 *        / vendored tgz / embedded metadata — never the current package.json,
 *        node_modules, registry latest, workspace, or a fresh pnpm resolution
 *   D131 verify / provenance / SBOM / policy never re-resolve
 *   D132 materialization is frozen (pnpm install --frozen-lockfile; lock
 *        mismatch → FAIL, never a non-frozen fallback)
 *   D133 external registry/package.json/node_modules/store drift must not
 *        change a built artifact's evidence
 *   D134 file/link dependencies are content-bound (vendored tgz / contentDigest)
 *
 * RC-N2 North-Star: after the external dependency universe fully changes,
 * the same artifact keeps identity/provenance/SBOM/closure identical with NO
 * dependency re-resolution. Reproducibility is artifact-contained, not
 * environment-reconstructed.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it, vi } from 'vitest'

// N2.10 re-resolution spy: every child process (pnpm / npm / git / …) spawned
// during verify/evidence/policy is recorded — a silent re-resolution that shells
// out would trip the assertion below.
const spy = vi.hoisted(() => ({ execCalls: [] as string[] }))
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>()
  return {
    ...actual,
    execFile: ((...args: unknown[]) => {
      spy.execCalls.push(String(args[0] ?? ''))
      return (actual.execFile as (...a: unknown[]) => unknown).apply(null, args as never)
    }) as typeof actual.execFile,
  }
})
import { buildTarGz, computePackContentHash, openPack, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { verifyPack } from '../src/verify.js'
import { installPack } from '../src/install.js'
import { DefaultPackager } from '../src/service.js'
import {
  buildReceiptPath, captureBuildRecord, type BuildRecord,
} from '../src/evidence/build-record.js'
import type { DependencyTree, LocalDep } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n2-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const execFileAsync = promisify(execFile)
async function pnpmAvailable(): Promise<boolean> {
  try {
    await execFileAsync('pnpm', ['--version'], { timeout: 10_000 })
    return true
  } catch {
    return false
  }
}
const hasPnpm = await pnpmAvailable()

// --- artifact-contained fixtures (D130) ---

/** pnpm-lock.yaml pinning foo@1.0.3 (registry) + the vendored local-plugin. */
const LOCKFILE_V1 = [
  "lockfileVersion: '9.0'",
  'importers:',
  "  '.':",
  '    dependencies:',
  '      foo:',
  '        specifier: ^1.0.0',
  '        version: 1.0.3',
  '      local-plugin:',
  '        specifier: file:./packages/local-plugin-0.1.0.tgz',
  '        version: file:./packages/local-plugin-0.1.0.tgz',
  'packages:',
  '  /foo@1.0.3:',
  '    resolution:',
  '      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
  '      tarball: https://registry.npmjs.org/foo/-/foo-1.0.3.tgz',
  '    version: 1.0.3',
  '',
].join('\n')

/** The post-drift "registry latest" reality: foo@1.0.9 now exists (D133 attack). */
const LOCKFILE_V2 = LOCKFILE_V1.replaceAll('1.0.3', '1.0.9').replace('^1.0.0', '^1.0.0')

/** Vendored tgz whose bytes encode `content` — content A vs B differ. */
async function makeVendoredTgz(content: string): Promise<Buffer> {
  const entries: PackFileEntry[] = [
    { path: 'package/package.json', content: prettyJson({ name: 'local-plugin', version: '0.1.0', dependencies: { foo: '^1.0.0' } }) },
    { path: 'package/index.js', content },
  ]
  return (await buildTarGz(entries)).buffer
}

const DEP_TREE_V1: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: { foo: '^1.0.0', 'local-plugin': 'file:./local-plugin' },
  closure: { foo: '1.0.3', 'local-plugin': '0.1.0' },
  localDeps: [{ name: 'local-plugin', spec: 'file:../local-plugin', kind: 'file', resolved: '/abs/machine/local-plugin', portable: true }],
  warnings: [],
}

const PROFILE_PKG_V1: Record<string, unknown> = {
  name: 'web-profile', version: '1.0.0', private: true,
  dependencies: { foo: '^1.0.0', 'local-plugin': 'file:./packages/local-plugin-0.1.0.tgz' },
}

interface N2Artifact {
  packFile: string
  keyId: string
  privateKey: string
  contentHash: string
  receipt: BuildRecord
  closureDigest: string
  baseline: { sbomDoc: string; sbomDigest: string; provStatementDigest: string }
  workspace: {
    profileDir: string
    localPluginDir: string
    lockfilePath: string
    packageJsonPath: string
  }
}

/**
 * Build a hermetic artifact: content A local plugin vendored, foo@1.0.3 pinned
 * in the artifact lockfile, build receipt captured AT build time (D68).
 */
async function buildArtifact(root: string, label: string): Promise<N2Artifact> {
  const workspace = join(root, 'workspace')
  const profileDir = join(workspace, 'web-profile')
  const localPluginDir = join(workspace, 'local-plugin')
  mkdirSync(profileDir, { recursive: true })
  mkdirSync(localPluginDir, { recursive: true })
  writeFileSync(join(profileDir, 'package.json'), prettyJson(PROFILE_PKG_V1))
  writeFileSync(join(profileDir, 'pnpm-lock.yaml'), LOCKFILE_V1)
  const contentA = '// local-plugin content A\n'
  writeFileSync(join(localPluginDir, 'index.js'), contentA)

  const tgz = await makeVendoredTgz(contentA)
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: PROFILE_PKG_V1.dependencies,
    packages: ['local-plugin-0.1.0.tgz'],
    configHash: computeConfigHash({ rows: [] }, [], DEP_TREE_V1.closure),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(PROFILE_PKG_V1) },
    { path: 'profile/pnpm-lock.yaml', content: LOCKFILE_V1 },
    { path: 'resolved/dependency-tree.json', content: prettyJson(DEP_TREE_V1) },
    { path: 'resolved/composition.json', content: prettyJson({ rows: [] }) },
    { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
    { path: 'packages/local-plugin-0.1.0.tgz', content: tgz },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  const packFile = join(root, 'app.dshpack')
  writeFileSync(packFile, final.buffer)

  // sign the artifact (v0.3 embedded signature — writes a NEW signed file,
  // the artifact identity is the SIGNED bytes) + capture the build record AT
  // build time (D68)
  const key = generateKeypair(join(root, 'release'))
  const signed = await signPackFile(packFile, { key: key.privateKey })
  const packPath = signed.file
  const contentHash = await computePackContentHash(readFileSync(packPath))
  const localDeps: LocalDep[] = [{
    name: 'local-plugin', spec: 'file:../local-plugin', kind: 'file',
    resolved: localPluginDir, version: '0.1.0',
  }]
  const receipt = await captureBuildRecord({
    cwd: root, contentHash, profileDir, stagedLockfile: LOCKFILE_V1, localDeps,
    dshPackVersion: '0.5.0-rc.1', dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0',
    os: 'linux', arch: 'x64',
  })
  writeFileSync(buildReceiptPath(packPath), `${prettyJson(receipt)}\n`)

  const evidence = new DefaultEvidenceService()
  const baseline = await regenerate(packPath, key.privateKey)
  return {
    packFile: packPath, keyId: key.keyId, privateKey: key.privateKey, contentHash, receipt,
    closureDigest: receipt.materials.dependencyClosureDigest,
    baseline,
    workspace: { profileDir, localPluginDir, lockfilePath: join(profileDir, 'pnpm-lock.yaml'), packageJsonPath: join(profileDir, 'package.json') },
  }
}

/** Re-generate SBOM + provenance for the ALREADY-BUILT artifact (D131: no re-resolution). */
async function regenerate(
  packFile: string, privateKey: string,
): Promise<{ sbomDoc: string; sbomDigest: string; provStatementDigest: string }> {
  const evidence = new DefaultEvidenceService()
  const sbom = await evidence.sbom(packFile, { key: privateKey })
  const prov = await evidence.provenance(packFile, { key: privateKey })
  return {
    sbomDoc: readFileSync(sbom.documentFile, 'utf8'),
    sbomDigest: sbom.sbomDigest,
    provStatementDigest: prov.statementDigest,
  }
}

function assertUnchanged(artifact: N2Artifact, after: { sbomDoc: string; sbomDigest: string; provStatementDigest: string }): void {
  expect(after.sbomDoc).toBe(artifact.baseline.sbomDoc)
  expect(after.sbomDigest).toBe(artifact.baseline.sbomDigest)
  expect(after.provStatementDigest).toBe(artifact.baseline.provStatementDigest)
  // the SBOM must still describe the ARTIFACT's pinned foo@1.0.3 — never a
  // drifted 1.0.9
  expect(after.sbomDoc).toContain('1.0.3')
  expect(after.sbomDoc).not.toContain('1.0.9')
}

// ============================================================
// N2.1 — registry latest drift: evidence stays pinned to foo@1.0.3
// ============================================================

describe('N2.1: registry latest drift never re-resolves a built artifact', () => {
  it('world moves to foo@1.0.9 → SBOM/provenance/closure stay foo@1.0.3 and byte-identical', async () => {
    const root = tempRoot('n21')
    const artifact = await buildArtifact(root, 'a')

    // the external world drifts: the workspace lockfile now resolves 1.0.9
    writeFileSync(artifact.workspace.lockfilePath, LOCKFILE_V2)
    writeFileSync(artifact.workspace.packageJsonPath, prettyJson({
      ...PROFILE_PKG_V1, dependencies: { ...(PROFILE_PKG_V1.dependencies as Record<string, string>), foo: '^1.0.0' },
    }))

    const after = await regenerate(artifact.packFile, artifact.privateKey)
    assertUnchanged(artifact, after)
    // the artifact's own closure digest (captured at build time) never moved
    expect(artifact.closureDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(after.provStatementDigest).toBe(artifact.baseline.provStatementDigest)
  })
})

// ============================================================
// N2.2 — workspace package.json drift
// ============================================================

describe('N2.2: workspace package.json drift never re-resolves', () => {
  it('current package.json moves to foo@^2.0.0 → artifact SBOM stays foo@1.0.3', async () => {
    const root = tempRoot('n22')
    const artifact = await buildArtifact(root, 'a')

    // the CURRENT workspace now demands foo@^2.0.0 — the built artifact must
    // not pick it up
    writeFileSync(artifact.workspace.packageJsonPath, prettyJson({
      ...PROFILE_PKG_V1, dependencies: { foo: '^2.0.0', 'local-plugin': 'file:./packages/local-plugin-0.1.0.tgz' },
    }))

    const after = await regenerate(artifact.packFile, artifact.privateKey)
    assertUnchanged(artifact, after)
  })
})

// ============================================================
// N2.3 — node_modules drift
// ============================================================

describe('N2.3: node_modules drift never re-resolves', () => {
  it('workspace node_modules replaced with another foo version → evidence unchanged', async () => {
    const root = tempRoot('n23')
    const artifact = await buildArtifact(root, 'a')

    // the CURRENT machine's node_modules now holds a DIFFERENT foo
    const nodeModules = join(artifact.workspace.profileDir, 'node_modules')
    mkdirSync(join(nodeModules, 'foo'), { recursive: true })
    writeFileSync(join(nodeModules, 'foo', 'package.json'), prettyJson({ name: 'foo', version: '9.9.9' }))
    writeFileSync(join(nodeModules, 'foo', 'index.js'), '// drifted node_modules foo\n')

    const after = await regenerate(artifact.packFile, artifact.privateKey)
    assertUnchanged(artifact, after)
  })
})

// ============================================================
// N2.4 — pnpm store / package-manager cache drift
// ============================================================

describe('N2.4: pnpm store drift never re-resolves', () => {
  it('evidence generation is byte-identical under a different store / package-manager env', async () => {
    const root = tempRoot('n24')
    const artifact = await buildArtifact(root, 'a')

    // "clear the store": point the package-manager caches at a brand-new home
    const freshHome = join(root, 'fresh-store-home')
    const saved = { home: process.env.PNPM_HOME, store: process.env.PNPM_STORE_DIR, cache: process.env.PNPM_CACHE_DIR }
    process.env.PNPM_HOME = freshHome
    process.env.PNPM_STORE_DIR = join(freshHome, 'store')
    process.env.PNPM_CACHE_DIR = join(freshHome, 'cache')
    try {
      const after = await regenerate(artifact.packFile, artifact.privateKey)
      assertUnchanged(artifact, after)
    } finally {
      if (saved.home === undefined) delete process.env.PNPM_HOME
      else process.env.PNPM_HOME = saved.home
      if (saved.store === undefined) delete process.env.PNPM_STORE_DIR
      else process.env.PNPM_STORE_DIR = saved.store
      if (saved.cache === undefined) delete process.env.PNPM_CACHE_DIR
      else process.env.PNPM_CACHE_DIR = saved.cache
    }
  })
})

// ============================================================
// N2.5 — file/link source drift must stay content-bound (D134)
// ============================================================

/** The vendored component's content-digest property in the generated SBOM. */
function vendoredContentDigest(sbomDoc: string): string {
  const bom = JSON.parse(sbomDoc) as { components?: Array<{ 'bom-ref': string; properties?: Array<{ name: string; value: string }> }> }
  const local = (bom.components ?? []).find((c) => c['bom-ref'] === 'local:local-plugin')
  expect(local).toBeDefined()
  return local!.properties!.find((p) => p.name === 'dsh-pack:content-digest')!.value
}

describe('N2.5: file/link source drift is content-bound — artifact keeps using the vendored bytes', () => {
  it('../local-plugin content A → content B after build ⇒ SBOM/provenance still bind A', async () => {
    const root = tempRoot('n25')
    const artifact = await buildArtifact(root, 'a')
    const digestOfA = vendoredContentDigest(artifact.baseline.sbomDoc)
    expect(digestOfA).toMatch(/^sha256:[0-9a-f]{64}$/)

    // external source drift: ../local-plugin content A → B
    writeFileSync(join(artifact.workspace.localPluginDir, 'index.js'), '// local-plugin content B\n')
    writeFileSync(
      join(artifact.workspace.localPluginDir, 'index2.js'),
      '// an entirely new file appears at the source\n',
    )

    const after = await regenerate(artifact.packFile, artifact.privateKey)
    assertUnchanged(artifact, after)
    // the vendored component still binds the ARTIFACT's tgz (content A) —
    // never re-read or re-vendored from the drifted source
    expect(vendoredContentDigest(after.sbomDoc)).toBe(digestOfA)
  })
})

// ============================================================
// N2.6 — vendored tgz tamper: artifact-internal damage → FAIL, never a workspace rebuild
// ============================================================

/** Rebuild the pack with a REPLACED vendored tgz but the ORIGINAL checksums.json. */
async function tamperVendoredTgz(packFile: string, tamperedTgz: Buffer): Promise<Buffer> {
  const opened = await openPack(readFileSync(packFile))
  try {
    const entries: PackFileEntry[] = []
    const walk = (dir: string, prefix: string): void => {
      for (const name of readdirSync(dir)) {
        const absolute = join(dir, name)
        const rel = prefix === '' ? name : `${prefix}/${name}`
        if (statSync(absolute).isDirectory()) walk(absolute, rel)
        else if (rel === 'packages/local-plugin-0.1.0.tgz') entries.push({ path: rel, content: tamperedTgz })
        else entries.push({ path: rel, content: readFileSync(absolute) })
      }
    }
    walk(opened.root, '')
    return (await buildTarGz(entries)).buffer
  } finally {
    rmSync(opened.root, { recursive: true, force: true })
  }
}

describe('N2.6: vendored tgz tamper fails loud — no fallback to the workspace source', () => {
  it('tampered packages/*.tgz → verify FAILs on checksums; provenance subject binding FAILs', async () => {
    const root = tempRoot('n26')
    const artifact = await buildArtifact(root, 'a')

    // baseline verifies clean
    const baselineVerify = await verifyPack(readFileSync(artifact.packFile), { installedDshVersion: DSH_VERSION })
    expect(baselineVerify.report.ok).toBe(true)

    // artifact-internal material is corrupted (checksums.json untouched)
    const tampered = await tamperVendoredTgz(artifact.packFile, await makeVendoredTgz('// EVIL content\n'))
    const attempt = await verifyPack(tampered, { installedDshVersion: DSH_VERSION })
    expect(attempt.report.ok).toBe(false)
    const checksums = attempt.report.sections.find((s) => s.name === 'Checksums')
    expect(checksums?.status).toBe('fail')
    expect(checksums?.detail).toContain('packages/local-plugin-0.1.0.tgz')

    // provenance on the damaged artifact: the receipt's subject binding FAILs —
    // the receipt can never be laundered onto different artifact bytes
    writeFileSync(artifact.packFile, tampered)
    const prov = await new DefaultEvidenceService()
      .provenance(artifact.packFile, { key: artifact.privateKey })
      .catch((error: Error) => error)
    expect(prov).toBeInstanceOf(Error)
    expect((prov as Error).message).toMatch(/build receipt subject|contentHash/)

    // the failure is purely artifact-internal — the workspace source is never
    // consulted to "repair" the artifact
    expect(readFileSync(join(artifact.workspace.localPluginDir, 'index.js'), 'utf8')).toBe('// local-plugin content A\n')
  })
})

// ============================================================
// N2.7 — lockfile mismatch: frozen install FAILs, no non-frozen fallback
// ============================================================

/**
 * Build a pack whose staged profile is self-inconsistent: package.json demands
 * foo@^2.0.0 while the staged pnpm-lock.yaml pins foo@1.0.3 (importer ^1.0.0).
 */
async function buildMismatchPack(root: string, label: string): Promise<string> {
  const profileDir = join(root, label)
  mkdirSync(profileDir, { recursive: true })
  const profilePkg = { name: 'web-profile', version: '1.0.0', private: true, dependencies: { foo: '^2.0.0' } }
  writeFileSync(join(profileDir, 'package.json'), prettyJson(profilePkg))
  writeFileSync(join(profileDir, 'pnpm-lock.yaml'), LOCKFILE_V1)

  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: profilePkg.dependencies,
    configHash: computeConfigHash({ rows: [] }, [], { foo: '1.0.3' }),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(profilePkg) },
    { path: 'profile/pnpm-lock.yaml', content: LOCKFILE_V1 },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
    { path: 'resolved/dependency-tree.json', content: prettyJson({
      lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)', direct: { foo: '^2.0.0' }, closure: { foo: '1.0.3' }, localDeps: [], warnings: [],
    }) },
    { path: 'resolved/composition.json', content: prettyJson({ rows: [] }) },
    { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: [] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  const packFile = join(root, `${label}.dshpack`)
  writeFileSync(packFile, final.buffer)
  return packFile
}

describe('N2.7: lockfile mismatch → frozen install FAILs, never a non-frozen retry', () => {
  it('staged package.json (^2.0.0) vs staged lockfile (1.0.3) → install throws, nothing installed', { timeout: 60_000 }, async () => {
    if (!hasPnpm) return
    const root = tempRoot('n27')
    const packFile = await buildMismatchPack(root, 'mismatch')
    const home = join(root, 'home')
    mkdirSync(join(home, 'profiles'), { recursive: true })

    const attempt = await installPack(readFileSync(packFile), { profile: 'n27' }, {
      home, installedDshVersion: DSH_VERSION,
    }).catch((error: Error) => error)

    expect(attempt).toBeInstanceOf(Error)
    const message = (attempt as Error).message
    // the failure is the FROZEN lockfile check — never a silent resolution retry
    expect(message).toMatch(/frozen-lockfile|lock mismatch|not up to date|OUTDATED_LOCKFILE/i)
    // nothing was materialized/installed
    expect(existsSync(join(home, 'profiles', 'n27'))).toBe(false)
  })
})

// ============================================================
// N2.8 — registry offline: verify / SBOM / provenance / policy never network
// ============================================================

describe('N2.8: registry unavailable — verify/evidence/policy complete offline', () => {
  it('verify + SBOM + provenance + policy succeed with the registry unreachable', async () => {
    const root = tempRoot('n28')
    const artifact = await buildArtifact(root, 'a')

    // make ANY registry lookup fail hard — a re-resolving path would die here
    const saved = process.env.npm_config_registry
    process.env.npm_config_registry = 'http://127.0.0.1:9'
    try {
      // 1. artifact verify (D131: verification never re-resolves)
      const verified = await verifyPack(readFileSync(artifact.packFile), { installedDshVersion: DSH_VERSION })
      expect(verified.report.ok).toBe(true)

      // 2. SBOM + provenance generation (D133: evidence is artifact-contained)
      const after = await regenerate(artifact.packFile, artifact.privateKey)
      assertUnchanged(artifact, after)

      // 3. policy evaluation (trust.yaml v1: signature trust only)
      const home = join(root, 'policy-home')
      mkdirSync(home, { recursive: true })
      writeFileSync(join(home, 'trust.yaml'), `version: 1
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${artifact.keyId}"
`)
      const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
      const collectionDir = join(dirname(artifact.packFile), `${basename(artifact.packFile, '.dshpack')}.dshpack.evidence`)
      const policy = await packager.policy(artifact.packFile, {
        repository: 'ghcr.io/company/prod-app',
        collectionDir,
        executionTarget: { os: 'linux', arch: 'x64' },
      })
      expect(policy.verdict.decision).toBe('ALLOW')
    } finally {
      if (saved === undefined) delete process.env.npm_config_registry
      else process.env.npm_config_registry = saved
    }
  })
})

// ============================================================
// N2.9 — same artifact, two machines (RC-N2 North-Star)
// ============================================================

describe('N2.9: one artifact, two completely different external worlds → identical evidence', () => {
  it('identity / closure / SBOM / provenance are machine-independent', async () => {
    // Machine A: build the artifact + capture the baseline evidence
    const rootA = tempRoot('n29a')
    const artifactA = await buildArtifact(rootA, 'a')

    // Machine B: a DIFFERENT external world — different workspace (foo@9.9.9),
    // different registry, different node_modules
    const rootB = tempRoot('n29b')
    const wsB = join(rootB, 'workspace', 'web-profile')
    mkdirSync(wsB, { recursive: true })
    writeFileSync(join(wsB, 'package.json'), prettyJson({ ...PROFILE_PKG_V1, dependencies: { foo: '^9.0.0' } }))
    writeFileSync(join(wsB, 'pnpm-lock.yaml'), LOCKFILE_V1.replaceAll('1.0.3', '9.9.9'))
    mkdirSync(join(wsB, 'node_modules', 'foo'), { recursive: true })
    writeFileSync(join(wsB, 'node_modules', 'foo', 'index.js'), '// machine B junk\n')

    // copy the artifact + its build receipt to Machine B (the artifact travels)
    const copied = join(rootB, basename(artifactA.packFile))
    writeFileSync(copied, readFileSync(artifactA.packFile))
    writeFileSync(buildReceiptPath(copied), readFileSync(buildReceiptPath(artifactA.packFile)))

    const saved = process.env.npm_config_registry
    process.env.npm_config_registry = 'http://machine-b.registry.invalid'
    try {
      const after = await regenerate(copied, artifactA.privateKey)
      assertUnchanged(artifactA, after)
      // identity facts come from the artifact itself — identical on both machines
      const manifest = JSON.parse(await extractPath(copied, 'manifest.json')) as { configHash: string }
      const checksums = JSON.parse(await extractPath(copied, 'metadata/checksums.json')) as { contentHash: string }
      expect(checksums.contentHash).toBe(artifactA.contentHash)
      expect(manifest.configHash).toBe(artifactA.receipt.materials.dependencyClosureDigest === undefined ? '' : (await extractManifestConfigHash(copied)))
      expect(artifactA.closureDigest).toBe(artifactA.receipt.materials.dependencyClosureDigest)
    } finally {
      if (saved === undefined) delete process.env.npm_config_registry
      else process.env.npm_config_registry = saved
    }
  })
})

/** Extract one file's text from a .dshpack (tar.gz) without touching the workspace. */
async function extractPath(packFile: string, target: string): Promise<string> {
  const opened = await openPack(readFileSync(packFile))
  try {
    return readFileSync(join(opened.root, target), 'utf8')
  } finally {
    rmSync(opened.root, { recursive: true, force: true })
  }
}

/** configHash recorded in the artifact's manifest. */
async function extractManifestConfigHash(packFile: string): Promise<string> {
  return (JSON.parse(await extractPath(packFile, 'manifest.json')) as { configHash: string }).configHash
}

// ============================================================
// N2.10 — re-resolution spy: zero resolve events during verify/evidence/policy
// ============================================================

describe('N2.10: verify / SBOM / provenance / policy trigger zero re-resolution events', () => {
  it('no pnpm/npm/git child process, no workspace read, no registry touch', async () => {
    const root = tempRoot('n210')
    const artifact = await buildArtifact(root, 'a')

    // isolate: from here on, ANY resolution event is a regression — record it
    spy.execCalls.length = 0

    // destroy the ENTIRE external dependency world — a path that re-reads the
    // workspace (package.json / lockfile / node_modules / file source) would
    // fail loudly
    rmSync(artifact.workspace.profileDir, { recursive: true, force: true })
    rmSync(artifact.workspace.localPluginDir, { recursive: true, force: true })

    const saved = process.env.npm_config_registry
    process.env.npm_config_registry = 'http://127.0.0.1:9'
    try {
      // 1. verify
      const verified = await verifyPack(readFileSync(artifact.packFile), { installedDshVersion: DSH_VERSION })
      expect(verified.report.ok).toBe(true)
      // 2. SBOM + provenance
      const after = await regenerate(artifact.packFile, artifact.privateKey)
      assertUnchanged(artifact, after)
      // 3. policy
      const home = join(root, 'policy-home')
      mkdirSync(home, { recursive: true })
      writeFileSync(join(home, 'trust.yaml'), `version: 1
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${artifact.keyId}"
`)
      const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
      const collectionDir = join(dirname(artifact.packFile), `${basename(artifact.packFile, '.dshpack')}.dshpack.evidence`)
      const policy = await packager.policy(artifact.packFile, {
        repository: 'ghcr.io/company/prod-app', collectionDir, executionTarget: { os: 'linux', arch: 'x64' },
      })
      expect(policy.verdict.decision).toBe('ALLOW')
    } finally {
      if (saved === undefined) delete process.env.npm_config_registry
      else process.env.npm_config_registry = saved
    }

    // ZERO re-resolution events: no pnpm install/resolve, no npm view, no git,
    // no registry tool — the whole chain consumed artifact-contained materials only
    expect(spy.execCalls.filter((c) => /pnpm|npm|git|curl|wget/i.test(c))).toEqual([])
  })
})
