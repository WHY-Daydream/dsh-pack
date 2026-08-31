/**
 * v0.5.0-rc.1 — N6 Native / Cross-platform regression matrix (D135–D139):
 *
 * The system must NEVER interpret limited static native signals as runtime
 * compatibility; the only compatibility conclusion comes from a Runtime
 * Attestation matching the CURRENT execution target exactly.
 *
 *   D135 native package indicators are descriptive evidence only, never
 *        compatibility conclusions
 *   D136 build environment matrix ≠ runtime compatibility matrix
 *   D137 runtime compatibility requires an attestation for the current
 *        execution target
 *   D138 an attestation from another OS/arch cannot authorize the current
 *        run, even if both targets are allowed by policy
 *   D139 unknown native/platform information stays UNKNOWN — never guessed
 *
 * RC-N6: A) SBOM native=true ⇒ system does NOT infer compatibility;
 *        B) current linux/x64 + attestation darwin/arm64 + policy allows both
 *           ⇒ DENY; C) current linux/x64 + attestation linux/x64 + sufficient
 *           coverage + no ambiguity ⇒ PASS.
 *
 * N6 does NOT add a compatibility database / ABI / libc / GPU / sandbox
 * engine (rc.1 scope guard) — adversarial tests + minimal fixes only.
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { canonicalJson, prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { DefaultPackager } from '../src/service.js'
import type { DependencyTree } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n6-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const MINIMAL_DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: {}, closure: {}, localDeps: [], warnings: [],
}

/** pnpm-lock.yaml with one vendored file dep (local-plugin). */
const LOCKFILE = [
  "lockfileVersion: '9.0'",
  'importers:',
  "  '.':",
  '    dependencies:',
  '      local-plugin:',
  '        specifier: file:./packages/local-plugin-0.1.0.tgz',
  '        version: file:./packages/local-plugin-0.1.0.tgz',
  'packages:',
  '  /local-plugin@file:./packages/local-plugin-0.1.0.tgz:',
  '    resolution:',
  '      integrity: sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==',
  '    version: 0.1.0',
  '',
].join('\n')

const DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: { 'local-plugin': 'file:./packages/local-plugin-0.1.0.tgz' },
  closure: { 'local-plugin': '0.1.0' },
  localDeps: [{ name: 'local-plugin', spec: 'file:./local-plugin', kind: 'file', resolved: '/abs/machine/local-plugin', portable: true }],
  warnings: [],
}

/** Vendored tgz whose package.json can carry a NATIVE signal (node-gyp etc.). */
async function makeTgz(scripts?: Record<string, string>, extra?: Record<string, unknown>): Promise<Buffer> {
  const pkgJson: Record<string, unknown> = { name: 'local-plugin', version: '0.1.0' }
  if (scripts !== undefined) pkgJson.scripts = scripts
  if (extra !== undefined) {
    for (const [k, v] of Object.entries(extra)) pkgJson[k] = v
  }
  const entries: PackFileEntry[] = [{ path: 'package/package.json', content: prettyJson(pkgJson) }]
  return (await buildTarGz(entries)).buffer
}

/** A vendored tgz with NO package.json at all — package metadata unavailable. */
async function makeBareTgz(): Promise<Buffer> {
  const entries: PackFileEntry[] = [{ path: 'package/index.js', content: '// no package.json\n' }]
  return (await buildTarGz(entries)).buffer
}

interface N6Artifact {
  packFile: string
  keyId: string
  privateKey: string
  collectionRoot: string
}

/** Build a signed artifact; `nativeScripts` makes the SBOM native:detected=true. */
async function buildArtifact(
  root: string, label: string, nativeScripts?: Record<string, string>, tgzOverride?: Buffer,
): Promise<N6Artifact> {
  const dir = join(root, label)
  mkdirSync(dir, { recursive: true })
  const tgz = tgzOverride ?? await makeTgz(nativeScripts)
  const profilePkg = { name: 'web-profile', version: '1.0.0', private: true, dependencies: { 'local-plugin': 'file:./packages/local-plugin-0.1.0.tgz' } }
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: profilePkg.dependencies,
    packages: ['local-plugin-0.1.0.tgz'],
    configHash: computeConfigHash({ rows: [] }, [], DEP_TREE.closure),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(profilePkg) },
    { path: 'profile/pnpm-lock.yaml', content: LOCKFILE },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
    { path: 'resolved/dependency-tree.json', content: prettyJson(DEP_TREE) },
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
  const packFile = join(dir, 'app.dshpack')
  writeFileSync(packFile, final.buffer)
  const key = generateKeypair(join(dir, 'release'))
  const signed = await signPackFile(packFile, { key: key.privateKey })
  const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
  return { packFile: signed.file, keyId: key.keyId, privateKey: key.privateKey, collectionRoot }
}

/** Deterministic attestation document with a CONTROLLABLE target (os/arch). */
function attDoc(opts: { observed?: string[]; coverage?: 'complete' | 'partial' | 'unknown'; os?: string; arch?: string; runId?: string } = {}): string {
  const normalized = {
    declaredCapabilityDigest: 'sha256:' + 'd'.repeat(64),
    observation: { coverage: opts.coverage ?? 'complete', reasons: [] },
    coldBoot: { status: 'PASS' },
    observed: { tools: [], skills: [], services: [], providers: opts.observed ?? [] },
    comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { dsh: 'x', node: 'x', os: opts.os ?? 'linux', arch: opts.arch ?? 'x64' },
  }
  const resultDigest = 'sha256:' + sha256Hex(canonicalJson(normalized))
  return JSON.stringify({
    schemaVersion: 1, subject: { contentHash: 'ignored' },
    metadata: { observedAt: '2026-08-30T00:00:00Z', runId: opts.runId ?? 'n6' },
    ...normalized,
    resultDigest,
  })
}

/** Sign ONE attestation envelope + document against the artifact. */
async function signAttestation(
  artifact: N6Artifact, docText: string, key: string,
): Promise<void> {
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

/** Sign build-provenance (build environment is a FACT, D71/D136). */
async function signProvenance(artifact: N6Artifact, key: string): Promise<void> {
  const evidence = new DefaultEvidenceService()
  await evidence.sign(artifact.packFile, {
    type: 'build-provenance',
    statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/app', gitCommit: 'a'.repeat(40) } },
    key,
  })
}

/** v2 policy: attestation required + optional runtime matrix + optional provenance. */
const n6Policy = (
  releaseKeyId: string,
  opts: { evidenceKeys?: string[]; runtimeMatrix?: string; requireProvenance?: boolean } = {},
): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKeyId}"
    requireEvidence:
${opts.requireProvenance === true ? '      provenance:\n        origin: build-time\n' : ''}      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
${(opts.evidenceKeys ?? [releaseKeyId]).map((k) => `      - "SHA256:${k}"`).join('\n')}
${opts.runtimeMatrix ?? ''}`

/** v2 policy WITHOUT any evidence requirement — evidence stays N/A. */
const noEvidencePolicy = (releaseKeyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKeyId}"
`

async function evaluate(
  artifact: N6Artifact, policyYaml: string,
  executionTarget: { os: string; arch: string } = { os: 'linux', arch: 'x64' },
): Promise<Awaited<ReturnType<DefaultPackager['policy']>>> {
  const home = join(dirname(artifact.packFile), 'policy-home')
  mkdirSync(home, { recursive: true })
  writeFileSync(join(home, 'trust.yaml'), policyYaml)
  const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
  return packager.policy(artifact.packFile, {
    repository: 'ghcr.io/company/prod-app',
    collectionDir: artifact.collectionRoot,
    executionTarget,
  })
}

/** The SBOM document text for an artifact (artifact-contained, D74). */
async function sbomDoc(artifact: N6Artifact): Promise<string> {
  const evidence = new DefaultEvidenceService()
  const sbom = await evidence.sbom(artifact.packFile, { key: artifact.privateKey })
  return readFileSync(sbom.documentFile, 'utf8')
}

// ============================================================
// N6.1 — native indicator is a FACT only, never a compatibility verdict (D135)
// ============================================================

describe('N6.1: nativeIndicator is descriptive evidence — no implicit ALLOW/DENY', () => {
  it('SBOM records native:detected=true; policy verdict is driven ONLY by the attestation', async () => {
    const root = tempRoot('n61')
    // a package whose install script invokes node-gyp → native signal (D78)
    const artifact = await buildArtifact(root, 'a', { install: 'node-gyp rebuild' })

    // 1. the SBOM records the fact — it does NOT draw a compatibility conclusion
    const doc = await sbomDoc(artifact)
    const bom = JSON.parse(doc) as {
      components?: Array<{ 'bom-ref': string; properties?: Array<{ name: string; value: string }> }>
    }
    const local = (bom.components ?? []).find((c) => c['bom-ref'] === 'local:local-plugin')
    expect(local).toBeDefined()
    const nativeProp = local!.properties!.find((p) => p.name === 'dsh-pack:native:detected')
    expect(nativeProp?.value).toBe('true')
    const reasons = local!.properties!.find((p) => p.name === 'dsh-pack:native:reasons')
    expect(reasons?.value).toContain('node-gyp')
    // no "compatible"/"incompatible" conclusion anywhere in the document
    expect(doc).not.toMatch(/compatible|incompatible/i)

    // 2. native=true does NOT trigger an implicit DENY: exact-target attestation → ALLOW
    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', runId: 'n61' }), artifact.privateKey)
    const withAtt = await evaluate(artifact, n6Policy(artifact.keyId))
    expect(withAtt.verdict.decision).toBe('ALLOW')
    expect(withAtt.verdict.evidenceTrust.attestation).toBe('VERIFIED')

    // 3. native=true does NOT trigger an implicit ALLOW either: no policy feature
    //    consumes it — with no evidence requirement the verdict is signature-only
    const bare = await evaluate(artifact, noEvidencePolicy(artifact.keyId))
    expect(bare.verdict.decision).toBe('ALLOW')
    expect(bare.verdict.evidenceTrust.attestation).toBe('N/A')
  })
})

// ============================================================
// N6.2 — build environment ≠ runtime compatibility (D136)
// ============================================================

describe('N6.2: build environment is a provenance fact, not a compatibility claim', () => {
  it('build=linux/x64 does not authorize a linux/x64 run by itself; and does not block a foreign run with a matching attestation', async () => {
    const root = tempRoot('n62')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    await signProvenance(artifact, releaseKey)

    // Case A: build env == runtime env (linux/x64), NO attestation → DENY.
    // "build matrix matches" is NOT a runtime compatibility conclusion (D136).
    const noAtt = await evaluate(artifact, n6Policy(artifact.keyId, { requireProvenance: true }))
    expect(noAtt.verdict.decision).toBe('DENY')
    expect(noAtt.verdict.evidenceTrust.attestation).toBe('ABSENT')

    // Case B: build=linux/x64, runtime=darwin/arm64 — the build provenance does
    // NOT block the run; only an EXACT darwin/arm64 attestation decides (D137).
    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'arm64', runId: 'n62' }), releaseKey)
    const foreign = await evaluate(artifact, n6Policy(artifact.keyId, { requireProvenance: true }), { os: 'darwin', arch: 'arm64' })
    expect(foreign.verdict.decision).toBe('ALLOW')
    expect(foreign.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })
})

// ============================================================
// N6.3 — wrong-target attestation cannot authorize the current run (D138)
// ============================================================

const BOTH_TARGETS_MATRIX = `    runtime:
      os: [linux, darwin]
      arch: [x64, arm64]
`

describe('N6.3: foreign-target attestation → DENY even when the policy allows both targets', () => {
  it('current linux/x64, attestation darwin/arm64, policy allows linux+darwin × x64+arm64 → DENY', async () => {
    const root = tempRoot('n63')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'arm64', runId: 'n63' }), releaseKey)

    const result = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(result.verdict.decision).toBe('DENY')
    const errors = result.verdict.errors.join('; ')
    // the DENY is the D111 exact-match gate — policy allowing darwin does not
    // let a darwin attestation prove a linux run
    expect(errors).toContain('exact match required')
    // and NOT a matrix-membership failure (linux/x64 IS allowed)
    expect(errors).not.toContain('not in allowed runtime matrix')
    expect(result.verdict.evidenceTrust.attestation).not.toBe('VERIFIED')
  })
})

// ============================================================
// N6.4 — exact-target attestation passes (D137)
// ============================================================

describe('N6.4: exact-target attestation with sufficient coverage → PASS', () => {
  it('current linux/x64, attestation linux/x64, policy allows linux/x64 → ALLOW', async () => {
    const root = tempRoot('n64')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', runId: 'n64' }), releaseKey)

    const result = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
    // no ambiguity, no target mismatch — the positive path works
    expect(result.verdict.errors.join('; ')).not.toContain('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).not.toContain('exact match required')
  })
})

// ============================================================
// N6.5 — same artifact, multiple target attestations (D110 ∩ D111)
// ============================================================

describe('N6.5: target filter runs BEFORE ambiguity — foreign targets never create AMBIGUOUS', () => {
  it('linux/x64 + darwin/arm64 attestations, current linux/x64, policy allows both → target filter → ALLOW', async () => {
    const root = tempRoot('n65')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', observed: [], runId: 'n65-linux' }), releaseKey)
    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'arm64', observed: [], runId: 'n65-darwin' }), releaseKey)

    const result = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
    // the foreign darwin/arm64 attestation must NOT create ambiguity
    expect(result.verdict.errors.join('; ')).not.toContain('AMBIGUOUS')
  })
})

// ============================================================
// N6.6 — same-target conflicting attestations still AMBIGUOUS
// ============================================================

describe('N6.6: same target + semantic conflict = AMBIGUOUS (D110 after the D111 filter)', () => {
  it('two linux/x64 attestations, observed=[] vs [process.exec] → AMBIGUOUS → DENY', async () => {
    const root = tempRoot('n66')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', observed: [], runId: 'n66-clean' }), releaseKey)
    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', observed: ['process.exec'], runId: 'n66-risk' }), releaseKey)

    const result = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
  })
})

// ============================================================
// N6.7 — unreadable/unknown platform metadata stays UNKNOWN (D139)
// ============================================================

interface BomLike {
  components?: Array<{ 'bom-ref': string; properties?: Array<{ name: string; value: string }> }>
}
const localComponent = (doc: string, ref: string): { 'bom-ref': string; properties: Array<{ name: string; value: string }> } => {
  const bom = JSON.parse(doc) as BomLike
  const c = (bom.components ?? []).find((x) => x['bom-ref'] === ref)
  expect(c).toBeDefined()
  return { 'bom-ref': ref, properties: c!.properties ?? [] }
}

describe('N6.7: unknown platform metadata stays UNKNOWN — never guessed (D139)', () => {
  it('a vendored package with NO package.json → no native:detected property is fabricated', async () => {
    const root = tempRoot('n67')
    const artifact = await buildArtifact(root, 'a', undefined, await makeBareTgz())
    const doc = await sbomDoc(artifact)

    // metadata unavailable ⇒ the SBOM records NO native claim at all — it does
    // NOT guess "UNKNOWN → native=false" and never a compatibility conclusion
    const local = localComponent(doc, 'local:local-plugin')
    expect(local.properties.some((p) => p.name === 'dsh-pack:native:detected')).toBe(false)
    expect(doc).not.toMatch(/compatible|incompatible/i)
  })

  it('no native signals → native:detected=false is a FACT of indicator absence, not a compatibility claim', async () => {
    const root = tempRoot('n67b')
    const artifact = await buildArtifact(root, 'a') // plain tgz, no scripts / gyp files
    const doc = await sbomDoc(artifact)

    const local = localComponent(doc, 'local:local-plugin')
    const nativeProp = local.properties.find((p) => p.name === 'dsh-pack:native:detected')
    expect(nativeProp?.value).toBe('false') // absence of INDICATORS, factually
    expect(doc).not.toMatch(/compatible|incompatible/i)
  })
})

// ============================================================
// N6.8 — declared os/cpu package fields: recorded facts, never a runtime verdict
// ============================================================

describe('N6.8: platform-specific package fields never become a compatibility engine', () => {
  it('vendored package declares os:[linux] cpu:[x64] → SBOM/policy verdicts stay attestation-driven', async () => {
    const root = tempRoot('n68')
    const artifact = await buildArtifact(root, 'a', undefined, await makeTgz(undefined, { os: ['linux'], cpu: ['x64'] }))
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    // 1. the SBOM reports the package WITHOUT any compatible/incompatible conclusion
    const doc = await sbomDoc(artifact)
    expect(doc).not.toMatch(/compatible|incompatible/i)

    // 2. the os/cpu declaration never forces ALLOW: a wrong-target attestation
    //    is still DENIED (only the attestation target decides, D137/D138)
    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'arm64', runId: 'n68-foreign' }), releaseKey)
    const denied = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(denied.verdict.decision).toBe('DENY')
    expect(denied.verdict.errors.join('; ')).toContain('exact match required')

    // 3. nor does it force DENY: an exact-target attestation still passes
    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'x64', runId: 'n68-exact' }), releaseKey)
    const allowed = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(allowed.verdict.decision).toBe('ALLOW')
    expect(allowed.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })
})

// ============================================================
// N6.9 — policy matrix membership ≠ attestation target match (D137)
// ============================================================

describe('N6.9: separate os/arch membership never adds up to a target match', () => {
  it('current linux/x64, attestation linux/arm64, both memberships allowed → DENY (exact match required)', async () => {
    const root = tempRoot('n69')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'linux', arch: 'arm64', runId: 'n69' }), releaseKey)

    const result = await evaluate(artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }))
    expect(result.verdict.decision).toBe('DENY')
    const errors = result.verdict.errors.join('; ')
    // linux ∈ allowedOs AND arm64 ∈ allowedArch — yet linux/arm64 ≠ linux/x64:
    // membership is NOT a target match, the Cartesian product does not authorize
    expect(errors).toContain('exact match required')
    expect(errors).not.toContain('not in allowed runtime matrix')
    expect(result.verdict.evidenceTrust.attestation).not.toBe('VERIFIED')
  })
})

// ============================================================
// N6.10 — runtime.os + runtime.arch = independent allowlists (Cartesian product)
// ============================================================

describe('N6.10: the runtime matrix is a Cartesian product — membership is not authorization', () => {
  it('a MIXED member (darwin/x64) of the product runs WITH a matching attestation', async () => {
    const root = tempRoot('n610a')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'x64', runId: 'n610-mixed' }), releaseKey)
    const allowed = await evaluate(
      artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }),
      { os: 'darwin', arch: 'x64' },
    )
    expect(allowed.verdict.decision).toBe('ALLOW')
    expect(allowed.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })

  it('a product-member attestation never authorizes a DIFFERENT current target', async () => {
    const root = tempRoot('n610b')
    const artifact = await buildArtifact(root, 'a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    // current darwin/x64; attestation darwin/arm64 — BOTH are in the Cartesian
    // product, but the attestation must match the CURRENT target exactly
    await signAttestation(artifact, attDoc({ os: 'darwin', arch: 'arm64', runId: 'n610' }), releaseKey)
    const denied = await evaluate(
      artifact, n6Policy(artifact.keyId, { runtimeMatrix: BOTH_TARGETS_MATRIX }),
      { os: 'darwin', arch: 'x64' },
    )
    expect(denied.verdict.decision).toBe('DENY')
    expect(denied.verdict.errors.join('; ')).toContain('exact match required')
    expect(denied.verdict.errors.join('; ')).not.toContain('not in allowed runtime matrix')
  })
})
