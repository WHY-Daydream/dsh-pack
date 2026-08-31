/**
 * v0.5.0-rc.1 — N3 Lifecycle Script Attack (D115 freeze):
 *
 * Lifecycle/package execution must never occur before the trust decision.
 * The pipeline is FORCED to be:
 *
 *   Verify → Evidence → Trust Policy → ALLOW → Materialize → pnpm → lifecycle
 *
 * and must NEVER become:
 *
 *   pnpm install → preinstall/install/postinstall/prepare → verify/policy  ❌
 *
 * Fixtures N3.1–N3.6 plant a SAFE canary script (writes a sentinel file via
 * $ATTACK_SENTINEL) in the profile's package.json lifecycle slot. The canary
 * only proves execution order — it never does anything harmful. Denials are
 * driven by the local trust.yaml v2 policy through
 * `packager.install(file, { policy })`: ANY non-ALLOW verdict (untrusted
 * issuer, ambiguous evidence, wrong execution target, malformed evidence)
 * must throw BEFORE materialization, so the sentinel MUST NOT exist. The
 * ALLOW case proves the canary CAN run — normal materialization is not
 * over-blocked.
 *
 * SBOM is used only to prove lifecycle existence + scriptDigest (D77); NO
 * lifecycle policy feature is added here (rc.1 scope guard).
 */
import { execFile } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultPackager } from '../src/service.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { LIFECYCLE_SCRIPTS } from '../src/evidence/sbom.js'
import type { DependencyTree } from '../src/types.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n3-${label}-`))
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

// --- fixture: a pack whose profile carries ONE lifecycle canary slot ---

const CANARY_SLOTS = ['preinstall', 'install', 'postinstall', 'prepare'] as const

/** Deterministic minimal lockfile — offline-safe, satisfies --frozen-lockfile (pnpm 11.x). */
const MINIMAL_LOCKFILE = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:
  .:
    dependencies: {}
`

/** Inline canary: proves this lifecycle slot EXECUTED (safe — a sentinel file only).
 *  Inline (not a separate file) because materialize only copies fixed profile
 *  paths (package.json / cordis.* / pnpm-lock.yaml) — an external canary.js
 *  would not exist in the profile dir when pnpm runs lifecycle scripts. */
const CANARY = `node -e "require('node:fs').writeFileSync(process.env.ATTACK_SENTINEL, 'fired')"`

async function makeLifecyclePack(
  root: string,
  slot: (typeof CANARY_SLOTS)[number],
): Promise<{ file: string; profileDir: string }> {
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'n3' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: {},
    configHash: computeConfigHash({ rows: [] }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const pkg = {
    name: 'n3-profile',
    version: '1.0.0',
    private: true,
    dependencies: {},
    scripts: { [slot]: CANARY },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(pkg) },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
    { path: 'profile/pnpm-lock.yaml', content: MINIMAL_LOCKFILE },
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
  const file = join(root, 'n3.dshpack')
  writeFileSync(file, final.buffer)
  return { file, profileDir: join(root, 'n3') }
}

/** Sign the pack with a fresh key; returns the SIGNED file (signPackFile writes `<name>.signed.dshpack`) + keyId. */
async function signPackWithFreshKey(file: string, root: string): Promise<{ signed: string; keyId: string }> {
  const key = generateKeypair(root)
  const result = await signPackFile(file, { key: key.privateKey })
  return { signed: result.file, keyId: result.keyId }
}

/** Full evidence collection (provenance build-time + sbom + attestation). */
async function attachTrustedEvidence(file: string, keyPath: string): Promise<void> {
  const evidence = new DefaultEvidenceService()
  await evidence.sign(file, {
    type: 'build-provenance',
    statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/n3' } },
    key: keyPath,
  })
  await evidence.sign(file, {
    type: 'sbom',
    statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: 'a'.repeat(64) } },
    key: keyPath,
  })
  const collectionRoot = join(dirname(file), `${basename(file, '.dshpack')}.dshpack.evidence`)
  const doc = {
    schemaVersion: 1, subject: { contentHash: 'ignored' },
    metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'n3' },
    coldBoot: { status: 'PASS' },
    observation: { coverage: 'complete', reasons: [] },
    observed: { tools: [], skills: [], services: [], providers: [] },
    comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
    resultDigest: 'sha256:' + 'b'.repeat(64),
  }
  const docText = JSON.stringify(doc)
  const docHex = sha256Hex(docText)
  const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
  mkdirSync(dirname(docFile), { recursive: true })
  writeFileSync(docFile, docText)
  await evidence.sign(file, {
    type: 'attestation',
    statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
    key: keyPath,
  })
}

function writeTrustYaml(home: string, text: string): void {
  mkdirSync(home, { recursive: true })
  writeFileSync(join(home, 'trust.yaml'), text)
}

/** Execution-order spy: a scratch events log + the sentinel path to probe. */
function spy(): { sentinel: string; events: string[] } {
  const sentinel = join(mkdtempSync(join(tmpdir(), 'dsh-pack-n3-sentinel-')), 'fired')
  tempDirs.push(dirname(sentinel))
  return { sentinel, events: [] }
}

/** `install(file, { policy })` must throw for a non-ALLOW verdict (D115 gate). */
async function expectInstallDenied(
  file: string,
  home: string,
  sentinel: string,
  policy: { repository: string; executionTarget: { os: string; arch: string } },
  reasonHint: string,
): Promise<void> {
  const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
  process.env.ATTACK_SENTINEL = sentinel
  await expect(packager.install(file, { policy })).rejects.toThrow(reasonHint)
  // D115: the lifecycle canary MUST NOT have fired — no pnpm → no lifecycle
  expect(existsSync(sentinel)).toBe(false)
  // materialize must not have happened either (no profile dir created)
  expect(existsSync(join(home, 'profiles', 'n3'))).toBe(false)
  delete process.env.ATTACK_SENTINEL
}

describe('N3 — Lifecycle Script Attack (D115: no execution before trust decision)', () => {
  it('N3.1: preinstall canary — untrusted artifact DENY → sentinel MUST NOT exist', async () => {
    const root = tempRoot('n31')
    const { file } = await makeLifecyclePack(root, 'preinstall')
    const { signed } = await signPackWithFreshKey(file, join(root, 'release')) // signed, but the policy trusts a DIFFERENT key
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${'f'.repeat(64)}"
`)
    const { sentinel } = spy()
    await expectInstallDenied(signed, home, sentinel, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } }, /trust policy/i)
  })

  it('N3.2: install canary — evidence issuer untrusted → DENY → sentinel absent', async () => {
    const root = tempRoot('n32')
    const { file } = await makeLifecyclePack(root, 'install')
    const releaseKey = generateKeypair(join(root, 'release'))
    const signed = (await signPackFile(file, { key: releaseKey.privateKey })).file
    // provenance + sbom signed by the TRUSTED release key; the attestation is
    // signed by an ATTACKER key → the v2 policy must reject the evidence issuer
    // (D109) BEFORE any materialization can run the install canary
    const attackerKey = generateKeypair(join(root, 'attacker'))
    await attachTrustedEvidence(signed, releaseKey.privateKey) // provenance/sbom/attestation with release key
    // overwrite the attestation envelope with an attacker-signed one: remove the
    // trusted attestation directory and re-sign with the attacker key
    const collectionRoot = join(dirname(signed), `${basename(signed, '.dshpack')}.dshpack.evidence`)
    rmSync(join(collectionRoot, 'attestation'), { recursive: true, force: true })
    const evidence = new DefaultEvidenceService()
    const doc = {
      schemaVersion: 1, subject: { contentHash: 'ignored' },
      metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'n32' },
      coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
      observed: { tools: [], skills: [], services: [], providers: [] },
      comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
      effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
      cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
      resultDigest: 'sha256:' + 'c'.repeat(64),
    }
    const docText = JSON.stringify(doc)
    const docHex = sha256Hex(docText)
    const docFile = join(collectionRoot, 'documents', `${docHex}.attestation.json`)
    mkdirSync(dirname(docFile), { recursive: true })
    writeFileSync(docFile, docText)
    await evidence.sign(signed, {
      type: 'attestation',
      statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: docHex } },
      key: attackerKey.privateKey,
    })

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKey.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
        trustedKeys:
          - "SHA256:${releaseKey.keyId}"
`)
    const { sentinel } = spy()
    await expectInstallDenied(signed, home, sentinel, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } }, /UNTRUSTED_EVIDENCE_ISSUER/i)
  })

  it('N3.3: postinstall canary — DENY AMBIGUOUS (two conflicting trusted attestations) → sentinel absent', async () => {
    const root = tempRoot('n33')
    const { file } = await makeLifecyclePack(root, 'postinstall')
    const releaseKey = generateKeypair(join(root, 'release'))
    const signed = (await signPackFile(file, { key: releaseKey.privateKey })).file
    const key = generateKeypair(join(root, 'attestor'))
    const evidence = new DefaultEvidenceService()
    const collectionRoot = join(dirname(signed), `${basename(signed, '.dshpack')}.dshpack.evidence`)
    const mkAttestation = async (providers: string[], runId: string): Promise<void> => {
      const doc = JSON.stringify({
        schemaVersion: 1, subject: { contentHash: 'ignored' },
        metadata: { observedAt: '2026-08-30T00:00:00Z', runId },
        coldBoot: { status: 'PASS' }, observation: { coverage: 'complete', reasons: [] },
        observed: { tools: [], skills: [], services: [], providers },
        comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
        effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
        cleanup: { status: 'PASS' }, environment: { dsh: 'x', node: 'x', os: 'linux', arch: 'x64' },
        resultDigest: 'sha256:' + 'b'.repeat(64),
      })
      const hex = sha256Hex(doc)
      const docFile = join(collectionRoot, 'documents', `${hex}.attestation.json`)
      mkdirSync(dirname(docFile), { recursive: true })
      writeFileSync(docFile, doc)
      await evidence.sign(signed, {
        type: 'attestation',
        statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: hex } },
        key: key.privateKey,
      })
    }
    await mkAttestation([], 'run-1')
    await mkAttestation(['process.exec'], 'run-2')

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKey.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
        trustedKeys:
          - "SHA256:${key.keyId}"
`)
    const { sentinel } = spy()
    await expectInstallDenied(signed, home, sentinel, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } }, /AMBIGUOUS/i)
  })

  it('N3.4: prepare canary — DENY + SBOM proves lifecycle existence + scriptDigest (D77)', async () => {
    const root = tempRoot('n34')
    const { file } = await makeLifecyclePack(root, 'prepare')
    const { signed } = await signPackWithFreshKey(file, join(root, 'release'))

    // SBOM evidence (D77): lifecycle.prepare is an existence+digest fact
    const sbom = new DefaultEvidenceService()
    const sbomResult = await sbom.sbom(signed, { key: join(root, 'release', 'dsh-pack-private.pem') })
    const document = JSON.parse(readFileSync(sbomResult.documentFile, 'utf8')) as {
      components?: Array<{ properties?: Array<{ name: string; value: string }> }>
    }
    const props = (document.components ?? []).flatMap((c) => c.properties ?? [])
    const prepare = props.find((p) => p.name === 'dsh-pack:npm-lifecycle:prepare')
    expect(prepare).toBeDefined()
    expect(prepare!.value).toMatch(/^sha256:[0-9a-f]{64}$/)
    // the digest is over the canary source — never the raw script text
    expect(prepare!.value).not.toContain('writeFileSync')

    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${'f'.repeat(64)}"
`)
    const { sentinel } = spy()
    await expectInstallDenied(signed, home, sentinel, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } }, /trust policy|untrusted|signer/i)
  })

  it('N3.5: trusted + ALLOW → lifecycle may execute normally (sentinel EXISTS)', async () => {
    const root = tempRoot('n35')
    const { file } = await makeLifecyclePack(root, 'postinstall')
    const key = generateKeypair(join(root, 'trusted'))
    const signed = (await signPackFile(file, { key: key.privateKey })).file
    await attachTrustedEvidence(signed, key.privateKey)
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${key.keyId}"
    requireEvidence:
      provenance:
        origin: build-time
      sbom: true
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${key.keyId}"
    source:
      allowedRepositories:
        - "github.com/company/*"
    runtime:
      os: [linux]
      arch: [x64]
`)
    const { sentinel } = spy()
    process.env.ATTACK_SENTINEL = sentinel
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
    const installed = await packager.install(signed, {
      policy: { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } },
    })
    expect(installed.profile).toBe('n3')
    // ALLOW → materialize → pnpm install → lifecycle may run → sentinel EXISTS
    expect(existsSync(sentinel)).toBe(true)
    delete process.env.ATTACK_SENTINEL
  })

  it('N3.6: wrong execution target — policy DENY → lifecycle never executes', async () => {
    const root = tempRoot('n36')
    const { file } = await makeLifecyclePack(root, 'prepare')
    const key = generateKeypair(join(root, 'attestor'))
    const { signed } = await signPackWithFreshKey(file, join(root, 'release'))
    await attachTrustedEvidence(signed, key.privateKey)
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${'f'.repeat(64)}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
        trustedKeys:
          - "SHA256:${key.keyId}"
    runtime:
      os: [linux, darwin]
      arch: [x64, arm64]
`)
    const { sentinel } = spy()
    // the attestation env is linux/x64 but we claim the CURRENT target is darwin/arm64
    await expectInstallDenied(signed, home, sentinel, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'darwin', arch: 'arm64' } }, /does not match current execution target|trust policy/i)
  })

  it('D115 regression: execution order — policy DENY happens BEFORE materialize/pnpm/lifecycle', async () => {
    const root = tempRoot('n37')
    const { file } = await makeLifecyclePack(root, 'postinstall')
    const { signed } = await signPackWithFreshKey(file, join(root, 'release'))
    const home = join(root, 'home')
    writeTrustYaml(home, `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${'f'.repeat(64)}"
`)
    const { sentinel, events } = spy()
    const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
    process.env.ATTACK_SENTINEL = sentinel

    // the guarded install evaluates policy FIRST and stops on DENY:
    // verify → evidence → policy-deny → STOP (no materialize, no pnpm, no lifecycle)
    const outcome = await packager.policy(signed, { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } })
    events.push('evaluate-policy')
    expect(outcome.verdict.decision).toBe('DENY')
    events.push(`policy-${outcome.verdict.decision.toLowerCase()}`)
    await expect(packager.install(signed, { policy: { repository: 'ghcr.io/company/prod-app', executionTarget: { os: 'linux', arch: 'x64' } } }))
      .rejects.toThrow()
    events.push('policy-deny-stops-install')

    expect(events).toEqual(['evaluate-policy', 'policy-deny', 'policy-deny-stops-install'])
    expect(existsSync(sentinel)).toBe(false) // lifecycle ∉ events
    expect(existsSync(join(home, 'profiles', 'n3'))).toBe(false) // materialize ∉ events
    delete process.env.ATTACK_SENTINEL
  })

  it('scope guard: NO lifecycle policy feature was added (rc.1 discipline)', async () => {
    // LIFECYCLE_SCRIPTS is still just the D77 existence-fact list — the policy
    // engine has no denyLifecycleScripts knob (that would be a future feature)
    expect(LIFECYCLE_SCRIPTS).toContain('preinstall')
    expect(LIFECYCLE_SCRIPTS).toContain('postinstall')
    const src = readFileSync(new URL('../src/image/trust-policy-v2.ts', import.meta.url), 'utf8')
    expect(src).not.toContain('denyLifecycleScripts')
    expect(src).not.toContain('allowLifecycle')
  })
})
