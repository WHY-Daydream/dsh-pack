/**
 * v0.5.0-rc.1 — N5 Evidence Ambiguity (D124–D128 freeze):
 *
 * When multiple Evidence items are all VALID + subject-bound + TRUSTED but
 * carry CONFLICTING semantics, the policy must NEVER guess which one is true:
 * non-equivalent trusted candidates for the same required slot →
 * AMBIGUOUS → DENY. No implicit selectors: no file order / filename /
 * createdAt / latest / signer-lexical / majority vote; coverage being higher,
 * timestamp being newer, or observed set being "cleaner" never wins by itself.
 *
 *   D124 ambiguity is judged only after VALID → subject → trusted issuer →
 *        type-specific constraint filtering
 *   D125 equivalent duplicates may collapse into one semantic candidate
 *   D126 non-equivalent trusted candidates → AMBIGUOUS → DENY
 *   D127 selection must not use file order / createdAt / filename / latest /
 *        signer lexical order as tie-breaker
 *   D128 stronger-looking evidence does not automatically win
 *
 * Semantic equivalence (per type):
 *   provenance            → canonical statementDigest
 *   SBOM                  → sbomDigest
 *   runtime attestation   → normalized resultDigest (+ target + coverage)
 *
 * RC-N5 North-Star: trusted attestation A observed=[] + trusted attestation
 * B observed=[process.exec], same target + coverage → DENY AMBIGUOUS under
 * ANY ordering/rename/timestamp/signer permutation.
 *
 * N5 does NOT add digest pinning or any selector feature (rc.1 scope guard).
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultPackager } from '../src/service.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { signEvidence } from '../src/evidence/envelope.js'
import type { DependencyTree } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n5-${label}-`))
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

async function makePack(): Promise<Buffer> {
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

interface ArtifactFixture {
  packFile: string
  keyId: string
  collectionRoot: string
}

interface AttDocOpts {
  observed?: string[]
  coverage?: 'complete' | 'partial' | 'unknown'
  os?: string
  arch?: string
  /** metadata is NON-deterministic by design (D96) — lets tests vary it freely */
  observedAt?: string
  runId?: string
}

/**
 * A deterministic-enough attestation document. The SEMANTIC anchor per D125 is
 * resultDigest (normalized) + target + coverage; metadata may differ between
 * two runs that observed the same facts. Tests construct these explicitly so
 * they can control equivalence independently of envelope bytes.
 */
function attDoc(opts: AttDocOpts = {}): string {
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
  const resultDigest = 'sha256:' + sha256Hex(JSON.stringify(normalized))
  return JSON.stringify({
    schemaVersion: 1, subject: { contentHash: 'ignored' },
    metadata: { observedAt: opts.observedAt ?? '2026-08-30T00:00:00Z', runId: opts.runId ?? 'n5' },
    ...normalized,
    resultDigest,
  })
}

/** Sign ONE attestation envelope + document against the artifact. */
async function signAttestation(
  artifact: ArtifactFixture, docText: string, key: string,
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

/** Sign provenance (different statements → different statementDigests). */
async function signProvenance(
  artifact: ArtifactFixture, statement: Record<string, unknown>, key: string,
): Promise<void> {
  const evidence = new DefaultEvidenceService()
  await evidence.sign(artifact.packFile, { type: 'build-provenance', statement, key })
}

/** Sign sbom evidence (statement carries sbomDigest). */
async function signSbom(
  artifact: ArtifactFixture, sbomDigest: string, key: string,
): Promise<void> {
  const evidence = new DefaultEvidenceService()
  await evidence.sign(artifact.packFile, {
    type: 'sbom',
    statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: sbomDigest } },
    key,
  })
}

async function buildArtifact(root: string, label: string): Promise<ArtifactFixture> {
  const dir = join(root, label)
  mkdirSync(dir, { recursive: true })
  const packFile = join(dir, 'app.dshpack')
  writeFileSync(packFile, await makePack())
  const key = generateKeypair(join(dir, 'release'))
  const signed = await signPackFile(packFile, { key: key.privateKey })
  const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
  return { packFile: signed.file, keyId: key.keyId, collectionRoot }
}

/** Evaluate with a REAL v2 trust.yaml; `attestationCoverage` controls the filter. */
async function evaluate(
  artifact: ArtifactFixture,
  opts: { policyYaml?: string; repository?: string } = {},
) {
  const home = join(dirname(artifact.packFile), 'policy-home')
  mkdirSync(home, { recursive: true })
  const yaml = opts.policyYaml ?? `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${artifact.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${artifact.keyId}"
`
  writeFileSync(join(home, 'trust.yaml'), yaml)
  const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION })
  return packager.policy(artifact.packFile, {
    repository: opts.repository ?? 'ghcr.io/company/prod-app',
    collectionDir: artifact.collectionRoot,
    executionTarget: { os: 'linux', arch: 'x64' },
  })
}

// ============================================================
// N5.1 — runtime observed conflict (the RC-N5 core)
// ============================================================

describe('N5.1: runtime observed conflict — same target, same coverage, conflicting observed sets', () => {
  it('trusted clean attestation + trusted process.exec attestation → AMBIGUOUS → DENY', async () => {
    const root = tempRoot('n51')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    // Attestation A: coverage=complete, observed=[] (the "clean" story)
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'clean' }), releaseKey)
    // Attestation B: coverage=complete, observed=[process.exec] (the risk)
    await signAttestation(artifact, attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'risk' }), releaseKey)

    const result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
    // never a silent ALLOW via first-read order
    expect(result.verdict.errors.join('; ')).not.toContain('ALLOW')
  })

  it('single clean attestation → ALLOW (the conflict above is real, not over-blocking)', async () => {
    const root = tempRoot('n51base')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete' }), releaseKey)
    const result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })
})

// ============================================================
// N5.2 — coverage conflict (filtering ≠ arbitrary preference, D128)
// ============================================================

describe('N5.2: coverage conflict — complete vs partial', () => {
  it('policy requires complete → partial filtered, complete unique → normal evaluation (ALLOW if clean)', async () => {
    const root = tempRoot('n52a')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    // partial + complete, BOTH trusted, same observed facts
    await signAttestation(artifact, attDoc({ observed: ['tool.foo'], coverage: 'partial', runId: 'p' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: ['tool.foo'], coverage: 'complete', runId: 'c' }), releaseKey)

    // default policy requires coverage: complete → partial excluded → unique → ALLOW
    const result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })

  it('policy accepts partial → BOTH are valid candidates → AMBIGUOUS → DENY', async () => {
    const root = tempRoot('n52b')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ observed: ['tool.foo'], coverage: 'partial', runId: 'p' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: ['tool.foo'], coverage: 'complete', runId: 'c' }), releaseKey)

    const result = await evaluate(artifact, { policyYaml: `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${artifact.keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: partial
    evidenceTrustedKeys:
      - "SHA256:${artifact.keyId}"
` })
    // complete ≠ partial semantically → ambiguity, NOT "complete wins"
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
  })
})

// ============================================================
// N5.3 — provenance source conflict (same artifact, two build sources)
// ============================================================

/** Policy that consumes ONLY provenance — isolates N5.3 from other evidence types. */
const PROV_POLICY = (keyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
    requireEvidence:
      provenance:
        origin: build-time
    evidenceTrustedKeys:
      - "SHA256:${keyId}"
`

/** Policy that consumes ONLY sbom — isolates N5.4 from other evidence types. */
const SBOM_POLICY = (keyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
    requireEvidence:
      sbom: true
    evidenceTrustedKeys:
      - "SHA256:${keyId}"
`

describe('N5.3: provenance git source conflict', () => {
  it('two trusted provenance statements with different git commits → AMBIGUOUS → DENY', async () => {
    const root = tempRoot('n53')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signProvenance(artifact, {
      capture: { mode: 'build-time' },
      source: { repository: 'github.com/company/app', gitCommit: 'aaaa'.repeat(10) },
    }, releaseKey)
    await signProvenance(artifact, {
      capture: { mode: 'build-time' },
      source: { repository: 'github.com/company/app', gitCommit: 'bbbb'.repeat(10) },
    }, releaseKey)

    const result = await evaluate(artifact, { policyYaml: PROV_POLICY(artifact.keyId) })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.provenance).toBe('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
  })

  it('two trusted provenance with the SAME statement → equivalent duplicate → NOT ambiguous', async () => {
    const root = tempRoot('n53base')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const statement = {
      capture: { mode: 'build-time' },
      source: { repository: 'github.com/company/app', gitCommit: 'aaaa'.repeat(10) },
    }
    await signProvenance(artifact, statement, releaseKey)
    await signProvenance(artifact, statement, releaseKey)

    const result = await evaluate(artifact, { policyYaml: PROV_POLICY(artifact.keyId) })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.provenance).toBe('VERIFIED')
  })
})

// ============================================================
// N5.4 — SBOM document conflict
// ============================================================

describe('N5.4: SBOM document conflict', () => {
  it('two trusted SBOM documents with different digests → AMBIGUOUS → DENY', async () => {
    const root = tempRoot('n54')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    // SBOM X: foo@1 + bar@2 ; SBOM Y: foo@1 only — different semantic documents
    await signSbom(artifact, 'x'.repeat(64), releaseKey)
    await signSbom(artifact, 'y'.repeat(64), releaseKey)

    const result = await evaluate(artifact, { policyYaml: SBOM_POLICY(artifact.keyId) })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.sbom).toBe('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
  })

  it('two trusted SBOM envelopes with the SAME digest → equivalent duplicate → NOT ambiguous', async () => {
    const root = tempRoot('n54base')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    await signSbom(artifact, 'x'.repeat(64), releaseKey)
    await signSbom(artifact, 'x'.repeat(64), releaseKey)

    const result = await evaluate(artifact, { policyYaml: SBOM_POLICY(artifact.keyId) })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.sbom).toBe('VERIFIED')
  })
})

// ============================================================
// N5.5 — equivalent duplicates across DIFFERENT trusted signers
// ============================================================

/** Policy trusting several evidence keys for the given requireEvidence fragment. */
const MULTI_KEY_POLICY = (
  trustedKey: string, evidenceKeys: string[], requireEvidenceYaml: string,
): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${trustedKey}"
    requireEvidence:
${requireEvidenceYaml}
    evidenceTrustedKeys:
${evidenceKeys.map((k) => `      - "SHA256:${k}"`).join('\n')}
`

const ATTESTATION_REQUIRE = `      runtimeAttestation:
        required: true
        coverage: complete`

describe('N5.5: equivalent duplicates across different trusted signers', () => {
  it('same SBOM digest signed by TWO trusted keys → equivalent duplicate → NOT ambiguous', async () => {
    const root = tempRoot('n55sbom')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const other = generateKeypair(join(root, 'other-key'))

    const statement = {
      format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json',
      sbomDigest: { algorithm: 'sha256', value: 'x'.repeat(64) },
    }
    await signSbom(artifact, 'x'.repeat(64), releaseKey)
    // Second envelope: SAME statement, OTHER trusted key. The D65 collection
    // rule refuses to overwrite the `<statementDigest>.json` file, so construct
    // the duplicate envelope directly (scanEnvelopes reads any .json name) —
    // the policy must still collapse it as an equivalent duplicate (D125).
    const firstEnvName = readdirSync(join(artifact.collectionRoot, 'sbom'))
      .filter((n) => n.endsWith('.json')).sort()[0]!
    const firstEnv = JSON.parse(
      readFileSync(join(artifact.collectionRoot, 'sbom', firstEnvName), 'utf8'),
    ) as { subject: { contentHash: string } }
    const dup = signEvidence({
      type: 'sbom',
      statement,
      subjectContentHash: firstEnv.subject.contentHash,
      keyPath: other.privateKey,
    })
    writeFileSync(join(artifact.collectionRoot, 'sbom', `${other.keyId}.json`), prettyJson(dup))

    const result = await evaluate(artifact, {
      policyYaml: MULTI_KEY_POLICY(artifact.keyId, [artifact.keyId, other.keyId], '      sbom: true'),
    })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.sbom).toBe('VERIFIED')
  })

  it('same attestation semantics (resultDigest+target+coverage) signed by TWO trusted keys, differing run metadata → NOT ambiguous', async () => {
    const root = tempRoot('n55att')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const other = generateKeypair(join(root, 'other-key'))

    // identical observed facts → identical resultDigest; metadata (runId/observedAt) differs (D96)
    await signAttestation(
      artifact,
      attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'run-A', observedAt: '2026-08-30T00:00:00Z' }),
      releaseKey,
    )
    await signAttestation(
      artifact,
      attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'run-B', observedAt: '2026-08-30T01:00:00Z' }),
      other.privateKey,
    )

    const result = await evaluate(artifact, {
      policyYaml: MULTI_KEY_POLICY(artifact.keyId, [artifact.keyId, other.keyId], ATTESTATION_REQUIRE),
    })
    expect(result.verdict.decision).toBe('ALLOW')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
  })
})

// ============================================================
// N5.6 — file-order randomization (attacks D116/D127 head-on)
// ============================================================

describe('N5.6: file-order randomization never flips the verdict', () => {
  it('trusted clean + trusted process.exec + untrusted clean → ALWAYS DENY AMBIGUOUS under randomized names', async () => {
    const root = tempRoot('n56')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')
    const attacker = generateKeypair(join(root, 'attacker-key'))

    // A: trusted clean · B: trusted process.exec · C: untrusted clean
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'clean-a' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'risk-b' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'clean-c' }), attacker.privateKey)

    const attDir = join(artifact.collectionRoot, 'attestation')
    // documents stay at canonical digest names (the envelope references them by
    // digest) — only the envelope FILE NAMES are randomized each round.
    for (let round = 0; round < 15; round++) {
      for (const name of readdirSync(attDir).filter((n) => n.endsWith('.json'))) {
        const rand = Math.random().toString(36).slice(2, 12)
        renameSync(join(attDir, name), join(attDir, `${rand}-${name}`))
      }
      const result = await evaluate(artifact)
      expect(result.verdict.decision).toBe('DENY')
      expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
      // a single ALLOW drift anywhere = blocker
      expect(result.verdict.errors.join('; ')).not.toContain('ALLOW')
    }
  })
})

// ============================================================
// N5.7 — createdAt must never become latest-wins
// ============================================================

/**
 * Rewrite an envelope's `signing.createdAt` (NOT covered by the D66 signature,
 * which binds only domain/type/subject/statementDigest) so tests can prove the
 * timestamp is never an implicit trust selector.
 */
function setEnvelopeCreatedAt(artifact: ArtifactFixture, docHex: string, createdAt: string): void {
  const dir = join(artifact.collectionRoot, 'attestation')
  for (const name of readdirSync(dir).filter((n) => n.endsWith('.json'))) {
    const env = JSON.parse(readFileSync(join(dir, name), 'utf8')) as {
      statement?: { attestationDigest?: { value?: string } }
      signing: { createdAt: string }
    }
    if (env.statement?.attestationDigest?.value === docHex) {
      env.signing.createdAt = createdAt
      writeFileSync(join(dir, name), prettyJson(env))
      return
    }
  }
  throw new Error(`attestation envelope for document ${docHex} not found`)
}

describe('N5.7: createdAt is not an implicit trust selector', () => {
  it('AMBIGUOUS whether the risky attestation is older OR newer', async () => {
    const root = tempRoot('n57')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    const badDoc = attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'bad' })
    const cleanDoc = attDoc({ observed: [], coverage: 'complete', runId: 'clean' })
    await signAttestation(artifact, badDoc, releaseKey)
    await signAttestation(artifact, cleanDoc, releaseKey)
    const badHex = sha256Hex(badDoc)
    const cleanHex = sha256Hex(cleanDoc)

    // bad = earlier, clean = later → latest-wins would pick clean → still AMBIGUOUS
    setEnvelopeCreatedAt(artifact, badHex, '2026-08-01T00:00:00Z')
    setEnvelopeCreatedAt(artifact, cleanHex, '2026-08-30T00:00:00Z')
    let result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')

    // flip: bad = later, clean = earlier → newest-wins would pick bad → still AMBIGUOUS
    setEnvelopeCreatedAt(artifact, badHex, '2026-08-30T00:00:00Z')
    setEnvelopeCreatedAt(artifact, cleanHex, '2026-08-01T00:00:00Z')
    result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
  })
})

// ============================================================
// N5.8 — signer identity order must never be a tie-break
// ============================================================

describe('N5.8: signer identity order is never a tie-break', () => {
  it('AMBIGUOUS both ways when the two trusted keys swap which content they signed', async () => {
    // round 1: release key → clean, other key → process.exec
    const root1 = tempRoot('n58a')
    const artifact1 = await buildArtifact(root1, 'a')
    const releaseKey1 = join(dirname(artifact1.packFile), 'release', 'dsh-pack-private.pem')
    const other1 = generateKeypair(join(root1, 'other-key'))
    await signAttestation(artifact1, attDoc({ observed: [], coverage: 'complete', runId: 'k1' }), releaseKey1)
    await signAttestation(artifact1, attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'k2' }), other1.privateKey)
    let result = await evaluate(artifact1, {
      policyYaml: MULTI_KEY_POLICY(artifact1.keyId, [artifact1.keyId, other1.keyId], ATTESTATION_REQUIRE),
    })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')

    // round 2: swap content across the SAME two key identities
    const root2 = tempRoot('n58b')
    const artifact2 = await buildArtifact(root2, 'a')
    const releaseKey2 = join(dirname(artifact2.packFile), 'release', 'dsh-pack-private.pem')
    const other2 = generateKeypair(join(root2, 'other-key'))
    await signAttestation(artifact2, attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'k2b' }), releaseKey2)
    await signAttestation(artifact2, attDoc({ observed: [], coverage: 'complete', runId: 'k1b' }), other2.privateKey)
    result = await evaluate(artifact2, {
      policyYaml: MULTI_KEY_POLICY(artifact2.keyId, [artifact2.keyId, other2.keyId], ATTESTATION_REQUIRE),
    })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
  })
})

// ============================================================
// N5.9 — evidence types stay independent (no cross-type masking)
// ============================================================

const ALL_EVIDENCE_REQUIRE = `      provenance:
        origin: build-time
      sbom: true
${ATTESTATION_REQUIRE}`

describe('N5.9: one ambiguous evidence type is not masked by clean others', () => {
  it('2 conflicting provenance + 1 unique SBOM + 1 unique attestation → DENY, only provenance AMBIGUOUS', async () => {
    const root = tempRoot('n59')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signProvenance(artifact, {
      capture: { mode: 'build-time' },
      source: { repository: 'github.com/company/app', gitCommit: 'aaaa'.repeat(10) },
    }, releaseKey)
    await signProvenance(artifact, {
      capture: { mode: 'build-time' },
      source: { repository: 'github.com/company/app', gitCommit: 'bbbb'.repeat(10) },
    }, releaseKey)
    await signSbom(artifact, 'x'.repeat(64), releaseKey)
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'n59' }), releaseKey)

    const result = await evaluate(artifact, {
      policyYaml: MULTI_KEY_POLICY(artifact.keyId, [artifact.keyId], ALL_EVIDENCE_REQUIRE),
    })
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.provenance).toBe('AMBIGUOUS')
    expect(result.verdict.evidenceTrust.sbom).toBe('VERIFIED')
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
    // audit chain: provenance fails, sbom + attestation pass independently
    const byStep = new Map(result.verdict.steps.map((s) => [s.step, s.ok]))
    expect(byStep.get('provenance-issuer')).toBe(false)
    expect(byStep.get('sbom-issuer')).toBe(true)
    expect(byStep.get('execution-target')).toBe(true)
  })
})

// ============================================================
// N5.10 — no majority vote: evidence is not a ballot
// ============================================================

describe('N5.10: multiple clean attestations cannot outvote one risky one', () => {
  it('A clean + B clean + C process.exec, all trusted → AMBIGUOUS, never clean-wins (2 vs 1)', async () => {
    const root = tempRoot('n510')
    const artifact = await buildArtifact(root, 'artifact-a')
    const releaseKey = join(dirname(artifact.packFile), 'release', 'dsh-pack-private.pem')

    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'clean-a' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: [], coverage: 'complete', runId: 'clean-b' }), releaseKey)
    await signAttestation(artifact, attDoc({ observed: ['process.exec'], coverage: 'complete', runId: 'risk-c' }), releaseKey)

    const result = await evaluate(artifact)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.evidenceTrust.attestation).toBe('AMBIGUOUS')
    // the two "clean" runs collapse to ONE semantic candidate — the risky one is
    // a second, non-equivalent candidate → AMBIGUOUS (2 vs 1 never wins)
    expect(result.verdict.errors.join('; ')).toContain('AMBIGUOUS')
    expect(result.verdict.errors.join('; ')).not.toContain('ALLOW')
  })
})
