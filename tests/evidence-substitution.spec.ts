/**
 * v0.5.0-rc.1 — N4 Evidence Substitution (D119–D123 freeze):
 *
 * Can a "validly-signed but wrong" evidence (wrong artifact, wrong document,
 * wrong issuer, wrong type, wrong origin) sneak into the collection and fool
 * the Trust Policy?
 *
 *   D119 Evidence subject binding is mandatory
 *   D120 Evidence document digest must match signed statement
 *   D121 Untrusted evidence can never override trusted evidence
 *   D122 Evidence type substitution is forbidden
 *   D123 Missing/invalid/ambiguous evidence fails closed
 *
 * Invariants under test (every evidence type):
 *
 *   Wrong subject    → NEVER trusted
 *   Wrong document   → NEVER trusted
 *   Wrong issuer     → NEVER trusted
 *
 * RC-N4 North-Star: a POLLUTED collection (trusted + attacker evidence mixed)
 * must be evaluated on the trusted, subject-bound, digest-valid evidence only
 * — an attacker's "cleaner-looking" evidence can never flip a DENY to ALLOW.
 *
 * N4 tests substitution only; N5 (two trusted-but-conflicting evidences) is
 * deliberately NOT implemented here — scope discipline.
 */
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair, signPackFile } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultPackager } from '../src/service.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import type { DependencyTree } from '../src/types.js'

const DSH_VERSION = '0.1.0-rc.5'
const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n4-${label}-`))
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

async function makePack(profileName: string): Promise<Buffer> {
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: profileName },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: DSH_VERSION, nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: [], dependencies: {},
    configHash: computeConfigHash({ rows: [] }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({ name: `${profileName}-profile`, version: '1.0.0', private: true, dependencies: {} }) },
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

// --- fixture builders: signed artifact + evidence collection ---

interface ArtifactFixture {
  /** Signed pack file path. */
  packFile: string
  /** Release key fingerprint (artifact signer + trusted evidence issuer). */
  keyId: string
  /** Evidence collection root for THIS artifact (`<pack>.dshpack.evidence`). */
  collectionRoot: string
}

/** Sign a pack with a fresh release key and return the signed file path + keyId. */
async function signWithFreshKey(root: string, name: string): Promise<{ privateKey: string; keyId: string }> {
  const key = generateKeypair(join(root, name))
  return { privateKey: key.privateKey, keyId: key.keyId }
}

/**
 * A standard attestation document for `contentHash`-agnostic fixtures.
 * `observed` entries land in observed.providers (like the T-series fixtures).
 */
function attestationDoc(opts: { observed?: string[]; coverage?: string; os?: string; arch?: string } = {}): string {
  return JSON.stringify({
    schemaVersion: 1, subject: { contentHash: 'ignored' },
    metadata: { observedAt: '2026-08-30T00:00:00Z', runId: 'n4' },
    coldBoot: { status: 'PASS' },
    observation: { coverage: opts.coverage ?? 'complete', reasons: [] },
    observed: { tools: [], skills: [], services: [], providers: opts.observed ?? [] },
    comparison: { declaredButNotObserved: [], observedButNotDeclared: [], authoritative: false },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { dsh: 'x', node: 'x', os: opts.os ?? 'linux', arch: opts.arch ?? 'x64' },
    resultDigest: 'sha256:' + 'b'.repeat(64),
  })
}

/** Write an attestation document into the collection and return its hex digest. */
function writeAttestationDoc(collectionRoot: string, docText: string): string {
  const hex = sha256Hex(docText)
  const docFile = join(collectionRoot, 'documents', `${hex}.attestation.json`)
  mkdirSync(dirname(docFile), { recursive: true })
  writeFileSync(docFile, docText)
  return hex
}

interface EvidenceSpec {
  type: 'build-provenance' | 'sbom' | 'attestation'
  statement: Record<string, unknown>
  key: string
  /** Attestation only: the document text to bind (written + digest-matched). */
  docText?: string
}

/** Sign one evidence envelope against `packFile` (subject = its contentHash). */
async function signEvidence(packFile: string, spec: EvidenceSpec): Promise<void> {
  const evidence = new DefaultEvidenceService()
  if (spec.type === 'attestation') {
    if (spec.docText === undefined) throw new Error('attestation evidence requires docText')
    const collectionRoot = join(dirname(packFile), `${basename(packFile, '.dshpack')}.dshpack.evidence`)
    const docHex = writeAttestationDoc(collectionRoot, spec.docText)
    await evidence.sign(packFile, {
      type: 'attestation',
      statement: {
        format: 'dsh-attestation', schemaVersion: 1,
        attestationDigest: { algorithm: 'sha256', value: docHex },
        ...spec.statement,
      },
      key: spec.key,
    })
  } else {
    await evidence.sign(packFile, { type: spec.type, statement: spec.statement, key: spec.key })
  }
}

/**
 * Build artifact A (or B): signed pack + full trusted evidence collection
 * (provenance build-time, sbom, attestation linux/x64 observed=[]).
 * Returns everything needed to attack it.
 */
async function buildArtifact(
  root: string, label: string,
  opts: { observed?: string[]; evidenceKey?: string } = {},
): Promise<ArtifactFixture> {
  const dir = join(root, label)
  mkdirSync(dir, { recursive: true })
  const packFile = join(dir, 'app.dshpack')
  writeFileSync(packFile, await makePack(label))
  const key = generateKeypair(join(dir, 'release'))
  const signed = await signPackFile(packFile, { key: key.privateKey })
  const evidenceKey = opts.evidenceKey ?? key.privateKey
  await signEvidence(signed.file, {
    type: 'build-provenance',
    statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/company/app' } },
    key: evidenceKey,
  })
  await signEvidence(signed.file, {
    type: 'sbom',
    statement: { format: 'cyclonedx', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: 'a'.repeat(64) } },
    key: evidenceKey,
  })
  await signEvidence(signed.file, {
    type: 'attestation',
    statement: {},
    docText: attestationDoc({ observed: opts.observed }),
    key: evidenceKey,
  })
  const collectionRoot = join(dirname(signed.file), `${basename(signed.file, '.dshpack')}.dshpack.evidence`)
  return { packFile: signed.file, keyId: key.keyId, collectionRoot }
}

const POLICY = (releaseKeyId: string, extra: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${releaseKeyId}"
    requireEvidence:
      provenance:
        origin: build-time
      sbom: true
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${releaseKeyId}"
${extra}
`

/**
 * Evaluate policy on an artifact with a REAL v2 trust.yaml (release key =
 * artifact signer + trusted evidence issuer), pointing at an ARBITRARY
 * collection root. Without the trust.yaml the engine sees a permissive empty
 * policy and ANY evidence would ALLOW — that would make the substitution
 * tests vacuous. Pass `policyYaml` to override the default (e.g. denyObserved).
 */
async function evaluate(artifact: ArtifactFixture, opts: { collectionRoot?: string; repository?: string; policyYaml?: string } = {}) {
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
      provenance:
        origin: build-time
      sbom: true
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
    collectionDir: opts.collectionRoot ?? artifact.collectionRoot,
    executionTarget: { os: 'linux', arch: 'x64' },
  })
}

// ============================================================
// N4.1–N4.3 — cross-artifact substitution (D119: wrong subject → NEVER trusted)
// ============================================================

/** Read the (deterministically first) envelope file of a type in a collection. */
function readEnvelopeFile(collectionRoot: string, type: string): string {
  const dir = join(collectionRoot, type)
  const file = readdirSync(dir).filter((n) => n.endsWith('.json')).sort()[0]
  if (file === undefined) throw new Error(`no envelope in ${dir}`)
  return readFileSync(join(dir, file), 'utf8')
}

/**
 * SUBSTITUTE: remove every envelope of `type` from the target collection and
 * plant a single attacker-supplied envelope there instead. This is the real
 * attack — a wrong-but-validly-signed evidence REPLACING the artifact's own.
 */
function substituteEnvelope(collectionRoot: string, type: string, envelopeText: string): void {
  const dir = join(collectionRoot, type)
  mkdirSync(dir, { recursive: true })
  for (const name of readdirSync(dir)) {
    if (name.endsWith('.json')) rmSync(join(dir, name), { force: true })
  }
  writeFileSync(join(dir, 'from-b.json'), envelopeText)
}

describe('N4.1–N4.3: cross-artifact substitution — Artifact B evidence vs Artifact A', () => {
  it('N4.1: provenance from Artifact B is never trusted for Artifact A', async () => {
    const root = tempRoot('n41')
    const artifactA = await buildArtifact(root, 'artifact-a')
    const artifactB = await buildArtifact(root, 'artifact-b')

    // REPLACE A's provenance with B's (VALID + TRUSTED key, but subject = B)
    substituteEnvelope(artifactA.collectionRoot, 'build-provenance', readEnvelopeFile(artifactB.collectionRoot, 'build-provenance'))

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    // B's provenance must fail subject binding → no trusted provenance →
    // origin cannot be evaluated → source cannot consume it
    const reasons = result.verdict.errors.join('; ')
    expect(reasons).toContain('no provenance candidate passed envelope + subject verification')
  })

  it('N4.2: SBOM from Artifact B is never trusted for Artifact A', async () => {
    const root = tempRoot('n42')
    const artifactA = await buildArtifact(root, 'artifact-a')
    const artifactB = await buildArtifact(root, 'artifact-b')

    substituteEnvelope(artifactA.collectionRoot, 'sbom', readEnvelopeFile(artifactB.collectionRoot, 'sbom'))

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('no sbom candidate passed envelope + subject verification')
  })

  it('N4.3: runtime attestation from Artifact B is never trusted for Artifact A', async () => {
    const root = tempRoot('n43')
    const artifactA = await buildArtifact(root, 'artifact-a')
    const artifactB = await buildArtifact(root, 'artifact-b')

    substituteEnvelope(artifactA.collectionRoot, 'attestation', readEnvelopeFile(artifactB.collectionRoot, 'attestation'))

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('no attestation candidate passed envelope + subject + document verification')
  })

  it('N4.1–N4.3 baseline: a clean collection still ALLOWs (the attacks above are real attacks, not over-blocking)', async () => {
    const root = tempRoot('n41base')
    const artifactA = await buildArtifact(root, 'artifact-a')
    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('ALLOW')
  })
})

// ============================================================
// N4.5 — attacker-signed clean evidence (D109/D121: untrusted never overrides)
// ============================================================

describe('N4.5: attacker-signed clean evidence cannot override trusted bad evidence', () => {
  const DENY_PROCESS_EXEC = (keyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
    requireEvidence:
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${keyId}"
    capabilities:
      denyObserved:
        - process.exec
`

  it('trusted attestation observing process.exec still DENYs even with an attacker clean attestation present', async () => {
    const root = tempRoot('n45')
    // TRUSTED attestation sees process.exec (bad news the policy must honor)
    const artifactA = await buildArtifact(root, 'artifact-a', { observed: ['process.exec'] })

    // attacker adds a CLEAN attestation (observed=[]) — VALID, subject=A, but
    // signed by a key NOT in evidenceTrustedKeys → must be filtered (D121)
    const attacker = generateKeypair(join(root, 'attacker'))
    const attDir = join(artifactA.collectionRoot, 'attestation')
    await signEvidence(artifactA.packFile, {
      type: 'attestation',
      statement: { coverage: 'complete' },
      docText: attestationDoc({ observed: [] }), // the "cleaner" story
      key: attacker.privateKey,
    })

    const result = await evaluate(artifactA, { policyYaml: DENY_PROCESS_EXEC(artifactA.keyId) })
    expect(result.verdict.decision).toBe('DENY')
    // the attacker evidence must not flip the verdict: trusted process.exec wins
    const reasons = result.verdict.errors.join('; ')
    expect(reasons).toContain('process.exec')
  })

  it('N4.5 baseline: without the trusted process.exec observation the same policy ALLOWs (the attack above is real, not over-blocking)', async () => {
    const root = tempRoot('n45base')
    const artifactA = await buildArtifact(root, 'artifact-a') // observed=[] (clean)
    const result = await evaluate(artifactA, { policyYaml: DENY_PROCESS_EXEC(artifactA.keyId) })
    expect(result.verdict.decision).toBe('ALLOW')
  })
})

// ============================================================
// N4.6 — evidence type confusion (D122: type cannot be faked by path/field)
// ============================================================

describe('N4.6: evidence type confusion', () => {
  it('a provenance envelope dropped into the attestation/ dir is NOT an attestation', async () => {
    const root = tempRoot('n46a')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // attacker renames a valid build-provenance envelope into the attestation dir
    const provText = readEnvelopeFile(artifactA.collectionRoot, 'build-provenance')
    substituteEnvelope(artifactA.collectionRoot, 'attestation', provText)
    // also remove the real attestation doc so nothing else lingers
    const docsDir = join(artifactA.collectionRoot, 'documents')
    for (const name of readdirSync(docsDir)) {
      if (name.endsWith('.attestation.json')) rmSync(join(docsDir, name), { force: true })
    }

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    // the renamed provenance envelope must NOT be accepted as attestation
    // (scanEnvelopes filters by envelope.type === dir type)
    expect(result.verdict.errors.join('; ')).toContain('runtime attestation required but absent')
  })

  it('an sbom-typed envelope whose statement is provenance-shaped is rejected', async () => {
    const root = tempRoot('n46b')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // attacker signs an envelope typed 'sbom' but whose statement carries
    // provenance fields (capture.mode) instead of an sbomDigest
    const attacker = generateKeypair(join(root, 'attacker'))
    const sbomDir = join(artifactA.collectionRoot, 'sbom')
    for (const name of readdirSync(sbomDir)) {
      if (name.endsWith('.json')) rmSync(join(sbomDir, name), { force: true })
    }
    await signEvidence(artifactA.packFile, {
      type: 'sbom',
      statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/evil/hook' } },
      key: attacker.privateKey,
    })

    const result = await evaluate(artifactA)
    // the forged sbom has no sbomDigest → not a valid sbom candidate; the real
    // sbom was removed → fail closed
    expect(result.verdict.decision).toBe('DENY')
  })
})

// ============================================================
// N4.7 — post-build endorsement cannot satisfy a build-time requirement (D101)
// ============================================================

describe('N4.7: post-build endorsement cannot satisfy build-time provenance', () => {
  it('provenance with capture.mode=post-build-receipt fails origin: build-time', async () => {
    const root = tempRoot('n47')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // REPLACE the trusted build-time provenance with a VALID trusted post-build
    // endorsement (same release key, same subject — but wrong capture mode)
    const provDir = join(artifactA.collectionRoot, 'build-provenance')
    for (const name of readdirSync(provDir)) {
      if (name.endsWith('.json')) rmSync(join(provDir, name), { force: true })
    }
    // sign with the SAME trusted key so issuer is not the failing step
    const trustedKey = join(dirname(artifactA.packFile), 'release', 'dsh-pack-private.pem')
    await signEvidence(artifactA.packFile, {
      type: 'build-provenance',
      statement: { capture: { mode: 'post-build-receipt' }, source: { repository: 'github.com/company/app' } },
      key: trustedKey,
    })

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('does not satisfy required')
  })
})

// ============================================================
// N4.9 — collection pollution (junk/malformed never alters the verdict)
// ============================================================

describe('N4.9: collection pollution does not alter the trusted verdict', () => {
  it('junk JSON + malformed JSON + foreign envelopes in every dir are ignored', async () => {
    const root = tempRoot('n49')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // pollute every evidence dir with junk (valid JSON, not an envelope),
    // malformed JSON, and a foreign envelope type
    for (const type of ['build-provenance', 'sbom', 'attestation']) {
      const dir = join(artifactA.collectionRoot, type)
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, 'junk.json'), JSON.stringify({ hello: 'world' }))
      writeFileSync(join(dir, 'malformed.json'), '{ this is not json !!!')
      writeFileSync(join(dir, 'foreign.json'), JSON.stringify({
        schemaVersion: 1, type: 'attestation', // wrong type for this dir
        subject: { contentHash: 'sha256:' + 'f'.repeat(64) },
        statementDigest: 'sha256:' + 'f'.repeat(64),
        statement: {}, signing: { algorithm: 'ed25519', keyId: 'f'.repeat(64), publicKey: '', signature: '' },
      }))
    }

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('ALLOW')
    // junk must never become a candidate: evidence trust is still VERIFIED
    expect(result.verdict.evidenceTrust).toEqual({ provenance: 'VERIFIED', sbom: 'VERIFIED', attestation: 'VERIFIED' })
  })

  it('malformed REQUIRED evidence fails closed (D123)', async () => {
    const root = tempRoot('n49b')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // corrupt the ONLY attestation envelope → required evidence now invalid
    const attDir = join(artifactA.collectionRoot, 'attestation')
    const attName = readdirSync(attDir).find((n) => n.endsWith('.json'))!
    writeFileSync(join(attDir, attName), '{ corrupted !!!')

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('runtime attestation required but absent')
  })
})

// ============================================================
// N4.10 — deterministic candidate selection (D110: no first/latest wins)
// ============================================================

describe('N4.10: candidate order / file rename does not alter the result', () => {
  it('renaming envelope files (lexicographic order change) keeps the verdict identical', async () => {
    const root = tempRoot('n410')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // capture the reference verdict
    const before = await evaluate(artifactA)
    expect(before.verdict.decision).toBe('ALLOW')

    // rename every envelope file so directory order flips
    for (const type of ['build-provenance', 'sbom', 'attestation']) {
      const dir = join(artifactA.collectionRoot, type)
      const names = readdirSync(dir).filter((n) => n.endsWith('.json')).sort()
      for (const name of names) {
        const content = readFileSync(join(dir, name), 'utf8')
        rmSync(join(dir, name), { force: true })
        writeFileSync(join(dir, `zz-renamed-${name}`), content)
      }
    }

    const after = await evaluate(artifactA)
    expect(after.verdict.decision).toBe('ALLOW')
    expect(after.verdict.errors).toEqual(before.verdict.errors)
  })

  it('duplicating an IDENTICAL envelope does not create ambiguity (statement-equivalent)', async () => {
    const root = tempRoot('n410b')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // copy the sbom envelope under a second name — same statementDigest →
    // semantically the same document → NOT ambiguous (D110 equivalence)
    const sbomText = readEnvelopeFile(artifactA.collectionRoot, 'sbom')
    writeFileSync(join(artifactA.collectionRoot, 'sbom', 'duplicate.json'), sbomText)

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('ALLOW')
  })
})

// ============================================================
// RC-N4 North-Star — a POLLUTED collection is evaluated on trusted,
// subject-bound, digest-valid evidence only
// ============================================================

describe('RC-N4 North-Star: polluted collection — trusted process.exec still DENYs', () => {
  const NORTH_STAR_POLICY = (keyId: string): string => `version: 2
registries:
  "ghcr.io/company/*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - "SHA256:${keyId}"
    requireEvidence:
      provenance:
        origin: build-time
      sbom: true
      runtimeAttestation:
        required: true
        coverage: complete
    evidenceTrustedKeys:
      - "SHA256:${keyId}"
    capabilities:
      denyObserved:
        - process.exec
`

  it('trusted bad evidence wins over attacker clean / B-substituted evidence', async () => {
    const root = tempRoot('n4ns')
    // artifact A with TRUSTED attestation observing process.exec
    const artifactA = await buildArtifact(root, 'artifact-a', { observed: ['process.exec'] })
    const artifactB = await buildArtifact(root, 'artifact-b')
    const attacker = generateKeypair(join(root, 'attacker'))

    // ---- pollute the collection (the user's exact North-Star layout) ----
    // provenance/: trusted-good (already there) + attacker-fake (different
    // statement → distinct digest, coexists; issuer-filtered by policy)
    await signEvidence(artifactA.packFile, {
      type: 'build-provenance',
      statement: { capture: { mode: 'build-time' }, source: { repository: 'github.com/evil/hook' } },
      key: attacker.privateKey,
    })
    // sbom/: trusted-good (already there) + artifact-B substitution
    const bSbom = readEnvelopeFile(artifactB.collectionRoot, 'sbom')
    writeFileSync(join(artifactA.collectionRoot, 'sbom', 'artifact-b.json'), bSbom)
    // runtime-attestation/: trusted-bad (already there) + attacker-clean
    await signEvidence(artifactA.packFile, {
      type: 'attestation',
      statement: { coverage: 'complete' },
      docText: attestationDoc({ observed: [] }), // attacker's "cleaner" story
      key: attacker.privateKey,
    })

    const result = await evaluate(artifactA, { policyYaml: NORTH_STAR_POLICY(artifactA.keyId) })
    expect(result.verdict.decision).toBe('DENY')
    // the verdict comes from the TRUSTED process.exec attestation — attacker
    // clean evidence never flips it to ALLOW
    const reasons = result.verdict.errors.join('; ')
    expect(reasons).toContain('process.exec')
    // the attacker-fake provenance + B-substituted sbom were filtered, so the
    // trusted evidence is what produced the DENY
    expect(result.verdict.evidenceTrust.attestation).toBe('VERIFIED')
    expect(result.verdict.evidenceTrust.provenance).toBe('VERIFIED')
    expect(result.verdict.evidenceTrust.sbom).toBe('VERIFIED')
  })
})

describe('N4.4: document digest substitution', () => {
  it('attestation document replaced with different content → digest mismatch → DENY', async () => {
    const root = tempRoot('n44a')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // overwrite the attestation document with DIFFERENT content (same file name)
    // — the envelope still points at the original digest
    const docsDir = join(artifactA.collectionRoot, 'documents')
    const docName = readdirSync(docsDir).find((n) => n.endsWith('.attestation.json'))!
    const replaced = attestationDoc({ observed: ['cleaner-observation'] }) // different bytes
    writeFileSync(join(docsDir, docName), replaced)

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('no attestation candidate passed envelope + subject + document verification')
  })

  it('SBOM document replaced with different content → digest mismatch → DENY (D120)', async () => {
    const root = tempRoot('n44b')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // plant a document file under the digest the envelope claims, with the
    // WRONG bytes (does not hash to the claimed digest)
    const claim = 'a'.repeat(64)
    const docsDir = join(artifactA.collectionRoot, 'documents')
    mkdirSync(docsDir, { recursive: true })
    writeFileSync(join(docsDir, `${claim}.cdx.json`), JSON.stringify({ bomFormat: 'CycloneDX', version: 1, components: [] }))

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('sbom')
  })
})

// ============================================================
// N4.8 — statement field tamper (D123: invalid evidence fails closed)
// ============================================================

describe('N4.8: statement field tamper', () => {
  it('tampered statement WITHOUT re-signing → statementDigest mismatch → DENY', async () => {
    const root = tempRoot('n48a')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // tamper the attestation ENVELOPE statement (coverage complete→partial) but
    // keep the original signature + statementDigest → self-integrity FAIL
    const attDir = join(artifactA.collectionRoot, 'attestation')
    const attName = readdirSync(attDir).find((n) => n.endsWith('.json'))!
    const envelope = JSON.parse(readFileSync(join(attDir, attName), 'utf8'))
    envelope.statement.coverage = 'partial' // field-level tamper, no re-sign
    writeFileSync(join(attDir, attName), JSON.stringify(envelope))

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('no attestation candidate passed envelope + subject + document verification')
  })

  it('tampered statement re-signed with an UNTRUSTED key → issuer DENY', async () => {
    const root = tempRoot('n48b')
    const artifactA = await buildArtifact(root, 'artifact-a')

    // REPLACE the trusted attestation with an attacker-signed one (subject stays
    // A, signature VALID, but issuer NOT in evidenceTrustedKeys → D109)
    const attacker = generateKeypair(join(root, 'attacker'))
    const attDir = join(artifactA.collectionRoot, 'attestation')
    for (const name of readdirSync(attDir)) {
      if (name.endsWith('.json')) rmSync(join(attDir, name), { force: true })
    }
    const docText = attestationDoc({ observed: [] })
    await signEvidence(artifactA.packFile, {
      type: 'attestation',
      statement: { coverage: 'complete' },
      docText,
      key: attacker.privateKey,
    })

    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('DENY')
    expect(result.verdict.errors.join('; ')).toContain('UNTRUSTED_EVIDENCE_ISSUER')
  })

  it('N4.8 baseline: an untouched envelope still verifies (attacks are real, not over-blocking)', async () => {
    const root = tempRoot('n48base')
    const artifactA = await buildArtifact(root, 'artifact-a')
    const result = await evaluate(artifactA)
    expect(result.verdict.decision).toBe('ALLOW')
  })
})

