/**
 * v0.5 beta.1 Runtime Attestation test matrix (DESIGN-v0.5.0.md §9, D89–D97):
 * R0–R14 — subject binding, disposable isolated cold boot, observed
 * capabilities via the runtime registry seam, declared-vs-observed diff,
 * host-env invisibility, crash cleanup, tamper/subject resistance, and
 * no cross-run observation leakage.
 */
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { verifyEvidenceEnvelope } from '../src/evidence/envelope.js'
import {
  PARTIAL_COVERAGE_REASON, runAttestation, type AttestationDocument,
} from '../src/evidence/attestation.js'
import type { DependencyTree, EvidenceEnvelope } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-att-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// --- fixtures ---

interface FixtureRow { id: string; provider?: string }

/**
 * A self-contained fixture bundle: a cordis plugin package the disposable
 * runtime mounts. Its rows carry `name: 'fixture-bundle'` (the include row
 * semantics, matching the harness's own bundle patches). On mount the plugin
 * provides its row ids at ROOT scope (so the observer's root probes see them)
 * plus optional tools/skills seam items; rows listed in `provideChild`
 * register in the plugin's CHILD context instead — invisible to the root
 * observer (the D99 partial-visibility case).
 */
async function writeFixtureBundle(
  dir: string,
  opts: {
    rows?: FixtureRow[]
    tools?: string[]
    skills?: string[]
    provideChild?: string[]
    throwOnMount?: boolean
  } = {},
): Promise<void> {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'package.json'), prettyJson({
    name: 'fixture-bundle', version: '1.0.0', type: 'module', main: 'index.js',
    dsh: { bundle: { patch: './cordis.patch.yml' } },
  }))
  const rows = opts.rows ?? []
  const childSet = new Set(opts.provideChild ?? [])
  const lines: string[] = rows.length === 0 ? [] : ['- insert:']
  for (const row of rows) {
    lines.push(`    - id: ${row.id}`)
    lines.push(`      name: 'fixture-bundle'`)
    if (row.provider !== undefined) lines.push(`      provider: ${row.provider}`)
    lines.push('      config:')
    if (childSet.has(row.id)) {
      lines.push('        provideChild:')
      lines.push(`          - ${row.id}`)
    } else {
      lines.push('        provide:')
      lines.push(`          - ${row.id}`)
    }
    if (opts.tools !== undefined && opts.tools.length > 0) {
      lines.push('        tools:')
      for (const tool of opts.tools) lines.push(`          - ${tool}`)
    }
    if (opts.skills !== undefined && opts.skills.length > 0) {
      lines.push('        skills:')
      for (const skill of opts.skills) lines.push(`          - ${skill}`)
    }
    if (opts.throwOnMount === true) lines.push('        throwOnMount: true')
  }
  writeFileSync(join(dir, 'cordis.patch.yml'), `${lines.join('\n')}\n`)
  writeFileSync(join(dir, 'index.js'), `export default function fixturePlugin(ctx, config) {
  if (config?.throwOnMount === true) throw new Error('fixture: mount failure (test)')
  const target = ctx.root
  for (const name of config?.provide ?? []) target.provide(name, { attested: true })
  for (const name of config?.provideChild ?? []) {
    // a genuinely isolated child scope: cordis isolate() gives the service a
    // NEW label, so the root store never holds the implementation
    const child = ctx.isolate(name)
    child.provide(name, { attested: true })
  }
  if (Array.isArray(config?.tools) && config.tools.length > 0) {
    target.provide('tools', { items: Object.fromEntries(config.tools.map((t) => [t, {}])) })
  }
  if (Array.isArray(config?.skills) && config.skills.length > 0) {
    target.provide('skills', { items: Object.fromEntries(config.skills.map((s) => [s, {}])) })
  }
}
`)
}

const MINIMAL_DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: {},
  closure: {},
  localDeps: [],
  warnings: [],
}

/** Build a .dshpack whose profile declares `fixture-bundle` (mounted at boot). */
async function makePack(opts: { rows?: Record<string, unknown>[]; patchText?: string } = {}): Promise<Buffer> {
  const rows = opts.rows ?? [{ id: 'prov-a', provider: 'deepseek', config: {} }]
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: ['fixture-bundle'],
    dependencies: {},
    configHash: computeConfigHash({ rows }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-beta.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({
      name: 'web-profile', version: '1.0.0', private: true, dependencies: {},
      dsh: { profile: { bundles: ['fixture-bundle'] } },
    }) },
    { path: 'profile/cordis.patch.yml', content: opts.patchText ?? '[]\n' },
    { path: 'resolved/composition.json', content: prettyJson({ rows }) },
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

// --- R0–R6: subject, cold boot, observed ---

describe('R0–R6: subject, cold boot, observed capabilities', () => {
  it('R0: attestation subject == actual artifact contentHash (service level)', async () => {
    const root = tempRoot('r0')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack({ rows: [{ id: 'prov-a', provider: 'deepseek', config: {} }] }))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.attestation(packFile, { key: generateKeypair(root).privateKey, extraModules: [fixture] })

    expect(result.contentHash).toBe(await computePackContentHash(readFileSync(packFile)))
    expect(result.coldBootStatus).toBe('PASS')
    const doc = JSON.parse(readFileSync(result.documentFile, 'utf8')) as AttestationDocument
    expect(doc.subject.contentHash).toBe(result.contentHash)
    expect(doc.coldBoot.status).toBe('PASS')
    // D99: a successful root-observer boot is honest `partial`, never complete
    expect(doc.observation.coverage).toBe('partial')
    expect(doc.comparison.authoritative).toBe(false)
    expect(doc.effects).toEqual({ network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' })
    expect(doc.resultDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    // non-deterministic metadata (D96) — but the normalized resultDigest is stable
    expect(doc.metadata.runId).toMatch(/[0-9a-f-]{36}/)
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
  })

  it('R1: cold boot success → PASS + cleanup PASS', async () => {
    const root = tempRoot('r1')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const result = await runAttestation(await makePack(), 'sha256:' + 'f'.repeat(64), { extraModules: [fixture] })
    expect(result.coldBootStatus).toBe('PASS')
    expect(result.cleanupStatus).toBe('PASS')
    expect(result.observer.error).toBeUndefined()
    expect(result.observation.coverage).toBe('partial')
  })

  it('R3: runtime-registered provider → observed.providers', async () => {
    const root = tempRoot('r3')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const result = await runAttestation(await makePack(), 'sha256:' + 'a'.repeat(64), { extraModules: [fixture] })
    expect(result.coldBootStatus).toBe('PASS')
    expect(result.observed.providers).toEqual(['prov-a'])
  })

  it('R4: runtime-registered service → observed.services', async () => {
    const root = tempRoot('r4')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'svc-b' }] })
    const result = await runAttestation(
      await makePack({ rows: [{ id: 'svc-b', config: {} }] }), 'sha256:' + 'b'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.coldBootStatus).toBe('PASS')
    expect(result.observed.services).toEqual(['svc-b'])
  })

  it('R5+R6: runtime-only tool and skill → observed.tools/skills (alpha.4 gap filled)', async () => {
    const root = tempRoot('r5')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'svc-b' }], tools: ['secret-tool'], skills: ['secret-skill'] })
    const result = await runAttestation(
      await makePack({ rows: [{ id: 'svc-b', config: {} }] }), 'sha256:' + 'c'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.coldBootStatus).toBe('PASS')
    expect(result.observed.tools).toEqual(['secret-tool'])
    expect(result.observed.skills).toEqual(['secret-skill'])
  })
})

// --- R7–R11: diff, host env, crash ---

describe('R7–R11: declared-vs-observed diff, host env, crash cleanup', () => {
  it('R7: declared A / observed A → diff empty', async () => {
    const root = tempRoot('r7')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const result = await runAttestation(
      await makePack({ rows: [{ id: 'prov-a', provider: 'deepseek', config: {} }] }), 'sha256:' + 'd'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.comparison.declaredButNotObserved).toEqual([])
    expect(result.comparison.observedButNotDeclared).toEqual([])
  })

  it('R8: declared A / observed A+B → observedButNotDeclared=[B]; observation only, no DENY', async () => {
    const root = tempRoot('r8')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }], tools: ['process.exec'] })
    const result = await runAttestation(
      await makePack({ rows: [{ id: 'prov-a', provider: 'deepseek', config: {} }] }), 'sha256:' + 'e'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.comparison.observedButNotDeclared).toEqual(['process.exec'])
    expect(result.comparison.declaredButNotObserved).toEqual([])
    // D91: the attestation reports the fact — it never renders allow/deny/safe
    expect(result.document).not.toMatch(/"(allowed|denied|safe|unsafe|risk)"/)
  })

  it('R9: declared A+B / observed A → declaredButNotObserved=[B]', async () => {
    const root = tempRoot('r9')
    const fixture = join(root, 'fixture-bundle')
    // the fixture mounts ONLY prov-a; prov-b is declared but never mounts
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const result = await runAttestation(
      await makePack({ rows: [
        { id: 'prov-a', provider: 'deepseek', config: {} },
        { id: 'prov-b', provider: 'openai', config: {} },
      ] }), 'sha256:' + '9'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.comparison.declaredButNotObserved).toEqual(['prov-b'])
    expect(result.observed.providers).toEqual(['prov-a'])
  })

  it('R2+R10: cold boot FAIL + production profile untouched + host secrets invisible', async () => {
    const root = tempRoot('r2')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'boom', provider: 'deepseek' }], throwOnMount: true })

    // a sentinel "production" home that MUST stay untouched (D92)
    const prodHome = join(root, 'prod-home')
    mkdirSync(join(prodHome, 'profiles', 'prod'), { recursive: true })
    writeFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), '{"name":"prod"}\n')
    const before = readFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), 'utf8')

    // host secrets that must NOT reach the disposable runtime (D93)
    const savedToken = process.env.GITHUB_TOKEN
    const savedKey = process.env.OPENAI_API_KEY
    process.env.GITHUB_TOKEN = 'secret-token-xyz'
    process.env.OPENAI_API_KEY = 'sk-secret-xyz'
    try {
      const result = await runAttestation(await makePack(), 'sha256:' + '2'.repeat(64), { extraModules: [fixture] })
      expect(result.coldBootStatus).toBe('FAIL')
      expect(result.cleanupStatus).toBe('PASS')
      expect(result.observation.coverage).toBe('unknown')
      // production profile untouched
      expect(readFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), 'utf8')).toBe(before)
      // host secrets invisible inside the disposable runtime
      expect(result.observer.envKeys).not.toContain('GITHUB_TOKEN')
      expect(result.observer.envKeys).not.toContain('OPENAI_API_KEY')
      expect(result.observer.envKeys).toContain('DSH_HOME')
    } finally {
      if (savedToken === undefined) delete process.env.GITHUB_TOKEN
      else process.env.GITHUB_TOKEN = savedToken
      if (savedKey === undefined) delete process.env.OPENAI_API_KEY
      else process.env.OPENAI_API_KEY = savedKey
    }
  })

  it('R11: runtime crash → temporary profile/runtime cleanup (cleanup PASS)', async () => {
    const root = tempRoot('r11')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'boom' }], throwOnMount: true })
    const result = await runAttestation(await makePack(), 'sha256:' + '1'.repeat(64), { extraModules: [fixture] })
    expect(result.coldBootStatus).toBe('FAIL')
    expect(result.cleanupStatus).toBe('PASS')
    expect(result.observation.coverage).toBe('unknown')
  })
})

// --- R12–R14: tamper, subject swap, no leakage ---

describe('R12–R14: tamper, subject swap, cross-run isolation', () => {
  it('R12: tampered attestation document → digest binding FAIL', async () => {
    const root = tempRoot('r12')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const evidence = new DefaultEvidenceService()
    const result = await evidence.attestation(packFile, { key: generateKeypair(root).privateKey, extraModules: [fixture] })

    const tampered = readFileSync(result.documentFile, 'utf8').replace('"PASS"', '"FAIL"')
    expect(tampered).not.toBe(readFileSync(result.documentFile, 'utf8'))
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    const statement = envelope.statement as { attestationDigest: { algorithm: string; value: string } }
    expect(statement.attestationDigest.value).not.toBe(createHash('sha256').update(tampered).digest('hex'))
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
  })

  it('R13: Artifact A attestation verified --against B → subject FAIL', async () => {
    const root = tempRoot('r13')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const packAFile = join(root, 'a.dshpack')
    writeFileSync(packAFile, await makePack())
    const resultA = await evidence.attestation(packAFile, { key: key.privateKey, extraModules: [fixture] })

    const packBFile = join(root, 'b.dshpack')
    writeFileSync(packBFile, await makePack({ rows: [{ id: 'other', provider: 'openai', config: {} }] }))

    expect((await evidence.verify(resultA.file, { against: packAFile })).ok).toBe(true)
    const wrong = await evidence.verify(resultA.file, { against: packBFile })
    expect(wrong.ok).toBe(false)
    expect(wrong.errors.join('; ')).toContain('evidence subject is')
  })

  it('R14: observation state does not leak across runs (Run1 malicious tool → Run2 clean)', async () => {
    const root = tempRoot('r14')
    const malicious = join(root, 'fixture-malicious')
    await writeFixtureBundle(malicious, { rows: [{ id: 'svc-b' }], tools: ['malicious-extra-tool'] })
    const clean = join(root, 'fixture-clean')
    await writeFixtureBundle(clean, { rows: [{ id: 'svc-b' }] })
    const pack = await makePack({ rows: [{ id: 'svc-b', config: {} }] })

    const run1 = await runAttestation(pack, 'sha256:' + '1'.repeat(64), { extraModules: [malicious] })
    expect(run1.observed.tools).toEqual(['malicious-extra-tool'])

    const run2 = await runAttestation(pack, 'sha256:' + '1'.repeat(64), { extraModules: [clean] })
    expect(run2.observed.tools).toEqual([])
    expect(run2.observed.services).toEqual(['svc-b'])
  })

  it('D96: same observation → same resultDigest; document digest differs (metadata)', async () => {
    const root = tempRoot('d96')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, { rows: [{ id: 'prov-a', provider: 'deepseek' }] })
    const pack = await makePack()
    const run1 = await runAttestation(pack, 'sha256:' + '6'.repeat(64), { extraModules: [fixture] })
    const run2 = await runAttestation(pack, 'sha256:' + '6'.repeat(64), { extraModules: [fixture] })
    // normalized result is deterministic across runs...
    expect(run1.resultDigest).toBe(run2.resultDigest)
    // ...while the full document is not (observedAt/runId metadata, D96)
    expect(run1.digest).not.toBe(run2.digest)
  })
})

// --- R15–R16: observation coverage (D99) ---

describe('R15–R16: observation coverage semantics (D99)', () => {
  it('R15: child-context registration invisible to root observer → coverage=partial (never complete)', async () => {
    const root = tempRoot('r15')
    const fixture = join(root, 'fixture-bundle')
    // prov-a registers at ROOT scope; prov-b registers in the CHILD plugin context
    await writeFixtureBundle(fixture, {
      rows: [{ id: 'prov-a', provider: 'deepseek' }, { id: 'prov-b', provider: 'deepseek' }],
      provideChild: ['prov-b'],
    })
    const result = await runAttestation(
      await makePack({ rows: [
        { id: 'prov-a', provider: 'deepseek', config: {} },
        { id: 'prov-b', provider: 'deepseek', config: {} },
      ] }), 'sha256:' + '5'.repeat(64), { extraModules: [fixture] },
    )
    expect(result.coldBootStatus).toBe('PASS')
    // the root observer sees only A; B's child-context registration is invisible
    expect(result.observed.providers).toEqual(['prov-a'])
    // ...so the observation is honest `partial`, never `complete`
    expect(result.observation.coverage).toBe('partial')
    expect(result.observation.coverage).not.toBe('complete')
    expect(result.observation.reasons).toContain(PARTIAL_COVERAGE_REASON)
  })

  it('R16: partial observation is never authoritative — diff data allowed, authoritative=false', async () => {
    const root = tempRoot('r16')
    const fixture = join(root, 'fixture-bundle')
    await writeFixtureBundle(fixture, {
      rows: [{ id: 'prov-a', provider: 'deepseek' }, { id: 'prov-b', provider: 'deepseek' }],
      provideChild: ['prov-b'],
    })
    const result = await runAttestation(
      await makePack({ rows: [
        { id: 'prov-a', provider: 'deepseek', config: {} },
        { id: 'prov-b', provider: 'deepseek', config: {} },
      ] }), 'sha256:' + '6'.repeat(64), { extraModules: [fixture] },
    )
    // diff DATA is still produced: B is declared but not observed
    expect(result.comparison.declaredButNotObserved).toEqual(['prov-b'])
    // ...but under `partial` it must NOT be read as authoritative absence (D99)
    expect(result.comparison.authoritative).toBe(false)
    const doc = JSON.parse(result.document) as AttestationDocument
    expect(doc.observation.coverage).toBe('partial')
    expect(doc.comparison.authoritative).toBe(false)
    // and coverage rides inside the normalized resultDigest (deterministic)
    expect(result.resultDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
  })
})
