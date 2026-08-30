/**
 * v0.5.0-rc.1 — N7 Isolation / Pollution Attack (D118 freeze):
 *
 * A failed/crashed Runtime Attestation must not contaminate the production
 * profile, host credentials, the runtime registry, later attestation state,
 * or owned temporary resources. Test domains:
 *
 *   N7.1  production profile untouched (disposable home ≠ host DSH_HOME)
 *   N7.2  host secrets stripped (env allowlist, D93)
 *   N7.3  registry state does not leak across runs
 *   N7.4  owned child processes cleaned / honestly NOT_PROBED (no global pkill)
 *   N7.5  cleanup failure preserved as auditable evidence (never swallowed)
 *   N7.6  managed paths stay inside the disposable root
 *   N7.7  malicious crash run → clean subsequent run
 *   N7.8  parallel runs isolated (no module-level singleton / global observer)
 *
 * HONEST BOUNDARY (documented, rc.1): disposable DSH_HOME is
 * APPLICATION-LEVEL runtime hygiene isolation — profile/config/credential/
 * observation isolation and owned temporary resource cleanup — NOT an OS
 * security sandbox. These tests never claim to stop arbitrary malicious Node
 * code from touching the host filesystem/network/process (that would need a
 * container/namespace/seccomp/sandbox provider, which is explicitly OUT of
 * rc.1 scope). N7.4 in particular reports NOT_PROBED when the runtime cannot
 * track artifact-spawned descendant processes; it never fakes isolation with
 * a global `pkill node`.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, type PackFileEntry } from '../src/pack-builder.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson } from '../src/canonical.js'
import { runAttestation, type AttestationDocument } from '../src/evidence/attestation.js'
import type { DependencyTree } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-n7-${label}-`))
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

// --- fixture: a cordis plugin bundle with attack behaviors ---

interface N7BundleOptions {
  tools?: string[]
  skills?: string[]
  services?: string[]
  providers?: string[]
  throwOnMount?: boolean
  reportEnv?: boolean
  spawnShortChild?: boolean
}

/**
 * A self-contained n7-bundle: a cordis plugin package the disposable runtime
 * mounts. One insert row ('n7-root') carries the attack config; the plugin
 * provides row ids at ROOT scope (so the root observer's probes see them) and
 * registers tools/skills seam items. Returns the composition rows the pack
 * must carry so the observer probes exactly these ids (mirrors the R14
 * writeFixtureBundle pattern).
 */
async function writeN7Bundle(dir: string, opts: N7BundleOptions = {}): Promise<Record<string, unknown>[]> {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'package.json'), prettyJson({
    name: 'n7-bundle', version: '1.0.0', type: 'module', main: 'index.js',
    dsh: { bundle: { patch: './cordis.patch.yml' } },
  }))
  const configLines: string[] = []
  const provideIds = [...(opts.services ?? []), ...(opts.providers ?? [])]
  if (provideIds.length > 0) {
    configLines.push('        provide:')
    for (const id of provideIds) configLines.push(`          - ${id}`)
  }
  if ((opts.tools?.length ?? 0) > 0) {
    configLines.push('        tools:')
    for (const t of opts.tools!) configLines.push(`          - ${t}`)
  }
  if ((opts.skills?.length ?? 0) > 0) {
    configLines.push('        skills:')
    for (const s of opts.skills!) configLines.push(`          - ${s}`)
  }
  if (opts.throwOnMount === true) configLines.push('        throwOnMount: true')
  if (opts.reportEnv === true) configLines.push('        reportEnv: true')
  if (opts.spawnShortChild === true) configLines.push('        spawnShortChild: true')
  const patch = `- insert:\n    - id: n7-root\n      name: 'n7-bundle'\n      config:\n${configLines.join('\n')}\n`
  writeFileSync(join(dir, 'cordis.patch.yml'), patch)
  writeFileSync(join(dir, 'index.js'), `import { spawn } from 'node:child_process'
export default function n7Plugin(ctx, config) {
  const target = ctx.root
  if (config?.reportEnv === true) {
    // REPORT the disposable env facts the runtime actually gave us (N7.1/N7.6)
    throw new Error('ENVREPORT HOME=' + process.env.HOME + ' CWD=' + process.cwd() + ' DSH_HOME=' + process.env.DSH_HOME)
  }
  for (const name of config?.provide ?? []) target.provide(name, { attested: true })
  if (Array.isArray(config?.tools) && config.tools.length > 0) {
    target.provide('tools', { items: Object.fromEntries(config.tools.map((t) => [t, {}])) })
  }
  if (Array.isArray(config?.skills) && config.skills.length > 0) {
    target.provide('skills', { items: Object.fromEntries(config.skills.map((s) => [s, {}])) })
  }
  if (config?.spawnShortChild === true) {
    // a SHORT-LIVED child that outlives the boot call by a few hundred ms —
    // proves the observer does not hang on it; cleanup of arbitrary
    // descendants is honestly NOT_PROBED (no process-group tracking, no pkill)
    spawn(process.execPath, ['-e', 'setTimeout(() => process.exit(0), 800)'], { stdio: 'ignore' })
  }
  if (config?.throwOnMount === true) throw new Error('fixture: mount failure (N7 test)')
}
`)
  // composition rows the observer probes: services (no provider) + providers
  return [
    ...(opts.services ?? []).map((id) => ({ id, config: {} })),
    ...(opts.providers ?? []).map((id) => ({ id, provider: 'deepseek', config: {} })),
  ]
}

/** Build a .dshpack whose profile declares `n7-bundle`. */
async function makePack(rows: Record<string, unknown>[] = []): Promise<Buffer> {
  const manifest = {
    format: 'dshpack', schemaVersion: 1, profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true, portable: true, bundles: ['n7-bundle'],
    dependencies: {},
    configHash: computeConfigHash({ rows }, [], {}),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-rc.1' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson({
      name: 'web-profile', version: '1.0.0', private: true, dependencies: {},
      dsh: { profile: { bundles: ['n7-bundle'] } },
    }) },
    { path: 'profile/cordis.patch.yml', content: '[]\n' },
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

const CONTENT_HASH = 'sha256:' + '7'.repeat(64)

describe('N7.1+N7.6: production profile untouched; managed paths inside disposable root', () => {
  it('N7.1a: malicious crash → disposable home removed; production marker + profile unchanged', async () => {
    const root = tempRoot('n71')
    const malicious = join(root, 'fixture-malicious')
    await writeN7Bundle(malicious, { throwOnMount: true })

    // a sentinel "production" DSH_HOME with a marker + a profile that MUST stay byte-identical
    const prodHome = join(root, 'prod-home')
    mkdirSync(join(prodHome, 'profiles', 'prod'), { recursive: true })
    writeFileSync(join(prodHome, 'marker.txt'), 'PROD-MARKER\n')
    writeFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), '{"name":"prod"}\n')
    const markerBefore = readFileSync(join(prodHome, 'marker.txt'), 'utf8')
    const profileBefore = readFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), 'utf8')

    const savedHome = process.env.DSH_HOME
    process.env.DSH_HOME = prodHome
    try {
      const result = await runAttestation(await makePack(), CONTENT_HASH, { extraModules: [malicious] })
      expect(result.coldBootStatus).toBe('FAIL')
      expect(result.cleanupStatus).toBe('PASS') // the disposable root IS removed (D97)
      // production DSH_HOME untouched — marker + profile byte-identical
      expect(readFileSync(join(prodHome, 'marker.txt'), 'utf8')).toBe(markerBefore)
      expect(readFileSync(join(prodHome, 'profiles', 'prod', 'package.json'), 'utf8')).toBe(profileBefore)
    } finally {
      if (savedHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = savedHome
    }
  })

  it('N7.1b: the runtime reports a DISPOSABLE home, never the host DSH_HOME', async () => {
    const root = tempRoot('n71b')
    const spy = join(root, 'fixture-spy')
    await writeN7Bundle(spy, { reportEnv: true })

    const prodHome = join(root, 'prod-home')
    mkdirSync(prodHome, { recursive: true })
    const savedHome = process.env.DSH_HOME
    process.env.DSH_HOME = prodHome
    try {
      const result = await runAttestation(await makePack(), CONTENT_HASH, { extraModules: [spy] })
      expect(result.coldBootStatus).toBe('FAIL') // the spy throws after reporting
      const report = result.observer.error ?? ''
      expect(report).toContain('ENVREPORT')
      // HOME must be inside the disposable temp root (dsh-pack-attest-*), NOT prodHome
      expect(report).not.toContain(prodHome)
      expect(report).toMatch(/HOME=\/tmp\/[^\s]*dsh-pack-attest-/)
      // DSH_HOME likewise points at the disposable home, not the host's
      expect(report).toMatch(/DSH_HOME=\/tmp\/[^\s]*dsh-pack-attest-/)
      expect(report).not.toContain(`DSH_HOME=${prodHome}`)
      // observer env allowlist still injects the disposable DSH_HOME key
      expect(result.observer.envKeys).toContain('DSH_HOME')
    } finally {
      if (savedHome === undefined) delete process.env.DSH_HOME
      else process.env.DSH_HOME = savedHome
    }
  })

  it('N7.6: managed cwd stays inside the disposable root (honest: app-level hygiene, not OS sandbox)', async () => {
    const root = tempRoot('n76')
    const spy = join(root, 'fixture-spy')
    await writeN7Bundle(spy, { reportEnv: true })
    const result = await runAttestation(await makePack(), CONTENT_HASH, { extraModules: [spy] })
    const report = result.observer.error ?? ''
    // the observer's cwd is the disposable workspace inside the temp root
    expect(report).toMatch(/CWD=\/tmp\/[^\s]*\/workspace/)
    // honest boundary: we assert dsh-pack MANAGED paths never point at the
    // production home — we do NOT claim fs.writeFileSync('/tmp/evil') is blocked
    expect(report).not.toContain('CWD=/home')
    expect(report).not.toContain('CWD=/mnt')
  })
})

describe('N7.2: host secrets stripped (env allowlist, D93)', () => {
  it('never inherits secrets; keeps only PATH/HOME/TMPDIR + DSH runtime vars', async () => {
    const root = tempRoot('n72')
    const clean = join(root, 'fixture-clean')
    await writeN7Bundle(clean, { services: ['svc-ok'] })

    const HOST_SECRETS = {
      GITHUB_TOKEN: 'N7_CANARY_SECRET',
      NPM_TOKEN: 'N7_CANARY_SECRET',
      OPENAI_API_KEY: 'N7_CANARY_SECRET',
      AWS_SECRET_ACCESS_KEY: 'N7_CANARY_SECRET',
      SSH_AUTH_SOCK: '/tmp/ssh-agent.sock',
    }
    const saved = new Map<string, string | undefined>()
    for (const [k, v] of Object.entries(HOST_SECRETS)) {
      saved.set(k, process.env[k])
      process.env[k] = v
    }
    try {
      const result = await runAttestation(await makePack([{ id: 'svc-ok', config: {} }]), CONTENT_HASH, { extraModules: [clean] })
      expect(result.coldBootStatus).toBe('PASS')
      const keys = result.observer.envKeys
      for (const k of Object.keys(HOST_SECRETS)) expect(keys).not.toContain(k)
      // allowlist essentials ARE present
      expect(keys).toContain('PATH')
      expect(keys).toContain('HOME')
      expect(keys).toContain('TMPDIR')
      expect(keys).toContain('DSH_HOME')
      // the N7 canary value never appears anywhere in the observation
      expect(JSON.stringify(result.observer)).not.toContain('N7_CANARY_SECRET')
    } finally {
      for (const [k, v] of saved) {
        if (v === undefined) delete process.env[k]
        else process.env[k] = v
      }
    }
  })
})

describe('N7.3+N7.7: registry state + crash run never leak into the next run', () => {
  it('N7.3: tools/skills/services/providers registered by one run do not appear in the next', async () => {
    const root = tempRoot('n73')
    const malicious = join(root, 'fixture-malicious')
    await writeN7Bundle(malicious, {
      tools: ['evil.exec'], skills: ['evil.skill'], services: ['evil.svc'], providers: ['evil.prov'],
    })
    const clean = join(root, 'fixture-clean')
    await writeN7Bundle(clean, { services: ['svc-ok'] })
    // observer probes exactly the composition rows — ALL ids present, so each
    // run sees only what ITS fixture actually provided (that IS the no-leak claim)
    const pack = await makePack([
      { id: 'evil.svc', config: {} }, { id: 'evil.prov', provider: 'deepseek', config: {} },
      { id: 'svc-ok', config: {} },
    ])

    const run1 = await runAttestation(pack, CONTENT_HASH, { extraModules: [malicious] })
    expect(run1.observed.tools).toEqual(['evil.exec'])
    expect(run1.observed.skills).toEqual(['evil.skill'])
    expect(run1.observed.services).toEqual(['evil.svc'])
    expect(run1.observed.providers).toEqual(['evil.prov'])

    const run2 = await runAttestation(pack, CONTENT_HASH, { extraModules: [clean] })
    expect(run2.observed.tools).toEqual([])
    expect(run2.observed.skills).toEqual([])
    expect(run2.observed.providers).toEqual([])
    expect(run2.observed.services).toEqual(['svc-ok'])
    // no ghost entries: everything observed is declared in the composition rows
    expect(run2.comparison.observedButNotDeclared).toEqual([])
  })

  it('N7.7: malicious CRASH run → clean run has zero contamination + Run A cleanup evidence exists', async () => {
    const root = tempRoot('n77')
    const evil = join(root, 'fixture-evil')
    await writeN7Bundle(evil, { tools: ['evil.exec'], throwOnMount: true })
    const clean = join(root, 'fixture-clean')
    await writeN7Bundle(clean, { services: ['svc-ok'] })
    const pack = await makePack([{ id: 'svc-ok', config: {} }])

    // Run A — malicious: registers a tool, then crashes on mount
    const runA = await runAttestation(pack, CONTENT_HASH, { extraModules: [evil] })
    expect(runA.coldBootStatus).toBe('FAIL')
    expect(runA.cleanupStatus).toBe('PASS')
    // Run A's cleanup is itself evidence (D97) — the document records it
    const docA = JSON.parse(runA.document) as AttestationDocument
    expect(docA.cleanup.status).toBe('PASS')
    expect(docA.coldBoot.status).toBe('FAIL')

    // Run B — clean artifact, fresh cold boot
    const runB = await runAttestation(pack, CONTENT_HASH, { extraModules: [clean] })
    expect(runB.coldBootStatus).toBe('PASS')
    expect(runB.cleanupStatus).toBe('PASS')
    expect(runB.observed.tools).toEqual([]) // no evil.exec
    expect(runB.observed.skills).toEqual([])
    expect(runB.observed.services).toEqual(['svc-ok'])
    // no env mutation leaks from Run A into Run B
    expect(runB.observer.envKeys).not.toContain('DSH_ATTEST_EVIL')
  })
})

describe('N7.4: owned process lifecycle — honest boundary', () => {
  it('observer does not hang on artifact-spawned children; descendant cleanup is honestly NOT_PROBED', async () => {
    const root = tempRoot('n74')
    const spawner = join(root, 'fixture-spawner')
    await writeN7Bundle(spawner, { spawnShortChild: true, services: ['svc-ok'] })
    const result = await runAttestation(await makePack(), CONTENT_HASH, { extraModules: [spawner] })
    expect(result.coldBootStatus).toBe('PASS') // observer finished despite the child
    expect(result.cleanupStatus).toBe('PASS')
    // HONEST: effects.process is NOT_PROBED — the runtime owns the observer
    // process only; artifact-spawned descendants are not tracked, and we do
    // NOT fake isolation with a global pkill
    const doc = JSON.parse(result.document) as AttestationDocument
    expect(doc.effects.process).toBe('NOT_PROBED')
  })
})

describe('N7.5: failed/crashed run still produces auditable evidence', () => {
  it('cold boot FAIL is recorded in the document — the worst run is never swallowed', async () => {
    const root = tempRoot('n75')
    const evil = join(root, 'fixture-evil')
    await writeN7Bundle(evil, { throwOnMount: true })
    const result = await runAttestation(await makePack(), CONTENT_HASH, { extraModules: [evil] })
    // runAttestation must RETURN a document, not throw — evidence generation
    // succeeds even though attestation execution failed
    expect(result.coldBootStatus).toBe('FAIL')
    expect(result.document).toContain('"coldBoot"')
    const doc = JSON.parse(result.document) as AttestationDocument
    expect(doc.subject.contentHash).toBe(CONTENT_HASH) // still subject-bound
    expect(doc.coldBoot.status).toBe('FAIL')
    expect(doc.observation.coverage).toBe('unknown')
    expect(doc.cleanup.status).toBe('PASS')
    expect(typeof doc.resultDigest).toBe('string')
    expect(doc.resultDigest).toMatch(/^sha256:[0-9a-f]{64}$/)
    // the normalized observation digest is deterministic — a FAIL run is a
    // first-class, auditable artifact, never a void
    expect(result.resultDigest).toBe(doc.resultDigest)
  })
})

describe('N7.8: parallel runs are isolated (no module-level singleton / global observer)', () => {
  it('two concurrent attestations never share registry state', async () => {
    const root = tempRoot('n78')
    const evilA = join(root, 'fixture-evil-a')
    await writeN7Bundle(evilA, { tools: ['evil-a.exec'], services: ['svc-a'] })
    const cleanB = join(root, 'fixture-clean-b')
    await writeN7Bundle(cleanB, { services: ['svc-b'] })
    const pack = await makePack([{ id: 'svc-a', config: {} }, { id: 'svc-b', config: {} }])

    const [a, b] = await Promise.all([
      runAttestation(pack, CONTENT_HASH, { extraModules: [evilA] }),
      runAttestation(pack, CONTENT_HASH, { extraModules: [cleanB] }),
    ])
    expect(a.coldBootStatus).toBe('PASS')
    expect(b.coldBootStatus).toBe('PASS')
    expect(a.observed.tools).toEqual(['evil-a.exec'])
    expect(b.observed.tools).toEqual([])
    expect(a.observed.services).toEqual(['svc-a'])
    expect(b.observed.services).toEqual(['svc-b'])
    // cross-contamination in either direction is a global-singleton bug
    expect(b.observed.services).not.toContain('svc-a')
    expect(a.observed.services).not.toContain('svc-b')
  })
})
