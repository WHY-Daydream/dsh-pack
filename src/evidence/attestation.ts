/**
 * v0.5 beta.1 Runtime Attestation (DESIGN-v0.5.0.md §9, D89–D97): cold boot of
 * the artifact's profile inside a disposable isolated DSH_HOME, observe what
 * the runtime ACTUALLY registers, diff it against the declared capability
 * manifest, and record shutdown/cleanup as evidence.
 *
 * Phase A only (D94): boot → register → initialize → dispose. No tool is ever
 * invoked. No OS-level tracing: observation goes through the runtime's own
 * registry seam (the cordis service registry probes). Effects are NOT_PROBED
 * unless actually probed (D95). Host environment is an ALLOWLIST (D93) — the
 * child never inherits secrets. Metadata (observedAt/runId) is non-deterministic
 * (D96); the normalized observation yields a deterministic resultDigest.
 * Cleanup itself is attestation evidence (D97).
 * @module @why-daydream/dsh-pack/evidence/attestation
 */

import { spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import {
  copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync,
  rmSync, statSync, symlinkSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import { canonicalJson, sha256Hex } from '../canonical.ts'
import { extractTarGz } from '../pack-builder.ts'
import { generateCapabilityManifestFromPack } from './capability.ts'

export const ATTESTATION_EVIDENCE_TYPE = 'attestation'
export const ATTESTATION_FORMAT = 'dsh-attestation'
export const ATTESTATION_SCHEMA_VERSION = 1
/** D95: not probed is a fact — never rendered as `false` ("proven not to"). */
export const NOT_PROBED = 'NOT_PROBED'
/** D99: the root observer cannot see child-context registrations — honest default. */
export const PARTIAL_COVERAGE_REASON = 'child-context services may not be visible from the root observer'
/** The disposable profile directory name inside the temp home. */
const ATTEST_PROFILE_NAME = 'attest'
/** Default cold-boot child timeout. */
const DEFAULT_TIMEOUT_MS = 60_000
/** Cordis infra service names that are not user-visible capabilities. */
const INFRA_SERVICES = new Set([
  'loader', 'include', 'hmr', 'timer', 'cmdline', 'launch-environment', 'launchEnv', 'base',
])

/** D99: how much of the runtime registration this observation actually saw. */
export type ObservationCoverage = 'complete' | 'partial' | 'unknown'

/** D99: explicit observation coverage — never a guessed percentage. */
export interface ObservationCoverageInfo {
  coverage: ObservationCoverage
  reasons: string[]
}

export interface ObservedCapability {
  id: string
  kind: 'provider' | 'service' | 'tool' | 'skill'
}

export interface ObservedSets {
  tools: string[]
  skills: string[]
  services: string[]
  providers: string[]
}

export interface AttestationComparison {
  declaredButNotObserved: string[]
  observedButNotDeclared: string[]
  /**
   * D99: false whenever observation.coverage !== 'complete' — a partial
   * observation must never be read as authoritative absence.
   */
  authoritative: boolean
}

export interface AttestationEnvironment {
  dsh: string
  node: string
  os: string
  arch: string
}

/**
 * The frozen attestation document (DESIGN-v0.5.0.md §9.3). The deterministic
 * part = { declaredCapabilityDigest, coldBoot, observed, comparison, effects,
 * cleanup, environment } — its canonical digest is `resultDigest` (D96).
 */
export interface AttestationDocument {
  schemaVersion: 1
  /** D89: bound to the ACTUAL artifact contentHash. */
  subject: { contentHash: string }
  /** Non-deterministic run facts (D96). */
  metadata: { observedAt: string; runId: string }
  /** D90: the declared manifest this run is diffed against. */
  declaredCapabilityDigest: string
  /** D99: how much of the runtime registration this run actually observed. */
  observation: ObservationCoverageInfo
  coldBoot: { status: 'PASS' | 'FAIL' }
  observed: ObservedSets
  comparison: AttestationComparison
  effects: { network: 'NOT_PROBED'; filesystem: 'NOT_PROBED'; process: 'NOT_PROBED' }
  cleanup: { status: 'PASS' | 'FAIL' }
  environment: AttestationEnvironment
  resultDigest: string
}

export interface AttestationRunOptions {
  /** Extra module dirs to copy into the disposable profile node_modules (fixtures). */
  extraModules?: string[]
  /** Cold-boot child timeout in ms (default 60s). */
  timeoutMs?: number
}

export interface AttestationRunResult {
  document: string
  digest: string
  resultDigest: string
  coldBootStatus: 'PASS' | 'FAIL'
  cleanupStatus: 'PASS' | 'FAIL'
  /** D99: explicit observation coverage for this run. */
  observation: ObservationCoverageInfo
  observed: ObservedSets
  comparison: AttestationComparison
  /** Raw observer dump (test view — NEVER part of the evidence document). */
  observer: { services: string[]; providers: string[]; tools: string[]; skills: string[]; envKeys: string[]; error?: string }
}

/** Deterministic digest over the normalized observation (D96). */
export function attestationResultDigest(normalized: {
  declaredCapabilityDigest: string
  observation: ObservationCoverageInfo
  coldBoot: { status: 'PASS' | 'FAIL' }
  observed: ObservedSets
  comparison: AttestationComparison
  effects: { network: 'NOT_PROBED'; filesystem: 'NOT_PROBED'; process: 'NOT_PROBED' }
  cleanup: { status: 'PASS' | 'FAIL' }
  environment: AttestationEnvironment
}): string {
  return `sha256:${sha256Hex(canonicalJson(normalized))}`
}

/**
 * Run the Phase-A cold-boot attestation for a `.dshpack`:
 * 1. materialize a disposable DSH_HOME/profile/workspace/effects (D92)
 * 2. spawn the observer child with an env ALLOWLIST (D93)
 * 3. observe registered capabilities via the runtime registry seam (D94)
 * 4. diff against the declared manifest (D90), keep effects NOT_PROBED (D95)
 * 5. dispose, then record cleanup itself as evidence (D97)
 *
 * The child never sees host secrets: the allowlist forwards only PATH, temp
 * HOME/TMPDIR/DSH_HOME and the attestation's own variables.
 */
export async function runAttestation(
  packBuffer: Buffer,
  contentHash: string,
  opts: AttestationRunOptions = {},
): Promise<AttestationRunResult> {
  const require = createRequire(import.meta.url)
  const appBootPkg = require.resolve('@deepseek-ai/dsh-app-boot/package.json')
  const appBootEntry = require.resolve('@deepseek-ai/dsh-app-boot')
  const sharedNodeModules = dirname(dirname(appBootPkg))

  const temp = mkdtempSync(join(tmpdir(), 'dsh-pack-attest-'))
  const home = join(temp, 'home')
  const profilesDir = join(home, 'profiles')
  const profileDir = join(profilesDir, ATTEST_PROFILE_NAME)
  const nodeModulesDir = join(profilesDir, 'node_modules')
  const installDir = join(temp, 'install')
  const installNodeModules = join(installDir, 'node_modules')
  const workspace = join(temp, 'workspace')
  const effectsDir = join(temp, 'effects')
  const staging = join(temp, 'staging')
  const observedFile = join(effectsDir, 'observed.json')
  const rowsFile = join(effectsDir, 'rows.json')
  const observerDir = join(nodeModulesDir, '.attest-observer')
  const observerFile = join(observerDir, 'observer.mjs')

  mkdirSync(profileDir, { recursive: true })
  mkdirSync(nodeModulesDir, { recursive: true })
  mkdirSync(installNodeModules, { recursive: true })
  mkdirSync(workspace, { recursive: true })
  mkdirSync(effectsDir, { recursive: true })
  mkdirSync(observerDir, { recursive: true })
  // a disposable "dsh installation": loadProfile resolves profile bundles
  // from the ANCHOR's node_modules (the real harness resolves them from the
  // dsh installation), so the anchor points here, never at the real project.
  const installPkg = join(installDir, 'package.json')
  writeFileSync(installPkg, `${JSON.stringify({ name: '@deepseek-ai/dsh', version: '0.0.0-disposable' })}\n`)

  let cleanupStatus: 'PASS' | 'FAIL' = 'PASS'
  let coldBootStatus: 'PASS' | 'FAIL' = 'FAIL'
  let observer: AttestationRunResult['observer'] = {
    services: [], providers: [], tools: [], skills: [], envKeys: [],
  }
  const environment = currentEnvironment()

  try {
    // ---- 1. materialize the disposable profile from the artifact (D92) ----
    await extractTarGz(packBuffer, staging)
    const stagedProfile = join(staging, 'profile')
    if (!existsSync(join(stagedProfile, 'package.json'))) {
      throw new Error('dsh-pack: pack has no profile/package.json — cannot attest')
    }
    for (const name of readdirSync(stagedProfile)) {
      const from = join(stagedProfile, name)
      if (statSync(from).isFile()) copyFileSync(from, join(profileDir, name))
    }
    writeFileSync(join(profileDir, 'cordis.yml'), '[]\n') // root config (empty entry list)

    // bridge the runtime packages (@deepseek-ai/*) into BOTH the disposable
    // dsh installation and the profile node_modules (bundle resolution walks
    // the anchor's node_modules; the loader walks the profile's)
    const scopedDir = join(sharedNodeModules, '@deepseek-ai')
    if (existsSync(scopedDir)) {
      for (const name of readdirSync(scopedDir)) {
        const target = join(scopedDir, name)
        if (!statSync(target).isDirectory()) continue
        for (const targetNodeModules of [installNodeModules, nodeModulesDir]) {
          const linkPath = join(targetNodeModules, '@deepseek-ai', name)
          mkdirSync(dirname(linkPath), { recursive: true })
          try { symlinkSync(target, linkPath, 'dir') } catch { /* already bridged */ }
        }
      }
    }
    // test/local fixtures → disposable install + profile node_modules, named
    // by their package.json `name` (the dir name is irrelevant)
    for (const moduleDir of opts.extraModules ?? []) {
      const packageName = modulePackageName(moduleDir) ?? basename(moduleDir)
      copyTree(moduleDir, join(installNodeModules, packageName))
      copyTree(moduleDir, join(nodeModulesDir, packageName))
    }

    // ---- 2. compose rows + write the observer (Phase A, D94) ----
    const compositionPath = join(staging, 'resolved', 'composition.json')
    const rows = existsSync(compositionPath)
      ? (JSON.parse(readFileSync(compositionPath, 'utf8')) as { rows?: Record<string, unknown>[] }).rows ?? []
      : []
    writeFileSync(rowsFile, JSON.stringify(rows))
    writeFileSync(observerFile, OBSERVER_SOURCE)

    // ---- 3. spawn the observer child with the env ALLOWLIST (D93) ----
    const childEnv: NodeJS.ProcessEnv = {
      PATH: process.env.PATH ?? '',
      HOME: home,
      TMPDIR: temp,
      DSH_HOME: home,
      DSH_TELEMETRY_DISABLED: '1',
      NODE_ENV: 'test',
      DSH_ATTEST_HOME: home,
      DSH_ATTEST_ANCHOR: installPkg,
      DSH_ATTEST_APPBOOT_IMPORT: pathToFileURL(appBootEntry).href,
      DSH_ATTEST_PROFILE: ATTEST_PROFILE_NAME,
      DSH_ATTEST_OBSERVED_FILE: observedFile,
      DSH_ATTEST_ROWS_FILE: rowsFile,
    }
    const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS
    const child = spawn(process.execPath, [observerFile], {
      cwd: workspace,
      env: childEnv,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let childError = ''
    child.stderr.on('data', (chunk: Buffer) => { childError += chunk.toString() })
    const exitCode = await new Promise<number>((resolveExit) => {
      const timer = setTimeout(() => {
        child.kill('SIGKILL')
        resolveExit(-1)
      }, timeoutMs)
      child.on('exit', (code) => {
        clearTimeout(timer)
        resolveExit(code ?? -1)
      })
    })

    // ---- 4. read the observation (registry seam, D94) ----
    if (exitCode === 0 && existsSync(observedFile)) {
      try {
        observer = JSON.parse(readFileSync(observedFile, 'utf8'))
        coldBootStatus = observer.error === undefined ? 'PASS' : 'FAIL'
      } catch {
        coldBootStatus = 'FAIL'
      }
    } else {
      coldBootStatus = 'FAIL'
      if (childError !== '') observer.error = childError.slice(0, 500)
    }
  } catch (error) {
    coldBootStatus = 'FAIL'
    observer.error = String((error as Error)?.message ?? error).slice(0, 500)
  } finally {
    // ---- 5. cleanup IS evidence (D97) ----
    try {
      rmSync(temp, { recursive: true, force: true })
      if (existsSync(temp)) cleanupStatus = 'FAIL'
    } catch {
      cleanupStatus = 'FAIL'
    }
  }

  // ---- assembly ----
  const declaredManifest = await generateCapabilityManifestFromPack(packBuffer, contentHash)
  const declaredCapabilityDigest = declaredManifest.digest
  const declaredIds = [
    ...declaredManifest.manifest.declared.providers.map((c) => c.id),
    ...declaredManifest.manifest.declared.services.map((c) => c.id),
  ]
  const observedSets: ObservedSets = {
    tools: normalizeIds(observer.tools),
    skills: normalizeIds(observer.skills),
    services: normalizeIds(observer.services),
    providers: normalizeIds(observer.providers),
  }
  const observedIds = [
    ...observedSets.providers, ...observedSets.services,
    ...observedSets.tools, ...observedSets.skills,
  ]
  // D99: explicit observation coverage — partial unless proven complete, and
  // never a guessed percentage. A successful root-observer boot is honest
  // `partial` (child-context services may be invisible); a failed boot `unknown`.
  const observation: ObservationCoverageInfo = coldBootStatus === 'PASS'
    ? { coverage: 'partial', reasons: [PARTIAL_COVERAGE_REASON] }
    : { coverage: 'unknown', reasons: ['cold boot failed — no observation'] }
  const comparison: AttestationComparison = {
    declaredButNotObserved: declaredIds.filter((id) => !observedIds.includes(id)).sort(),
    observedButNotDeclared: observedIds.filter((id) => !declaredIds.includes(id)).sort(),
    authoritative: observation.coverage === 'complete',
  }
  const effects = { network: NOT_PROBED, filesystem: NOT_PROBED, process: NOT_PROBED } as const
  const normalized = {
    declaredCapabilityDigest,
    observation,
    coldBoot: { status: coldBootStatus },
    observed: observedSets,
    comparison,
    effects,
    cleanup: { status: cleanupStatus },
    environment,
  }
  const resultDigest = attestationResultDigest(normalized)
  const document: AttestationDocument = {
    schemaVersion: ATTESTATION_SCHEMA_VERSION,
    subject: { contentHash },
    metadata: { observedAt: new Date().toISOString(), runId: randomUUID() },
    ...normalized,
    resultDigest,
  }
  const serialized = canonicalJson(document)
  return {
    document: serialized,
    digest: `sha256:${sha256Hex(serialized)}`,
    resultDigest,
    coldBootStatus,
    cleanupStatus,
    observation,
    observed: observedSets,
    comparison,
    observer,
  }
}

/** Deduplicate + sort observed ids deterministically. */
function normalizeIds(items: unknown): string[] {
  if (!Array.isArray(items)) return []
  const ids = new Set<string>()
  for (const item of items) {
    if (typeof item === 'string' && item !== '') {
      ids.add(item)
    } else if (item !== null && typeof item === 'object' && typeof (item as { id?: unknown }).id === 'string') {
      ids.add((item as { id: string }).id)
    }
  }
  return [...ids].sort()
}

/** Runtime facts for the environment block (deterministic per machine). */
function currentEnvironment(): AttestationEnvironment {
  const require = createRequire(import.meta.url)
  let dsh = 'unknown'
  try { dsh = (JSON.parse(readFileSync(require.resolve('@deepseek-ai/dsh-app-boot/package.json'), 'utf8')) as { version?: string }).version ?? 'unknown' } catch { /* unavailable */ }
  return { dsh, node: process.version, os: process.platform, arch: process.arch }
}

/** Recursively copy a directory (fixtures into the disposable node_modules). */
function copyTree(source: string, dest: string): void {
  mkdirSync(dest, { recursive: true })
  for (const name of readdirSync(source)) {
    const from = join(source, name)
    const to = join(dest, name)
    const stat = statSync(from)
    if (stat.isDirectory()) copyTree(from, to)
    else if (stat.isFile()) copyFileSync(from, to)
  }
}

/** The `name` from a module dir's package.json, when present. */
function modulePackageName(moduleDir: string): string | undefined {
  try {
    const pkg = JSON.parse(readFileSync(join(moduleDir, 'package.json'), 'utf8')) as { name?: unknown }
    return typeof pkg.name === 'string' && pkg.name !== '' ? pkg.name : undefined
  } catch {
    return undefined
  }
}

/**
 * The Phase-A observer (runs INSIDE the disposable environment with the env
 * allowlist). It boots the profile via the harness seam, probes the cordis
 * service registry for the composed rows and the tools/skills seams, dumps the
 * observation, disposes the tree, and exits. Never invokes a tool (D94).
 */
const OBSERVER_SOURCE = `/**
 * dsh-pack attestation observer (Phase A, D94) — runs inside the disposable
 * DSH_HOME with the env allowlist. Boots the profile, observes what the
 * runtime ACTUALLY registered through the cordis registry seam, dumps the
 * observation, disposes, exits.
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

// The harness seam is imported by ABSOLUTE path: the observer does not sit in
// a position where node's module walk can see sibling packages.
const appBoot = await import(process.env.DSH_ATTEST_APPBOOT_IMPORT)

const home = process.env.DSH_ATTEST_HOME
const anchor = process.env.DSH_ATTEST_ANCHOR
const profileName = process.env.DSH_ATTEST_PROFILE
const observedFile = process.env.DSH_ATTEST_OBSERVED_FILE
const rowsFile = process.env.DSH_ATTEST_ROWS_FILE

const dump = {
  services: [], providers: [], tools: [], skills: [],
  envKeys: Object.keys(process.env).sort(),
}

try {
  const loaded = appBoot.loadProfile('dsh-pack-attest', profileName, anchor, home)
  const bundlePatches = loaded.layers.flatMap((layer) => layer.patches)
  const patches = [...bundlePatches, ...loaded.patches]
  const rootConfig = join(loaded.dir, 'cordis.yml')
  const ctx = await appBoot.boot('dsh-pack-attest', rootConfig, patches, () => {})
  try {
    if (typeof appBoot.assertEntriesActivated === 'function') {
      await appBoot.assertEntriesActivated(ctx, 'dsh-pack-attest')
    }
  } catch { /* entries that fail to mount are simply not observed */ }

  const probe = (name) => {
    try { return ctx.get(name) } catch { return undefined }
  }
  const rows = JSON.parse(readFileSync(rowsFile, 'utf8'))
  for (const row of rows) {
    if (typeof row?.id !== 'string' || row.id === '') continue
    const service = probe(row.id)
    if (service === undefined) continue
    if (typeof row.provider === 'string' && row.provider !== '') {
      dump.providers.push({ id: row.id, kind: 'provider' })
    } else {
      dump.services.push({ id: row.id, kind: 'service' })
    }
  }
  for (const seam of ['tools', 'skills']) {
    const service = probe(seam)
    if (service === undefined) continue
    const items = []
    try {
      if (service !== null && typeof service === 'object') {
        const record = service.items ?? service.registry ?? service
        if (record instanceof Map) items.push(...record.keys())
        else if (Array.isArray(record)) items.push(...record)
        else if (typeof record === 'object') items.push(...Object.keys(record))
      }
    } catch { /* not enumerable — recorded as absent */ }
    for (const item of items) {
      if (typeof item === 'string' && item !== '') dump[seam].push({ id: item, kind: seam.slice(0, -1) })
    }
  }
  try { await ctx.fiber.dispose() } catch { /* tree already disposed */ }
} catch (error) {
  dump.error = String(error?.message ?? error)
}
writeFileSync(observedFile, JSON.stringify(dump))
process.exit(0)
`
