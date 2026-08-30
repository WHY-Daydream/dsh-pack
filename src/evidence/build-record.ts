/**
 * v0.5 Build Provenance v2 — build-time capture (DESIGN-v0.5.0.md alpha.2,
 * D68–D71). A BuildRecord answers "what was this artifact ACTUALLY built
 * from?", captured IN the `/pack` build, never inferred afterwards from the
 * current repo state (that would be forgery: "现在是什么环境" ≠ "构建当时是什么环境").
 *
 * Flow: capture build inputs (git source, materials, environment) → build →
 * contentHash computed → BuildRecord assembled with subject = contentHash →
 * written as `<name>.dshpack.build-receipt.json` (sidecar) and optionally
 * signed as a `build-provenance` Evidence (subject binding, D64).
 *
 * D68 source identity comes from the build site; dirty defaults to FAIL at
 * sign time unless --allow-dirty, which then REQUIRES sourceTreeDigest.
 * D69 materials are digested separately (profile manifest, bundle patches,
 * source vs artifact lockfile, canonical dependency closure with content
 * digests for file:/link: deps).
 * D70 configHash never substitutes these materials.
 * D71 environment is evidence of HOW it was built — never a compatibility
 * claim (runtime matrix is a separate future Evidence).
 * @module @why-daydream/dsh-pack/evidence/build-record
 */

import { execFile } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { canonicalJson, parseYaml, sha256Hex, utcNowIso } from '../canonical.ts'
import { parsePackageKey } from '../dependency-resolver.ts'
import type { LocalDep } from '../types.ts'

const execFileAsync = promisify(execFile)
const GIT_COMMIT_RE = /^[0-9a-f]{40,64}$/
const DIGEST_RE = /^sha256:[0-9a-f]{64}$/

// --- BuildRecord schema (frozen, D68–D71) ---

export interface BuildSource {
  /** `git remote get-url origin` (best-effort). */
  repository?: string
  /** Full commit SHA from the build site (D68) — never a short hash. */
  gitCommit?: string
  /** Working tree dirty at build time (D68). */
  dirty: boolean
  /** REQUIRED when dirty: digest of the actual dirty tree state. */
  sourceTreeDigest?: string
}

export interface BuildMaterials {
  /** sha256 of the SOURCE profile/package.json bytes. */
  profileManifestDigest: string
  /** sha256 per bundle-configuration patch text (profile/cordis.patch.yml). */
  bundlePatchDigests: string[]
  /** sha256 of the ORIGINAL pnpm-lock.yaml bytes (build input, D69). */
  sourceLockfileDigest?: string
  /** sha256 of the lockfile INSIDE the artifact (post rewrite — differs from source). */
  artifactLockfileDigest?: string
  /** sha256(canonicalJson(closure entries)) — registry integrity + file:/link: contentDigest (D69). */
  dependencyClosureDigest: string
}

/** D71: how the artifact was built — evidence, not a compatibility declaration. */
export interface BuildEnvironment {
  dshPack: string
  dsh: string
  node: string
  pnpm: string
  os: string
  arch: string
}

/**
 * D72: how this record came to be signed — the trust boundary between
 * build-time attestation and post-build endorsement.
 *
 * `build-time`: the record was captured AT the build site and signed
 * immediately (pack `--evidence-key`) — this is a cryptographic attestation
 * of the build moment.
 *
 * `post-build-receipt`: the record is a re-signed copy of an UNSIGNED build
 * receipt, consumed later (`/pack evidence provenance`) — the unsigned
 * receipt could have been edited after the build, so this is an endorsement
 * of the artifact by the signer, NOT proof the signed inputs are the
 * unmodified build-moment state.
 */
export type CaptureMode = 'build-time' | 'post-build-receipt'

export interface BuildCapture {
  mode: CaptureMode
}

/** The frozen build receipt (also the `build-provenance` Evidence statement). */
export interface BuildRecord {
  schemaVersion: 1
  /** The immutable artifact anchor (D64) — bound AFTER the build. */
  subject: { contentHash: string }
  source: BuildSource
  materials: BuildMaterials
  environment: BuildEnvironment
  /** D72: build-time attestation vs post-build receipt endorsement. */
  capture: BuildCapture
  createdAt: string
}

export interface CaptureBuildRecordInput {
  /** Build site for git detection (D68) — the directory `/pack` ran in. */
  cwd: string
  /** The computed artifact anchor — bound after build (D64). */
  contentHash: string
  /** Profile directory (source package.json / pnpm-lock.yaml / patch). */
  profileDir: string
  /** Bundle-configuration patch text (profile/cordis.patch.yml), if any. */
  bundlePatchText?: string
  /** The lockfile staged INTO the artifact (rewritten), if any. */
  stagedLockfile?: string
  /** file:/link:/tarball direct deps — content digests required (D69). */
  localDeps: readonly LocalDep[]
  dshPackVersion: string
  dshVersion: string
  nodeVersion: string
  pnpmVersion: string
  os: string
  arch: string
}

/** Capture the build record AT BUILD TIME (D68: never after the fact). */
export async function captureBuildRecord(input: CaptureBuildRecordInput): Promise<BuildRecord> {
  if (!DIGEST_RE.test(input.contentHash)) {
    throw new Error(`build record subject contentHash must be sha256:<64 hex> (got ${JSON.stringify(input.contentHash)})`)
  }
  const source = await captureGitSource(input.cwd)
  const materials = captureMaterials(input)
  return {
    schemaVersion: 1,
    subject: { contentHash: input.contentHash },
    source,
    materials,
    environment: {
      dshPack: input.dshPackVersion,
      dsh: input.dshVersion,
      node: input.nodeVersion,
      pnpm: input.pnpmVersion,
      os: input.os,
      arch: input.arch,
    },
    // D72: this record is captured AT the build site — when it is signed
    // immediately by `pack --evidence-key` it is a build-time attestation.
    capture: { mode: 'build-time' },
    createdAt: utcNowIso(),
  }
}

// --- D68: git source identity from the build site ---

/**
 * Capture the git state of `cwd` (best-effort): full commit SHA, remote URL,
 * and — when the tree is dirty — a sourceTreeDigest over the dirty entries so
 * the commit alone never claims to describe inputs it does not (D68).
 */
export async function captureGitSource(cwd: string): Promise<BuildSource> {
  let gitCommit: string | undefined
  let repository: string | undefined
  try {
    const { stdout } = await execFileAsync('git', ['rev-parse', 'HEAD'], { cwd, timeout: 10_000 })
    const commit = stdout.trim()
    if (!GIT_COMMIT_RE.test(commit)) {
      throw new Error(`git commit is not a full SHA: ${commit}`)
    }
    gitCommit = commit
  } catch {
    return { dirty: false } // not a git build site — no source identity to claim
  }

  try {
    const { stdout } = await execFileAsync('git', ['remote', 'get-url', 'origin'], { cwd, timeout: 10_000 })
    repository = stdout.trim() || undefined
  } catch {
    repository = undefined
  }

  let dirty = false
  let porcelain = ''
  try {
    const { stdout } = await execFileAsync('git', ['status', '--porcelain'], { cwd, timeout: 10_000 })
    porcelain = stdout
    dirty = porcelain !== ''
  } catch {
    porcelain = ''
  }

  if (dirty) {
    const sourceTreeDigest = dirtyTreeDigest(cwd, porcelain)
    return {
      ...(repository !== undefined ? { repository } : {}),
      gitCommit,
      dirty: true,
      sourceTreeDigest,
    }
  }
  return {
    ...(repository !== undefined ? { repository } : {}),
    gitCommit,
    dirty: false,
  }
}

/** sha256 over the canonical inventory of the dirty tree state (D68). */
function dirtyTreeDigest(cwd: string, porcelain: string): string {
  const entries: { status: string; path: string; contentHash?: string }[] = []
  for (const line of porcelain.split('\n')) {
    if (line.trim() === '') continue
    // porcelain format: `XY path` (rename: `XY old -> new`)
    const status = line.slice(0, 2)
    const path = line.slice(3).split(' -> ').pop() ?? ''
    const absolute = join(cwd, path)
    let contentHash: string | undefined
    if (existsSync(absolute) && statSync(absolute).isFile()) {
      contentHash = sha256Hex(readFileSync(absolute))
    }
    entries.push({ status, path, ...(contentHash !== undefined ? { contentHash } : {}) })
  }
  entries.sort((a, b) => a.path.localeCompare(b.path))
  return `sha256:${sha256Hex(canonicalJson(entries))}`
}

/** The build receipt sidecar path next to a `.dshpack` (written at pack time). */
export function buildReceiptPath(packFile: string): string {
  return join(dirname(packFile), `${basename(packFile, '.dshpack')}.dshpack.build-receipt.json`)
}

// --- D69: materials digests ---

function captureMaterials(input: CaptureBuildRecordInput): BuildMaterials {
  const profileManifestPath = join(input.profileDir, 'package.json')
  const profileManifestDigest = existsSync(profileManifestPath)
    ? `sha256:${sha256Hex(readFileSync(profileManifestPath))}`
    : `sha256:${sha256Hex('')}`
  const bundlePatchDigests: string[] = []
  if (input.bundlePatchText !== undefined && input.bundlePatchText !== '') {
    bundlePatchDigests.push(`sha256:${sha256Hex(input.bundlePatchText)}`)
  }
  const sourceLockfilePath = join(input.profileDir, 'pnpm-lock.yaml')
  const sourceLockfileDigest = existsSync(sourceLockfilePath)
    ? `sha256:${sha256Hex(readFileSync(sourceLockfilePath))}`
    : undefined
  const artifactLockfileDigest = input.stagedLockfile !== undefined
    ? `sha256:${sha256Hex(input.stagedLockfile)}`
    : undefined
  const sourceLockfileText = existsSync(sourceLockfilePath) ? readFileSync(sourceLockfilePath, 'utf8') : undefined
  const dependencyClosureDigest = computeDependencyClosureDigest(sourceLockfileText, input.localDeps)
  return {
    profileManifestDigest,
    bundlePatchDigests,
    ...(sourceLockfileDigest !== undefined ? { sourceLockfileDigest } : {}),
    ...(artifactLockfileDigest !== undefined ? { artifactLockfileDigest } : {}),
    dependencyClosureDigest,
  }
}

/**
 * Canonical dependency closure digest (D69): registry entries carry
 * name/version/resolved/integrity from the lockfile `packages:` map; file:/
 * link:/tarball deps carry a CONTENT digest (a path that changed content must
 * change the digest — P7). Sorted + canonicalJson → sha256.
 */
export function computeDependencyClosureDigest(
  lockfileText: string | undefined,
  localDeps: readonly LocalDep[],
): string {
  const entries: unknown[] = []
  if (lockfileText !== undefined) {
    try {
      const lock = parseYaml(lockfileText) as Record<string, unknown>
      const packages = lock.packages as Record<string, unknown> | undefined
      if (packages !== undefined) {
        for (const key of Object.keys(packages).sort()) {
          const parsed = parsePackageKey(key)
          if (parsed === undefined) continue
          if (parsed.version.startsWith('file:') || parsed.version.startsWith('link:')) continue
          const entry = packages[key] as {
            version?: unknown
            resolution?: { integrity?: unknown; tarball?: unknown }
          } | undefined
          const resolution = entry?.resolution
          const integrity = typeof resolution?.integrity === 'string' && resolution.integrity !== ''
            ? resolution.integrity
            : undefined
          const resolved = typeof resolution?.tarball === 'string' && resolution.tarball !== ''
            ? resolution.tarball
            : undefined
          entries.push({
            name: parsed.name,
            version: entry?.version ?? parsed.version,
            ...(resolved !== undefined ? { resolved } : {}),
            ...(integrity !== undefined ? { integrity } : {}),
            source: 'registry',
          })
        }
      }
    } catch {
      // unparseable lockfile: fall through with registry entries empty — the
      // local deps below still contribute content digests
    }
  }
  for (const dep of localDeps) {
    const contentDigest = localDepContentDigest(dep)
    entries.push({
      name: dep.name,
      spec: dep.spec,
      source: dep.kind,
      ...(contentDigest !== undefined ? { contentDigest } : {}),
    })
  }
  return `sha256:${sha256Hex(canonicalJson(entries))}`
}

/** Content digest of a local dep: dir → canonical file inventory; tgz → bytes. */
function localDepContentDigest(dep: LocalDep): string | undefined {
  if (dep.kind === 'tarball') {
    try {
      return `sha256:${sha256Hex(readFileSync(dep.resolved))}`
    } catch {
      return undefined
    }
  }
  try {
    if (!existsSync(dep.resolved) || !statSync(dep.resolved).isDirectory()) return undefined
    const files: { path: string; hash: string }[] = []
    const walk = (dir: string, prefix: string): void => {
      for (const name of readdirSync(dir)) {
        const absolute = join(dir, name)
        const rel = prefix === '' ? name : `${prefix}/${name}`
        if (statSync(absolute).isDirectory()) walk(absolute, rel)
        else files.push({ path: rel, hash: sha256Hex(readFileSync(absolute)) })
      }
    }
    walk(dep.resolved, '')
    files.sort((a, b) => a.path.localeCompare(b.path))
    return `sha256:${sha256Hex(canonicalJson(files))}`
  } catch {
    return undefined
  }
}

// --- receipt validation (consumed by `/pack evidence provenance`, D68) ---

/** Validate a build receipt (the sidecar written at pack time). */
export function validateBuildRecord(
  value: unknown,
): { ok: true; record: BuildRecord } | { ok: false; errors: string[] } {
  if (value === null || typeof value !== 'object') return { ok: false, errors: ['build receipt is not an object'] }
  const v = value as Record<string, unknown>
  const errors: string[] = []
  if (v.schemaVersion !== 1) errors.push(`build receipt schemaVersion must be 1 (got ${String(v.schemaVersion)})`)
  const subject = v.subject as Record<string, unknown> | undefined
  if (subject === null || typeof subject !== 'object' || typeof subject.contentHash !== 'string'
    || !DIGEST_RE.test(subject.contentHash)) {
    errors.push('build receipt subject.contentHash must be sha256:<64 hex>')
  }
  const source = v.source as Record<string, unknown> | undefined
  if (source === null || typeof source !== 'object' || typeof source.dirty !== 'boolean') {
    errors.push('build receipt source.dirty must be a boolean')
  } else {
    if (source.gitCommit !== undefined && (typeof source.gitCommit !== 'string' || !GIT_COMMIT_RE.test(source.gitCommit))) {
      errors.push('build receipt source.gitCommit must be a full commit SHA')
    }
    if (source.dirty === true) {
      if (typeof source.sourceTreeDigest !== 'string' || !DIGEST_RE.test(source.sourceTreeDigest)) {
        errors.push('build receipt source.sourceTreeDigest required when dirty')
      }
    }
  }
  const materials = v.materials as Record<string, unknown> | undefined
  if (materials === null || typeof materials !== 'object'
    || typeof materials.profileManifestDigest !== 'string'
    || typeof materials.dependencyClosureDigest !== 'string') {
    errors.push('build receipt materials.profileManifestDigest and dependencyClosureDigest required')
  }
  const environment = v.environment as Record<string, unknown> | undefined
  if (environment === null || typeof environment !== 'object') {
    errors.push('build receipt environment must be an object')
  } else {
    for (const key of ['dshPack', 'dsh', 'node', 'pnpm', 'os', 'arch']) {
      if (typeof environment[key] !== 'string') errors.push(`build receipt environment.${key} must be a string`)
    }
  }
  // D72: the capture origin is mandatory — a record must state whether it is a
  // build-time capture or a post-build re-signing of an unsigned receipt.
  const capture = v.capture as Record<string, unknown> | undefined
  if (capture === null || typeof capture !== 'object' || typeof capture.mode !== 'string'
    || (capture.mode !== 'build-time' && capture.mode !== 'post-build-receipt')) {
    errors.push('build receipt capture.mode must be "build-time" or "post-build-receipt"')
  }
  if (errors.length > 0) return { ok: false, errors }
  return { ok: true, record: value as unknown as BuildRecord }
}
