/**
 * Packager service implementation (DESIGN.md Appendix A — the frozen
 * `ctx.packager` seam). Orchestrates the v0.1 pack pipeline: profile read →
 * snapshot → dependency closure → preflight (D7) → secret scan/redact →
 * configHash → deterministic archive → checksums. Also the inspect / verify /
 * install entry points.
 * @module @why-daydream/dsh-pack/service
 */

import { execFile } from 'node:child_process'
import { existsSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { promisify } from 'node:util'
import { PROFILE_ROOT_CONFIG, buildSnapshot } from './config-snapshot.ts'
import { resolveDependencies, rewriteLockfileForStaging } from './dependency-resolver.ts'
import { buildPortablePlan } from './portable.ts'
import { scanAndRedact, redactPatchText } from './secret-scanner.ts'
import { buildManifest, bundleIdentities, computeConfigHash } from './manifest.ts'
import { buildTarGz, checksumsJson, computePackContentHash, type PackFileEntry } from './pack-builder.ts'
import { verifyPack } from './verify.ts'
import { inspectPack } from './inspect.ts'
import { installPack } from './install.ts'
import { diffPacks } from './diff.ts'
import { signPackFile, generateKeypair } from './sign.ts'
import { buildReceiptPath, captureBuildRecord } from './evidence/build-record.ts'
import { DefaultEvidenceService } from './evidence/service.ts'
import { verifyEvidenceEnvelope, verifyEvidenceSubject } from './evidence/envelope.ts'
import { attestationSemanticFields } from './evidence/attestation.ts'
import { applyTrustPolicy, type TrustPolicy } from './image/trust.ts'
import {
  evaluateTrustPolicyV2, loadTrustPolicyFile, resolveTrustPolicyV2,
  type AttestationCandidate, type EvidenceCandidate, type PolicyEvaluationResult,
  type ProvenanceCandidate, type SbomCandidate,
} from './image/trust-policy-v2.ts'
import { loadProfileDir, resolveDshHome, resolveInstallAnchor } from './profile-reader.ts'
import { canonicalJson, prettyJson, sha256Hex, todayStamp, utcNowIso } from './canonical.ts'
import type {
  DependencyTree, EvidenceEnvelope, InstallOptions, InstallResult, KeygenResult, Manifest, PackDiff, PackInspection,
  PackOptions, PackResult, SignOptions, SignResult, VerificationReport, Warning,
} from './types.ts'

const execFileAsync = promisify(execFile)

/** Error carrying the command exit code (DESIGN.md §8.2). */
export class PackError extends Error {
  constructor(message: string, readonly exitCode: number) {
    super(message)
    this.name = 'PackError'
  }
}

/** The frozen v0.1 service surface (DESIGN.md Appendix A). */
export interface PackagerService {
  pack(opts: PackOptions): Promise<PackResult>
  inspect(file: string): Promise<PackInspection>
  verify(file: string, opts?: { ignoreRuntimeVersion?: boolean; requireSignature?: boolean }): Promise<VerificationReport>
  install(file: string, opts: InstallOptions): Promise<InstallResult>
  /** v0.2: drift report between two packs. */
  diff(fileA: string, fileB: string): Promise<PackDiff>
  /** v0.3: embed an ed25519 signature + provenance into a copy of the pack. */
  sign(file: string, opts: SignOptions): Promise<SignResult>
  /** v0.3: generate an ed25519 keypair. */
  keygen(opts: { outDir?: string }): Promise<KeygenResult>
  /**
   * v0.5 beta.2: evaluate the LOCAL trust.yaml v1/v2 policy for an artifact
   * (DESIGN-v0.5.0.md §10, D100–D111). Only VERIFIED inputs are consumed: the
   * signature goes through the full verify chain, and evidence envelopes must
   * pass self-integrity + subject==contentHash before evaluation (D100).
   * Evidence issuer trust is decided per type (D109), candidates are selected
   * deterministically (D110), and the attestation environment must match the
   * current execution target (D111).
   */
  policy(file: string, opts?: { repository?: string; collectionDir?: string; executionTarget?: { os: string; arch: string } }): Promise<PolicyEvaluationResult>
}

export interface PackagerContext {
  /** Override $DSH_HOME (tests). */
  home?: string
  /** Override the installed dsh version (tests). */
  installedDshVersion?: string
  /** Override the packager version (tests). */
  packagerVersion?: string
  /** v0.5: build site for git provenance capture (D68; default process.cwd()). */
  buildCwd?: string
}

/** Read the installed dsh version from the install anchor (D15). */
export function readInstalledDshVersion(): string {
  const anchor = resolveInstallAnchor()
  try {
    const pkg = JSON.parse(readFileSync(anchor.anchor, 'utf8')) as { version?: string }
    return pkg.version ?? 'unknown'
  } catch {
    return 'unknown'
  }
}

/** Default in-process implementation of the packager service. */
export class DefaultPackager implements PackagerService {
  constructor(private readonly context: PackagerContext = {}) {}

  private home(): string {
    return this.context.home ?? resolveDshHome()
  }

  private installedDshVersion(): string {
    return this.context.installedDshVersion ?? readInstalledDshVersion()
  }

  async pack(opts: PackOptions): Promise<PackResult> {
    const home = this.home()
    const profile = loadProfileDir(opts.profile, home)
    const anchor = resolveInstallAnchor()
    const snapshot = buildSnapshot(profile, home, anchor.anchor)
    const bundles = profile.manifest.dsh?.profile?.bundles ?? []
    const depTree = resolveDependencies(profile.dir, profile.manifest.dependencies ?? {}, bundles)

    // --- preflight (D7: non-portable directory deps fail by default; --portable vendors them) ---
    const nonPortable = depTree.localDeps.filter((dep) => dep.kind !== 'tarball')
    if (nonPortable.length > 0 && !opts.allowNonportable && !opts.portable) {
      const lines = nonPortable.map((dep) => `  ${dep.name} -> ${dep.spec}`).join('\n')
      throw new PackError(
        `Non-portable dependency detected:\n${lines}\n`
        + 'v0.1 cannot create an installable snapshot containing directory dependencies.\n'
        + 'Use --allow-nonportable, or wait for v0.2 --portable.',
        1,
      )
    }

    // --- strict preflight (exit 3) ---
    if (opts.strict) {
      const strictErrors: string[] = []
      if (depTree.lockfile === 'MISSING') strictErrors.push('pnpm-lock.yaml missing')
      for (const warning of depTree.warnings) {
        if (warning.includes('github spec without')) strictErrors.push(warning)
      }
      if (strictErrors.length > 0) throw new PackError(`Strict preflight failed: ${strictErrors.join('; ')}`, 3)
    }

    // --- vendoring (MUST-2 tarballs; v0.2 --portable vendors the local closure) ---
    const vendors: { tgz: string; content: Buffer }[] = []
    let stagedDeps: Record<string, string> = { ...(profile.manifest.dependencies ?? {}) }
    let stagedLockfile: string | undefined
    if (opts.portable) {
      const plan = await buildPortablePlan(profile.dir, profile.manifest.dependencies ?? {})
      for (const [tgz, content] of Object.entries(plan.tgzs)) vendors.push({ tgz, content })
      stagedDeps = plan.stagedDeps
      stagedLockfile = plan.lockfile
      // configHash identity for vendored local dir deps = name + real version
      // (invariant to the spec rewrite, MUST-2 principle).
      for (const pkg of plan.packages) {
        if (pkg.kind === 'directory') depTree.closure[pkg.name] = pkg.version
        const local = depTree.localDeps.find((dep) => dep.name === pkg.name)
        if (local !== undefined) local.portable = true
      }
    } else {
      for (const dep of depTree.localDeps) {
        if (dep.kind !== 'tarball') continue
        if (!existsSync(dep.resolved)) {
          throw new PackError(`tarball dependency ${dep.name} missing: ${dep.resolved}`, 1)
        }
        const tgz = basename(dep.resolved)
        vendors.push({ tgz, content: readFileSync(dep.resolved) })
        stagedDeps[dep.name] = `file:./packages/${tgz}`
      }
      stagedLockfile = rewriteLockfileForStaging(profile.dir, stagedDeps)
    }

    // --- secret scan / redact (DESIGN.md §6) ---
    const scan = scanAndRedact(snapshot.rows, snapshot.rowSources)
    const high = scan.hits.filter((hit) => hit.confidence === 'high').length
    if (high > 0 && opts.strict && !opts.allowSecrets) {
      throw new PackError(`Strict preflight: ${high} high-confidence secret(s) detected; use --allow-secrets to pack anyway`, 3)
    }
    // The packed profile patch must not carry plaintext secrets either (D9).
    const packedPatch = redactPatchText(profile.patchText ?? '', scan.hits)

    // --- configHash (frozen formula, §7.3) ---
    const identities = bundleIdentities(bundles, depTree)
    const configHash = computeConfigHash(snapshot.composition, identities, depTree.closure)

    // --- runtime facts ---
    const dshVersion = this.installedDshVersion()
    const pnpmVersion = await this.detectPnpmVersion()

    // --portable vendored every local dir dep, so the pack is installable;
    // otherwise only packs without non-tarball local deps are installable (D7).
    const installable = opts.portable ? true : nonPortable.length === 0
    const manifest = buildManifest({
      profileName: opts.profile,
      excludedLayersPresent: snapshot.excludedLayersPresent,
      dshVersion,
      nodeVersion: process.versions.node,
      pnpmVersion,
      platform: `${process.platform}-${process.arch}`,
      bundles,
      dependencies: profile.manifest.dependencies ?? {},
      redacted: scan.redacted,
      configHash,
      installable,
      // DESIGN §3.3/§5.2: a --allow-nonportable pack must be `portable:false`
      // (directory file:/link: deps are not vendored in v0.1).
      portable: installable,
      ...(vendors.length > 0 ? { packages: vendors.map((vendor) => vendor.tgz) } : {}),
      packagerVersion: this.context.packagerVersion ?? '0.1.0',
      createdAt: utcNowIso(),
    })

    const warnings: Warning[] = [
      ...depTree.warnings.map((message) => ({ code: 'dependency', message })),
      ...scan.warnings,
      ...(pnpmVersion === 'unknown' ? [{ code: 'pnpm-version', message: 'pnpm --version unavailable; runtime.pnpmVersion = "unknown"' }] : []),
      ...(anchor.source === 'fallback' ? [{
        code: 'install-anchor-fallback',
        message: 'could not locate the @deepseek-ai/dsh installation; in-box bundle resolution degrades to the profile node_modules',
      }] : []),
    ]
    if (snapshot.excludedLayersPresent) {
      warnings.push({ code: 'excluded-layers', message: 'home/--patch layers excluded from the snapshot (machine/invocation-local)' })
    }

    // --- assemble entries ---
    const stagedPackage = {
      ...profile.manifest,
      dependencies: stagedDeps,
    }
    const entries: PackFileEntry[] = [
      { path: 'manifest.json', content: prettyJson(manifest) },
      { path: 'profile/package.json', content: prettyJson(stagedPackage) },
      { path: 'profile/cordis.patch.yml', content: packedPatch.text },
      ...(stagedLockfile !== undefined ? [{ path: 'profile/pnpm-lock.yaml', content: stagedLockfile }] : []),
      { path: 'profile/cordis.yml', content: PROFILE_ROOT_CONFIG },
      { path: 'resolved/cordis.effective.yml', content: snapshot.effectiveYaml },
      { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: snapshot.layers }) },
      { path: 'resolved/dependency-tree.json', content: prettyJson(depTree) },
      { path: 'resolved/composition.json', content: prettyJson(snapshot.composition) },
      ...(scan.envExample !== '' ? [{ path: 'env/.env.example', content: scan.envExample }] : []),
      { path: 'README.md', content: renderReadme(manifest, warnings) },
      ...vendors.map((vendor) => ({ path: `packages/${vendor.tgz}`, content: vendor.content })),
    ]

    // --- checksums + contentHash (checksums.json itself is never in files) ---
    const checksumEntries: PackFileEntry[] = [
      ...entries,
      { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings }) },
    ]
    const built = await buildTarGz(checksumEntries)
    const allEntries: PackFileEntry[] = [
      ...checksumEntries,
      { path: 'metadata/checksums.json', content: checksumsJson(built.contentHash, built.files) },
    ]
    const final = await buildTarGz(allEntries)

    // --- v0.5 build receipt + optional build-provenance evidence (D68–D71) ---
    // The receipt records what this artifact WAS built from, captured in the
    // build site NOW — never inferred later from a changed repo state.
    const receipt = await captureBuildRecord({
      cwd: this.context.buildCwd ?? process.cwd(),
      contentHash: built.contentHash,
      profileDir: profile.dir,
      ...(profile.patchText !== undefined ? { bundlePatchText: profile.patchText } : {}),
      ...(stagedLockfile !== undefined ? { stagedLockfile } : {}),
      localDeps: depTree.localDeps,
      dshPackVersion: this.context.packagerVersion ?? '0.1.0',
      dshVersion,
      nodeVersion: process.versions.node,
      pnpmVersion,
      os: process.platform,
      arch: process.arch,
    })
    // D68 gate BEFORE any output is written: a dirty tree must not claim a
    // commit that does not describe the actual inputs — default FAIL;
    // --allow-dirty records sourceTreeDigest instead of a false claim.
    if (opts.evidenceKey !== undefined && receipt.source.dirty && opts.allowDirty !== true) {
      throw new PackError(
        'provenance FAIL: working tree is dirty; commit first or use --allow-dirty (records sourceTreeDigest instead of a false claim)',
        3,
      )
    }

    const outDir = opts.outDir ?? process.cwd()
    const file = join(outDir, `${opts.profile}-${todayStamp()}.dshpack`)
    writeFileSync(file, final.buffer)
    const receiptFile = buildReceiptPath(file)
    writeFileSync(receiptFile, prettyJson(receipt))
    let evidenceFile: string | undefined
    if (opts.evidenceKey !== undefined) {
      const evidenceService = new DefaultEvidenceService()
      evidenceFile = (await evidenceService.sign(file, {
        type: 'build-provenance',
        statement: receipt,
        key: opts.evidenceKey,
        ...(opts.signer !== undefined ? { signer: opts.signer } : {}),
      })).file
    }
    return {
      file,
      profile: opts.profile,
      manifest,
      warnings,
      redacted: scan.redacted,
      receipt: receiptFile,
      ...(evidenceFile !== undefined ? { evidence: evidenceFile } : {}),
    }
  }

  private async detectPnpmVersion(): Promise<string> {
    try {
      const { stdout } = await execFileAsync('pnpm', ['--version'], { timeout: 5_000 })
      return stdout.trim() || 'unknown'
    } catch {
      return 'unknown'
    }
  }

  async inspect(file: string): Promise<PackInspection> {
    const buffer = readFileSync(file)
    const inspection = await inspectPack(buffer)
    return { ...inspection, file }
  }

  async verify(file: string, opts?: { ignoreRuntimeVersion?: boolean; requireSignature?: boolean }): Promise<VerificationReport> {
    const buffer = readFileSync(file)
    const installedDshVersion = this.installedDshVersion()
    const { report, root } = await verifyPack(buffer, {
      installedDshVersion,
      ...(opts?.ignoreRuntimeVersion === true ? { ignoreRuntimeVersion: true } : {}),
      ...(opts?.requireSignature === true ? { requireSignature: true } : {}),
    })
    rmSync(root, { recursive: true, force: true })
    return report
  }

  /**
   * v0.5 beta.2 — trust.yaml v2 evaluation for one artifact (D100–D111):
   * verified signature → evidence candidates (D100) → resolve the LOCAL policy
   * (v1/v2, D107) → evaluate → ALLOW / DENY with the auditable chain.
   */
  async policy(
    file: string,
    opts: { repository?: string; collectionDir?: string; executionTarget?: { os: string; arch: string } } = {},
  ): Promise<PolicyEvaluationResult> {
    const bytes = readFileSync(file)
    const contentHash = await computePackContentHash(bytes)

    // 1. verified signature (v0.3/v0.4 chain — VALID ≠ TRUSTED, D19/D29)
    const report = await this.verify(file)
    const signatureSection = report.sections.find((s) => s.name === 'Signature')

    // 2. evidence candidates (D100): EVERY envelope of each type, verified or
    //    not, in deterministic file order — presence/signature/issuer are
    //    reported separately (D106) and selection is deterministic (D110).
    const collectionRoot = opts.collectionDir
      ?? join(dirname(file), `${basename(file, '.dshpack')}.dshpack.evidence`)
    const provenance = this.provenanceCandidates(collectionRoot, contentHash)
    const sbom = this.sbomCandidates(collectionRoot, contentHash)
    const attestation = this.attestationCandidates(collectionRoot, contentHash)

    // 3. resolve the local policy for the repository (provenance source by default)
    const repository = opts.repository ?? provenance.find((c) => c.verified)?.repository ?? ''
    const decision = resolveTrustPolicyV2(loadTrustPolicyFile(this.home()), repository)

    // 4. signature input from the v1 trust fields (trustedKeys, D55)
    const trustVerdict = applyTrustPolicy(signatureSection, {
      ...(decision.requireSignature ? { requireSignature: true } : {}),
      ...(decision.requireTrusted ? { requireTrusted: true } : {}),
      ...(decision.trustedKeys !== undefined ? { trustedKeys: decision.trustedKeys } : {}),
    })

    // 5. evaluate — verified inputs only (D100), bound to the current target (D111)
    const executionTarget = opts.executionTarget ?? { os: process.platform, arch: process.arch }
    const verdict = evaluateTrustPolicyV2(decision, {
      signature: { status: trustVerdict.signature, trust: trustVerdict.trust },
      executionTarget,
      provenance,
      sbom,
      attestation,
    })
    return { contentHash, repository, decision, verdict, executionTarget }
  }

  /** D100: scan one evidence type directory — every `.json` envelope in deterministic file order. */
  private scanEnvelopes(collectionRoot: string, type: string): EvidenceEnvelope[] {
    const dir = join(collectionRoot, type)
    if (!existsSync(dir)) return []
    const envelopes: EvidenceEnvelope[] = []
    for (const name of readdirSync(dir).sort()) {
      if (!name.endsWith('.json')) continue
      try {
        const envelope = JSON.parse(readFileSync(join(dir, name), 'utf8')) as EvidenceEnvelope
        if (envelope.type !== type) continue
        envelopes.push(envelope)
      } catch { /* unreadable — skip, never a candidate */ }
    }
    return envelopes
  }

  /** D100: verify an envelope's self-integrity + subject binding against the artifact. */
  private verifiedBase(
    envelope: EvidenceEnvelope, contentHash: string,
  ): { verified: boolean; keyId: string; statementDigest: string } {
    const envVerdict = verifyEvidenceEnvelope(envelope)
    if (!envVerdict.ok) return { verified: false, keyId: '', statementDigest: envelope.statementDigest }
    const subjectOk = verifyEvidenceSubject(envelope, contentHash).ok
    return { verified: subjectOk, keyId: envVerdict.keyId, statementDigest: envelope.statementDigest }
  }

  /** D109/D110: build-provenance candidates — origin + repository read from the verified statement. */
  private provenanceCandidates(collectionRoot: string, contentHash: string): ProvenanceCandidate[] {
    return this.scanEnvelopes(collectionRoot, 'build-provenance').map((envelope) => {
      const base = this.verifiedBase(envelope, contentHash)
      const statement = envelope.statement as { capture?: { mode?: unknown }; source?: { repository?: unknown } } | undefined
      return {
        ...base,
        ...(typeof statement?.capture?.mode === 'string' ? { origin: statement.capture.mode } : {}),
        ...(typeof statement?.source?.repository === 'string' ? { repository: statement.source.repository } : {}),
      }
    })
  }

  /** D109/D110/D120: sbom candidates — documentKey is the semantic document anchor.
   *  D120 (rc.1): when a document file EXISTS under the claimed digest it MUST
   *  hash to that digest — a substituted SBOM document makes the candidate
   *  UNVERIFIED (mirrors the attestation document check). A MISSING document
   *  keeps the v0.3 signing workflow semantics (envelope-only trust), because
   *  `evidence.sign` does not require a document file. */
  private sbomCandidates(collectionRoot: string, contentHash: string): SbomCandidate[] {
    return this.scanEnvelopes(collectionRoot, 'sbom').map((envelope) => {
      const base = this.verifiedBase(envelope, contentHash)
      const statement = envelope.statement as { sbomDigest?: { value?: unknown } } | undefined
      const digestValue = statement?.sbomDigest?.value
      if (typeof digestValue !== 'string' || digestValue === '') {
        return { ...base }
      }
      const documentFile = join(collectionRoot, 'documents', `${digestValue}.cdx.json`)
      if (existsSync(documentFile) && sha256Hex(readFileSync(documentFile, 'utf8')) !== digestValue) {
        return { ...base, verified: false, documentKey: digestValue }
      }
      return { ...base, documentKey: digestValue }
    })
  }

  /**
   * D109/D110/D111: attestation candidates — the document is digest-matched
   * against the envelope statement BEFORE its contents are trusted (D100/D99);
   * a missing/mismatched document makes the candidate UNVERIFIED (the evidence
   * is not self-consistent). The environment is read from the verified
   * document for the D111 target binding. D125 semantic fields are computed by
   * the SHARED `attestationSemanticFields` (also used by the remote discovery
   * path — beta.1 D178: both paths can never diverge).
   */
  private attestationCandidates(collectionRoot: string, contentHash: string): AttestationCandidate[] {
    return this.scanEnvelopes(collectionRoot, 'attestation').map((envelope) => {
      const base = this.verifiedBase(envelope, contentHash)
      const statement = envelope.statement as { attestationDigest?: { value?: unknown } } | undefined
      const digestValue = statement?.attestationDigest?.value
      if (!base.verified || typeof digestValue !== 'string' || digestValue === '') {
        return { ...base, verified: false, observed: [] }
      }
      const documentFile = join(collectionRoot, 'documents', `${digestValue}.attestation.json`)
      if (!existsSync(documentFile)) return { ...base, verified: false, observed: [] }
      const documentBytes = readFileSync(documentFile)
      if (sha256Hex(documentBytes.toString('utf8')) !== digestValue) return { ...base, verified: false, observed: [] }
      const semantics = attestationSemanticFields(documentBytes)
      return {
        ...base,
        documentKey: digestValue,
        ...(semantics.semanticKey !== undefined ? { semanticKey: semantics.semanticKey } : {}),
        ...(semantics.coverage !== undefined ? { coverage: semantics.coverage } : {}),
        ...(semantics.environment !== undefined ? { environment: semantics.environment } : {}),
        observed: semantics.observed,
      }
    })
  }

  async install(file: string, opts: InstallOptions): Promise<InstallResult> {
    // D115 (rc.1): lifecycle/package execution must NEVER happen before the
    // trust decision. When a policy gate is requested, evaluate the FULL v2
    // policy FIRST and refuse to materialize on any non-ALLOW verdict —
    // installPack runs `pnpm install`, which would execute the profile's
    // preinstall/install/postinstall/prepare scripts.
    if (opts.policy !== undefined) {
      const evaluation = await this.policy(file, {
        ...(opts.policy.repository !== undefined ? { repository: opts.policy.repository } : {}),
        ...(opts.policy.collectionDir !== undefined ? { collectionDir: opts.policy.collectionDir } : {}),
        ...(opts.policy.executionTarget !== undefined ? { executionTarget: opts.policy.executionTarget } : {}),
      })
      if (evaluation.verdict.decision !== 'ALLOW') {
        throw new Error(
          `dsh-pack: install blocked by trust policy before materialization (${evaluation.verdict.decision}): `
          + evaluation.verdict.errors.join('; '),
        )
      }
    }
    const buffer = readFileSync(file)
    const { result, staging } = await installPack(buffer, opts, {
      home: this.home(),
      installedDshVersion: this.installedDshVersion(),
    })
    rmSync(staging, { recursive: true, force: true })
    return result
  }

  async diff(fileA: string, fileB: string): Promise<PackDiff> {
    const payload = await diffPacks(readFileSync(fileA), readFileSync(fileB))
    return { ...payload, fileA, fileB }
  }

  async sign(file: string, opts: SignOptions): Promise<SignResult> {
    return signPackFile(file, { ...opts })
  }

  async keygen(opts: { outDir?: string }): Promise<KeygenResult> {
    const { keyId, privateKey, publicKey } = generateKeypair(opts.outDir ?? process.cwd())
    return { keyId, privateKey, publicKey }
  }
}

/** Auto-generated README.md inside every pack. */
export function renderReadme(manifest: Manifest, warnings: readonly Warning[]): string {
  const lines = [
    `# ${manifest.profile.name} — dsh-pack snapshot`,
    '',
    `- format: ${manifest.format} (schemaVersion ${manifest.schemaVersion})`,
    `- created: ${manifest.createdAt}`,
    `- dsh: ${manifest.runtime.dshVersion}`,
    `- configHash: ${manifest.configHash}`,
    `- installable: ${String(manifest.installable)}`,
    '',
    '## Restore',
    '',
    '```text',
    `/pack install ${manifest.profile.name}.dshpack`,
    '```',
    '',
    '## Bundles',
    '',
    ...manifest.bundles.map((bundle) => `- ${bundle}`),
    '',
    '## Warnings',
    '',
    ...(warnings.length > 0 ? warnings.map((warning) => `- [${warning.code}] ${warning.message}`) : ['- none']),
    '',
  ]
  return lines.join('\n')
}
