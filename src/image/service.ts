/**
 * v0.4 ImageService implementation (DESIGN-v0.4.md §9/§10, D27): imports
 * `.dshpack` artifacts into the content-addressed local store (digest =
 * contentHash, D21), resolves tag/digest references, and runs images as
 * TEMPORARY runtime profiles — verify → trust policy → materialize → boot
 * hand-off, never touching the user's existing profiles (D27).
 *
 * Trust is a thin bridge on top of v0.3 verification (D29): the Signature
 * verify section proves integrity + authenticity, applyTrustPolicy enforces
 * `--require-signature` / `--require-trusted` (VALID ≠ TRUSTED, D19).
 * @module @why-daydream/dsh-pack/image/service
 */

import { randomUUID } from 'node:crypto'
import { existsSync, readFileSync, readdirSync, rmSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { installPack } from '../install.ts'
import { validateManifest } from '../manifest.ts'
import { computePackContentHash, openPack } from '../pack-builder.ts'
import { verifyPack } from '../verify.ts'
import { buildImageManifest, imageManifestDigest, type ImageManifest } from './manifest.ts'
import type { ImageReference } from './reference.ts'
import { parseReference, repository } from './reference.ts'
import { ImageResolveError, resolveImage, type ResolvedImage } from './resolver.ts'
import type { ImageStore } from './store.ts'
import { applyTrustPolicy, type TrustPolicy } from './trust.ts'
import { loadRegistryCredentials } from './registry/auth.ts'
import { RegistryClient } from './registry/client.ts'
import { pullImage, type PullResult } from './registry/pull.ts'
import { pushImage, type PushResult } from './registry/push.ts'
import { parseRemoteReference, registryBaseUrl, repoPath } from './registry/reference.ts'
import type { DshContentDigest, OciManifestDigest } from './digests.ts'
import { DEFAULT_LOCKFILE, addLockEntry, loadLockfile, saveLockfile } from './lockfile.ts'
import {
  loadTrustPolicy, mergeCliTightening, resolveTrustPolicy, type TrustPolicyDecision,
} from './trust-policy.ts'

export interface ImportOptions {
  /** Apply a mutable tag after import, e.g. `why-daydream/agent:v1`. */
  tag?: string
}

export interface ImportResult {
  /** artifact digest (= pack contentHash, D21). */
  digest: string
  manifestDigest: string
  /** the applied tag reference, when `--tag` was given. */
  ref?: string
}

export interface InspectResult {
  ref: string
  manifest: ImageManifest
  manifestDigest: string
  artifactDigest: string
  artifactSize: number
  configHash: string
  signature: 'VALID' | 'INVALID' | 'MISSING' | 'UNKNOWN'
  trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A'
}

export interface RunOptions extends TrustPolicy {
  /** Persistent install instead of a temporary runtime (image → mutable profile, D26). */
  profile?: string
}

export interface RunResult {
  profile: string
  dir: string
  configHash: string
  digest: string
  signature: 'VALID' | 'INVALID' | 'MISSING'
  trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A'
  /** hand-off command (temporary runtime: `dsh --profile .run-<uuid>`). */
  boot: string
  temporary: boolean
}

export interface LockOptions {
  /** lockfile path (default `dsh-lock.json` in cwd). */
  file?: string
}

export interface LockResult {
  mutableRef: string
  /** immutable ref: `repo@sha256:<manifestDigest>` (D48). */
  resolved: string
  manifestDigest: OciManifestDigest
  file: string
}

export interface PruneEntry {
  digest: string
  bytes: number
}

export interface RuntimeCacheEntry {
  profile: string
  bytes: number
}

export interface PruneResult {
  reachableManifests: number
  reachableBlobs: number
  orphanManifests: PruneEntry[]
  orphanBlobs: PruneEntry[]
  runtimeCache: RuntimeCacheEntry[]
  reclaimableBytes: number
  applied: boolean
}

/** Recursive directory size in bytes (for the prune runtime report, D62). */
function dirBytes(dir: string): number {
  let total = 0
  for (const name of readdirSync(dir)) {
    const absolute = join(dir, name)
    total += statSync(absolute).isDirectory() ? dirBytes(absolute) : statSync(absolute).size
  }
  return total
}

/** v0.4 default in-process image service (LocalImageStore backend). */
export class DefaultImageService {
  constructor(
    private readonly store: ImageStore,
    private readonly context: { home: string; installedDshVersion: string },
  ) {}

  /** Import a `.dshpack` into the store: blob + manifest (+ optional tag). */
  async import(packPath: string, options?: ImportOptions): Promise<ImportResult> {
    if (!existsSync(packPath)) throw new Error(`pack file not found: ${packPath}`)
    const bytes = readFileSync(packPath)
    const contentHash = await computePackContentHash(bytes)

    // manifest inputs come from the pack's own manifest.json
    const opened = await openPack(bytes)
    let configHash = ''
    let dshVersion = ''
    try {
      const parsed = validateManifest(opened.manifest)
      if (!parsed.ok) throw new Error(`pack manifest invalid: ${parsed.errors.join('; ')}`)
      configHash = parsed.manifest.configHash
      dshVersion = parsed.manifest.runtime.dshVersion
    } finally {
      rmSync(opened.root, { recursive: true, force: true })
    }

    await this.store.putBlob(contentHash, bytes)
    const nodeMajor = Number(process.versions.node.split('.')[0])
    const manifest = buildImageManifest({
      artifactDigest: contentHash,
      artifactSize: bytes.length,
      configHash,
      dshVersion,
      ...(Number.isFinite(nodeMajor) ? { node: `>=${nodeMajor}` } : {}),
    })
    const manifestDigest = imageManifestDigest(manifest)
    await this.store.putManifest(manifestDigest, manifest)

    let ref: string | undefined
    if (options?.tag !== undefined) {
      const target = parseReference(options.tag)
      if (target.digest !== undefined || target.tag === undefined) {
        throw new Error('--tag must be a tag reference (e.g. why-daydream/agent:v1), not a digest')
      }
      await this.store.setTag(repository(target), target.tag, manifestDigest)
      ref = `${repository(target)}:${target.tag}`
    }
    return { digest: contentHash, manifestDigest, ...(ref !== undefined ? { ref } : {}) }
  }

  /** Inspect an image: manifest + artifact facts + signature/trust status. */
  async inspect(refStr: string): Promise<InspectResult> {
    const resolved = await resolveImage(this.store, parseReference(refStr))
    const bytes = await this.store.getBlob(resolved.artifactDigest)
    let signature: InspectResult['signature'] = 'UNKNOWN'
    let trust: InspectResult['trust'] = 'N/A'
    if (bytes !== undefined) {
      const { report } = await verifyPack(bytes, { installedDshVersion: this.context.installedDshVersion })
      const section = report.sections.find((s) => s.name === 'Signature')
      const verdict = applyTrustPolicy(section, {})
      signature = verdict.signature
      trust = verdict.trust
    }
    return {
      ref: refStr,
      manifest: resolved.manifest,
      manifestDigest: resolved.manifestDigest,
      artifactDigest: resolved.artifactDigest,
      artifactSize: resolved.manifest.artifact.size,
      configHash: resolved.manifest.configHash,
      signature,
      trust,
    }
  }

  /** Add a mutable tag alias (tag updates are allowed; digests never move). */
  async tag(source: string, target: string): Promise<string> {
    const resolved = await resolveImage(this.store, parseReference(source))
    const targetRef = parseReference(target)
    if (targetRef.digest !== undefined || targetRef.tag === undefined) {
      throw new Error('target must be a tag reference (e.g. why-daydream/agent:latest), not a digest')
    }
    await this.store.setTag(repository(targetRef), targetRef.tag, resolved.manifestDigest)
    return `${repository(targetRef)}:${targetRef.tag}`
  }

  /** Remove a tag, or a digest-form image (manifest + artifact blob). */
  async remove(refStr: string): Promise<void> {
    const ref = parseReference(refStr)
    if (ref.tag !== undefined && ref.digest === undefined) {
      await this.store.removeTag(repository(ref), ref.tag)
      return
    }
    if (ref.digest === undefined) throw new Error('reference must carry a tag or a digest')
    const resolved = await resolveImage(this.store, ref)
    // Dangling-ref guard: an image still referenced by any tag must not be
    // deleted — "CAS 可以脏，但引用图不能坏" (DESIGN-v0.4.md §7). Deleting
    // the manifest+blob here would break every other tag pointing at them.
    // Reference counting / GC is the v0.4.1 reservation.
    const live = (await this.store.listRefs()).filter((e) => e.manifestDigest === resolved.manifestDigest)
    if (live.length > 0) {
      const names = live.map((e) => `${e.repo}:${e.tag}`).join(', ')
      throw new Error(`image ${refStr} is still referenced by tag(s): ${names} — remove those tags first`)
    }
    await this.store.removeManifest(resolved.manifestDigest)
    await this.store.removeBlob(resolved.artifactDigest)
  }

  /** Resolve a reference to its manifest + artifact digest (digest-first). */
  async resolve(refStr: string): Promise<ResolvedImage & { ref: ImageReference }> {
    const ref = parseReference(refStr)
    return resolveImage(this.store, ref)
  }

  /** Push a local image to an OCI registry (DESIGN-v0.4.1.md §4). */
  async push(localRef: string, remoteRef: string): Promise<PushResult> {
    return pushImage(this.store, localRef, remoteRef, { installedDshVersion: this.context.installedDshVersion })
  }

  /** Pull from an OCI registry, digest-first (DESIGN-v0.4.1.md §5). */
  async pull(remoteRef: string, options?: { requireSignature?: boolean; requireTrusted?: boolean }): Promise<PullResult> {
    return pullImage(this.store, remoteRef, {
      installedDshVersion: this.context.installedDshVersion,
      ...(options?.requireSignature === true ? { requireSignature: true } : {}),
      ...(options?.requireTrusted === true ? { requireTrusted: true } : {}),
    })
  }

  /**
   * Lock a mutable remote tag to its immutable OCI manifest digest
   * (DESIGN-v0.4.2.md §9, D46/D48): resolve the remote manifest (the OCI
   * envelope is validated), pin `repo@sha256:<manifestDigest>` into
   * dsh-lock.json. Lock ≠ Trust (D47) — the lockfile is a version pin only;
   * running a locked image still runs the full OCI → DSH → Signature → Trust
   * chain (D49).
   */
  async lock(remoteRefStr: string, options?: LockOptions): Promise<LockResult> {
    const remoteRef = parseRemoteReference(remoteRefStr)
    const client = new RegistryClient({
      baseUrl: registryBaseUrl(remoteRef.registry),
      repo: repoPath(remoteRef),
      credentials: loadRegistryCredentials(remoteRef.registry),
    })
    const requested = remoteRef.digest ?? (remoteRef.tag as string)
    const { digest } = await client.getManifest(requested)
    if (remoteRef.digest !== undefined && digest !== remoteRef.digest) {
      throw new Error(`manifest digest mismatch: expected ${remoteRef.digest}, actual ${digest} (transport integrity failure)`)
    }
    const resolved = `${repository(remoteRef)}@${digest}`
    const file = options?.file ?? DEFAULT_LOCKFILE
    const lockfile = addLockEntry(loadLockfile(file), remoteRefStr, digest, resolved)
    saveLockfile(file, lockfile)
    return { mutableRef: remoteRefStr, resolved, manifestDigest: digest, file }
  }

  /**
   * Local CAS garbage collection (DESIGN-v0.4.2.md §12, D57–D63): mark-and-
   * sweep reachability over refs → manifests → artifact blobs. Only
   * UNREACHABLE objects are removed (D58); a blob reachable through ANY
   * manifest/ref is kept (D60). Default dry-run (D61); `--apply` performs the
   * destructive sweep. Runtime cache is REPORT-ONLY (D62 — no active-runtime
   * marker exists yet, conservative). dsh-lock.json / trust.yaml are NOT GC
   * roots (D63).
   */
  async prune(options?: { apply?: boolean }): Promise<PruneResult> {
    // Phase 1 — Mark (D59/D60): refs → manifest → artifact blob
    const reachableManifests = new Set<string>()
    const reachableBlobs = new Set<string>()
    for (const ref of await this.store.listRefs()) {
      reachableManifests.add(ref.manifestDigest)
      const manifest = await this.store.getManifest(ref.manifestDigest)
      if (manifest !== undefined) reachableBlobs.add(manifest.artifact.digest)
    }

    // Phase 2 — Sweep (compute; delete only with --apply)
    const orphanManifests: PruneEntry[] = []
    for (const digest of await this.store.listManifestDigests()) {
      if (reachableManifests.has(digest)) continue
      orphanManifests.push({ digest, bytes: (await this.store.getManifestSize(digest)) ?? 0 })
    }
    const orphanBlobs: PruneEntry[] = []
    for (const digest of await this.store.listBlobDigests()) {
      if (reachableBlobs.has(digest)) continue
      orphanBlobs.push({ digest, bytes: (await this.store.getBlobSize(digest)) ?? 0 })
    }

    // Runtime cache — conservative report-only (D62)
    const runtimeCache: RuntimeCacheEntry[] = []
    const profilesDir = join(this.context.home, 'profiles')
    if (existsSync(profilesDir)) {
      for (const name of readdirSync(profilesDir)) {
        if (!name.startsWith('.run-')) continue
        runtimeCache.push({ profile: name, bytes: dirBytes(join(profilesDir, name)) })
      }
    }

    const reclaimableBytes = [...orphanManifests, ...orphanBlobs].reduce((sum, e) => sum + e.bytes, 0)
    if (options?.apply === true) {
      for (const entry of orphanManifests) await this.store.removeManifest(entry.digest)
      for (const entry of orphanBlobs) await this.store.removeBlob(entry.digest as DshContentDigest)
    }
    return {
      reachableManifests: reachableManifests.size,
      reachableBlobs: reachableBlobs.size,
      orphanManifests,
      orphanBlobs,
      runtimeCache,
      reclaimableBytes,
      applied: options?.apply === true,
    }
  }

  /** Ensure a remote ref's image is local: pull when missing (cache-only policy). */
  private async ensureLocal(refStr: string): Promise<PullResult | undefined> {
    try {
      await resolveImage(this.store, parseReference(refStr))
      return undefined // already local (tag mirror from a previous pull)
    } catch (error) {
      if (!(error instanceof ImageResolveError)) throw error
      // not local → digest-first pull (verify → trust → import). Trust policy
      // enforcement stays in run() — a rejected image must fail before boot.
      return pullImage(this.store, refStr, { installedDshVersion: this.context.installedDshVersion })
    }
  }

  /** All tag refs, for `image ls` (REPOSITORY / TAG / DIGEST). */
  async list(): Promise<Awaited<ReturnType<ImageStore['listRefs']>>> {
    return this.store.listRefs()
  }

  /**
   * Run an image: resolve → blob present → v0.3 full verify (integrity +
   * signature + D15 version gate) → trust policy → materialize a TEMPORARY
   * runtime profile (`.run-<uuid>`, D27) → boot hand-off. `--profile <name>`
   * degrades to a persistent install (image → mutable profile, D26).
   */
  async run(refStr: string, options?: RunOptions): Promise<RunResult> {
    const ref = parseReference(refStr)
    // remote refs: ensure the image is local first — pull (digest-first,
    // verify → trust → import) when the tag/digest is not in the store.
    let localRef = refStr
    if (ref.registry !== undefined) {
      const pulled = await this.ensureLocal(refStr)
      if (pulled !== undefined && ref.digest !== undefined) {
        // Digest-form remote ref: the local store is keyed by the DSH manifest
        // digest (imageManifestDigest), NOT the OCI manifest digest — resolve
        // the pulled image through its DSH manifest digest.
        localRef = `local@${pulled.dshManifestDigest}`
      }
    }
    const resolved = await resolveImage(this.store, parseReference(localRef))
    const bytes = await this.store.getBlob(resolved.artifactDigest)
    if (bytes === undefined) {
      throw new ImageResolveError(`artifact blob ${resolved.artifactDigest} missing from local store`)
    }

    // 1. integrity + authenticity: v0.3 full verify (also the D15 version gate).
    //    An INVALID signature hard-fails here; a MISSING one is left to the
    //    trust policy below.
    const { report } = await verifyPack(bytes, { installedDshVersion: this.context.installedDshVersion })
    if (!report.ok) {
      const failed = report.sections.filter((s) => s.status === 'fail')
        .map((s) => `${s.name}: ${s.detail ?? ''}`)
      throw new Error(`image verification failed before boot: ${failed.join('; ')}`)
    }

    // 2. trust policy (VALID ≠ TRUSTED, D19/D29): the LOCAL trust.yaml policy
    //    (DESIGN-v0.4.2.md D50–D56) applies to REMOTE images; CLI can only
    //    TIGHTEN it (D54). Local refs keep the v0.4.1 CLI-only semantics (D53).
    const signatureSection = report.sections.find((s) => s.name === 'Signature')
    let decision: TrustPolicyDecision = {
      requireSignature: options?.requireSignature === true,
      requireTrusted: options?.requireTrusted === true,
    }
    if (ref.registry !== undefined) {
      // D54: CLI can only TIGHTEN the local policy — effective = policy OR CLI
      decision = mergeCliTightening(resolveTrustPolicy(loadTrustPolicy(this.context.home), repository(ref)), {
        ...(options?.requireSignature === true ? { requireSignature: true } : {}),
        ...(options?.requireTrusted === true ? { requireTrusted: true } : {}),
      })
    }
    const verdict = applyTrustPolicy(signatureSection, {
      ...(decision.requireSignature ? { requireSignature: true } : {}),
      ...(decision.requireTrusted ? { requireTrusted: true } : {}),
      ...(decision.trustedKeys !== undefined ? { trustedKeys: decision.trustedKeys } : {}),
    })
    if (!verdict.ok) throw new Error(`image trust policy rejected: ${verdict.error}`)

    // 3. materialize: temporary runtime profile (D27) or persistent (--profile)
    const temporary = options?.profile === undefined
    const profile = temporary ? `.run-${randomUUID()}` : (options.profile as string)
    const { staging } = await installPack(bytes, { profile }, {
      home: this.context.home,
      installedDshVersion: this.context.installedDshVersion,
    })
    rmSync(staging, { recursive: true, force: true })

    return {
      profile,
      dir: join(this.context.home, 'profiles', profile),
      configHash: resolved.manifest.configHash,
      digest: resolved.artifactDigest,
      signature: verdict.signature,
      trust: verdict.trust,
      boot: `dsh --profile ${profile}`,
      temporary,
    }
  }
}
