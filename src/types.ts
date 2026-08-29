/**
 * Shared v0.1 types for dsh-pack. Mirrors DESIGN.md Appendix A (Packager
 * Service API) and the frozen manifest schema (§3.3).
 * @module @why-daydream/dsh-pack/types
 */

/** Pack service options (DESIGN.md Appendix A, frozen v0.1). */
export interface PackOptions {
  /** Profile name under `$DSH_HOME/profiles/<profile>`. */
  profile: string
  /** Preflight aborts on any violation (exit code 3). */
  strict?: boolean
  /** Output directory for the `.dshpack` file (default cwd). */
  outDir?: string
  /** Allow a pack containing high-confidence secrets (default false). */
  allowSecrets?: boolean
  /** Allow `file:`/`link:` directory deps → `installable:false` pack (D7). */
  allowNonportable?: boolean
  /** v0.2 placeholder. */
  portable?: boolean
}

/** Install service options (DESIGN.md Appendix A, frozen v0.1). */
export interface InstallOptions {
  /** Override `manifest.profile.name`. */
  profile?: string
  /** Replace an existing same-named profile (staging + atomic swap). */
  force?: boolean
  /** Skip the exact dshVersion match (D15). */
  ignoreRuntimeVersion?: boolean
}

/** Result of a successful pack. */
export interface PackResult {
  /** Absolute path of the created `.dshpack`. */
  file: string
  /** Packed profile name. */
  profile: string
  /** The generated manifest. */
  manifest: Manifest
  /** Warning list also persisted to `metadata/warnings.json`. */
  warnings: Warning[]
  /** Number of high-confidence secrets redacted. */
  redacted: number
}

/** Summary returned by `/pack inspect`. */
export interface PackInspection {
  file: string
  manifest: Manifest
  warnings: Warning[]
  /** Entry path → byte size, in archive order. */
  entries: { path: string; size: number }[]
}

/** One section of a verify report. */
export interface VerificationSection {
  name: string
  status: 'ok' | 'fail' | 'warn'
  detail?: string
}

/** Result of `/pack verify`. */
export interface VerificationReport {
  ok: boolean
  sections: VerificationSection[]
}

/** Result of `/pack install`. */
export interface InstallResult {
  profile: string
  dir: string
}

/** A diagnostic warning persisted to `metadata/warnings.json`. */
export interface Warning {
  code: string
  message: string
}

/** One observed config layer (DESIGN.md §4.3). */
export interface LayerInfo {
  type: 'bundle' | 'profile' | 'home' | 'cli-overlay'
  /** Logical identifier, never a filesystem path. */
  id: string
  included: boolean
  rows: number
  reason?: 'machine-local' | 'invocation-local'
}

/** Classified dependency spec (DESIGN.md §5.2). */
export type SpecKind = 'npm' | 'github' | 'tarball' | 'file' | 'link'

/** A local (non-portable) dependency entry (DESIGN.md §5.3). */
export interface LocalDep {
  name: string
  spec: string
  kind: Exclude<SpecKind, 'npm' | 'github'>
  /** Absolute path on the pack machine — diagnostics only, never packed into configHash. */
  resolved: string
  /** false until vendored; --portable marks closure members true. */
  portable?: boolean
}

/** Dependency resolution result (DESIGN.md §5.3). */
export interface DependencyTree {
  lockfile: string
  direct: Record<string, string>
  /** name → locked version (source of truth: pnpm-lock.yaml). */
  closure: Record<string, string>
  localDeps: LocalDep[]
  /** Floating github branch, missing lockfile, … */
  warnings: string[]
}

/** Frozen manifest schema v1 (DESIGN.md §3.3). */
export interface Manifest {
  format: 'dshpack'
  schemaVersion: 1
  profile: { name: string }
  snapshot: { scope: 'profile'; excludedLayersPresent: boolean }
  runtime: {
    dshVersion: string
    nodeVersion: string
    pnpmVersion: string
    platform: string
  }
  installable: boolean
  portable: boolean
  bundles: string[]
  dependencies: Record<string, string>
  /** v0.2 --portable: vendored tgz file names (in `packages/`). */
  packages?: string[]
  secrets?: { redacted: number }
  configHash: string
  createdAt: string
  packager: { name: string; version: string }
}

/** One differing manifest field (v0.2 `/pack diff`). */
export interface ManifestChange {
  field: string
  before: unknown
  after: unknown
}

/** One bundle-level difference (added / removed / version changed). */
export interface BundleChange {
  name: string
  kind: 'added' | 'removed' | 'changed'
  before?: string
  after?: string
}

/** One config leaf difference inside the composed tree. */
export interface ConfigChange {
  /** Row + dotted field path, e.g. `llm-deepseek.config.temperature`. */
  path: string
  kind: 'added' | 'removed' | 'changed'
  before?: unknown
  after?: unknown
}

/** One dependency difference (spec and/or locked version). */
export interface DependencyChange {
  name: string
  specBefore?: string
  specAfter?: string
  versionBefore?: string
  versionAfter?: string
}

/** Result of `/pack diff <a> <b>` (v0.2). */
export interface PackDiff {
  fileA: string
  fileB: string
  manifest: ManifestChange[]
  bundles: BundleChange[]
  config: ConfigChange[]
  dependencies: DependencyChange[]
  configHashA: string
  configHashB: string
  configHashEqual: boolean
}

/** v0.3 embedded ed25519 signature (`metadata/signature.json`). */
export interface SignatureInfo {
  schemaVersion: 1
  algorithm: 'ed25519'
  /** sha256 of the public key DER (SPKI) — display + trust allowlist. */
  keyId: string
  /** Public key PEM (SPKI) — self-contained verification. */
  publicKey: string
  /** The signed integrity anchor (contentHash string). */
  contentHash: string
  /** base64 ed25519 signature over `contentHash`. */
  signature: string
  createdAt: string
}

/** Options for `/pack sign` (v0.3). */
export interface SignOptions {
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Optional human-readable signer identity for provenance.json. */
  signer?: string
  /** Output directory (default: alongside the input). */
  outDir?: string
  /** Replace an existing signature on an already-signed pack (default false). */
  force?: boolean
}

/** Result of `/pack sign`. */
export interface SignResult {
  file: string
  keyId: string
  contentHash: string
  signer?: string
}

/** Result of `/pack keygen`. */
export interface KeygenResult {
  privateKey: string
  publicKey: string
  keyId: string
}
