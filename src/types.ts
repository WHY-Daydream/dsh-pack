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
  /** v0.5: capture + write a build receipt sidecar (always written; D68–D71). */
  provenance?: boolean
  /** v0.5: sign a `build-provenance` Evidence at build time with this private key (D68 dirty FAIL unless allowDirty). */
  evidenceKey?: string
  /** v0.5: allow signing provenance from a dirty tree — records sourceTreeDigest (D68). */
  allowDirty?: boolean
  /** v0.5: display signer label for the signed evidence (display only). */
  signer?: string
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
  /** v0.5: path of the written build receipt sidecar (D68–D71), if captured. */
  receipt?: string
  /** v0.5: path of the signed `build-provenance` Evidence, when --evidence-key. */
  evidence?: string
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

// --- v0.5 Signed Evidence Envelope (DESIGN-v0.5.0.md §3, D64–D67) ---

/**
 * Module-level input to `signEvidence` (src/evidence/envelope.ts): the
 * evidence payload is authenticated via a canonical statement digest, and the
 * signature covers the domain-separated canonical object
 * `{domain, schemaVersion, type, subject.contentHash, statementDigest}` —
 * NOT the raw envelope JSON (D66; domain = `dsh-pack:evidence:v1` so the same
 * key signing other protocols can never collide).
 */
export interface EvidenceSignInput {
  /** Evidence class, e.g. `build-provenance` / `sbom` / `runtime-attestation` (D64). */
  type: string
  /** The immutable artifact anchor this evidence is ABOUT (D64). */
  subjectContentHash: string
  /** The evidence payload (opaque to the envelope; hashed canonically). */
  statement: unknown
  /** Path to the private key PEM (pkcs8). */
  keyPath: string
  /** Optional human-readable signer label (display only — trust identity is keyId). */
  signer?: string
}

/** v0.5 evidence signing block — self-contained like SignatureInfo (D66). */
export interface EvidenceSigning {
  algorithm: 'ed25519'
  /**
   * sha256 of the public key DER (SPKI) — display + future policy trust anchor.
   * Verification ALWAYS recomputes this from the embedded public key and
   * rejects mismatches: policy consumes verifiedKeyId, never a claimed keyId.
   */
  keyId: string
  /** Public key PEM (SPKI) — self-contained verification. */
  publicKey: string
  /** base64 ed25519 signature over the domain-separated `evidenceSigningInput(...)`. */
  signature: string
  createdAt: string
}

/**
 * v0.5 Signed Evidence Envelope (DESIGN-v0.5.0.md §3): a standalone,
 * self-authenticating statement ABOUT an immutable artifact. `subject.contentHash`
 * binds the evidence to exactly one artifact (D64); `statementDigest` anchors the
 * payload; the signature covers the canonical `{type, subject, statementDigest}`
 * triple (D66). Evidence is a SEPARATE object — it never enters the artifact
 * contentHash and never touches the existing Artifact Signature anchor (D65).
 */
export interface EvidenceEnvelope {
  schemaVersion: 1
  /** Evidence class, e.g. `build-provenance` / `sbom` / `runtime-attestation` (D64). */
  type: string
  subject: { contentHash: string }
  /** The evidence payload (opaque to the envelope). */
  statement: unknown
  /** `sha256:` + hex over `canonicalJson(statement)` — the statement anchor. */
  statementDigest: string
  signing: EvidenceSigning
}

/** Options for `/pack evidence sign` (v0.5). */
export interface EvidenceSignOptions {
  /** Evidence class (D64). */
  type: string
  /** The evidence payload (object) — canonicalized, hashed and signed. */
  statement: unknown
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Optional human-readable signer label (display only). */
  signer?: string
  /** Output directory (default: alongside the input pack). */
  outDir?: string
}

/** Result of `/pack evidence sign`. */
export interface EvidenceSignResult {
  /** Written sidecar path `<name>.dshpack.evidence.json`. */
  file: string
  /** Signer fingerprint (sha256 of the public key DER). */
  keyId: string
  /** The immutable subject anchor (D64). */
  contentHash: string
  type: string
  statementDigest: string
  signer?: string
}

/** Result of `/pack evidence verify`. */
export interface EvidenceVerifyResult {
  ok: boolean
  keyId: string
  type: string
  /** The envelope's declared subject anchor. */
  subject: string
  statementDigest: string
  /** Ordered failure reasons (empty when ok). */
  errors: string[]
}

/** Options for `/pack evidence provenance` (v0.5 alpha.2, D68–D71). */
export interface ProvenanceSignOptions {
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Allow signing from a dirty tree — uses the recorded sourceTreeDigest (D68). */
  allowDirty?: boolean
  /** Optional human-readable signer label (display only). */
  signer?: string
  /** Output directory (default: alongside the input pack). */
  outDir?: string
}

/**
 * Result of `/pack evidence provenance`: the build-provenance Evidence signed
 * from the pack's BUILD-TIME receipt (never from the current repo state, D68).
 */
export interface ProvenanceSignResult extends EvidenceSignResult {
  /** Full git commit SHA recorded at build time (D68), if the site was a git repo. */
  gitCommit?: string
  /** Whether the build tree was dirty at pack time (D68). */
  dirty: boolean
  /** sourceTreeDigest present when dirty (D68). */
  sourceTreeDigest?: string
  /**
   * D72: this result is always a POST-BUILD endorsement — the unsigned
   * receipt is re-signed here, so it is never marked `build-time`.
   */
  captureMode: 'post-build-receipt'
}

/** Options for `/pack evidence sbom` (v0.5 alpha.3, D73–D80). */
export interface SbomSignOptions {
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Optional human-readable signer label (display only). */
  signer?: string
  /** Output directory (default: alongside the input pack). */
  outDir?: string
}

/**
 * Result of `/pack evidence sbom`: the CycloneDX 1.7 document
 * (`documents/<sbomDigest>.cdx.json`) plus its Signed Evidence envelope
 * (`sbom/<statementDigest>.json`) bound to the artifact contentHash (D75).
 */
export interface SbomSignResult extends EvidenceSignResult {
  /** The standalone CycloneDX document path (D73/D75). */
  documentFile: string
  /** Deterministic digest over the document bytes (D80). */
  sbomDigest: string
  /** Number of CycloneDX components (display + tests). */
  componentCount: number
}

/** Options for `/pack evidence capability` (v0.5 alpha.4, D81–D88). */
export interface CapabilitySignOptions {
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Optional human-readable signer label (display only). */
  signer?: string
  /** Output directory (default: alongside the input pack). */
  outDir?: string
}

/**
 * Result of `/pack evidence capability`: the declared capability manifest
 * document (`documents/<capabilityDigest>.capability.json`) plus its Signed
 * Evidence envelope (`capability/<statementDigest>.json`) bound to the
 * artifact contentHash (D82).
 */
export interface CapabilitySignResult extends EvidenceSignResult {
  /** The standalone declared-capability manifest document path. */
  documentFile: string
  /** Deterministic digest over the document bytes (D88). */
  capabilityDigest: string
  /** Number of declared capabilities (providers + services; display + tests). */
  capabilityCount: number
}

/** Options for `/pack evidence attestation` (v0.5 beta.1, D89–D97). */
export interface AttestationSignOptions {
  /** Path to the private key PEM (pkcs8). */
  key: string
  /** Optional human-readable signer label (display only). */
  signer?: string
  /** Output directory (default: alongside the input pack). */
  outDir?: string
  /** Extra module dirs copied into the disposable profile node_modules (fixtures). */
  extraModules?: string[]
  /** Cold-boot child timeout in ms (default 60s). */
  timeoutMs?: number
}

/**
 * Result of `/pack evidence attestation`: the Runtime Attestation document
 * (`documents/<attestationDigest>.attestation.json`) plus its Signed Evidence
 * envelope (`attestation/<statementDigest>.json`) bound to the artifact
 * contentHash (D89). Metadata is non-deterministic; `resultDigest` covers the
 * normalized observation (D96).
 */
export interface AttestationSignResult extends EvidenceSignResult {
  /** The standalone attestation document path. */
  documentFile: string
  /** Digest over the exact document bytes. */
  attestationDigest: string
  /** Deterministic digest over the normalized observation (D96). */
  resultDigest: string
  coldBootStatus: 'PASS' | 'FAIL'
  cleanupStatus: 'PASS' | 'FAIL'
  /** Number of observed capabilities (display + tests). */
  observedCount: number
}
