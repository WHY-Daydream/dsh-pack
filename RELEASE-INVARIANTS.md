# v0.5.0-rc.1 — Release Invariant Review

> Freeze of the v0.5 security semantics after the supply-chain adversarial matrix
> (rc.1). Every invariant below maps **Decision → implementation entry →
> adversarial/regression test → status**, plus a call-site reverse audit that
> checks for SECOND entry points bypassing an invariant.
>
> The review adds NO new mechanisms — it only verifies that the existing
> semantics are pinned by tests and that no old API path sneaks around them.

## Method

```
Invariant
   ↓
DESIGN Decision (D-number)
   ↓
Implementation entry (file:function)
   ↓
Adversarial / regression tests
   ↓
PASS / GAP
```

---

## RI-01 — RI-16 release gate

| ID | Invariant | Decision | Implementation entry | Adversarial / regression test | Status |
|----|-----------|----------|----------------------|-------------------------------|--------|
| RI-01 | `configHash ≠ contentHash ≠ OCI blobDigest ≠ OCI manifestDigest` | D21/D32/D48, DESIGN §7.3 | `pack-builder.ts:computePackContentHash` · `image/manifest.ts:imageManifestDigest` · `image/registry/descriptor.ts:verifyDescriptorBytes` | `image-registry-e2e.spec.ts` criterion 2 (`blobDigest ≠ contentHash`), identity unit tests | PASS |
| RI-02 | Artifact Signature `VALID ≠ TRUSTED` | D19/D29/D55 | `image/trust.ts:applyTrustPolicy` (keyId whitelist) | `policy.spec.ts` (untrusted signer), `image-registry-e2e` criterion 6, `lifecycle.spec.ts` N3.2 | PASS |
| RI-03 | Evidence Signature `VALID ≠ Evidence Issuer TRUSTED` | D109 | `trust-policy-v2.ts` `attestation-issuer` step (`evidenceTrustedKeys`) | `evidence-ambiguity.spec.ts` N5.1, `mutable-ref-cache.spec.ts` N1.4 | PASS |
| RI-04 | Evidence must bind the actual immutable `contentHash` | D64/D100 | `evidence/envelope.ts:verifyEvidenceSubject` + recomputed `computePackContentHash` at sign/verify | `evidence-substitution.spec.ts` (N4), `dependency-reresolution.spec.ts` N2.6 (provenance subject binding) | PASS |
| RI-05 | Evidence statement ↔ external document digest-bound | D120/D100 | `service.ts:sbomCandidates` / `attestationCandidates` (document sha256 must equal the claimed digest) | `evidence-substitution.spec.ts` (SBOM document substitution — N4), `mutable-ref-cache.spec.ts` N1.10 | PASS |
| RI-06 | Build Evidence ≠ Artifact Identity — Evidence never enters `contentHash` | D65/D72 | `evidence/envelope.ts` (evidence points AT the artifact, never joins it) | `evidence-substitution.spec.ts`, DESIGN identity tests | PASS |
| RI-07 | build-time provenance ≠ post-build endorsement | D72 | `evidence/build-record.ts:captureBuildRecord` (captured AT build) + receipt anti-tamper (`subject == actual contentHash`) in `evidence/service.ts:provenance` | `evidence-substitution.spec.ts` N4.7, `dependency-reresolution.spec.ts` N2.6 | PASS |
| RI-08 | Declared Capability ≠ Observed Capability | D83/D99 | `evidence/capability.ts:generateCapabilityManifestFromPack` (declared) vs `evidence/attestation.ts` observed sets + `comparison` | `attestation.spec.ts`, `capability.spec.ts` (declaredButNotObserved) | PASS |
| RI-09 | `partial/unknown` observation ≠ authoritative absence | D99/D102 | `trust-policy-v2.ts` `COVERAGE_ORDER` (unknown < partial < complete) + attestation.ts coverage semantics | `policy.spec.ts` coverage cases, `evidence-ambiguity.spec.ts` N5.2 | PASS |
| RI-10 | Conflicting trusted Evidence → `AMBIGUOUS → DENY`, never first/latest/majority wins | D110/D124–128 | `trust-policy-v2.ts:evaluateTrustPolicyV2` (semanticKey distinct set after VALID→subject→trust→constraints) | `evidence-ambiguity.spec.ts` N5.1–N5.10 (incl. order/createdAt/signer randomization) | PASS |
| RI-11 | Runtime Attestation must exact-match the CURRENT execution target | D111/D137–138 | `trust-policy-v2.ts:evaluateAttestationTarget` (env == target exact; ambiguity AFTER filter) | `native-cross-platform.spec.ts` N6.3–N6.6, N6.9–N6.10 | PASS |
| RI-12 | native/build metadata is fact, not compatibility; `UNKNOWN` stays `UNKNOWN` | D135–139/D78/D79 | `evidence/sbom.ts:packageMetadataProperties` / `nativeReasons` (indicator only; no fabricated state) | `native-cross-platform.spec.ts` N6.1, N6.7, N6.8 | PASS · fixed in `4adf4e2` |
| RI-13 | Trust Decision happens BEFORE materialize / package execution | D115 | `service.ts:DefaultPackager.install` policy gate (non-ALLOW → throw) before `installPack`; `image/service.ts:run` verify→trust→installPack | `lifecycle.spec.ts` N3.3–N3.6 (sentinel absent on DENY) | PASS · fixed in `0fec6f0` |
| RI-14 | `Lock ≠ Trust`, `Cache ≠ Trust`, mutable tag ≠ immutable identity | D112/D113/D129 | `image/service.ts:ensureLocal` (remote tag → current registry; digest → re-verified cache hit) · `image/lockfile.ts` | `mutable-ref-cache.spec.ts` N1.1–N1.7 (tag drift, cache hit, 404, tamper) | PASS · fixed in `5c9efa6` |
| RI-15 | Dependency identity only from artifact-contained materials; ZERO re-resolution | D130–134 | `generateSbomFromPack` / `generateCapabilityManifestFromPack` / `runAttestation` all `extractTarGz(packBuffer)`; `install.ts:frozenInstall` (no fallback); `resolveDependencies` is build-time only | `dependency-reresolution.spec.ts` N2.1–N2.10 (drift matrix + child-process spy) | PASS |
| RI-16 | Disposable Runtime = application-level hygiene isolation; crash never pollutes | D118/D92/D27 | `install.ts` staging + atomic swap (MUST-3); `attestation.ts` disposable staging + env allowlist (no host secrets); `run()` `.run-<uuid>` temporary profiles | `lifecycle.spec.ts` (isolation/pollution regression matrix), N3.5/N3.6 | PASS |

All 16 invariants: **PASS**.

---

## Five real implementation gaps found by the adversarial matrix

These prove rc.1 was not formal testing — each was a genuine hole:

| Round | Gap | Root cause | Fix |
|-------|-----|-----------|-----|
| N3 | `pnpm install` / lifecycle execution ran BEFORE the trust decision | materialize order | `0fec6f0` — trust gate first (D115) |
| N4 | SBOM evidence never validated the actual document digest | document substitution | `f3d6dca` — D120 document digest check |
| N5 | Runtime Attestation equivalence keyed on the whole document digest → non-deterministic run metadata (D96) caused false `AMBIGUOUS` | wrong semantic anchor | `44d81cd` — semantic identity (resultDigest+target+coverage, D125) |
| N1 | remote mutable tag resolved through the stale local tag mirror → registry drifted to B but cached A ran | tag mirror ≠ identity | `5c9efa6` — remote tag follows the current registry identity (D112/D129) |
| N6 | unreadable package metadata (`meta.manifest ?? {}`) fabricated `native:detected=false` | UNKNOWN → false guess | `4adf4e2` — UNKNOWN stays UNKNOWN (D139) |

---

## Call-site reverse audit (second-entry check)

Audit question per gate: *is there ANOTHER API path that bypasses the invariant?*

| Entry point | Checked | Result |
|-------------|---------|--------|
| `installPack` / materialize | exactly TWO callers: `service.ts:install` (policy gate first — RI-13) and `image/service.ts:run` (verifyPack → trust → installPack). No un-gated caller; CLI `install` goes through the gated service. | PASS · no bypass |
| `run` / remote run / locked run | every run path: resolve → blob present → `verifyPack` (integrity + signature) → trust policy → materialize. Locked run = digest identity; mutable run = current registry identity (N1 fix). | PASS |
| `ensureLocal` / `pull` / cache | `pull` fixed order: transport → DSH integrity → signature → trust → import; `ensureLocal`: tag → always current registry, digest → cache hit still re-verified by `run` (RI-14). | PASS |
| `verifyPack` | called by pull, push (self-attestation), inspect, run — every place bytes become a runtime input; recomputes contentHash over actual bytes (RI-01/RI-04). | PASS |
| evidence collectors (sbom / capability / provenance / attestation) | all `extractTarGz(packBuffer, tmpdir)` — artifact-contained only; envelope + subject + document-digest verification before any consumption (RI-04/05/15); provenance reads the build receipt sidecar with subject anti-tamper (RI-07). | PASS |
| `evaluateTrustPolicyV2` | single evaluator for the v2 chain; order: presence → signature → issuer → coverage → matrix → exact target → ambiguity (RI-09/10/11). | PASS |
| `buildSbomDocument` | artifact-contained inputs only; native/UNKNOWN semantics fixed (RI-12); deterministic canonical bytes (D80). | PASS |
| runtime attestation collector (`runAttestation`) | cold boot runs in a DISPOSABLE staging profile with an env allowlist (never host secrets, D92); it is the attestation protocol itself, not a bypass — and it never mutates the formal profile. | PASS |
| `resolveDependencies` | ONLY caller is `pack()` (build time — the artifact's origin). No verify/evidence/policy/install path calls it (RI-15, proven by the N2.10 child-process spy). | PASS |
| `import` / `diff` / `inspect` / `resolve` | non-executing operations (byte caching / pure inspection / store queries) — no lifecycle execution, no trust decision needed (D53 local semantics). | PASS |

**Audit conclusion: no second entry point bypasses any of the 16 invariants.**

---

## rc.1 final state

```
typecheck        ✅
vitest           324/324 ✅ (34 files)
attack surfaces   7 (N3/N7/N4/N5/N1/N2/N6)
real gaps found  5 (N3/N4/N5/N1/N6), all fixed with minimal fixes
new mechanisms   0 (no new Evidence types / trust.yaml features / encryption / compatibility engines)
```

The v0.5 story: every critical security assertion has been actively attack-tested —
reproducibility is artifact-contained, authorization is never cached, and
UNKNOWN is never guessed into a security fact.
