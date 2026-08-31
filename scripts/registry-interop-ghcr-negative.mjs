#!/usr/bin/env node
/**
 * v0.6.0-rc.1 Real GHCR NEGATIVE acceptance gate (R8, D191–D199).
 * Runs ONLY in GitHub Actions via workflow_dispatch
 * (.github/workflows/registry-interop-ghcr.yml) with GITHUB_TOKEN + packages:write.
 *
 * beta.2 covered the happy path (I8/I9/I10). rc.1 attacks the NEGATIVE side on
 * a REAL registry:
 *
 *   R8a — mutable tag drift never rewrites a resolved immutable identity:
 *         publish Evidence E against M, lock M by digest, re-point the mutable
 *         tag at a DIFFERENT manifest M2 → discovery pinned to M still finds E
 *         and M2's "evidence" (none) is never conflated with M's (D197/N1).
 *   R8b — RC6-N4 ★ distribution cannot manufacture authorization: the SAME
 *         GHCR bytes ALLOW with the current trusted issuer, then DENY after the
 *         key is removed locally — GHCR never becomes a Trust Authority
 *         (D189, only the current trust.yaml decides).
 *   R8c — GHCR negative acceptance: a forged descriptor / wrong digest is
 *         rejected by the full verification chain, not accepted "because GHCR
 *         said so" (D191/D195).
 *
 * The gate RECORDS the ACTUAL GHCR capability observed (D183, never preset):
 *
 *   GHCR mode: native-referrers | tag-fallback
 *
 * Release Interop Debt (non-blocking for rc.1): a real `oras discover` CLI
 * smoke (dsh-pack publish → oras discover sees it; ORAS-compatible publish →
 * dsh-pack discover sees it) is scheduled for the FINAL v0.6 Release Review —
 * this script deliberately does NOT install or shell out to ORAS (D187: ORAS
 * is an independent oracle, never a runtime dependency).
 *
 * Log discipline: host/repo/status/mode only — NEVER tokens or auth headers.
 */
import { createHash, generateKeyPairSync } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { RegistryClient } from '../lib/image/registry/client.js'
import { buildOciManifest } from '../lib/image/registry/manifest.js'
import { signEvidence } from '../lib/evidence/envelope.js'
import { publishRemoteEvidence } from '../lib/evidence/remote/publication.js'
import { discoverRemoteEvidence } from '../lib/evidence/remote/discovery.js'
import { evaluateRemoteEvidenceTrust } from '../lib/evidence/remote/trust.js'
import { EVIDENCE_ARTIFACT_TYPES } from '../lib/evidence/remote/types.js'
import { buildGhcrRepository } from './ghcr-fixture.mjs'

const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
const OCI_EMPTY_BLOB = Buffer.from('{}', 'utf8')
const OCI_EMPTY_BLOB_DIGEST = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'

// ---- env (injected by the workflow, dies with the job) ----
const GHCR_OWNER = process.env['GHCR_OWNER']
const RUN_ID = process.env['RUN_ID']
const REGISTRY_USERNAME = process.env['DSH_REGISTRY_USERNAME']
const REGISTRY_TOKEN = process.env['DSH_REGISTRY_TOKEN']

const REPO = 'dsh-pack-interop'
const { repository, remoteRef, scope } = buildGhcrRepository(GHCR_OWNER, REPO)
const REMOTE_REF = remoteRef(`run-${RUN_ID}`)
const SCOPE = scope()

let passed = 0
let failed = 0
function check(name, ok, detail = '') {
  if (ok) {
    passed++
    console.log(`  ✓ ${name}`)
  } else {
    failed++
    console.error(`  ✗ ${name}${detail !== '' ? ` — ${detail}` : ''}`)
  }
}
const log = (step) => console.log(`\n[GHCR-NEGATIVE] ${step}`)

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`

async function main() {
  console.log(`[GHCR-NEGATIVE] target: ${REMOTE_REF} (repo ${repository})`)

  if (GHCR_OWNER === undefined || RUN_ID === undefined || REGISTRY_USERNAME === undefined || REGISTRY_TOKEN === undefined) {
    console.error('[GHCR-NEGATIVE] missing env (GHCR_OWNER/RUN_ID/DSH_REGISTRY_USERNAME/DSH_REGISTRY_TOKEN).')
    console.error('[GHCR-NEGATIVE] runs ONLY in GitHub Actions registry-interop-ghcr.yml (workflow_dispatch, GITHUB_TOKEN).')
    process.exit(2)
  }

  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-ghcr-negative-'))
  try {
    const credentials = { username: REGISTRY_USERNAME, password: REGISTRY_TOKEN }
    const client = new RegistryClient({ baseUrl: 'https://ghcr.io', repo: repository, credentials })

    // ---- fixture: Agent Image M + signed provenance E ----
    log('fixture: push Agent Image M + sign provenance')
    const artifactBytes = Buffer.from(`agent-negative-${RUN_ID}-bytes`)
    const contentHash = sha256(artifactBytes)
    await client.uploadBlob(OCI_EMPTY_BLOB_DIGEST, OCI_EMPTY_BLOB)
    await client.uploadBlob(contentHash, artifactBytes)
    const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: contentHash, mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
    const configDigest = sha256(configBytes)
    await client.uploadBlob(configDigest, configBytes)
    const subjectManifest = Buffer.from(JSON.stringify(buildOciManifest(
      { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: configDigest, size: configBytes.length },
      { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: contentHash, size: artifactBytes.length },
    )), 'utf8')
    const mDigest = sha256(subjectManifest)
    const putSubject = await client.putManifestRaw(`run-${RUN_ID}`, subjectManifest)
    check('Agent Image M PUT accepted', putSubject.status === 200 || putSubject.status === 201, `status ${putSubject.status}`)

    const { privateKey } = generateKeyPairSync('ed25519')
    const keyFile = join(root, 'evidence.pem')
    writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
    const envelope = signEvidence({
      type: 'build-provenance', // the DSH provenance Evidence type (PROVENANCE_EVIDENCE_TYPE)
      subjectContentHash: contentHash,
      statement: { schemaVersion: 1, format: 'dsh-test', note: `ghcr-negative-${RUN_ID}` },
      keyPath: keyFile,
    })
    const keyId = envelope.signing.keyId

    // ---- R8a setup: publish E to GHCR (subject = M) ----
    const pub = await publishRemoteEvidence({
      reference: REMOTE_REF,
      subjectDescriptor: { mediaType: OCI_MANIFEST_MEDIA_TYPE, digest: mDigest, size: subjectManifest.length },
      envelopeBytes: Buffer.from(JSON.stringify(envelope), 'utf8'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      credentials,
    })
    console.log(`  GHCR mode: ${pub.mode}`)
    check('publication mode is a recognized OCI path', pub.mode === 'native-referrers' || pub.mode === 'tag-fallback', pub.mode)

    // ---- R8a ★ tag drift: lock M by digest, then re-point the mutable tag ----
    log('R8a ★: mutable tag drift never rewrites the resolved immutable M (D197/N1)')
    const digestRef = REMOTE_REF.split(':')[0] + `@${mDigest}` // digest-pinned reference
    // a DIFFERENT, VALID OCI manifest (empty config/layers). The previous
    // equals(subjectManifest) guard was ALWAYS true (identical build args →
    // identical bytes), so the mutable tag received the illegal
    // {"drifted":true} body and GHCR rejected the PUT with 500. The placeholder
    // is a legal manifest that differs from M by construction.
    const drifted = driftedPlaceholder()
    // push the drifted manifest under the SAME mutable tag (tag → M2)
    const driftDigest = sha256(drifted)
    await client.uploadBlob(OCI_EMPTY_BLOB_DIGEST, OCI_EMPTY_BLOB)
    const putDrift = await client.putManifestRaw(`run-${RUN_ID}`, drifted)
    check('mutable tag re-pointed to a different manifest', putDrift.status === 200 || putDrift.status === 201, `status ${putDrift.status}`)

    // discovery PINNED to M by digest: the tag drift must be INVISIBLE
    const pinned = await discoverRemoteEvidence({ reference: digestRef, actualContentHash: contentHash, credentials })
    check('digest-pinned discovery complete', pinned.complete === true)
    if (pinned.complete) {
      check('pinned discovery finds exactly E for M (not the drifted tag)', pinned.candidates.length === 1, `count ${pinned.candidates.length}`)
      check('candidate subject == M (tag drift ignored)', pinned.candidates[0]?.subject.manifestDigest === mDigest)
      check('candidate contentHash == C', pinned.candidates[0]?.subject.contentHash === contentHash)
    }

    // ---- R8b ★ RC6-N4: same GHCR bytes, current trust.yaml decides ----
    log('R8b ★ RC6-N4: same GHCR bytes ALLOW (trusted) then DENY (revoked locally)')
    const home = join(root, 'home')
    mkdirSync(home, { recursive: true })
    const trustPolicy = (evidenceTrustedKeys) => JSON.stringify({
      version: 2,
      registries: {
        'ghcr.io/*': {
          requireSignature: false,
          requireTrusted: false,
          evidenceTrustedKeys,
          requireEvidence: { provenance: { required: true } },
        },
      },
    }, null, 2)
    const writeTrust = (keys) => writeFileSync(join(home, 'trust.yaml'), trustPolicy(keys), 'utf8')

    writeTrust([keyId])
    const allow = await evaluateRemoteEvidenceTrust({
      reference: digestRef, actualContentHash: contentHash, home, credentials,
      signature: { status: 'MISSING', trust: 'N/A' },
    })
    check('trusted issuer → ALLOW', allow.decision === 'ALLOW', allow.verdict.errors.join('; '))

    writeTrust(['sha256:' + '0'.repeat(64)]) // issuer removed locally
    const deny = await evaluateRemoteEvidenceTrust({
      reference: digestRef, actualContentHash: contentHash, home, credentials,
      signature: { status: 'MISSING', trust: 'N/A' },
    })
    check('issuer revoked locally → DENY (GHCR is NOT a Trust Authority)', deny.decision === 'DENY', deny.verdict.errors.join('; '))
    check('DENY is issuer trust (UNTRUSTED_EVIDENCE_ISSUER)', deny.verdict.errors.some((e) => e.includes('UNTRUSTED_EVIDENCE_ISSUER')))

    // ---- R8c ★ negative acceptance: wrong digest never passes ----
    log('R8c ★: a wrong digest is rejected by the verification chain, not by "who said so"')
    const forgedDiscovery = await discoverRemoteEvidence({ reference: digestRef, actualContentHash: sha256(Buffer.from('attacker-known-C')), credentials })
    check('discovery with WRONG C fails closed (no ALLOW-able candidate)', forgedDiscovery.complete === true && forgedDiscovery.candidates.length === 0, `complete=${forgedDiscovery.complete} candidates=${forgedDiscovery.candidates.length}`)
  } finally {
    rmSync(root, { recursive: true, force: true })
  }

  console.log(`\n[GHCR-NEGATIVE] ${passed} passed, ${failed} failed`)
  process.exit(failed > 0 ? 1 : 0)
}

/** A minimal OCI manifest that is NOT the subject manifest (mutable-tag drift). */
function driftedPlaceholder() {
  return Buffer.from(JSON.stringify({
    schemaVersion: 2,
    mediaType: OCI_MANIFEST_MEDIA_TYPE,
    config: { mediaType: 'application/vnd.oci.empty.v1+json', digest: OCI_EMPTY_BLOB_DIGEST, size: OCI_EMPTY_BLOB.length },
    layers: [],
  }), 'utf8')
}

main().catch((error) => {
  console.error(`[GHCR-NEGATIVE] fatal: ${String(error)}`)
  process.exit(1)
})
