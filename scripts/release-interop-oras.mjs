#!/usr/bin/env node
/**
 * RG6-09 — real ORAS bidirectional interoperability smoke (v0.6.0 Final
 * Release Review, HARD RELEASE BLOCKER).
 *
 * Runs ONLY in GitHub Actions via workflow_dispatch
 * (.github/workflows/release-interop-oras.yml) where the OFFICIAL oras CLI
 * is installed (GitHub-hosted runner can reach the official releases).
 *
 * ORAS is used strictly as an INDEPENDENT interoperability oracle (D187):
 *   ORAS-01 — dsh-pack publish → real `oras discover` sees the referrer
 *   ORAS-02 — external ORAS-compatible publication → dsh-pack discover
 *             passes BOTH OCI and DSH Evidence verification
 *
 * It is NOT a runtime dependency (not in package.json) and no third-party
 * binary mirrors are used — only the official oras CLI from GitHub Actions.
 *
 * Log discipline: host/repo/status/mode only — NEVER tokens or auth headers.
 * Credentials come from env (injected by the workflow, die with the job).
 */
import { createHash, generateKeyPairSync } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { RegistryClient } from '../lib/image/registry/client.js'
import { buildOciManifest } from '../lib/image/registry/manifest.js'
import { signEvidence } from '../lib/evidence/envelope.js'
import { publishRemoteEvidence } from '../lib/evidence/remote/publication.js'
import { discoverRemoteEvidence } from '../lib/evidence/remote/discovery.js'
import { EVIDENCE_ARTIFACT_TYPES } from '../lib/evidence/remote/types.js'
import { buildGhcrRepository } from './ghcr-fixture.mjs'

const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
const OCI_EMPTY_BLOB = Buffer.from('{}', 'utf8')
const OCI_EMPTY_BLOB_DIGEST = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'

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
const log = (step) => console.log(`\n[ORAS-INTEROP] ${step}`)

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`

/** Run the OFFICIAL oras CLI (independent oracle). */
function oras(args, opts = {}) {
  return execFileSync('oras', args, { encoding: 'utf8', ...opts }).trim()
}

async function main() {
  console.log(`[ORAS-INTEROP] target: ${REMOTE_REF} (repo ${repository})`)

  if (GHCR_OWNER === undefined || RUN_ID === undefined || REGISTRY_USERNAME === undefined || REGISTRY_TOKEN === undefined) {
    console.error('[ORAS-INTEROP] missing env (GHCR_OWNER/RUN_ID/DSH_REGISTRY_USERNAME/DSH_REGISTRY_TOKEN).')
    console.error('[ORAS-INTEROP] runs ONLY in GitHub Actions release-interop-oras.yml (workflow_dispatch, GITHUB_TOKEN).')
    process.exit(2)
  }

  // the OFFICIAL CLI must be present — this is the whole point of the gate
  try {
    const version = oras(['version'])
    console.log(`  oras CLI: ${version.split('\n')[0] ?? version}`)
    check('official oras CLI available', version.toLowerCase().includes('oras version'), version.slice(0, 60))
  } catch {
    console.error('[ORAS-INTEROP] oras CLI not found — install the official binary first.')
    process.exit(2)
  }

  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-oras-'))
  try {
    const credentials = { username: REGISTRY_USERNAME, password: REGISTRY_TOKEN }
    const client = new RegistryClient({ baseUrl: 'https://ghcr.io', repo: repository, credentials })

    // ---- fixture: Agent Image M (subject of the evidence) ----
    log('fixture: push Agent Image M')
    const artifactBytes = Buffer.from(`agent-oras-${RUN_ID}-bytes`)
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
    const digestRef = REMOTE_REF.split(':')[0] + `@${mDigest}`
    const tagRef = REMOTE_REF // ghcr.io/<repo>:run-<id>

    // ---- evidence key + signed build-provenance envelope ----
    const { privateKey } = generateKeyPairSync('ed25519')
    const keyFile = join(root, 'evidence.pem')
    writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
    const envelope = signEvidence({
      type: 'build-provenance',
      subjectContentHash: contentHash,
      statement: { schemaVersion: 1, format: 'dsh-test', note: `oras-interop-${RUN_ID}` },
      keyPath: keyFile,
    })
    const envelopeBytes = Buffer.from(JSON.stringify(envelope), 'utf8')

    // =====================================================================
    // ORAS-01 ★ — dsh-pack publish → real `oras discover` sees the referrer
    // =====================================================================
    log('ORAS-01 ★: dsh-pack publish Evidence E → oras discover sees it')
    const pub = await publishRemoteEvidence({
      reference: REMOTE_REF,
      subjectDescriptor: { mediaType: OCI_MANIFEST_MEDIA_TYPE, digest: mDigest, size: subjectManifest.length },
      envelopeBytes,
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      credentials,
    })
    console.log(`  GHCR mode: ${pub.mode}`)
    check('publication acknowledged', /^sha256:[0-9a-f]{64}$/.test(pub.evidenceManifestDigest))

    // the INDEPENDENT oras discover must see the referrer of M
    const discovered = oras(['discover', digestRef, '--format', 'json'])
    check('oras discover succeeded', discovered.length > 0)
    const discoveredJson = JSON.parse(discovered)
    const artifacts = discoveredJson?.artifacts ?? []
    check('oras discover lists exactly the published evidence', artifacts.length === 1, `count ${artifacts.length}`)
    const artifact = artifacts[0] ?? {}
    check('oras discover referrer digest == evidence manifest digest', artifact.digest === pub.evidenceManifestDigest, `${artifact.digest} vs ${pub.evidenceManifestDigest}`)
    check('oras discover artifactType == provenance', artifact.artifactType === EVIDENCE_ARTIFACT_TYPES.provenance, artifact.artifactType)

    // =====================================================================
    // ORAS-02 ★ — external ORAS publication → dsh-pack discover verifies it
    // =====================================================================
    log('ORAS-02 ★: ORAS-compatible publication → dsh-pack discover PASSES OCI + DSH verification')
    const externalEnvelope = signEvidence({
      type: 'build-provenance',
      subjectContentHash: contentHash,
      statement: { schemaVersion: 1, format: 'dsh-test', note: `oras-external-${RUN_ID}` },
      keyPath: keyFile,
    })
    const extFile = join(root, 'external-envelope.json')
    writeFileSync(extFile, JSON.stringify(externalEnvelope), 'utf8')
    // attach an envelope with the DSH carrier layer media type, subject = M —
    // a publication produced by an EXTERNAL OCI client (oras), not dsh-pack
    oras([
      'attach', '--subject', tagRef, '--artifact-type', EVIDENCE_ARTIFACT_TYPES.provenance,
      `${extFile}:application/vnd.dsh.evidence.envelope.v1+json`,
    ])
    check('oras attach (external publication) succeeded', true)

    const discovery = await discoverRemoteEvidence({ reference: digestRef, actualContentHash: contentHash, credentials })
    check('dsh-pack discovery complete', discovery.complete === true)
    if (discovery.complete) {
      // the EXTERNAL evidence is visible AND passes the full OCI→DSH chain
      const external = discovery.candidates.find((c) => {
        const stmt = c.envelope.statement ?? {}
        return stmt.note === `oras-external-${RUN_ID}`
      })
      check('external evidence discovered as a VALID candidate', external !== undefined)
      check('external candidate subject == M (OCI binding)', external?.subject.manifestDigest === mDigest)
      check('external candidate contentHash == C (DSH binding)', external?.subject.contentHash === contentHash)
      check('external candidate evidenceType == build-provenance', external?.evidenceType === 'build-provenance')
    }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }

  console.log(`\n[ORAS-INTEROP] ${passed} passed, ${failed} failed`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((error) => {
  console.error(`[ORAS-INTEROP] fatal: ${String(error)}`)
  process.exit(1)
})
