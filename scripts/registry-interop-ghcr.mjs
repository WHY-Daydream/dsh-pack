#!/usr/bin/env node
/**
 * v0.6.0-beta.2 Real GHCR Registry Interoperability gate (I8/I9/I10, D183–D190).
 * Runs ONLY in GitHub Actions via workflow_dispatch
 * (.github/workflows/registry-interop-ghcr.yml) with GITHUB_TOKEN + packages:write.
 *
 * The gate RECORDS the ACTUAL GHCR capability observed (D183 — capability is
 * decided by protocol response, never hardcoded by vendor name):
 *
 *   GHCR mode: native-referrers | tag-fallback
 *
 * I8 ★ — GHCR publication round-trip: Agent Image M + Evidence E accepted;
 *         M before == M after (D155/D188 — publication never rewrites the subject)
 * I9 ★ — GHCR discovery: discover (repo, M) → the FULL OCI→DSH verification
 *         chain runs (digest, subject == M, carrier, envelope, contentHash == C) —
 *         NOT just "the API returned a descriptor" (D189)
 * I10  — GHCR Trust integration smoke: real remote evidence + trusted issuer →
 *        ALLOW; remove the evidence trusted key → DENY (a real registry must
 *        NOT change Trust semantics; only the current trust.yaml decides)
 *
 * Log discipline: host/repo/status/mode only — NEVER tokens or auth headers.
 * Credentials come from env (injected by the workflow, die with the job).
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

const DSH_VERSION = '0.1.0-rc.5'
const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
const OCI_EMPTY_BLOB = Buffer.from('{}', 'utf8')
const OCI_EMPTY_BLOB_DIGEST = 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'

// ---- env (injected by the workflow, dies with the job) ----
const GHCR_OWNER = process.env['GHCR_OWNER']
const RUN_ID = process.env['RUN_ID']
const REGISTRY_USERNAME = process.env['DSH_REGISTRY_USERNAME']
const REGISTRY_TOKEN = process.env['DSH_REGISTRY_TOKEN']

const REPO = 'dsh-pack-interop'
// lowercase canonical OCI namespace (D183 fixture — no uppercase ghost identity)
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
const log = (step) => console.log(`\n[GHCR-INTEROP] ${step}`)

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`

/** Minimal raw probe (status + a header only — no auth values logged). */
async function rawProbe(url, headers = {}) {
  const response = await fetch(url, { headers, redirect: 'follow' })
  return { status: response.status, headers: response.headers }
}

async function main() {
  console.log(`[GHCR-INTEROP] target: ${REMOTE_REF} (repo ${repository})`)

  if (GHCR_OWNER === undefined || RUN_ID === undefined || REGISTRY_USERNAME === undefined || REGISTRY_TOKEN === undefined) {
    console.error('[GHCR-INTEROP] missing env (GHCR_OWNER/RUN_ID/DSH_REGISTRY_USERNAME/DSH_REGISTRY_TOKEN).')
    console.error('[GHCR-INTEROP] runs ONLY in GitHub Actions registry-interop-ghcr.yml (workflow_dispatch, GITHUB_TOKEN).')
    process.exit(2)
  }

  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-ghcr-interop-'))
  try {
    const credentials = { username: REGISTRY_USERNAME, password: REGISTRY_TOKEN }
    const client = new RegistryClient({ baseUrl: 'https://ghcr.io', repo: repository, credentials })

    // ---- 0. protocol ping: 401 + Bearer challenge (anonymous) ----
    log('item 0: GET /v2/ → 401 + Bearer challenge')
    const ping = await rawProbe('https://ghcr.io/v2/')
    check('GET /v2/ returns 401', ping.status === 401, `status ${ping.status}`)
    const challenge = ping.headers.get('www-authenticate') ?? ''
    check('WWW-Authenticate is a Bearer challenge', challenge.toLowerCase().startsWith('bearer'), challenge.slice(0, 40))

    // ---- fixture: a minimal Agent Image M (DSH-anchored subject) ----
    log('fixture: push Agent Image M (subject of the evidence)')
    const artifactBytes = Buffer.from(`agent-run-${RUN_ID}-bytes`)
    const contentHash = sha256(artifactBytes) // the independently known C (D150)
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
    const mBefore = mDigest
    log(`  M before = ${mBefore}`)

    // ---- evidence key + signed provenance envelope ----
    const { privateKey } = generateKeyPairSync('ed25519')
    const keyFile = join(root, 'evidence.pem')
    writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
    const envelope = signEvidence({
      type: 'build-provenance', // the DSH provenance Evidence type (PROVENANCE_EVIDENCE_TYPE)
      subjectContentHash: contentHash,
      statement: { schemaVersion: 1, format: 'dsh-test', note: `ghcr-interop-${RUN_ID}` },
      keyPath: keyFile,
    })

    // ---- I8 ★ publication: evidence E attached to M (D160–D165) ----
    log('I8 ★: publish Evidence E to GHCR (subject = M)')
    const pub = await publishRemoteEvidence({
      reference: REMOTE_REF,
      subjectDescriptor: { mediaType: OCI_MANIFEST_MEDIA_TYPE, digest: mDigest, size: subjectManifest.length },
      envelopeBytes: Buffer.from(JSON.stringify(envelope), 'utf8'),
      artifactType: EVIDENCE_ARTIFACT_TYPES.provenance,
      credentials,
    })
    check('publication acknowledged', /^sha256:[0-9a-f]{64}$/.test(pub.evidenceManifestDigest))
    // D183 — RECORD the ACTUAL GHCR capability observed (never preset)
    console.log(`  GHCR mode: ${pub.mode}`)
    check('publication mode is a recognized OCI path', pub.mode === 'native-referrers' || pub.mode === 'tag-fallback', pub.mode)

    // ---- I8 ★ subject unchanged: M after == M before (D155) ----
    log('I8 ★: M after == M before (publication never rewrites the subject)')
    const mAfter = (await client.getManifest(mDigest)).digest
    check('M unchanged by evidence publication (D155)', mAfter === mBefore, `${mBefore} vs ${mAfter}`)

    // ---- I9 ★ discovery: full OCI→DSH verification chain on GHCR data ----
    log('I9 ★: discover (repo, M) → full verification chain')
    const discovery = await discoverRemoteEvidence({ reference: REMOTE_REF, actualContentHash: contentHash, credentials })
    check('discovery complete', discovery.complete === true)
    if (discovery.complete) {
      check('exactly the published evidence is discovered', discovery.candidates.length === 1, `count ${discovery.candidates.length}`)
      const candidate = discovery.candidates[0]
      check('candidate source is a recognized path', candidate?.source === 'referrers-api' || candidate?.source === 'tag-fallback', candidate?.source)
      // D189 — full verification: OCI digest → subject == M → envelope → contentHash == C
      check('candidate subject == M', candidate?.subject.manifestDigest === mBefore)
      check('candidate contentHash == C', candidate?.subject.contentHash === contentHash)
      check('candidate envelope verified (type provenance)', candidate?.evidenceType === 'provenance')
    }

    // ---- I10 trust smoke: real GHCR evidence + CURRENT trust.yaml ----
    log('I10: trust smoke — trusted issuer → ALLOW; revoked → DENY (real registry does not change Trust semantics)')
    const home = join(root, 'home')
    mkdirSync(home, { recursive: true })
    const keyId = envelope.signing.keyId
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
      reference: REMOTE_REF,
      actualContentHash: contentHash,
      home,
      credentials,
      signature: { status: 'MISSING', trust: 'N/A' },
    })
    check('trusted issuer → ALLOW', allow.decision === 'ALLOW', allow.verdict.errors.join('; '))

    writeTrust([]) // revoke the evidence issuer
    const deny = await evaluateRemoteEvidenceTrust({
      reference: REMOTE_REF,
      actualContentHash: contentHash,
      home,
      credentials,
      signature: { status: 'MISSING', trust: 'N/A' },
    })
    check('issuer revoked → DENY (current trust.yaml decides)', deny.decision === 'DENY', deny.verdict.errors.join('; '))
    check('DENY reason is issuer trust (VALID ≠ TRUSTED)', deny.verdict.errors.some((e) => e.includes('UNTRUSTED_EVIDENCE_ISSUER')))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }

  console.log(`\n[GHCR-INTEROP] ${passed} passed, ${failed} failed`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((error) => {
  console.error(`[GHCR-INTEROP] fatal: ${String(error)}`)
  process.exit(1)
})
