#!/usr/bin/env node
/**
 * Real GHCR Protocol E2E — the Internet North-Star (DESIGN-v0.4.2.md §3/§7,
 * D41–D44). Runs ONLY in GitHub Actions via workflow_dispatch
 * (.github/workflows/ghcr-e2e.yml) with GITHUB_TOKEN + packages:write; never
 * on fork PRs (D43). This script is a PROTOCOL acceptance test — the mock
 * registry stays the business-logic regression gate (D41).
 *
 * 8-item checklist (§3): ① GET /v2/ → 401 + Bearer challenge
 * ② token acquisition with pull,push scope ③ HEAD blob 404 → 200 (+
 * Docker-Content-Digest) ④ POST uploads/ → Location → PUT ?digest → 201
 * ⑤ OCI manifest PUT Content-Type ⑥ tag pull Content-Type + Docker-Content-
 * Digest == bytes ⑦ digest pull == tag resolve ⑧ DSH contentHash + Signature
 * VALID + Trust VERIFIED + run configHash consistent (D44).
 *
 * Log discipline (§5): only host/repo/status/scope — NEVER tokens or auth
 * headers. Credentials come from env (D42/D45) and die with the job.
 */
import { execFile } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { LocalImageStore } from '../lib/image/local-store.js'
import { RegistryClient } from '../lib/image/registry/client.js'
import { DefaultImageService } from '../lib/image/service.js'
import { DefaultPackager } from '../lib/service.js'
import { buildGhcrRepository } from './ghcr-fixture.mjs'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'

// ---- env (D42/D45: injected by the workflow, dies with the job) ----
const GHCR_OWNER = process.env['GHCR_OWNER']
const RUN_ID = process.env['RUN_ID']
const REGISTRY_USERNAME = process.env['DSH_REGISTRY_USERNAME']
const REGISTRY_TOKEN = process.env['DSH_REGISTRY_TOKEN']

const REPO = 'dsh-pack-e2e'
// OCI Distribution Spec: repository <name> must be lowercase [a-z0-9...].
// GitHub account/org display names (e.g. WHY-Daydream) are NOT valid OCI
// namespace components — map the owner to a canonical lowercase repository
// (shared fixture module: target ref / registry URL / Bearer scope all use
// the SAME string — no uppercase ghost identity in auth scope).
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
const log = (step) => console.log(`\n[GHCR-E2E] ${step}`)

// ---- raw HTTP probe helpers (status/headers only — no auth values logged) ----
async function rawFetch(url, { method = 'GET', headers = {} } = {}) {
  const response = await fetch(url, { method, headers, redirect: 'follow' })
  const status = response.status
  const outHeaders = {}
  response.headers.forEach((value, key) => { outHeaders[key] = value })
  const body = Buffer.from(await response.arrayBuffer())
  return { status, headers: outHeaders, body }
}

const sha256 = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`

function basicAuth(user, token) {
  return `Basic ${Buffer.from(`${user}:${token}`, 'utf8').toString('base64')}`
}

async function pnpmAvailable() {
  try {
    await execFileAsync('pnpm', ['--version'], { timeout: 10_000 })
    return true
  } catch {
    return false
  }
}

// ---- fixture: machine A builds a signed portable pack ----
async function makeSignedPack(outDir) {
  const homeA = join(outDir, 'homeA')
  mkdirSync(join(homeA, 'profiles', 'web'), { recursive: true })
  const profileA = join(homeA, 'profiles', 'web')
  writeFileSync(join(profileA, 'package.json'), JSON.stringify({
    name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
  }, null, 2))
  writeFileSync(join(profileA, 'cordis.patch.yml'), `# web
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
`)
  await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: profileA, timeout: 120_000 })

  const packager = new DefaultPackager({ home: homeA, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.2' })
  const packed = await packager.pack({ profile: 'web', outDir, portable: true })
  const key = await packager.keygen({ outDir: mkdtempSync(join(outDir, 'keys-')) })
  const signed = await packager.sign(packed.file, { key: key.privateKey, signer: 'ghcr-e2e' })
  return { file: signed.file, keyId: key.keyId }
}

function makeImageEnv(root) {
  const home = join(root, 'home')
  mkdirSync(join(home, 'profiles'), { recursive: true })
  const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
    home,
    installedDshVersion: DSH_VERSION,
  })
  return { images, home }
}

async function main() {
  console.log(`[GHCR-E2E] target: ${REMOTE_REF} (scope ${SCOPE})`)

  // ---- guard: only meaningful in CI with credentials ----
  if (GHCR_OWNER === undefined || RUN_ID === undefined || REGISTRY_USERNAME === undefined || REGISTRY_TOKEN === undefined) {
    console.error('[GHCR-E2E] missing env (GHCR_OWNER/RUN_ID/DSH_REGISTRY_USERNAME/DSH_REGISTRY_TOKEN).')
    console.error('[GHCR-E2E] this script runs ONLY in GitHub Actions ghcr-e2e.yml (workflow_dispatch, GITHUB_TOKEN).')
    process.exit(2)
  }
  if (!(await pnpmAvailable())) {
    console.error('[GHCR-E2E] pnpm unavailable (corepack) — run materialization needs pnpm.')
    process.exit(2)
  }

  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-ghcr-'))
  try {
    // ---- ① 401 + Bearer challenge on unauthenticated /v2/ ----
    log('item 1: GET /v2/ → 401 + WWW-Authenticate Bearer challenge')
    const ping = await rawFetch('https://ghcr.io/v2/')
    check('GET /v2/ returns 401', ping.status === 401, `status ${ping.status}`)
    const challenge = ping.headers['www-authenticate'] ?? ''
    check('WWW-Authenticate is a Bearer challenge', challenge.toLowerCase().startsWith('bearer'), challenge.slice(0, 40))

    // ---- ② token acquisition with pull,push scope ----
    log('item 2: Bearer token acquisition (scope pull,push)')
    const tokenUrl = `https://ghcr.io/token?service=ghcr.io&scope=${encodeURIComponent(SCOPE)}`
    const tokenRes = await rawFetch(tokenUrl, { headers: { Authorization: basicAuth(REGISTRY_USERNAME, REGISTRY_TOKEN) } })
    check('token endpoint 200', tokenRes.status === 200, `status ${tokenRes.status}`)
    let bearerToken
    try {
      bearerToken = JSON.parse(tokenRes.body.toString('utf8')).token
    } catch {
      bearerToken = undefined
    }
    check('token acquired', typeof bearerToken === 'string' && bearerToken !== '', 'no token in response')
    if (bearerToken === undefined) process.exit(1)

    // ---- fixture + sign + import (machine A) ----
    log('fixture: portable signed pack → local import')
    const { file, keyId } = await makeSignedPack(root)
    const { images: imagesA } = makeImageEnv(join(root, 'machine-a'))
    const localTag = `org/${REPO}:run-${RUN_ID}`
    const imported = await imagesA.import(file, { tag: localTag })
    const originalConfigHash = (await imagesA.resolve(localTag)).manifest.configHash
    console.log(`  contentHash ${imported.digest} / key SHA256:${keyId}`)

    // ---- ③④⑤ push (Bearer flow, blob HEAD 404 → upload → 201, manifest PUT) ----
    log('item 3/4/5: push → HEAD blob 404 → POST uploads/ → PUT ?digest → 201 → manifest PUT')
    process.env['DSH_REGISTRY_USERNAME'] = REGISTRY_USERNAME
    process.env['DSH_REGISTRY_TOKEN'] = REGISTRY_TOKEN
    const pushed = await imagesA.push(localTag, REMOTE_REF)
    delete process.env['DSH_REGISTRY_USERNAME']
    delete process.env['DSH_REGISTRY_TOKEN']
    check('push succeeded with OCI manifest PUT (Content-Type accepted)', /^sha256:[0-9a-f]{64}$/.test(pushed.ociManifestDigest))
    check('blobDigest ≠ contentHash (D32)', pushed.blobDigest !== imported.digest)
    check('contentHash unchanged by push', pushed.contentHash === imported.digest)

    // HEAD blob now exists (200) + Docker-Content-Digest verifiable
    const probeClient = new RegistryClient({
      baseUrl: 'https://ghcr.io',
      repo: repository,
      credentials: { username: REGISTRY_USERNAME, password: REGISTRY_TOKEN },
    })
    check('blob HEAD now 200 (exists)', await probeClient.blobExists(pushed.blobDigest))

    // ---- ⑥ tag pull: Content-Type + Docker-Content-Digest == bytes ----
    log('item 6: tag pull → Content-Type + Docker-Content-Digest match bytes')
    const manifestProbe = await rawFetch(`https://ghcr.io/v2/${repository}/manifests/run-${RUN_ID}`, {
      headers: { Accept: OCI_MANIFEST_MEDIA_TYPE, Authorization: `Bearer ${bearerToken}` },
    })
    check('manifest GET 200', manifestProbe.status === 200, `status ${manifestProbe.status}`)
    check('Content-Type is OCI image manifest', manifestProbe.headers['content-type']?.startsWith(OCI_MANIFEST_MEDIA_TYPE) === true)
    const actualManifestDigest = sha256(manifestProbe.body)
    check(
      'Docker-Content-Digest == actual manifest bytes',
      manifestProbe.headers['docker-content-digest'] === actualManifestDigest,
      `header ${manifestProbe.headers['docker-content-digest']} vs bytes ${actualManifestDigest}`,
    )
    check('manifest digest matches the push result', actualManifestDigest === pushed.ociManifestDigest)

    // ---- ⑦⑧ pull tag on a fresh machine (contentHash + VALID + VERIFIED) ----
    log('item 7/8: fresh machine pull by tag → DSH layer checks (D44)')
    process.env['DSH_PACK_TRUSTED_KEYS'] = keyId
    const { images: imagesB } = makeImageEnv(join(root, 'machine-b'))
    const pulled = await imagesB.pull(REMOTE_REF)
    delete process.env['DSH_PACK_TRUSTED_KEYS']
    check('contentHash identical after push→pull', pulled.contentHash === imported.digest)
    check('Signature VALID', pulled.signature === 'VALID', pulled.signature)
    check('Trust VERIFIED', pulled.trust === 'VERIFIED', pulled.trust)

    // ---- ⑦ digest pull on another fresh machine (immutable) ----
    log('item 7 (digest form): pull @manifestDigest on a fresh machine')
    const digestRef = `ghcr.io/${repository}@${pushed.ociManifestDigest}`
    const { images: imagesC } = makeImageEnv(join(root, 'machine-c'))
    const byDigest = await imagesC.pull(digestRef)
    check('digest pull yields the same contentHash as tag pull', byDigest.contentHash === pulled.contentHash)

    // ---- ⑧ run --require-trusted → configHash consistent ----
    log('item 8: run --require-trusted → configHash consistent (trust before materialization)')
    process.env['DSH_PACK_TRUSTED_KEYS'] = keyId
    const run = await imagesC.run(digestRef, { requireTrusted: true })
    delete process.env['DSH_PACK_TRUSTED_KEYS']
    check('run materialized a temporary runtime', run.temporary === true && run.profile.startsWith('.run-'))
    check('run configHash == original pack configHash', run.configHash === originalConfigHash)
    check('run signature/trust carry through', run.signature === 'VALID' && run.trust === 'VERIFIED')
  } finally {
    rmSync(root, { recursive: true, force: true })
  }

  console.log(`\n[GHCR-E2E] ${passed} passed, ${failed} failed`)
  process.exit(failed > 0 ? 1 : 0)
}

main().catch((error) => {
  console.error(`[GHCR-E2E] fatal: ${String(error)}`)
  process.exit(1)
})
