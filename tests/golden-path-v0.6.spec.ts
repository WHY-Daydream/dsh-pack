/**
 * RG6-06 — v0.6.0 distributed Evidence GOLDEN PATH (Final Release Review).
 *
 * The complete v0.6 story in one chain (replacing the v0.5 golden path):
 *
 *   Pack Agent Image (contentHash C) → Sign → Build Evidence chain
 *     (provenance / SBOM / capability / runtime attestation)
 *   → Publish Image → OCI M
 *   → Publish Evidence as OCI referrers
 *   → remote discovery (pagination complete)
 *   → OCI verification (digest + subject == M)
 *   → DSH contentHash C binding
 *   → Evidence issuer trust (VALID ≠ TRUSTED)
 *   → CURRENT trust.yaml decision
 *   → ALLOW
 *
 * Then ONLY the trusted issuer is revoked:
 *
 *   same Registry bytes · same M · same C → DENY (UNTRUSTED_EVIDENCE_ISSUER)
 *
 * This is the v0.6 release golden path: a real Registry can never turn
 * Distribution into a Trust Authority.
 * @module tests/golden-path-v0.6.spec.ts
 */
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { sha256Hex } from '../src/canonical.ts'
import { signEvidence } from '../src/evidence/envelope.ts'
import { discoverRemoteEvidence } from '../src/evidence/remote/discovery.ts'
import { evaluateRemoteEvidenceTrust } from '../src/evidence/remote/trust.ts'
import {
  EVIDENCE_ARTIFACT_TYPES,
  EVIDENCE_DOCUMENT_LAYER_MEDIA_TYPE,
  EVIDENCE_ENVELOPE_LAYER_MEDIA_TYPE,
} from '../src/evidence/remote/types.ts'
import { buildOciManifest } from '../src/image/registry/manifest.ts'
import { MockRegistry } from './helpers/mock-registry.ts'

const OCI_MANIFEST_MEDIA_TYPE = 'application/vnd.oci.image.manifest.v1+json'
const EMPTY_DESCRIPTOR = {
  mediaType: 'application/vnd.oci.empty.v1+json',
  digest: 'sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a',
  size: 2,
}
const TARGET = { os: 'linux', arch: 'x64' }

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-gp-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

const digestOf = (bytes: Buffer): string => `sha256:${sha256Hex(bytes)}`

interface GpCtx {
  mock: MockRegistry
  home: string
  keyFile: string
  keyId: string
  contentHash: string
  subjectDigest: string
  reference: string
}

/** Native mock registry + Agent Image M at :prod → C, plus an evidence key. */
async function setupGoldenPath(): Promise<GpCtx> {
  const mock = new MockRegistry()
  await mock.start()
  const home = tempRoot('home')
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const keyFile = join(home, 'evidence.pem')
  writeFileSync(keyFile, privateKey.export({ type: 'pkcs8', format: 'pem' }).toString())
  const keyId = sha256Hex(publicKey.export({ type: 'spki', format: 'der' }))

  // Pack Agent Image: artifact bytes → independently known contentHash C
  const artifactBytes = Buffer.from('golden-path-artifact-bytes')
  const contentHash = digestOf(artifactBytes)
  const configBytes = Buffer.from(JSON.stringify({ schemaVersion: 1, artifact: { digest: contentHash, mediaType: 'application/vnd.dsh.artifact.v1' } }), 'utf8')
  const agentManifest = Buffer.from(JSON.stringify(buildOciManifest(
    { mediaType: 'application/vnd.dsh.image.manifest.v1+json', digest: digestOf(configBytes), size: configBytes.length },
    { mediaType: 'application/vnd.dsh.pack.v1+gzip', digest: contentHash, size: artifactBytes.length },
  )), 'utf8')
  const subjectDigest = digestOf(agentManifest)
  mock.manifests.set('prod', { bytes: agentManifest, digest: subjectDigest })
  mock.manifests.set(subjectDigest, { bytes: agentManifest, digest: subjectDigest })

  const reference = `127.0.0.1:${mock.port}/company/prod:prod`
  return { mock, home, keyFile, keyId, contentHash, subjectDigest, reference }
}

function plainEnvelope(keyFile: string, contentHash: string, type: string, note: string): Buffer {
  const envelope = signEvidence({ type, subjectContentHash: contentHash, statement: { schemaVersion: 1, format: 'dsh-test', note }, keyPath: keyFile })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

function attestationDocument(tools: string[]): Buffer {
  return Buffer.from(JSON.stringify({
    declaredCapabilityDigest: 'sha256:' + 'b'.repeat(64),
    observation: { coverage: 'complete', reasons: [] },
    coldBoot: { status: 'PASS' },
    observed: { tools, skills: [], services: [], providers: [] },
    comparison: { missing: [], extra: [], mismatched: [] },
    effects: { network: 'NOT_PROBED', filesystem: 'NOT_PROBED', process: 'NOT_PROBED' },
    cleanup: { status: 'PASS' },
    environment: { os: TARGET.os, arch: TARGET.arch },
    resultDigest: 'sha256:' + 'c'.repeat(64),
  }), 'utf8')
}

function attestationEnvelope(keyFile: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'attestation',
    subjectContentHash: contentHash,
    statement: { format: 'dsh-attestation', schemaVersion: 1, attestationDigest: { algorithm: 'sha256', value: sha256Hex(document) } },
    keyPath: keyFile,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

function sbomEnvelope(keyFile: string, contentHash: string, document: Buffer): Buffer {
  const envelope = signEvidence({
    type: 'sbom',
    subjectContentHash: contentHash,
    statement: { format: 'cyclonedx-1.7', specVersion: '1.7', mediaType: 'application/vnd.cyclonedx+json', sbomDigest: { algorithm: 'sha256', value: sha256Hex(document) } },
    keyPath: keyFile,
  })
  return Buffer.from(JSON.stringify(envelope), 'utf8')
}

/** Publish one evidence object through the REAL HTTP publication path. */
async function publishEvidence(
  ctx: GpCtx,
  opts: { envelopeBytes: Buffer; artifactType: string; documentBytes?: Buffer },
): Promise<void> {
  const { publishRemoteEvidence } = await import('../src/evidence/remote/publication.ts')
  await publishRemoteEvidence({
    reference: ctx.reference,
    subjectDescriptor: { mediaType: OCI_MANIFEST_MEDIA_TYPE, digest: ctx.subjectDigest, size: ctx.mock.manifests.get(ctx.subjectDigest)?.bytes.length ?? 0 },
    envelopeBytes: opts.envelopeBytes,
    ...(opts.documentBytes !== undefined ? { documentBytes: opts.documentBytes } : {}),
    artifactType: opts.artifactType,
  })
}

describe('RG6-06 ★ v0.6.0 golden path — distribution can never manufacture authorization', () => {
  it('Pack → Evidence chain → Publish → Discover → Verify → Trust → ALLOW; revoke → same bytes → DENY', async () => {
    const ctx = await setupGoldenPath()

    // ---- 1. Sign + Build the local Evidence chain ----
    const sbomDoc = Buffer.from('{"bom":{"components":[{"type":"library","name":"tar"}]}}')
    const attDoc = attestationDocument(['filesystem.read'])
    await publishEvidence(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'build-provenance', 'gp-provenance'), artifactType: EVIDENCE_ARTIFACT_TYPES.provenance })
    await publishEvidence(ctx, { envelopeBytes: sbomEnvelope(ctx.keyFile, ctx.contentHash, sbomDoc), documentBytes: sbomDoc, artifactType: EVIDENCE_ARTIFACT_TYPES.sbom })
    await publishEvidence(ctx, { envelopeBytes: plainEnvelope(ctx.keyFile, ctx.contentHash, 'capability', 'gp-capability'), artifactType: EVIDENCE_ARTIFACT_TYPES.capability })
    await publishEvidence(ctx, { envelopeBytes: attestationEnvelope(ctx.keyFile, ctx.contentHash, attDoc), documentBytes: attDoc, artifactType: EVIDENCE_ARTIFACT_TYPES['runtime-attestation'] })

    // ---- 2. CURRENT trust.yaml: full chain trusted ----
    const writeTrust = (evidenceTrustedKeys: string[]): void => {
      writeFileSync(join(ctx.home, 'trust.yaml'), JSON.stringify({
        version: 2,
        registries: {
          [`127.0.0.1:${ctx.mock.port}/company/*`]: {
            requireEvidence: {
              provenance: { required: true },
              runtimeAttestation: { required: true, coverage: 'complete' },
            },
            evidenceTrustedKeys,
          },
        },
      }, null, 2), 'utf8')
    }
    writeTrust([ctx.keyId])

    // ---- 3. Remote discovery: pagination complete → OCI verify → C binding ----
    const discovery = await discoverRemoteEvidence({ reference: ctx.reference, actualContentHash: ctx.contentHash })
    expect(discovery.complete).toBe(true)
    if (!discovery.complete) return
    const types = discovery.candidates.map((c) => c.evidenceType).sort()
    // the four verified candidates: build-provenance, sbom, capability, attestation
    expect(types).toEqual(['attestation', 'build-provenance', 'capability', 'sbom'])
    for (const c of discovery.candidates) {
      expect(c.subject.manifestDigest).toBe(ctx.subjectDigest) // OCI binding
      expect(c.subject.contentHash).toBe(ctx.contentHash) // DSH binding
    }

    // ---- 4. Trust Gate: issuer trust + CURRENT trust.yaml → ALLOW ----
    const allow = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference,
      actualContentHash: ctx.contentHash,
      home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' },
      executionTarget: TARGET,
    })
    expect(allow.decision).toBe('ALLOW')
    expect(allow.verdict.errors).toEqual([])

    // ---- 5. ONLY the trusted issuer is revoked: same bytes, same M, same C → DENY ----
    writeTrust(['sha256:' + '0'.repeat(64)]) // issuer no longer in the CURRENT trust.yaml
    const deny = await evaluateRemoteEvidenceTrust({
      reference: ctx.reference,
      actualContentHash: ctx.contentHash,
      home: ctx.home,
      signature: { status: 'MISSING', trust: 'N/A' },
      executionTarget: TARGET,
    })
    expect(deny.decision).toBe('DENY')
    expect(deny.verdict.errors.some((e) => e.includes('UNTRUSTED_EVIDENCE_ISSUER'))).toBe(true)
  })
})
