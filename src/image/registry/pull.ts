/**
 * v0.4.1 pull pipeline (DESIGN-v0.4.1.md §5, D38/D39) — digest-first, in a
 * fixed order: OCI Transport Integrity (manifest/config/blob digests
 * recomputed over actual bytes) → DSH Artifact Integrity (verifyPack +
 * contentHash must equal the config's) → Signature Authenticity (v0.3,
 * inside the pack) → Trust Policy → LocalImageStore.import. Transport
 * failures are reported distinctly from DSH semantic failures (E2E criteria
 * 4/5), and nothing the registry says is ever trusted (§6).
 * @module @why-daydream/dsh-pack/image/registry/pull
 */

import { computePackContentHash } from '../../pack-builder.ts'
import { imageManifestDigest, validateImageManifest } from '../manifest.ts'
import { repository } from '../reference.ts'
import type { ImageStore } from '../store.ts'
import { applyTrustPolicy, type TrustPolicy } from '../trust.ts'
import { verifyPack } from '../../verify.ts'
import { loadRegistryCredentials } from './auth.ts'
import { RegistryClient } from './client.ts'
import { verifyDescriptorBytes } from './descriptor.ts'
import { parseRemoteReference, registryBaseUrl, repoPath } from './reference.ts'
import type { DshContentDigest, OciBlobDigest, OciManifestDigest } from './types.ts'

export interface PullResult {
  contentHash: DshContentDigest
  ociManifestDigest: OciManifestDigest
  dshManifestDigest: string
  signature: 'VALID' | 'INVALID' | 'MISSING'
  trust: 'VERIFIED' | 'UNTRUSTED' | 'N/A'
}

export interface PullContext extends TrustPolicy {
  installedDshVersion: string
  /** Mirror the full remote ref as a local tag (default true). */
  setLocalTag?: boolean
}

/** Pull an image from an OCI registry into the local store (frozen §5 order). */
export async function pullImage(
  store: ImageStore,
  remoteRefInput: string,
  context: PullContext,
): Promise<PullResult> {
  const remoteRef = parseRemoteReference(remoteRefInput)
  const client = new RegistryClient({
    baseUrl: registryBaseUrl(remoteRef.registry),
    repo: repoPath(remoteRef),
    credentials: loadRegistryCredentials(remoteRef.registry),
  })

  // 1. GET manifest (tag or digest); digest-form must match exactly (D38)
  const requested = remoteRef.digest ?? (remoteRef.tag as string)
  const { digest: manifestTransportDigest, manifest: ociManifest } = await client.getManifest(requested)
  if (remoteRef.digest !== undefined && manifestTransportDigest !== remoteRef.digest) {
    throw new Error(
      `manifest digest mismatch: expected ${remoteRef.digest}, actual ${manifestTransportDigest} (transport integrity failure)`,
    )
  }

  // 2. GET config blob (DSH Image Manifest) + verify bytes
  const configBytes = await client.getBlob(ociManifest.config.digest as OciBlobDigest)
  verifyDescriptorBytes('config blob', ociManifest.config, configBytes)
  let dshParsed: ReturnType<typeof validateImageManifest>
  try {
    dshParsed = validateImageManifest(JSON.parse(configBytes.toString('utf8')))
  } catch {
    throw new Error('registry returned an unparseable DSH image manifest (config blob)')
  }
  if (!dshParsed.ok) {
    throw new Error(`registry returned an invalid DSH image manifest: ${dshParsed.errors.join('; ')}`)
  }
  const dshManifest = dshParsed.manifest

  // 3. GET the .dshpack layer + verify bytes (transport integrity)
  const layer = ociManifest.layers[0] as { digest: string; size: number }
  const packBytes = await client.getBlob(layer.digest as OciBlobDigest)
  verifyDescriptorBytes('pack blob', layer, packBytes)

  // 4. DSH artifact integrity (D39): verifyPack + contentHash == config
  const { report } = await verifyPack(packBytes, { installedDshVersion: context.installedDshVersion })
  if (!report.ok) {
    const failed = report.sections.filter((s) => s.status === 'fail').map((s) => `${s.name}: ${s.detail ?? ''}`)
    throw new Error(`pulled artifact fails DSH verification: ${failed.join('; ')}`)
  }
  const recomputed = await computePackContentHash(packBytes) as DshContentDigest
  if (recomputed !== dshManifest.artifact.digest) {
    throw new Error(
      `DSH contentHash mismatch: config declares ${dshManifest.artifact.digest}, actual ${recomputed} (artifact integrity failure)`,
    )
  }

  // 5. Signature + Trust (v0.3 section; default policy = cache-only, D29)
  const signatureSection = report.sections.find((s) => s.name === 'Signature')
  const verdict = applyTrustPolicy(signatureSection, {
    ...(context.requireSignature === true ? { requireSignature: true } : {}),
    ...(context.requireTrusted === true ? { requireTrusted: true } : {}),
  })
  if (!verdict.ok) throw new Error(`image trust policy rejected: ${verdict.error}`)

  // 6. LocalImageStore.import (content-addressed) + optional tag mirror
  const dshManifestDigest = imageManifestDigest(dshManifest)
  await store.putBlob(recomputed, packBytes)
  await store.putManifest(dshManifestDigest, dshManifest)
  if (remoteRef.tag !== undefined && context.setLocalTag !== false) {
    await store.setTag(repository(remoteRef), remoteRef.tag, dshManifestDigest)
  }

  return {
    contentHash: recomputed,
    ociManifestDigest: manifestTransportDigest,
    dshManifestDigest,
    signature: verdict.signature,
    trust: verdict.trust,
  }
}
