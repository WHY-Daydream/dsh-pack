/**
 * v0.4.1 remote reference handling (DESIGN-v0.4.1.md §7/§10, D32/D38): a
 * reference is REMOTE iff it carries a registry (host[:port]); local refs
 * (`agent:v1`) address the local store. Remote refs map to OCI registry API
 * URLs — https by default, http for localhost (keeps the mock-registry E2E
 * and local dev registries working without TLS).
 * @module @why-daydream/dsh-pack/image/registry/reference
 */

import { parseReference, type ImageReference } from '../reference.ts'

/** A remote reference: registry is required, plus a tag and/or digest. */
export interface RemoteReference extends ImageReference {
  registry: string
}

export function isRemoteRef(ref: ImageReference): ref is RemoteReference {
  return ref.registry !== undefined
}

/** Parse an input as a REMOTE reference; local refs are rejected. */
export function parseRemoteReference(input: string): RemoteReference {
  const ref = parseReference(input)
  if (ref.registry === undefined) {
    throw new Error(`not a remote reference (missing registry host): ${JSON.stringify(input)}`)
  }
  if (ref.tag === undefined && ref.digest === undefined) {
    throw new Error('remote reference must carry a tag or a digest')
  }
  return ref as RemoteReference
}

export function isLocalhostRegistry(registry: string): boolean {
  const host = registry.split(':')[0]
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
}

/** Registry API base: `https://<registry>` (http for localhost). */
export function registryBaseUrl(registry: string): string {
  return `${isLocalhostRegistry(registry) ? 'http' : 'https'}://${registry}`
}

/** The repository path: `namespace/name` (or just `name`). */
export function repoPath(ref: RemoteReference): string {
  return [ref.namespace, ref.name].filter(Boolean).join('/')
}

/** `GET/PUT /v2/<repo>/manifests/<tag-or-digest>`. */
export function manifestEndpoint(base: string, repo: string, tagOrDigest: string): string {
  return `${base}/v2/${repo}/manifests/${encodeURIComponent(tagOrDigest)}`
}

/** `HEAD/GET/POST/PUT /v2/<repo>/blobs/<digest>`. */
export function blobEndpoint(base: string, repo: string, digest: string): string {
  return `${base}/v2/${repo}/blobs/${encodeURIComponent(digest)}`
}

/** `POST /v2/<repo>/blobs/uploads/` — monolithic upload start. */
export function uploadsEndpoint(base: string, repo: string): string {
  return `${base}/v2/${repo}/blobs/uploads/`
}
