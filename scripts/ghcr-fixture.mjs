#!/usr/bin/env node
/**
 * GHCR E2E repository fixture construction (DESIGN-v0.4.2.md §3/§7, D41–D44).
 *
 * OCI Distribution Spec: repository <name> must be lowercase [a-z0-9...]; a
 * GitHub account/org display name (e.g. WHY-Daydream) is NOT a valid OCI
 * namespace component. This module maps the GitHub owner input to ONE canonical
 * lowercase repository string shared by the image ref, the registry API URL and
 * the Bearer auth scope — no uppercase ghost identity in any of them.
 * @module ghcr-fixture
 */

/**
 * Build the canonical GHCR fixture repository for an owner input.
 * @param {string} owner GitHub account/org display name (input; may be mixed case)
 * @param {string} repo  fixed fixture repository leaf name, e.g. `dsh-pack-e2e`
 * @returns {{ repository: string, remoteRef: (tag: string) => string, scope: () => string }}
 */
export function buildGhcrRepository(owner, repo) {
  const repository = `${owner.toLowerCase()}/${repo}`
  return {
    repository,
    /** Full remote image ref `ghcr.io/<repo>:<tag>` (parser-valid lowercase). */
    remoteRef: (tag) => `ghcr.io/${repository}:${tag}`,
    /** Bearer token scope — the SAME canonical repository string. */
    scope: () => `repository:${repository}:pull,push`,
  }
}
