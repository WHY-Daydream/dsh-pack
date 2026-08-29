/**
 * v0.4.1 registry auth (DESIGN-v0.4.1.md §8): anonymous pull + username/token
 * (Basic) + Bearer challenge. Credentials come from
 * `DSH_REGISTRY_USERNAME` / `DSH_REGISTRY_TOKEN` or
 * `~/.dsh/registry-auth.json` (`{ "<registry>": { username, password|token } }`)
 * — NEVER from the pack, the image manifest or provenance.
 * @module @why-daydream/dsh-pack/image/registry/auth
 */

import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'

/** A `WWW-Authenticate` challenge we understand. */
export type AuthChallenge =
  | { scheme: 'bearer'; realm: string; service?: string; scope?: string }
  | { scheme: 'basic' }

export interface RegistryCredentials {
  username?: string
  password?: string
  /** pre-authorized bearer token (e.g. anonymous pull tokens). */
  token?: string
}

/** Parse `WWW-Authenticate` (Bearer/Basic); unknown schemes → undefined. */
export function parseWwwAuthenticate(header: string | undefined): AuthChallenge | undefined {
  if (header === undefined || header === '') return undefined
  const trimmed = header.trim()
  const lower = trimmed.toLowerCase()
  if (lower.startsWith('bearer')) {
    const params = parseChallengeParams(trimmed.slice('bearer'.length))
    const realm = params['realm']
    if (realm === undefined || realm === '') return undefined
    return {
      scheme: 'bearer',
      realm,
      ...(params['service'] !== undefined ? { service: params['service'] } : {}),
      ...(params['scope'] !== undefined ? { scope: params['scope'] } : {}),
    }
  }
  if (lower.startsWith('basic')) return { scheme: 'basic' }
  return undefined
}

/** Naive `key="value"` param parser — sufficient for the v0.4.1 subset. */
function parseChallengeParams(input: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const match of input.matchAll(/([a-zA-Z0-9_]+)="([^"]*)"/g)) {
    out[match[1] as string] = match[2] as string
  }
  return out
}

/** Load credentials for a registry host: env first, then ~/.dsh/registry-auth.json. */
export function loadRegistryCredentials(registry: string): RegistryCredentials {
  const envUsername = process.env['DSH_REGISTRY_USERNAME']
  const envToken = process.env['DSH_REGISTRY_TOKEN']
  if (envUsername !== undefined || envToken !== undefined) {
    return {
      ...(envUsername !== undefined ? { username: envUsername } : {}),
      ...(envToken !== undefined ? { password: envToken } : {}),
    }
  }
  const file = join(homedir(), '.dsh', 'registry-auth.json')
  if (!existsSync(file)) return {}
  try {
    const parsed = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    const entry = parsed[registry] as Record<string, unknown> | undefined
    if (entry === undefined) return {}
    return {
      ...(typeof entry['username'] === 'string' ? { username: entry['username'] } : {}),
      ...(typeof entry['password'] === 'string' ? { password: entry['password'] } : {}),
      ...(typeof entry['token'] === 'string' ? { token: entry['token'] } : {}),
    }
  } catch {
    return {}
  }
}

/** `Authorization: Basic base64(user:password)`. */
export function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username}:${password}`, 'utf8').toString('base64')}`
}
