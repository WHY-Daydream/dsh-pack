/**
 * Human-command surface (DESIGN.md §8): one `pack` command (name matches the
 * official `^[a-z][a-z0-9_-]*$` constraint) with subcommands dispatched from
 * `rawInput`: `/pack [name]`, `/pack inspect`, `/pack verify`, `/pack install`.
 * Renders the ✓/⚠/✗ output style and maps failures to CommandResult errors.
 * @module @why-daydream/dsh-pack/commands
 */

import type { CommandInvocation, CommandResult } from '@deepseek-ai/dsh-commands'
import type { DefaultImageService } from './image/service.ts'
import type { PackagerService } from './service.ts'
import { PackError } from './service.ts'
import type { PackDiff, PackOptions } from './types.ts'

/** A parsed /pack invocation. */
export interface ParsedInvocation {
  sub: 'pack' | 'inspect' | 'verify' | 'install' | 'diff' | 'sign' | 'keygen' | 'image' | 'run' | 'push' | 'pull'
  positionals: string[]
  flags: Record<string, string | boolean>
}

/** Tokenize rawInput and classify the subcommand + flags. */
export function parseCommand(rawInput: string): ParsedInvocation {
  const tokens = rawInput.trim().split(/\s+/).filter(Boolean)
  let sub: ParsedInvocation['sub'] = 'pack'
  if (tokens[0] === 'inspect' || tokens[0] === 'verify' || tokens[0] === 'install'
    || tokens[0] === 'diff' || tokens[0] === 'sign' || tokens[0] === 'keygen'
    || tokens[0] === 'image' || tokens[0] === 'run' || tokens[0] === 'push' || tokens[0] === 'pull') {
    sub = tokens[0]
    tokens.shift()
  }
  const positionals: string[] = []
  const flags: Record<string, string | boolean> = {}
  const boolFlags = new Set([
    'strict', 'allow-secrets', 'allow-nonportable', 'force', 'ignore-runtime-version', 'json', 'portable',
    'require-signature', 'require-trusted',
  ])
  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i] as string
    if (token.startsWith('--')) {
      const key = token.slice(2)
      if (boolFlags.has(key)) {
        flags[key] = true
      } else {
        const value = tokens[i + 1]
        if (value === undefined) throw new PackError(`dsh-pack: --${key} requires a value`, 1)
        flags[key] = value
        i++
      }
    } else {
      positionals.push(token)
    }
  }
  return { sub, positionals, flags }
}

/** Build a CommandResult from a PackError (exit code surfaces in the text). */
function fail(error: unknown): CommandResult {
  if (error instanceof PackError) {
    return { kind: 'error', text: `✗ ${error.message} (exit ${error.exitCode})` }
  }
  return { kind: 'error', text: `✗ ${String(error instanceof Error ? error.message : error)}` }
}

/** Render the v0.1 pack summary (DESIGN.md §8.3 demo style). */
function renderPackSummary(invocation: ParsedInvocation, outcome: Awaited<ReturnType<PackagerService['pack']>>): string {
  const lines = [
    `Analyzing profile "${invocation.positionals[0] ?? outcome.profile}"...`,
    `✓ ${outcome.manifest.bundles.length} bundles`,
    `✓ ${Object.keys(outcome.manifest.dependencies).length} dependencies`,
    '✓ effective config generated',
  ]
  if (outcome.manifest.snapshot.excludedLayersPresent) {
    lines.push('⚠ excluded machine-local layers detected (home/--patch) — not packed')
  }
  lines.push(`✓ ${outcome.redacted} secrets redacted`)
  for (const warning of outcome.warnings) lines.push(`⚠ [${warning.code}] ${warning.message}`)
  lines.push('✓ configuration validated', '', `Created: ${outcome.file}`)
  return lines.join('\n')
}

/** Render a verify report (DESIGN.md §7.5 sections). */
function renderVerifyReport(report: Awaited<ReturnType<PackagerService['verify']>>, json: boolean): string {
  if (json) {
    return JSON.stringify(report, null, 2)
  }
  const lines = report.sections.map((section) => {
    const mark = section.status === 'ok' ? '✓' : section.status === 'fail' ? '✗' : '⚠'
    const detail = section.detail !== undefined ? ` — ${section.detail}` : ''
    return `${mark} ${section.name}${detail}`
  })
  lines.push('', report.ok ? 'Package verified.' : 'Package verification FAILED.')
  return lines.join('\n')
}

/** Shorten a sha256:<hex> configHash for display. */
function shortHash(hash: string): string {
  return hash.length > 16 ? `${hash.slice(0, 15)}…` : hash
}

/** Format a leaf value for diff output. */
function fmtValue(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

/** Render a /pack diff report (v0.2, four domains + configHash verdict). */
function renderDiff(diff: PackDiff): string {
  const lines: string[] = [`Profile Drift: ${diff.fileA} vs ${diff.fileB}`, '']
  if (diff.manifest.length > 0) {
    lines.push('Manifest')
    for (const change of diff.manifest) {
      lines.push(`  ${change.field}: ${fmtValue(change.before)} → ${fmtValue(change.after)}`)
    }
    lines.push('')
  }
  if (diff.bundles.length > 0) {
    lines.push('Bundles')
    for (const change of diff.bundles) {
      if (change.kind === 'added') lines.push(`  + ${change.name}@${change.after ?? ''}`)
      else if (change.kind === 'removed') lines.push(`  - ${change.name}@${change.before ?? ''}`)
      else lines.push(`  ~ ${change.name}: ${change.before ?? ''} → ${change.after ?? ''}`)
    }
    lines.push('')
  }
  if (diff.config.length > 0) {
    lines.push('Config')
    for (const change of diff.config) {
      if (change.kind === 'added') lines.push(`  + ${change.path}: ${fmtValue(change.after)}`)
      else if (change.kind === 'removed') lines.push(`  - ${change.path}: ${fmtValue(change.before)}`)
      else lines.push(`  ${change.path}: ${fmtValue(change.before)} → ${fmtValue(change.after)}`)
    }
    lines.push('')
  }
  if (diff.dependencies.length > 0) {
    lines.push('Dependencies')
    for (const change of diff.dependencies) {
      const parts: string[] = []
      if (change.specBefore !== undefined && change.specAfter !== undefined && change.specBefore !== change.specAfter) {
        parts.push(`spec ${change.specBefore} → ${change.specAfter}`)
      }
      if (change.versionBefore !== undefined && change.versionAfter !== undefined && change.versionBefore !== change.versionAfter) {
        parts.push(`${change.versionBefore} → ${change.versionAfter}`)
      }
      lines.push(`  ${change.name}: ${parts.join(' | ') || 'changed'}`)
    }
    lines.push('')
  }
  const verdict = diff.configHashEqual ? 'EQUAL' : 'DIFFERENT'
  lines.push(`configHash: ${shortHash(diff.configHashA)} → ${shortHash(diff.configHashB)}  [${verdict}]`)
  return lines.join('\n')
}

/** Dispatch a parsed invocation against the packager service. */
export async function runCommand(
  invocation: ParsedInvocation,
  packager: PackagerService,
  images?: DefaultImageService,
): Promise<CommandResult> {
  try {
    switch (invocation.sub) {
      case 'pack': {
        const opts: PackOptions = {
          profile: invocation.positionals[0] ?? 'web',
          strict: invocation.flags['strict'] === true,
          allowSecrets: invocation.flags['allow-secrets'] === true,
          allowNonportable: invocation.flags['allow-nonportable'] === true,
          portable: invocation.flags['portable'] === true,
        }
        if (typeof invocation.flags['out'] === 'string') opts.outDir = invocation.flags['out']
        const outcome = await packager.pack(opts)
        return { kind: 'success', text: renderPackSummary(invocation, outcome) }
      }
      case 'inspect': {
        const file = invocation.positionals[0]
        if (file === undefined) return { kind: 'error', text: '✗ usage: /pack inspect <file.dshpack> [--json]' }
        const inspection = await packager.inspect(file)
        if (invocation.flags['json'] === true) {
          return { kind: 'success', text: JSON.stringify(inspection, null, 2) }
        }
        const m = inspection.manifest
        const lines = [
          `File: ${file}`,
          `Profile: ${m.profile.name}`,
          `configHash: ${m.configHash}`,
          `installable: ${String(m.installable)} portable: ${String(m.portable)}`,
          `dsh: ${m.runtime.dshVersion} | node ${m.runtime.nodeVersion} | pnpm ${m.runtime.pnpmVersion}`,
          `Bundles (${m.bundles.length}): ${m.bundles.join(', ')}`,
          `Dependencies (${Object.keys(m.dependencies).length}): ${Object.keys(m.dependencies).join(', ')}`,
          `Secrets redacted: ${m.secrets?.redacted ?? 0}`,
          `Warnings (${inspection.warnings.length}): ${inspection.warnings.map((w) => w.message).join('; ') || 'none'}`,
          `Entries: ${inspection.entries.length} files, ${inspection.entries.reduce((sum, e) => sum + e.size, 0)} bytes total`,
        ]
        return { kind: 'success', text: lines.join('\n') }
      }
      case 'verify': {
        const file = invocation.positionals[0]
        if (file === undefined) return { kind: 'error', text: '✗ usage: /pack verify <file.dshpack> [--json] [--ignore-runtime-version] [--require-signature]' }
        const report = await packager.verify(file, {
          ignoreRuntimeVersion: invocation.flags['ignore-runtime-version'] === true,
          requireSignature: invocation.flags['require-signature'] === true,
        })
        return { kind: report.ok ? 'success' : 'error', text: renderVerifyReport(report, invocation.flags['json'] === true) }
      }
      case 'install': {
        const file = invocation.positionals[0]
        if (file === undefined) return { kind: 'error', text: '✗ usage: /pack install <file.dshpack> [--profile <name>] [--force] [--ignore-runtime-version]' }
        const profile = typeof invocation.flags['profile'] === 'string' ? invocation.flags['profile'] : undefined
        const result = await packager.install(file, {
          ...(profile !== undefined ? { profile } : {}),
          force: invocation.flags['force'] === true,
          ignoreRuntimeVersion: invocation.flags['ignore-runtime-version'] === true,
        })
        return {
          kind: 'success',
          text: `✓ profile "${result.profile}" restored (${result.dir})\nNext: dsh --profile ${result.profile}`,
        }
      }
      case 'diff': {
        const fileA = invocation.positionals[0]
        const fileB = invocation.positionals[1]
        if (fileA === undefined || fileB === undefined) {
          return { kind: 'error', text: '✗ usage: /pack diff <a.dshpack> <b.dshpack> [--json]' }
        }
        const diff = await packager.diff(fileA, fileB)
        if (invocation.flags['json'] === true) {
          return { kind: 'success', text: JSON.stringify(diff, null, 2) }
        }
        return { kind: 'success', text: renderDiff(diff) }
      }
      case 'sign': {
        const file = invocation.positionals[0]
        const key = typeof invocation.flags['key'] === 'string' ? invocation.flags['key'] : undefined
        if (file === undefined || key === undefined) {
          return { kind: 'error', text: '✗ usage: /pack sign <file.dshpack> --key <private.pem> [--signer <name>] [--out <dir>] [--force]' }
        }
        const signer = typeof invocation.flags['signer'] === 'string' ? invocation.flags['signer'] : undefined
        const outDir = typeof invocation.flags['out'] === 'string' ? invocation.flags['out'] : undefined
        const result = await packager.sign(file, {
          key,
          ...(signer !== undefined ? { signer } : {}),
          ...(outDir !== undefined ? { outDir } : {}),
          force: invocation.flags['force'] === true,
        })
        const lines = [
          `✓ signed: ${result.file}`,
          `  Key fingerprint: SHA256:${result.keyId}`,
          `  contentHash: ${result.contentHash}`,
          ...(result.signer !== undefined ? [`  signer: ${result.signer} (display label only — trust identity is the fingerprint)`] : []),
        ]
        return { kind: 'success', text: lines.join('\n') }
      }
      case 'keygen': {
        const outDir = typeof invocation.flags['out'] === 'string' ? invocation.flags['out'] : undefined
        const result = await packager.keygen(outDir !== undefined ? { outDir } : {})
        return {
          kind: 'success',
          text: `✓ ed25519 keypair generated\n  Key fingerprint: SHA256:${result.keyId}\n  private: ${result.privateKey} (chmod 600)\n  public:  ${result.publicKey}`,
        }
      }
      case 'image': {
        if (images === undefined) return { kind: 'error', text: '✗ image commands unavailable (image service not provided)' }
        const imageSub = invocation.positionals[0]
        const args = invocation.positionals.slice(1)
        switch (imageSub) {
          case 'import': {
            const file = args[0]
            if (file === undefined) return { kind: 'error', text: '✗ usage: /pack image import <file.dshpack> [--tag <ref>]' }
            const tag = typeof invocation.flags['tag'] === 'string' ? invocation.flags['tag'] : undefined
            const result = await images.import(file, tag !== undefined ? { tag } : {})
            const lines = [`✓ imported ${file}`, `  digest: ${result.digest}`, `  manifest: ${result.manifestDigest}`]
            if (result.ref !== undefined) lines.push(`  tagged: ${result.ref}`)
            return { kind: 'success', text: lines.join('\n') }
          }
          case 'ls': {
            const entries = await images.list()
            if (entries.length === 0) return { kind: 'success', text: 'REPOSITORY   TAG   DIGEST\n(no images)' }
            const rows = entries.map((e) => `${e.repo.padEnd(24)} ${e.tag.padEnd(12)} ${shortHash(e.manifestDigest)}`)
            return { kind: 'success', text: ['REPOSITORY                   TAG          DIGEST', ...rows].join('\n') }
          }
          case 'inspect': {
            const ref = args[0]
            if (ref === undefined) return { kind: 'error', text: '✗ usage: /pack image inspect <ref> [--json]' }
            const info = await images.inspect(ref)
            if (invocation.flags['json'] === true) return { kind: 'success', text: JSON.stringify(info, null, 2) }
            const lines = [
              `Image: ${info.ref}`,
              `  manifest: ${info.manifestDigest}`,
              `  artifact: ${info.artifactDigest} (${info.artifactSize} bytes)`,
              `  configHash: ${info.configHash}`,
              `  platform: dsh ${info.manifest.platform.dshVersion}`,
              `  signature: ${info.signature}`,
              `  trust: ${info.trust}`,
            ]
            return { kind: 'success', text: lines.join('\n') }
          }
          case 'tag': {
            const source = args[0]
            const target = args[1]
            if (source === undefined || target === undefined) {
              return { kind: 'error', text: '✗ usage: /pack image tag <src> <dst>' }
            }
            const applied = await images.tag(source, target)
            return { kind: 'success', text: `✓ ${applied}` }
          }
          case 'rm': {
            const ref = args[0]
            if (ref === undefined) return { kind: 'error', text: '✗ usage: /pack image rm <ref>' }
            await images.remove(ref)
            return { kind: 'success', text: `✓ removed ${ref}` }
          }
          case 'lock': {
            const ref = args[0]
            if (ref === undefined) {
              return { kind: 'error', text: '✗ usage: /pack image lock <remoteRef> [--file <path>]' }
            }
            const file = typeof invocation.flags['file'] === 'string' ? invocation.flags['file'] : undefined
            const result = await images.lock(ref, file !== undefined ? { file } : {})
            return {
              kind: 'success',
              text: `Resolved:\n\n${result.mutableRef}\n        ↓\n${result.resolved}\n\nLock written: ${result.file}`,
            }
          }
          default:
            return { kind: 'error', text: `✗ unknown image subcommand ${JSON.stringify(imageSub)} (import | ls | inspect | tag | rm | lock)` }
        }
      }
      case 'run': {
        if (images === undefined) return { kind: 'error', text: '✗ run unavailable (image service not provided)' }
        const ref = invocation.positionals[0]
        if (ref === undefined) {
          return { kind: 'error', text: '✗ usage: /pack run <ref> [--require-signature] [--require-trusted] [--profile <name>]' }
        }
        const profile = typeof invocation.flags['profile'] === 'string' ? invocation.flags['profile'] : undefined
        const result = await images.run(ref, {
          ...(invocation.flags['require-signature'] === true ? { requireSignature: true } : {}),
          ...(invocation.flags['require-trusted'] === true ? { requireTrusted: true } : {}),
          ...(profile !== undefined ? { profile } : {}),
        })
        const lines = [
          `✓ ${result.temporary ? 'temporary runtime' : 'profile'} "${result.profile}" materialized (${result.dir})`,
          `  digest: ${result.digest}`,
          `  configHash: ${result.configHash}`,
          `  signature: ${result.signature}`,
          `  trust: ${result.trust}`,
          `  boot: ${result.boot}`,
        ]
        return { kind: 'success', text: lines.join('\n') }
      }
      case 'push': {
        if (images === undefined) return { kind: 'error', text: '✗ push unavailable (image service not provided)' }
        const localRef = invocation.positionals[0]
        const remoteRef = invocation.positionals[1]
        if (localRef === undefined || remoteRef === undefined) {
          return { kind: 'error', text: '✗ usage: /pack push <localRef> <remoteRef>' }
        }
        const result = await images.push(localRef, remoteRef)
        return {
          kind: 'success',
          text: `✓ pushed ${result.remoteRef}\n  contentHash: ${result.contentHash}\n  blobDigest: ${result.blobDigest}\n  manifest: ${result.ociManifestDigest}`,
        }
      }
      case 'pull': {
        if (images === undefined) return { kind: 'error', text: '✗ pull unavailable (image service not provided)' }
        const remoteRef = invocation.positionals[0]
        if (remoteRef === undefined) {
          return { kind: 'error', text: '✗ usage: /pack pull <remoteRef> [--require-signature] [--require-trusted]' }
        }
        const result = await images.pull(remoteRef, {
          ...(invocation.flags['require-signature'] === true ? { requireSignature: true } : {}),
          ...(invocation.flags['require-trusted'] === true ? { requireTrusted: true } : {}),
        })
        return {
          kind: 'success',
          text: `✓ pulled ${remoteRef}\n  contentHash: ${result.contentHash}\n  signature: ${result.signature}\n  trust: ${result.trust}`,
        }
      }
    }
  } catch (error) {
    return fail(error)
  }
}

/** Command handler bound to a packager + optional image service. */
export function makeHandler(
  packager: PackagerService,
  images?: DefaultImageService,
): (invocation: CommandInvocation) => Promise<CommandResult> {
  return async (invocation) => {
    const parsed = parseCommand(invocation.rawInput)
    return runCommand(parsed, packager, images)
  }
}
