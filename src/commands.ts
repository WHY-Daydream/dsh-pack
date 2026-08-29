/**
 * Human-command surface (DESIGN.md §8): one `pack` command (name matches the
 * official `^[a-z][a-z0-9_-]*$` constraint) with subcommands dispatched from
 * `rawInput`: `/pack [name]`, `/pack inspect`, `/pack verify`, `/pack install`.
 * Renders the ✓/⚠/✗ output style and maps failures to CommandResult errors.
 * @module @why-daydream/dsh-pack/commands
 */

import type { CommandInvocation, CommandResult } from '@deepseek-ai/dsh-commands'
import type { PackagerService } from './service.ts'
import { PackError } from './service.ts'
import type { PackDiff, PackOptions } from './types.ts'

/** A parsed /pack invocation. */
export interface ParsedInvocation {
  sub: 'pack' | 'inspect' | 'verify' | 'install' | 'diff'
  positionals: string[]
  flags: Record<string, string | boolean>
}

/** Tokenize rawInput and classify the subcommand + flags. */
export function parseCommand(rawInput: string): ParsedInvocation {
  const tokens = rawInput.trim().split(/\s+/).filter(Boolean)
  let sub: ParsedInvocation['sub'] = 'pack'
  if (tokens[0] === 'inspect' || tokens[0] === 'verify' || tokens[0] === 'install' || tokens[0] === 'diff') {
    sub = tokens[0]
    tokens.shift()
  }
  const positionals: string[] = []
  const flags: Record<string, string | boolean> = {}
  const boolFlags = new Set([
    'strict', 'allow-secrets', 'allow-nonportable', 'force', 'ignore-runtime-version', 'json', 'portable',
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
export async function runCommand(invocation: ParsedInvocation, packager: PackagerService): Promise<CommandResult> {
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
        if (file === undefined) return { kind: 'error', text: '✗ usage: /pack verify <file.dshpack> [--json] [--ignore-runtime-version]' }
        const report = await packager.verify(file, { ignoreRuntimeVersion: invocation.flags['ignore-runtime-version'] === true })
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
    }
  } catch (error) {
    return fail(error)
  }
}

/** Command handler bound to a packager instance. */
export function makeHandler(packager: PackagerService): (invocation: CommandInvocation) => Promise<CommandResult> {
  return async (invocation) => {
    const parsed = parseCommand(invocation.rawInput)
    return runCommand(parsed, packager)
  }
}
