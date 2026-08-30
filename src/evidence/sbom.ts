/**
 * v0.5 alpha.3 SBOM Evidence — CycloneDX 1.7 generator (DESIGN-v0.5.0.md §7,
 * D73–D80). The SBOM describes the ARTIFACT, never the current machine (D74):
 * it consumes ONLY files inside the `.dshpack` (staged lockfile, vendored
 * tgzs, embedded package metadata, dependency closure). Output is
 * deterministic canonical bytes (D80), unknown stays UNKNOWN (D79), no
 * absolute machine paths (D76), lifecycle scripts are existence+digest facts
 * (D77), native is an indicator only (D78).
 * @module @why-daydream/dsh-pack/evidence/sbom
 */

import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { canonicalJson, parseYaml, sha256Hex } from '../canonical.ts'
import { collectFiles, extractTarGz } from '../pack-builder.ts'
import { parsePackageKey } from '../dependency-resolver.ts'
import type { DependencyTree } from '../types.ts'

export const SBOM_FORMAT = 'cyclonedx'
export const SBOM_SPEC_VERSION = '1.7'
export const SBOM_MEDIA_TYPE = 'application/vnd.cyclonedx+json'
export const SBOM_EVIDENCE_TYPE = 'sbom'

/** npm lifecycle scripts that are explicit supply-chain facts (D77). */
export const LIFECYCLE_SCRIPTS = [
  'preinstall', 'install', 'postinstall', 'prepare', 'prepublish', 'prepack', 'postpack',
] as const

/** Native-artifact signals (D78) — indicators only, never a compatibility claim. */
const NATIVE_SCRIPT_SIGNALS = ['node-gyp', 'node-pre-gyp', 'prebuild', 'prebuildify'] as const
const NATIVE_FILE_SIGNALS = ['binding.gyp', 'gypfile', '.gypfile'] as const

export interface CycloneDxProperty {
  name: string
  value: string
}

export interface CycloneDxComponent {
  type: 'library'
  'bom-ref': string
  name: string
  version?: string
  purl?: string
  properties?: CycloneDxProperty[]
}

export interface CycloneDxBom {
  bomFormat: 'CycloneDX'
  specVersion: string
  version: 1
  metadata?: { component?: CycloneDxComponent }
  components: CycloneDxComponent[]
  dependencies?: { ref: string; dependsOn: string[] }[]
}

/** Artifact-internal inputs (D74) — everything comes from inside the .dshpack. */
export interface SbomBuildInput {
  /** profile/package.json inside the artifact (staged). */
  profilePackageJson: Record<string, unknown>
  /** artifact/staged pnpm-lock.yaml text, or undefined when the pack has none. */
  lockfileText?: string
  /** resolved/dependency-tree.json. */
  depTree: DependencyTree
  /** packages/<tgz> filename → tgz bytes (vendored closure, MUST-2). */
  vendoredTgzs?: ReadonlyMap<string, Buffer>
  /** packages/<tgz> filename → {manifest, files} extracted from the archive. */
  vendoredMetadata?: ReadonlyMap<string, VendoredTgzMeta>
}

export interface VendoredTgzMeta {
  manifest?: Record<string, unknown>
  /** Relative archive paths (npm convention: `package/...`). */
  files: string[]
}

/** Standard Package URL for an npm package (D73/D76). */
export function npmPurl(name: string, version: string): string {
  const encoded = name.startsWith('@') ? `%40${name.slice(1)}` : name
  return `pkg:npm/${encoded}@${version}`
}

/** Deterministic digest over the EXACT document bytes (D80) — S8 anchor. */
export function sbomDocumentDigest(document: string): string {
  return `sha256:${sha256Hex(document)}`
}

/**
 * Build the CycloneDX 1.7 BOM from artifact-internal inputs. Everything is
 * sorted (components by bom-ref, properties by name, edges by ref) so the
 * canonical bytes are byte-for-byte reproducible (D80).
 */
export function buildSbomDocument(input: SbomBuildInput): CycloneDxBom {
  const registry = registryComponents(input.lockfileText)
  const local = localComponents(input)
  const rootName = String(input.profilePackageJson.name ?? 'root')
  const rootRef = `profile:${rootName}`
  const profile: CycloneDxComponent = { type: 'library', 'bom-ref': rootRef, name: rootName }
  if (typeof input.profilePackageJson.version === 'string' && input.profilePackageJson.version !== '') {
    profile.version = input.profilePackageJson.version
  }
  const profileProps = packageMetadataProperties(input.profilePackageJson)
  if (profileProps.length > 0) profile.properties = profileProps

  const components = [profile, ...registry, ...local]
    .sort((a, b) => a['bom-ref'].localeCompare(b['bom-ref']))

  const bom: CycloneDxBom = {
    bomFormat: 'CycloneDX',
    specVersion: SBOM_SPEC_VERSION,
    version: 1,
    components,
  }
  if (profile.name !== '') bom.metadata = { component: profile }
  const edges = dependencyEdges(input, rootRef, byName(components))
  if (edges.length > 0) bom.dependencies = edges.sort((a, b) => a.ref.localeCompare(b.ref))
  return bom
}

/**
 * Generate the deterministic SBOM document for a `.dshpack` buffer: extracts
 * the archive and consumes ONLY artifact-internal materials (D74).
 */
export async function generateSbomFromPack(
  packBuffer: Buffer,
): Promise<{ document: string; digest: string; bom: CycloneDxBom }> {
  const root = mkdtempSync(join(tmpdir(), 'dsh-pack-sbom-'))
  try {
    await extractTarGz(packBuffer, root)
    const profilePkgPath = join(root, 'profile', 'package.json')
    if (!existsSync(profilePkgPath)) {
      throw new Error('dsh-pack: pack has no profile/package.json — cannot build SBOM')
    }
    const profilePackageJson = JSON.parse(readFileSync(profilePkgPath, 'utf8')) as Record<string, unknown>
    const lockfilePath = join(root, 'profile', 'pnpm-lock.yaml')
    const lockfileText = existsSync(lockfilePath) ? readFileSync(lockfilePath, 'utf8') : undefined
    const depTree = JSON.parse(
      readFileSync(join(root, 'resolved', 'dependency-tree.json'), 'utf8'),
    ) as DependencyTree

    const vendoredTgzs = new Map<string, Buffer>()
    const vendoredMetadata = new Map<string, VendoredTgzMeta>()
    const packagesDir = join(root, 'packages')
    if (existsSync(packagesDir)) {
      for (const name of readdirSync(packagesDir).sort()) {
        if (!name.endsWith('.tgz')) continue
        const bytes = readFileSync(join(packagesDir, name))
        vendoredTgzs.set(name, bytes)
        vendoredMetadata.set(name, await extractVendoredTgzMeta(bytes))
      }
    }

    const bom = buildSbomDocument({
      profilePackageJson,
      ...(lockfileText !== undefined ? { lockfileText } : {}),
      depTree,
      vendoredTgzs,
      vendoredMetadata,
    })
    const document = canonicalJson(bom)
    return { document, digest: sbomDocumentDigest(document), bom }
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
}

// --- registry components (from the artifact's staged lockfile) ---

function registryComponents(lockfileText: string | undefined): CycloneDxComponent[] {
  if (lockfileText === undefined) return []
  const components: CycloneDxComponent[] = []
  const seen = new Set<string>()
  try {
    const lock = parseYaml(lockfileText) as Record<string, unknown>
    const packages = lock.packages as Record<string, unknown> | undefined
    if (packages !== undefined) {
      for (const key of Object.keys(packages).sort()) {
        const parsed = parsePackageKey(key)
        if (parsed === undefined) continue
        if (parsed.version.startsWith('file:') || parsed.version.startsWith('link:')) continue
        const entry = packages[key] as {
          version?: unknown
          resolution?: { integrity?: unknown; tarball?: unknown }
        } | undefined
        const version = typeof entry?.version === 'string' && entry.version !== ''
          ? entry.version
          : parsed.version
        const bomRef = npmPurl(parsed.name, version)
        if (seen.has(bomRef)) continue
        seen.add(bomRef)
        const resolution = entry?.resolution
        const props: CycloneDxProperty[] = []
        const resolved = typeof resolution?.tarball === 'string' && resolution.tarball !== ''
          ? resolution.tarball
          : undefined
        const integrity = typeof resolution?.integrity === 'string' && resolution.integrity !== ''
          ? resolution.integrity
          : undefined
        if (resolved !== undefined) props.push({ name: 'dsh-pack:resolved', value: resolved })
        if (integrity !== undefined) props.push({ name: 'dsh-pack:integrity', value: integrity })
        const component: CycloneDxComponent = {
          type: 'library',
          'bom-ref': bomRef,
          name: parsed.name,
          version,
          purl: bomRef,
        }
        if (props.length > 0) component.properties = props
        components.push(component)
      }
    }
  } catch {
    // unparseable staged lockfile — registry components unavailable (D79)
  }
  return components
}

// --- local / vendored components (D76: contentDigest, no machine paths) ---

function localComponents(input: SbomBuildInput): CycloneDxComponent[] {
  const stagedDeps = (input.profilePackageJson.dependencies ?? {}) as Record<string, string>
  const components: CycloneDxComponent[] = []
  for (const dep of [...input.depTree.localDeps].sort((a, b) => a.name.localeCompare(b.name))) {
    const sourceType = dep.kind === 'tarball' || dep.portable === true ? 'vendored' : dep.kind
    const props: CycloneDxProperty[] = [{ name: 'dsh-pack:source-type', value: sourceType }]
    const stagedSpec = stagedDeps[dep.name]
    const tgzMatch = typeof stagedSpec === 'string' ? /^file:\.\/packages\/(.+)$/.exec(stagedSpec) : null
    if (tgzMatch !== null && input.vendoredTgzs !== undefined) {
      // vendored content IS in the artifact → real content digest (D76)
      const tgzBytes = input.vendoredTgzs.get(tgzMatch[1] as string)
      if (tgzBytes !== undefined) {
        props.push({ name: 'dsh-pack:content-digest', value: `sha256:${sha256Hex(tgzBytes)}` })
        const meta = input.vendoredMetadata?.get(tgzMatch[1] as string)
        if (meta !== undefined) {
          props.push(...packageMetadataProperties(meta.manifest ?? {}, meta.files))
        }
      }
    }
    // non-vendored file:/link: content is NOT in the artifact → digest unknown (D79)
    const component: CycloneDxComponent = { type: 'library', 'bom-ref': `local:${dep.name}`, name: dep.name }
    const version = closureVersion(input.depTree.closure, dep.name)
    if (version !== undefined) component.version = version
    component.properties = props
    components.push(component)
  }
  return components
}

/** A usable version from the closure map (never a spec string). */
function closureVersion(closure: Record<string, string>, name: string): string | undefined {
  const version = closure[name]
  if (version === undefined) return undefined
  if (version.startsWith('file:') || version.startsWith('link:') || version.startsWith('github:')) return undefined
  if (version.startsWith('^') || version.startsWith('~')) return undefined
  return version
}

// --- package metadata facts (D77/D78/D79) ---

function packageMetadataProperties(
  manifest: Record<string, unknown>,
  files?: readonly string[],
): CycloneDxProperty[] {
  const props: CycloneDxProperty[] = []
  // D79: license is the DECLARED value, or UNKNOWN — never guessed.
  const license = typeof manifest.license === 'string' && manifest.license !== '' ? manifest.license : undefined
  props.push({ name: 'dsh-pack:license', value: license ?? 'UNKNOWN' })
  // D77: lifecycle existence + scriptDigest (never the raw script text).
  const scripts = manifest.scripts
  if (scripts !== null && typeof scripts === 'object') {
    const scriptMap = scripts as Record<string, unknown>
    for (const name of LIFECYCLE_SCRIPTS) {
      const script = scriptMap[name]
      if (typeof script === 'string' && script !== '') {
        props.push({ name: `dsh-pack:npm-lifecycle:${name}`, value: `sha256:${sha256Hex(script)}` })
      }
    }
  }
  // D78: native is an indicator only — never a runtime compatibility claim.
  const reasons = nativeReasons(manifest, files)
  props.push({ name: 'dsh-pack:native:detected', value: reasons.length > 0 ? 'true' : 'false' })
  if (reasons.length > 0) props.push({ name: 'dsh-pack:native:reasons', value: reasons.join(',') })
  return props
}

function nativeReasons(manifest: Record<string, unknown>, files?: readonly string[]): string[] {
  const reasons = new Set<string>()
  const scripts = manifest.scripts
  if (scripts !== null && typeof scripts === 'object') {
    for (const script of Object.values(scripts as Record<string, unknown>)) {
      if (typeof script !== 'string') continue
      for (const signal of NATIVE_SCRIPT_SIGNALS) {
        if (script.includes(signal)) reasons.add(signal)
      }
    }
  }
  if (files !== undefined) {
    // npm archives carry a `package/` prefix — strip it for signal matching.
    const normalized = files.map((f) => (f.startsWith('package/') ? f.slice('package/'.length) : f))
    for (const signal of NATIVE_FILE_SIGNALS) {
      if (normalized.includes(signal)) reasons.add(signal)
    }
  }
  return [...reasons].sort()
}

/** Extract {manifest, files} from a vendored tgz (npm convention: `package/`). */
async function extractVendoredTgzMeta(tgzBytes: Buffer): Promise<VendoredTgzMeta> {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-pack-vtgz-'))
  try {
    await extractTarGz(tgzBytes, dir)
    const files = collectFiles(dir)
    let manifest: Record<string, unknown> | undefined
    for (const candidate of [join(dir, 'package', 'package.json'), join(dir, 'package.json')]) {
      if (existsSync(candidate)) {
        manifest = JSON.parse(readFileSync(candidate, 'utf8')) as Record<string, unknown>
        break
      }
    }
    return { ...(manifest !== undefined ? { manifest } : {}), files }
  } catch {
    return { files: [] }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
}

// --- dependency edges (D73): root → direct deps + vendored → declared deps ---
// All edges come from artifact-internal materials (D74): the root's direct
// deps come from resolved/dependency-tree.json; a vendored component's edges
// come from its artifact-contained package.json `dependencies` (never from a
// re-resolve, and only when the referenced component exists in this SBOM).

function byName(components: CycloneDxComponent[]): Map<string, string> {
  const map = new Map<string, string>()
  for (const component of components) map.set(component.name, component['bom-ref'])
  return map
}

/** tgz filename (packages/) → local component bom-ref. */
function localRefByTgz(input: SbomBuildInput): Map<string, string> {
  const stagedDeps = (input.profilePackageJson.dependencies ?? {}) as Record<string, string>
  const map = new Map<string, string>()
  for (const dep of input.depTree.localDeps) {
    const spec = stagedDeps[dep.name]
    const match = typeof spec === 'string' ? /^file:\.\/packages\/(.+)$/.exec(spec) : null
    if (match !== null) map.set(match[1] as string, `local:${dep.name}`)
  }
  return map
}

function dependencyEdges(
  input: SbomBuildInput,
  rootRef: string,
  refs: Map<string, string>,
): { ref: string; dependsOn: string[] }[] {
  const edges: { ref: string; dependsOn: string[] }[] = []

  // profile root → its direct dependencies (D74: from dependency-tree.json)
  const rootDependsOn = Object.keys(input.depTree.direct)
    .map((name) => refs.get(name))
    .filter((ref): ref is string => ref !== undefined)
    .sort()
  if (rootDependsOn.length > 0) edges.push({ ref: rootRef, dependsOn: rootDependsOn })

  // vendored components → deps declared in their artifact-contained package.json
  if (input.vendoredMetadata !== undefined) {
    const localRefs = localRefByTgz(input)
    for (const tgzName of [...input.vendoredMetadata.keys()].sort()) {
      const meta = input.vendoredMetadata.get(tgzName)
      const declared = meta?.manifest?.dependencies
      if (declared === null || typeof declared !== 'object') continue
      const dependsOn = Object.keys(declared as Record<string, unknown>)
        .map((name) => refs.get(name))
        .filter((ref): ref is string => ref !== undefined)
        .sort()
      if (dependsOn.length === 0) continue
      const componentRef = localRefs.get(tgzName)
      if (componentRef === undefined) continue
      edges.push({ ref: componentRef, dependsOn })
    }
  }

  return edges
}
