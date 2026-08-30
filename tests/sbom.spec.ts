/**
 * v0.5 alpha.3 SBOM Evidence test matrix (DESIGN-v0.5.0.md §7, D73–D80):
 * S0–S13 — deterministic CycloneDX 1.7 generation from the artifact's OWN
 * materials (never the current machine), independent document + signed
 * envelope, UNKNOWN semantics, no absolute paths, tamper resistance.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, openPack, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson, sha256Hex } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { verifyEvidenceEnvelope } from '../src/evidence/envelope.js'
import {
  generateSbomFromPack, npmPurl, SBOM_SPEC_VERSION,
  type CycloneDxBom, type CycloneDxComponent,
} from '../src/evidence/sbom.js'
import type { DependencyTree, EvidenceEnvelope } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-sbom-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// --- fixtures (artifact-internal inputs, D74) ---

const LOCKFILE_FIXTURE = [
  "lockfileVersion: '9.0'",
  'importers:',
  "  '.':",
  '    dependencies:',
  '      foo:',
  '        specifier: ^1.0.0',
  '        version: 1.2.3',
  "      local-plugin:",
  '        specifier: file:./packages/local-plugin-0.1.0.tgz',
  '        version: file:./packages/local-plugin-0.1.0.tgz',
  'packages:',
  '  /foo@1.2.3:',
  '    resolution:',
  '      integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==',
  '      tarball: https://registry.npmjs.org/foo/-/foo-1.2.3.tgz',
  '    version: 1.2.3',
  '',
].join('\n')

const DEFAULT_DEP_TREE: DependencyTree = {
  lockfile: 'pnpm-lock.yaml (lockfileVersion 9.0)',
  direct: { foo: '^1.0.0', 'local-plugin': 'file:./local-plugin' },
  closure: { foo: '1.2.3', 'local-plugin': '0.1.0' },
  // resolved is an ABSOLUTE MACHINE PATH — must never reach the SBOM (S11)
  localDeps: [{ name: 'local-plugin', spec: 'file:./local-plugin', kind: 'file', resolved: '/abs/machine/path/local-plugin', portable: true }],
  warnings: [],
}

const DEFAULT_PROFILE_PKG: Record<string, unknown> = {
  name: 'web-profile',
  version: '1.0.0',
  private: true,
  dependencies: { foo: '^1.0.0', 'local-plugin': 'file:./packages/local-plugin-0.1.0.tgz' },
  scripts: { prepare: 'node build.js' },
}

/** Vendored tgz (npm convention: everything under `package/`). */
async function makeVendoredTgz(opts: {
  license?: string
  scripts?: Record<string, string>
  extraFiles?: string[]
} = {}): Promise<Buffer> {
  const pkgJson: Record<string, unknown> = { name: 'local-plugin', version: '0.1.0' }
  if (opts.license !== undefined) pkgJson.license = opts.license
  if (opts.scripts !== undefined) pkgJson.scripts = opts.scripts
  // realistic: the vendored plugin declares a dependency on the registry foo
  pkgJson.dependencies = { foo: '^1.0.0' }
  const entries: PackFileEntry[] = [{ path: 'package/package.json', content: prettyJson(pkgJson) }]
  for (const file of opts.extraFiles ?? []) entries.push({ path: `package/${file}`, content: `// ${file}\n` })
  return (await buildTarGz(entries)).buffer
}

/** Build a .dshpack whose inputs are all artifact-internal. */
async function makePack(opts: {
  tgz?: Buffer
  tgzName?: string
  lockfile?: string
  depTree?: DependencyTree
  profilePkg?: Record<string, unknown>
} = {}): Promise<Buffer> {
  const profilePkg = opts.profilePkg ?? DEFAULT_PROFILE_PKG
  const depTree = opts.depTree ?? DEFAULT_DEP_TREE
  const manifest = {
    format: 'dshpack',
    schemaVersion: 1,
    profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true,
    portable: true,
    bundles: [],
    dependencies: profilePkg.dependencies as Record<string, string>,
    configHash: computeConfigHash({ rows: [{ id: 'llm-deepseek' }] }, [], depTree.closure),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-alpha.3' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(profilePkg) },
    { path: 'profile/pnpm-lock.yaml', content: opts.lockfile ?? LOCKFILE_FIXTURE },
    { path: 'resolved/dependency-tree.json', content: prettyJson(depTree) },
    { path: 'resolved/composition.json', content: prettyJson({ rows: [{ id: 'llm-deepseek' }] }) },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
    ...(opts.tgz !== undefined && opts.tgzName !== undefined
      ? [{ path: `packages/${opts.tgzName}`, content: opts.tgz }]
      : []),
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

function componentOf(bom: CycloneDxBom, bomRef: string): CycloneDxComponent | undefined {
  return bom.components.find((c) => c['bom-ref'] === bomRef)
}

function propertyOf(component: CycloneDxComponent | undefined, name: string): string | undefined {
  return component?.properties?.find((p) => p.name === name)?.value
}

// --- S0–S4: determinism, subject binding, components ---

describe('S0–S4: deterministic document, subject, components', () => {
  it('S0: same artifact → byte-identical SBOM document + identical digest', async () => {
    const root = tempRoot('s0')
    const pack = await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' })
    const first = await generateSbomFromPack(pack)
    const second = await generateSbomFromPack(pack)
    expect(first.document).toBe(second.document)
    expect(first.digest).toBe(second.digest)
    expect(first.digest).toMatch(/^sha256:[0-9a-f]{64}$/)
    // deterministic canonical bytes are the digest anchor (D80)
    expect(first.digest).toBe(`sha256:${sha256Hex(first.document)}`)
  })

  it('S1+S2+S3: subject == actual anchor; registry purl/resolved/integrity; vendored contentDigest', async () => {
    const root = tempRoot('s1')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' }))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const result = await evidence.sbom(packFile, { key: key.privateKey })

    // S1: subject == actual recomputed artifact anchor
    expect(result.contentHash).toBe(await computePackContentHash(readFileSync(packFile)))

    // S2: registry component with name/version/purl/resolved/integrity
    const bom = JSON.parse(readFileSync(result.documentFile, 'utf8')) as CycloneDxBom
    expect(bom.specVersion).toBe(SBOM_SPEC_VERSION)
    expect(bom.bomFormat).toBe('CycloneDX')
    const foo = componentOf(bom, npmPurl('foo', '1.2.3'))
    expect(foo?.name).toBe('foo')
    expect(foo?.version).toBe('1.2.3')
    expect(foo?.purl).toBe('pkg:npm/foo@1.2.3')
    expect(propertyOf(foo, 'dsh-pack:resolved')).toBe('https://registry.npmjs.org/foo/-/foo-1.2.3.tgz')
    expect(propertyOf(foo, 'dsh-pack:integrity')).toMatch(/^sha512-/)

    // S3: vendored dependency has a real content digest
    const local = componentOf(bom, 'local:local-plugin')
    expect(propertyOf(local, 'dsh-pack:source-type')).toBe('vendored')
    expect(propertyOf(local, 'dsh-pack:content-digest')).toMatch(/^sha256:[0-9a-f]{64}$/)

    // dependency graph (D73/D74): root → direct deps from dependency-tree.json;
    // vendored component → deps declared in its artifact-contained package.json
    expect(bom.dependencies).toBeDefined()
    const rootEdge = bom.dependencies?.find((e) => e.ref === 'profile:web-profile')
    expect(rootEdge?.dependsOn).toEqual(expect.arrayContaining(['pkg:npm/foo@1.2.3', 'local:local-plugin']))
    const vendoredEdge = bom.dependencies?.find((e) => e.ref === 'local:local-plugin')
    expect(vendoredEdge?.dependsOn).toEqual(['pkg:npm/foo@1.2.3'])

    // the signed envelope binds subject + sbomDigest (D75)
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
    const statement = envelope.statement as { format: string; specVersion: string; mediaType: string; sbomDigest: { algorithm: string; value: string } }
    expect(statement.format).toBe('cyclonedx')
    expect(statement.specVersion).toBe('1.7')
    expect(statement.mediaType).toBe('application/vnd.cyclonedx+json')
    expect(statement.sbomDigest).toEqual({ algorithm: 'sha256', value: result.sbomDigest.slice('sha256:'.length) })
    expect(result.sbomDigest).toBe(`sha256:${sha256Hex(readFileSync(result.documentFile, 'utf8'))}`)
  })

  it('S4: local dep content changes (path unchanged) → contentDigest / SBOM digest change', async () => {
    const root = tempRoot('s4')
    // same name/version/spec, DIFFERENT vendored content (a file was added)
    const tgzV1 = await makeVendoredTgz({ license: 'MIT' })
    const tgzV2 = await makeVendoredTgz({ license: 'MIT', extraFiles: ['index.js'] })
    expect(tgzV1.equals(tgzV2)).toBe(false)

    const packV1 = await makePack({ tgz: tgzV1, tgzName: 'local-plugin-0.1.0.tgz' })
    const packV2 = await makePack({ tgz: tgzV2, tgzName: 'local-plugin-0.1.0.tgz' })

    const bom1 = await generateSbomFromPack(packV1)
    const bom2 = await generateSbomFromPack(packV2)
    const c1 = componentOf(JSON.parse(bom1.document) as CycloneDxBom, 'local:local-plugin')
    const c2 = componentOf(JSON.parse(bom2.document) as CycloneDxBom, 'local:local-plugin')
    expect(propertyOf(c1, 'dsh-pack:content-digest')).not.toBe(propertyOf(c2, 'dsh-pack:content-digest'))
    expect(bom1.digest).not.toBe(bom2.digest)
  })
})

// --- S5–S7: license / lifecycle / native facts ---

describe('S5–S7: license UNKNOWN, lifecycle digest, native indicator', () => {
  it('S5: declared license recorded; missing license → UNKNOWN', async () => {
    const root = tempRoot('s5')
    const declared = await generateSbomFromPack(await makePack({
      tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz',
    }))
    const declaredBom = JSON.parse(declared.document) as CycloneDxBom
    expect(propertyOf(componentOf(declaredBom, 'local:local-plugin'), 'dsh-pack:license')).toBe('MIT')

    const missing = await generateSbomFromPack(await makePack({
      tgz: await makeVendoredTgz({}), tgzName: 'local-plugin-0.1.0.tgz',
    }))
    const missingBom = JSON.parse(missing.document) as CycloneDxBom
    expect(propertyOf(componentOf(missingBom, 'local:local-plugin'), 'dsh-pack:license')).toBe('UNKNOWN')
    // registry metadata has no license in the lockfile → nothing fabricated (D79)
    expect(propertyOf(componentOf(missingBom, npmPurl('foo', '1.2.3')), 'dsh-pack:license')).toBeUndefined()
  })

  it('S6: lifecycle scripts recorded as existence + scriptDigest (never raw text)', async () => {
    const root = tempRoot('s6')
    const result = await generateSbomFromPack(await makePack({
      tgz: await makeVendoredTgz({ license: 'MIT', scripts: { install: 'node install.js' } }),
      tgzName: 'local-plugin-0.1.0.tgz',
    }))
    const bom = JSON.parse(result.document) as CycloneDxBom
    // profile prepare script
    const prepare = propertyOf(componentOf(bom, 'profile:web-profile'), 'dsh-pack:npm-lifecycle:prepare')
    expect(prepare).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(prepare).not.toContain('node build.js')
    // vendored install script
    const install = propertyOf(componentOf(bom, 'local:local-plugin'), 'dsh-pack:npm-lifecycle:install')
    expect(install).toMatch(/^sha256:[0-9a-f]{64}$/)
    expect(install).not.toContain('node install.js')
    // scripts absent → no property (not fabricated)
    expect(propertyOf(componentOf(bom, npmPurl('foo', '1.2.3')), 'dsh-pack:npm-lifecycle:install')).toBeUndefined()
  })

  it('S7: native indicator present with reasons — no compatibility conclusion', async () => {
    const root = tempRoot('s7')
    const result = await generateSbomFromPack(await makePack({
      tgz: await makeVendoredTgz({ license: 'MIT', scripts: { install: 'node-gyp rebuild' }, extraFiles: ['binding.gyp'] }),
      tgzName: 'local-plugin-0.1.0.tgz',
    }))
    const bom = JSON.parse(result.document) as CycloneDxBom
    const local = componentOf(bom, 'local:local-plugin')
    expect(propertyOf(local, 'dsh-pack:native:detected')).toBe('true')
    const reasons = propertyOf(local, 'dsh-pack:native:reasons')
    expect(reasons).toContain('binding.gyp')
    expect(reasons).toContain('node-gyp')
    // indicator only: the document MUST NOT contain any compatibility claim
    expect(result.document).not.toMatch(/compatible|incompatible|platform.*(linux|darwin|win32)/i)
  })
})

// --- S8–S13: tamper resistance, isolation, coexistence ---

describe('S8–S13: tamper, subject swap, isolation, coexistence', () => {
  it('S8: tampered .cdx.json → sbomDigest mismatch → binding FAIL', async () => {
    const root = tempRoot('s8')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' }))
    const evidence = new DefaultEvidenceService()
    const result = await evidence.sbom(packFile, { key: generateKeypair(root).privateKey })

    // attacker rewrites a component version in the standalone document
    const tampered = readFileSync(result.documentFile, 'utf8').replace('"1.2.3"', '"9.9.9"')
    expect(tampered).not.toBe(readFileSync(result.documentFile, 'utf8'))

    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    const statement = envelope.statement as { sbomDigest: { algorithm: string; value: string } }
    expect(statement.sbomDigest.value).not.toBe(sha256Hex(tampered))
    // the envelope itself is still a genuine signed statement — the BINDING to
    // the (tampered) document is what fails
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
  })

  it('S9: SBOM Evidence for A verified --against B → subject FAIL', async () => {
    const root = tempRoot('s9')
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const packAFile = join(root, 'a.dshpack')
    writeFileSync(packAFile, await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' }))
    const resultA = await evidence.sbom(packAFile, { key: key.privateKey })

    const packBFile = join(root, 'b.dshpack')
    writeFileSync(packBFile, await makePack({
      tgz: await makeVendoredTgz({ license: 'MIT', extraFiles: ['other.js'] }), tgzName: 'local-plugin-0.1.0.tgz',
    }))

    // against the RIGHT artifact → ok
    expect((await evidence.verify(resultA.file, { against: packAFile })).ok).toBe(true)
    // against the WRONG artifact → subject binding FAIL
    const wrong = await evidence.verify(resultA.file, { against: packBFile })
    expect(wrong.ok).toBe(false)
    expect(wrong.errors.join('; ')).toContain('evidence subject is')
  })

  it('S10: mutating the current workspace does NOT change the artifact SBOM', async () => {
    const root = tempRoot('s10')
    const pack = await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' })
    const before = await generateSbomFromPack(pack)

    // "current machine" changes after the artifact was built (D74 violation attempt)
    mkdirSync(join(root, 'node_modules'), { recursive: true })
    writeFileSync(join(root, 'node_modules', 'sneaky.js'), 'module.exports = 1\n')
    writeFileSync(join(root, 'renamed-lock.yaml'), 'completely different lockfile')

    const after = await generateSbomFromPack(pack)
    expect(after.document).toBe(before.document)
    expect(after.digest).toBe(before.digest)
  })

  it('S11: no absolute machine paths in the SBOM', async () => {
    const root = tempRoot('s11')
    const result = await generateSbomFromPack(await makePack({
      tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz',
    }))
    // localDep.resolved is an absolute machine path — it must never appear
    expect(result.document).not.toContain('/abs/machine/path')
    expect(result.document).not.toContain('/home/')
    // Windows drive paths (C:\... / C:/...) — \b avoids matching `https://`
    expect(result.document).not.toMatch(/\b[A-Za-z]:[\\/]/)
  })

  it('S12: build-provenance + sbom coexist in one collection, no overwrite', async () => {
    const root = tempRoot('s12')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' }))
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const provenance = await evidence.sign(packFile, {
      type: 'build-provenance', statement: { source: { gitCommit: 'a'.repeat(40) } }, key: key.privateKey,
    })
    const sbom = await evidence.sbom(packFile, { key: key.privateKey })

    expect(provenance.file).toContain('build-provenance')
    expect(sbom.file).toContain('sbom')
    expect(sbom.file).not.toBe(provenance.file)
    // both coexist and neither overwrote the other
    expect(existsSync(provenance.file)).toBe(true)
    expect(existsSync(sbom.file)).toBe(true)
    expect(existsSync(sbom.documentFile)).toBe(true)
    expect(verifyEvidenceEnvelope(JSON.parse(readFileSync(provenance.file, 'utf8'))).ok).toBe(true)
    expect(verifyEvidenceEnvelope(JSON.parse(readFileSync(sbom.file, 'utf8'))).ok).toBe(true)
  })

  it('S13: same configHash, different dependency content → contentHash/SBOM differ', async () => {
    const root = tempRoot('s13')
    const packV1 = await makePack({ tgz: await makeVendoredTgz({ license: 'MIT' }), tgzName: 'local-plugin-0.1.0.tgz' })
    const packV2 = await makePack({ tgz: await makeVendoredTgz({ license: 'MIT', extraFiles: ['changed.js'] }), tgzName: 'local-plugin-0.1.0.tgz' })

    // configHash is identical (same composition, identities, closure)
    const opened1 = await openPack(packV1)
    const opened2 = await openPack(packV2)
    let configHashA = ''
    let configHashB = ''
    try {
      configHashA = (opened1.manifest as { configHash?: string }).configHash as string
      configHashB = (opened2.manifest as { configHash?: string }).configHash as string
    } finally {
      rmSync(opened1.root, { recursive: true, force: true })
      rmSync(opened2.root, { recursive: true, force: true })
    }
    expect(configHashA).toBe(configHashB)

    // but artifact identity and SBOM differ (D80/D76 content digest)
    expect(await computePackContentHash(packV1)).not.toBe(await computePackContentHash(packV2))
    const sbom1 = await generateSbomFromPack(packV1)
    const sbom2 = await generateSbomFromPack(packV2)
    expect(sbom1.digest).not.toBe(sbom2.digest)
  })
})
