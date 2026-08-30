/**
 * v0.5 alpha.4 Declared Capability Manifest test matrix (DESIGN-v0.5.0.md §8,
 * D81–D88): C0–C10 — deterministic pure-artifact-inspection manifest bound to
 * the actual contentHash, declared/observed separation, UNKNOWN semantics, no
 * allow/deny, no cold boot, tamper/subject resistance, coexistence.
 */
import { createHash } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import { buildTarGz, computePackContentHash, type PackFileEntry } from '../src/pack-builder.js'
import { generateKeypair } from '../src/sign.js'
import { computeConfigHash } from '../src/manifest.js'
import { prettyJson } from '../src/canonical.js'
import { DefaultEvidenceService } from '../src/evidence/service.js'
import { verifyEvidenceEnvelope } from '../src/evidence/envelope.js'
import {
  CAPABILITY_FORMAT, CAPABILITY_SCHEMA_VERSION, CAPABILITY_UNKNOWN_REASON,
  generateCapabilityManifestFromPack,
  type CapabilityManifest, type DeclaredCapability,
} from '../src/evidence/capability.js'
import type { DependencyTree, EvidenceEnvelope } from '../src/types.js'

const tempDirs: string[] = []
function tempRoot(label: string): string {
  const dir = mkdtempSync(join(tmpdir(), `dsh-pack-cap-${label}-`))
  tempDirs.push(dir)
  return dir
}
afterEach(() => {
  for (const dir of tempDirs.splice(0)) rmSync(dir, { recursive: true, force: true })
})

// --- fixtures ---

const DEFAULT_PATCH = `# web
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        temperature: 0.3
`

const DEFAULT_ROWS: Record<string, unknown>[] = [
  { id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.3 } },
]

const DEFAULT_PROFILE_PKG: Record<string, unknown> = {
  name: 'web-profile', version: '1.0.0', private: true,
  dependencies: { foo: '^1.0.0' },
  dsh: { profile: { bundles: [] } },
}

const LOCKFILE_FIXTURE = [
  "lockfileVersion: '9.0'",
  'importers:',
  "  '.':",
  '    dependencies:',
  '      foo:',
  '        specifier: ^1.0.0',
  '        version: 1.2.3',
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
  direct: { foo: '^1.0.0' },
  closure: { foo: '1.2.3' },
  localDeps: [],
  warnings: [],
}

async function makePack(opts: {
  rows?: Record<string, unknown>[]
  patchText?: string
  lockfile?: string
  depTree?: DependencyTree
} = {}): Promise<Buffer> {
  const manifest = {
    format: 'dshpack',
    schemaVersion: 1,
    profile: { name: 'web' },
    snapshot: { scope: 'profile', excludedLayersPresent: false },
    runtime: { dshVersion: '0.1.0-rc.5', nodeVersion: '24.6.0', pnpmVersion: '10.15.0', platform: 'linux-x64' },
    installable: true,
    portable: true,
    bundles: [],
    dependencies: DEFAULT_PROFILE_PKG.dependencies as Record<string, string>,
    configHash: computeConfigHash({ rows: opts.rows ?? DEFAULT_ROWS }, [], (opts.depTree ?? DEFAULT_DEP_TREE).closure),
    createdAt: '2026-08-30T00:00:00Z',
    packager: { name: '@why-daydream/dsh-pack', version: '0.5.0-alpha.4' },
  }
  const entries: PackFileEntry[] = [
    { path: 'manifest.json', content: prettyJson(manifest) },
    { path: 'profile/package.json', content: prettyJson(DEFAULT_PROFILE_PKG) },
    { path: 'profile/cordis.patch.yml', content: opts.patchText ?? DEFAULT_PATCH },
    { path: 'resolved/composition.json', content: prettyJson({ rows: opts.rows ?? DEFAULT_ROWS }) },
    { path: 'resolved/dependency-tree.json', content: prettyJson(opts.depTree ?? DEFAULT_DEP_TREE) },
    { path: 'resolved/layers.json', content: prettyJson({ schemaVersion: 1, layers: [] }) },
    { path: 'profile/pnpm-lock.yaml', content: opts.lockfile ?? LOCKFILE_FIXTURE },
    { path: 'metadata/warnings.json', content: prettyJson({ schemaVersion: 1, warnings: [] }) },
  ]
  const built = await buildTarGz(entries)
  const final = await buildTarGz([
    ...entries,
    { path: 'metadata/checksums.json', content: prettyJson({ schemaVersion: 1, contentHash: built.contentHash, files: built.files }) },
  ])
  return final.buffer
}

function declaredOf(manifest: CapabilityManifest, kind: 'providers' | 'services'): DeclaredCapability[] {
  return manifest.declared[kind]
}

// --- C0–C4: determinism, subject, classification ---

describe('C0–C4: determinism, subject binding, classification', () => {
  it('C0: same artifact → byte-identical manifest + identical digest', async () => {
    const root = tempRoot('c0')
    const pack = await makePack()
    const first = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'a'.repeat(64))
    const second = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'a'.repeat(64))
    expect(first.document).toBe(second.document)
    expect(first.digest).toBe(second.digest)
    expect(first.digest).toMatch(/^sha256:[0-9a-f]{64}$/)
  })

  it('C1+C2+C3: subject == actual anchor; stable ids; provider/service kind correct', async () => {
    const root = tempRoot('c1')
    const packFile = join(root, 'app.dshpack')
    // 'search' row comes from a bundle layer (not declared by the profile patch)
    const pack = await makePack({
      rows: [
        { id: 'llm-deepseek', provider: 'deepseek', config: { temperature: 0.3 } },
        { id: 'search', config: { provider: 'vector' } },
      ],
    })
    writeFileSync(packFile, pack)
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const result = await evidence.capability(packFile, { key: key.privateKey })

    // C1: subject == actual recomputed artifact anchor
    expect(result.contentHash).toBe(await computePackContentHash(readFileSync(packFile)))

    const manifest = JSON.parse(readFileSync(result.documentFile, 'utf8')) as CapabilityManifest
    expect(manifest.subject.contentHash).toBe(result.contentHash)
    // C2: stable ids (not display names)
    expect(declaredOf(manifest, 'providers').map((c) => c.id)).toEqual(['llm-deepseek'])
    expect(declaredOf(manifest, 'services').map((c) => c.id)).toEqual(['search'])
    // C3: kind + source attribution (D85)
    expect(declaredOf(manifest, 'providers')[0]).toEqual({
      id: 'llm-deepseek', kind: 'provider', declaredBy: { layer: 'profile:cordis.patch.yml' },
    })
    expect(declaredOf(manifest, 'services')[0]).toEqual({
      id: 'search', kind: 'service', declaredBy: { layer: 'bundle' },
    })

    // the signed envelope binds subject + capabilityDigest (D82/D88)
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
    const statement = envelope.statement as { format: string; schemaVersion: number; capabilityDigest: { algorithm: string; value: string } }
    expect(statement.format).toBe(CAPABILITY_FORMAT)
    expect(statement.schemaVersion).toBe(CAPABILITY_SCHEMA_VERSION)
    expect(statement.capabilityDigest).toEqual({ algorithm: 'sha256', value: result.capabilityDigest.slice('sha256:'.length) })
  })

  it('C4: same id from different sources/kinds is NOT merged (sources preserved)', async () => {
    const root = tempRoot('c4')
    const pack = await makePack({
      patchText: `# web
- insert:
    - id: hybrid
      provider: deepseek
`,
      rows: [
        { id: 'hybrid', provider: 'deepseek' },
        { id: 'hybrid', config: {} },
      ],
    })
    const { document } = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'b'.repeat(64))
    const manifest = JSON.parse(document) as CapabilityManifest
    // the two declarations stay separate: provider (profile layer) vs service (bundle layer)
    expect(declaredOf(manifest, 'providers').map((c) => c.id)).toEqual(['hybrid'])
    expect(declaredOf(manifest, 'services').map((c) => c.id)).toEqual(['hybrid'])
    expect(declaredOf(manifest, 'providers').length + declaredOf(manifest, 'services').length).toBe(2)
  })
})

// --- C5–C10: empty set, isolation, tamper, coexistence, undiscoverable ---

describe('C5–C10: empty set, isolation, tamper, coexistence, undiscoverable', () => {
  it('C5: no capability declarations → empty sets (never guessed)', async () => {
    const root = tempRoot('c5')
    const pack = await makePack({ rows: [] })
    const { document } = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'c'.repeat(64))
    const manifest = JSON.parse(document) as CapabilityManifest
    expect(manifest.declared.providers).toEqual([])
    expect(manifest.declared.services).toEqual([])
    expect(manifest.declared.tools).toEqual([])
    expect(manifest.declared.skills).toEqual([])
    expect(manifest.undiscoverable.tools.reason).toBe(CAPABILITY_UNKNOWN_REASON)
    expect(manifest.undiscoverable.skills.reason).toBe(CAPABILITY_UNKNOWN_REASON)
  })

  it('C6: mutating the current workspace does NOT change the artifact manifest', async () => {
    const root = tempRoot('c6')
    const pack = await makePack()
    const before = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'd'.repeat(64))
    writeFileSync(join(root, 'sneaky-patch.yml'), '- insert:\n    - id: injected\n      provider: evil\n')
    const after = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'd'.repeat(64))
    expect(after.document).toBe(before.document)
    expect(after.digest).toBe(before.digest)
  })

  it('C7: tampered capability document → digest mismatch → binding FAIL', async () => {
    const root = tempRoot('c7')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const evidence = new DefaultEvidenceService()
    const result = await evidence.capability(packFile, { key: generateKeypair(root).privateKey })

    const tampered = readFileSync(result.documentFile, 'utf8').replace('llm-deepseek', 'evil-injected')
    expect(tampered).not.toBe(readFileSync(result.documentFile, 'utf8'))
    const envelope = JSON.parse(readFileSync(result.file, 'utf8')) as EvidenceEnvelope
    const statement = envelope.statement as { capabilityDigest: { algorithm: string; value: string } }
    expect(statement.capabilityDigest.value).not.toBe(createHash('sha256').update(tampered).digest('hex'))
    // the envelope itself is still a genuine signed statement — the BINDING to
    // the tampered document is what fails
    expect(verifyEvidenceEnvelope(envelope).ok).toBe(true)
  })

  it('C8: capability evidence for A verified --against B → subject FAIL', async () => {
    const root = tempRoot('c8')
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()
    const packAFile = join(root, 'a.dshpack')
    writeFileSync(packAFile, await makePack())
    const resultA = await evidence.capability(packAFile, { key: key.privateKey })

    const packBFile = join(root, 'b.dshpack')
    writeFileSync(packBFile, await makePack({ rows: [{ id: 'other', provider: 'openai' }] }))

    expect((await evidence.verify(resultA.file, { against: packAFile })).ok).toBe(true)
    const wrong = await evidence.verify(resultA.file, { against: packBFile })
    expect(wrong.ok).toBe(false)
    expect(wrong.errors.join('; ')).toContain('evidence subject is')
  })

  it('C9: provenance + sbom + capability coexist in one collection, no overwrite', async () => {
    const root = tempRoot('c9')
    const packFile = join(root, 'app.dshpack')
    writeFileSync(packFile, await makePack())
    const key = generateKeypair(root)
    const evidence = new DefaultEvidenceService()

    const provenance = await evidence.sign(packFile, {
      type: 'build-provenance', statement: { source: { gitCommit: 'a'.repeat(40) } }, key: key.privateKey,
    })
    const sbom = await evidence.sbom(packFile, { key: key.privateKey })
    const capability = await evidence.capability(packFile, { key: key.privateKey })

    expect(provenance.file).toContain('build-provenance')
    expect(sbom.file).toContain('sbom')
    expect(capability.file).toContain('capability')
    expect(new Set([provenance.file, sbom.file, capability.file]).size).toBe(3)
    // all coexist; nothing overwrote anything
    for (const file of [provenance.file, sbom.file, capability.file]) {
      expect(verifyEvidenceEnvelope(JSON.parse(readFileSync(file, 'utf8'))).ok).toBe(true)
    }
  })

  it('C10: tools/skills statically undiscoverable — UNKNOWN + reason, no observed/no allow-deny', async () => {
    const root = tempRoot('c10')
    const pack = await makePack()
    const { document } = await generateCapabilityManifestFromPack(pack, 'sha256:' + 'e'.repeat(64))
    const manifest = JSON.parse(document) as CapabilityManifest

    // declared/observed separation (D83): NO observed section exists at all
    expect((manifest as unknown as Record<string, unknown>).observed).toBeUndefined()
    // no permission judgment (D87): no allow/deny/safe keys anywhere
    expect(document).not.toMatch(/"(allowed|denied|safe|unsafe|leastPrivilege)"/)
    // tools/skills are empty with an honest reason (C10) — nothing guessed,
    // no runtime execution happened (the generator only reads the archive)
    expect(manifest.declared.tools).toEqual([])
    expect(manifest.declared.skills).toEqual([])
    expect(manifest.undiscoverable.tools.reason).toContain('runtime registration')
    expect(manifest.undiscoverable.skills.reason).toContain('runtime registration')
  })
})
