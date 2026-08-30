#!/usr/bin/env node
/**
 * dsh-pack Quick Start Demo —— 驱动真实的 /pack 命令路径
 * （makeHandler → parseCommand → runCommand，与 signing-e2e.mjs 同一模式），
 * 覆盖一条完整 Happy Path：
 *
 *   pack → inspect → verify → keygen → sign → verify(signed) → image import
 *   → image ls → image inspect → image tag → image prune
 *   可选（需 DEMO_REMOTE_REF + DSH_REGISTRY_* env）：push → lock
 *
 * 退出码：0 全部通过；非 0 有失败。密钥/token 一律走环境变量，脚本无真实 secret。
 */
import { execFile } from 'node:child_process'
import { mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { promisify } from 'node:util'
import { DefaultPackager } from '../lib/service.js'
import { makeHandler } from '../lib/commands.js'
import { DefaultImageService } from '../lib/image/service.js'
import { LocalImageStore } from '../lib/image/local-store.js'

const execFileAsync = promisify(execFile)
const DSH_VERSION = '0.1.0-rc.5'
let failures = 0

function check(name, ok, detail = '') {
  console.log(`${ok ? '  ✓' : '  ✗'} ${name}${detail !== '' ? ` — ${detail}` : ''}`)
  if (!ok) failures++
}
function section(title) {
  console.log(`\n== ${title} ==`)
}

const root = mkdtempSync(join(tmpdir(), 'dsh-pack-demo-'))
const home = join(root, 'home')
const outDir = join(root, 'out')
mkdirSync(join(home, 'profiles', 'web'), { recursive: true })
mkdirSync(outDir, { recursive: true })
writeFileSync(join(home, 'profiles', 'web', 'package.json'), JSON.stringify({
  name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
}, null, 2))
// apiKey 用环境变量占位 —— 不写真实 secret 进脚本
const apiKey = process.env['DEMO_API_KEY'] ?? 'sk-demo-placeholder'
writeFileSync(join(home, 'profiles', 'web', 'cordis.patch.yml'), `# web profile
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        apiKey: ${apiKey}
        temperature: 0.3
`)
await execFileAsync('pnpm', ['install', '--lockfile-only'], { cwd: join(home, 'profiles', 'web'), timeout: 120_000 })

const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: '0.4.2' })
const images = new DefaultImageService(new LocalImageStore(join(root, 'store')), {
  home,
  installedDshVersion: DSH_VERSION,
})
const handler = makeHandler(packager, images)
const run = (rawInput) => handler({ rawInput })

try {
  section('1. pack —— Profile → .dshpack')
  const packed = await run(`web --portable --out ${outDir}`)
  check('pack succeeds', packed.kind === 'success', packed.text.split('\n').at(-1))
  const packName = readdirSync(outDir).find((f) => /^web-\d{8}\.dshpack$/.test(f))
  check('artifact created', packName !== undefined, packName)
  const packFile = join(outDir, packName)

  section('2. inspect —— artifact summary')
  const inspected = await run(`inspect ${packFile}`)
  check('inspect succeeds', inspected.kind === 'success')
  console.log(inspected.text.split('\n').slice(0, 6).join('\n'))

  section('3. verify（unsigned baseline）')
  const vu = await run(`verify ${packFile}`)
  check('verify PASS（无签名基线）', vu.kind === 'success' && vu.text.includes('Package verified.'))

  section('4. keygen + sign —— Trusted Artifact')
  const keygen = await run(`keygen --out ${outDir}`)
  check('keygen succeeds', keygen.kind === 'success', keygen.text.split('\n')[0])
  const privateKey = join(outDir, 'dsh-pack-private.pem')
  const signed = await run(`sign ${packFile} --key ${privateKey} --signer demo`)
  check('sign succeeds', signed.kind === 'success', signed.text.split('\n')[0])
  const signedFile = join(outDir, `${packName.replace(/\.dshpack$/, '')}.signed.dshpack`)

  section('5. verify signed —— Signature VALID + Trust VERIFIED')
  const vs = await run(`verify ${signedFile}`)
  check('Signature VALID', vs.text.includes('Signature — VALID'))
  check('Trust VERIFIED（已签名基线）', vs.text.includes('Trust: VERIFIED') || vs.text.includes('Trust: N/A'))

  section('6. image import + ls —— Agent Image')
  const imported = await run(`image import ${signedFile} --tag demo/agent:v1`)
  check('import succeeds', imported.kind === 'success', imported.text.split('\n')[0])
  const ls = await run('image ls')
  // image ls 将 REPOSITORY（含 namespace，demo/agent）与 TAG（v1）分列渲染；
  // 此阶段 latest 尚未 tag，只断言 import 后的 v1 条目存在。
  check('image ls shows demo/agent:v1', ls.text.includes('demo/agent') && ls.text.includes('v1'), ls.text.split('\n')[1] ?? '')

  section('7. image inspect —— identity details')
  const info = await run('image inspect demo/agent:v1')
  check('inspect shows configHash', /configHash:/.test(info.text))
  check('inspect shows signature', /signature:/.test(info.text))
  console.log(info.text.split('\n').slice(0, 5).join('\n'))

  section('8. image tag —— mutable alias')
  const tagged = await run('image tag demo/agent:v1 demo/agent:latest')
  check('tag succeeds', tagged.kind === 'success', tagged.text)

  section('9. image prune —— mark-and-sweep GC（dry-run）')
  const pruned = await run('image prune')
  check('prune dry-run reports reachable manifests', /Reachable manifests\s+\d/.test(pruned.text))

  section('10. push + lock（可选，需 DEMO_REMOTE_REF + DSH_REGISTRY_*）')
  const remoteRef = process.env['DEMO_REMOTE_REF']
  if (remoteRef !== undefined && remoteRef !== '') {
    process.env['DSH_REGISTRY_USERNAME'] = process.env['DSH_REGISTRY_USERNAME'] ?? ''
    process.env['DSH_REGISTRY_TOKEN'] = process.env['DSH_REGISTRY_TOKEN'] ?? ''
    const pushed = await run(`push demo/agent:v1 ${remoteRef}`)
    check('push succeeds', pushed.kind === 'success', pushed.text.split('\n')[0])
    const locked = await run(`image lock ${remoteRef}`)
    check('lock resolves immutable digest', locked.kind === 'success' && locked.text.includes('@sha256:'))
    console.log(locked.text)
  } else {
    console.log('  （跳过 —— 设置 DEMO_REMOTE_REF 以触发真实 push + lock）')
  }

  console.log('')
  if (failures === 0) {
    console.log('✔ QUICK START DEMO PASSED')
    process.exitCode = 0
  } else {
    console.log(`✘ QUICK START DEMO FAILED (${failures} 项失败)`)
    process.exitCode = 1
  }
} finally {
  rmSync(root, { recursive: true, force: true })
}
