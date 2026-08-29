/**
 * v0.3 signing 真实 CLI 端到端验收（2026-08-29）。
 *
 * 驱动真实的 /pack 命令路径（makeHandler → parseCommand → runCommand），
 * 覆盖发布验收的 8 个场景：
 *   1. keygen          —— ed25519 密钥对 + SHA256 指纹（chmod 600）
 *   2. pack + sign     —— 真实 profile → .dshpack → .signed.dshpack
 *   3. verify（无白名单）—— Signature VALID + Trust N/A
 *   4. trusted/untrusted —— DSH_PACK_TRUSTED_KEYS 白名单（VALID ≠ TRUSTED）
 *   5. unsigned + --require-signature —— WARN / FAIL
 *   6. tamper          —— 篡改真实内容后 Signature INVALID + FAIL
 *   7. re-sign         —— 默认拒绝，--force 替换
 *
 * 退出码：0 全部通过；非 0 有失败。
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DefaultPackager } from '../lib/service.js'
import { makeHandler } from '../lib/commands.js'
import { buildTarGz, collectFiles, openPack } from '../lib/pack-builder.js'

const DSH_VERSION = '0.1.0-rc.5'
let failures = 0

function check(name, ok, detail = '') {
  console.log(`${ok ? '✓' : '✗'} ${name}${detail !== '' ? ` — ${detail}` : ''}`)
  if (!ok) failures++
}
function section(title) {
  console.log(`\n== ${title} ==`)
}

const root = mkdtempSync(join(tmpdir(), 'dsh-pack-signing-e2e-'))
const home = join(root, 'home')
const outDir = join(root, 'out')
mkdirSync(join(home, 'profiles', 'web'), { recursive: true })
mkdirSync(outDir, { recursive: true })
writeFileSync(join(home, 'profiles', 'web', 'package.json'), JSON.stringify({
  name: 'web-profile', private: true, version: '0.0.0', dependencies: {}, dsh: { profile: { bundles: [] } },
}, null, 2))
writeFileSync(join(home, 'profiles', 'web', 'cordis.patch.yml'), `# web profile
- insert:
    - id: llm-deepseek
      provider: deepseek
      config:
        apiKey: sk-1234567890abcdef1234
        temperature: 0.3
`)

const packager = new DefaultPackager({ home, installedDshVersion: DSH_VERSION, packagerVersion: '0.3.0' })
const handler = makeHandler(packager)
const run = (rawInput) => handler({ rawInput })

try {
  section('1. keygen')
  const keygen = await run(`keygen --out ${outDir}`)
  check('keygen succeeds', keygen.kind === 'success', keygen.text.split('\n')[0])
  check('keygen shows SHA256 fingerprint', /Key fingerprint: SHA256:[0-9a-f]{64}/.test(keygen.text))
  const keyId = /SHA256:([0-9a-f]{64})/.exec(keygen.text)?.[1] ?? ''
  const privateKey = join(outDir, 'dsh-pack-private.pem')
  const publicKey = join(outDir, 'dsh-pack-public.pem')
  check('private key written with chmod 600', existsSync(privateKey) && (statSync(privateKey).mode & 0o777) === 0o600)
  check('public key written', existsSync(publicKey))
  check('keyId is 64 hex (cryptographic fingerprint)', /^[0-9a-f]{64}$/.test(keyId))

  section('2. pack + sign')
  const packed = await run(`web --out ${outDir}`)
  check('pack succeeds', packed.kind === 'success', packed.text.split('\n').at(-1))
  const packName = readdirSync(outDir).find((f) => /^web-\d{8}\.dshpack$/.test(f))
  check('pack artifact created', packName !== undefined, packName)
  const packFile = join(outDir, packName)
  const sign = await run(`sign ${packFile} --key ${privateKey} --signer WHY-Daydream`)
  check('sign succeeds', sign.kind === 'success', sign.text.split('\n')[0])
  check('sign shows fingerprint + signer label', /Key fingerprint: SHA256:[0-9a-f]{64}/.test(sign.text) && sign.text.includes('WHY-Daydream'))
  const signedFile = join(outDir, `${packName.replace(/\.dshpack$/, '')}.signed.dshpack`)
  check('signed artifact created', existsSync(signedFile), signedFile)

  section('3. verify signed（无白名单）')
  const v1 = await run(`verify ${signedFile}`)
  check('verify PASS', v1.kind === 'success' && v1.text.includes('Package verified.'))
  check('Signature VALID', v1.text.includes('Signature — VALID'))
  check('Key SHA256 fingerprint shown', /Key SHA256:[0-9a-f]{12}/.test(v1.text))
  check('Trust N/A（未配置白名单）', v1.text.includes('Trust: N/A'))
  check('signer label shown (display only)', v1.text.includes('WHY-Daydream'))

  section('4. trusted / untrusted（VALID ≠ TRUSTED）')
  process.env.DSH_PACK_TRUSTED_KEYS = keyId
  const v2 = await run(`verify ${signedFile}`)
  check('pinned fingerprint → Trust VERIFIED', v2.kind === 'success' && v2.text.includes('Trust: VERIFIED'))
  process.env.DSH_PACK_TRUSTED_KEYS = 'f'.repeat(64)
  const v3 = await run(`verify ${signedFile}`)
  check('不同指纹 → Signature 仍 VALID', v3.text.includes('Signature — VALID'))
  check('不同指纹 → Trust UNTRUSTED（VALID ≠ TRUSTED）', v3.text.includes('Trust: UNTRUSTED') && !v3.text.includes('Trust: VERIFIED'))
  delete process.env.DSH_PACK_TRUSTED_KEYS

  section('5. unsigned + --require-signature')
  const vu = await run(`verify ${packFile}`)
  check('unsigned → PASS/WARN（Signature 缺失）', vu.kind === 'success' && vu.text.includes('unsigned pack'))
  const vuReq = await run(`verify ${packFile} --require-signature`)
  check('unsigned + --require-signature → FAIL', vuReq.kind === 'error' && vuReq.text.includes('unsigned pack'))

  section('6. tampered signed pack')
  const opened = await openPack(readFileSync(signedFile))
  let tampered
  try {
    writeFileSync(join(opened.root, 'README.md'), '# TAMPERED\n')
    const entries = collectFiles(opened.root).map((p) => ({ path: p, content: readFileSync(join(opened.root, p)) }))
    const rebuilt = await buildTarGz(entries)
    tampered = rebuilt.buffer
  } finally {
    rmSync(opened.root, { recursive: true, force: true })
  }
  const tamperedFile = join(outDir, 'tampered.dshpack')
  writeFileSync(tamperedFile, tampered)
  const vt = await run(`verify ${tamperedFile}`)
  check('篡改内容 → verify FAIL', vt.kind === 'error' && vt.text.includes('Package verification FAILED.'))
  check('篡改内容 → Signature INVALID', vt.text.includes('✗ Signature'))

  section('7. re-sign guard')
  const rs = await run(`sign ${signedFile} --key ${privateKey}`)
  check('已签包默认拒绝再签', rs.kind === 'error' && rs.text.includes('already signed'))
  const rsForce = await run(`sign ${signedFile} --key ${privateKey} --force`)
  check('--force 替换签名成功', rsForce.kind === 'success' && rsForce.text.includes('signed'))

  console.log('')
  if (failures === 0) {
    console.log('✔ SIGNING CLI E2E PASSED')
    process.exitCode = 0
  } else {
    console.log(`✘ SIGNING CLI E2E FAILED (${failures} 项失败)`)
    process.exitCode = 1
  }
} finally {
  rmSync(root, { recursive: true, force: true })
}
