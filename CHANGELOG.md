# Changelog

本项目的版本历史。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- **v0.4 规划**：Agent Image / Distribution Model（`.dshpack` 如何成为正式发布单元：
  `dsh push/pull/run`），随后 v0.5 Encryption（私密插件源码 / 企业离线分发场景才需要）。
  Signing 已知边界（吊销 / 轮换 / 多签名 / 过期）同列后续。

## [v0.3.0] - 2026-08-29

### Trusted Artifact：嵌入式 ed25519 签名（Signing / Provenance / Trust）

定位演进：v0.1 可验证快照 → v0.2 可移植 Artifact → **v0.3 可信 Artifact**——
回答"这个包是谁做的、有没有被篡改、能否信任"。

### Added

- **`/pack keygen`**：生成 ed25519 密钥对（私钥 `dsh-pack-private.pem` chmod 0600 +
  公钥 + `Key fingerprint: SHA256:<keyId>`；keyId = 公钥 SPKI DER 的 sha256）。
- **`/pack sign <file> --key <pem> [--signer <name>] [--force]`**：确定性重建包，嵌入
  `metadata/signature.json`（自包含验签：公钥内嵌，被签对象 = contentHash 锚点字符串）+
  `metadata/provenance.json`（Artifact → Build → Signer 轻量来源），产出
  `<name>.signed.dshpack`（原包不覆盖）。
- **verify 新增 Signature 分节**：锚点取**实际文件字节重算**的 contentHash（纵深防御，
  防 checksums.json 被一并改写）；`--require-signature` 强制签名（缺失 FAIL）；
  `DSH_PACK_TRUSTED_KEYS` 白名单 → `Trust: VERIFIED / UNTRUSTED / N/A` 三态。
- **contentHash 排除集扩展（D17 扩展）**：checksums.json + signature.json +
  provenance.json 均不参与完整性锚——加签名不改变被签值，sign-then-embed 保持有效。

### 安全语义（冻结，DESIGN.md D18/D19）

- **VALID ≠ TRUSTED（D19）**：`Signature VALID` 只证明"对应私钥持有者签过该锚点"；
  `Trust VERIFIED` 才代表"该指纹在本地信任白名单内"。两者严格分离——CLI E2E 有专项
  断言：untrusted 指纹下 Signature 仍 VALID。
- **signer 不是信任根**：`--signer` 只是显示标签（display metadata），绝不参与 Trust
  判定；密码学身份一律来自 public key fingerprint（keyId）。
- **re-sign 显式破坏（D18）**：已签包再次 `/pack sign` 默认 FAIL（exit 1）；
  `--force` 显式替换——防止"官方签名包被任意重签覆盖"（与 install `--force` 同原则）。

### 工程笔记

- **真实 CLI 端到端验收发现并修复 1 个 bug**：`DefaultPackager.verify` 未透传
  `requireSignature`（单测直调 verifyPack、绕过服务层），导致
  `/pack verify --require-signature` 对未签名包不生效。已修复并补服务级回归测试——
  这正是"收住功能、跑真实用户路径"的价值。

### 验收（2026-08-29）

- 64 单测全绿（新增：re-sign 默认拒绝 + `--force` 替换、trust 三态 + `SHA256:` 前缀
  归一化、provenance 定稿结构、require-signature 服务层回归）+ typecheck 通过
- 真实 CLI E2E（`scripts/signing-e2e.mjs`）23 项断言全过：keygen → pack+sign →
  verify（VALID / Trust N/A）→ trusted/untrusted（VALID≠TRUSTED）→ unsigned+require
  → tamper（Signature INVALID）→ re-sign
- 2 个真实 pnpm North-Star E2E（v0.1 roundtrip + --portable）无回归

## [v0.2.0] - 2026-08-29

### 首个公开 Git 发布（First public Git release）

v0.1.0 是仓库初始化前的开发里程碑（见下），本仓库的 Git 历史从 v0.2.0 开始，
与协议层面已经过 Review + North-Star E2E 验证的 v0.1 快照能力无缝衔接。

### Added

- **`/pack diff <a> <b>`**：两个 `.dshpack` 的配置漂移对比，四个域
  （Manifest / Bundles / Config / Dependencies）+ configHash 判定，支持 `--json`。
- **`--portable`**：把 profile 的本地 `file:`/`link:` 目录依赖整体 vendoring 进包，
  使"带了本地插件的可运行环境"也能跨机器一键恢复：
  - 本地依赖图 **DFS 闭包**（传递依赖 + cycle 检测）；
  - 确定性 tgz vendoring（npm `package/` 条目前缀、mtime=0、pnpm 兼容 integrity）；
  - 传递 spec 重写（`file:`/`link:` → `file:vendor/<tgz>`）；
  - **pnpm lockfile 目录形态 → tarball 形态重写**（importer + `packages:` 键 +
    `snapshots:` 值，同时覆盖声明形式与 pnpm 项目相对路径形式）；
  - manifest 新增可选 `packages` 字段（schema v1 minor 扩展，§3.4 兼容规则）；
  - verify 的 Packages 分节支持 vendored tgz 校验。
- North-Star E2E：`pack --portable` → 干净 `DSH_HOME` 真实 `pnpm install --frozen-lockfile`
  → install 侧 configHash == manifest 完全一致。

### 工程笔记：`--portable` 实现中踩到的三个真实问题

这三个问题很好地说明这个项目处理的是 dependency graph、lockfile semantics 与
reproducible artifact，而不是简单的压缩脚本：

1. **异步 staging 竞态（ENOENT 时有时无）**：`buildVendoredTgz` 里
   `return createPackageTgz(staging)` 没有 `await`，async 函数的 `finally` 会在
   tar.c 异步读文件完成前就 `rmSync` 掉 staging 目录 → 偶发 ENOENT。
   修复：`return await ...`，保证清理发生在归档完成之后。
2. **package.json 被覆盖**：vendored tgz 的构建顺序是先写重写后的 package.json
   再 `copyTreeExcluding` 拷贝源码树，导致重写结果被源目录的原始 package.json 盖回。
   修复：先拷文件、最后写重写后的 package.json。
3. **pnpm 项目相对路径语义**：pnpm lockfile 里 `file:`/`link:` 依赖按**项目根相对路径**
   寻址（传递依赖与声明 spec 不同），只按声明 spec 重写会导致 B 机 frozen install
   去 `scandir` 打包机的本地路径。修复：闭包收集时计算每个包的项目相对路径，
   重写同时匹配声明形式与 `file:`/`link:` 项目相对形式。

### Fixed（v0.1 代码审查，详见 `DESIGN.md` Appendix D / `TRACEABILITY.md`）

- `portable` 标志在 `--allow-nonportable` 下仍为 `true`（协议违反）→ 改为与
  `installable` 一致。
- staged lockfile 重写不完整：漏 `specifier` 与 `packages:` 键 → tarball 依赖在
  目标机 frozen install 必失败。
- secret 定位用 `.` 拼接路径，字段名含 `.` 时明文会静默留在包内 → 改为 segments
  数组精确定位。

## [v0.1.0] - 2026-08-28 ~ 2026-08-29

### 仓库初始化前的开发里程碑（Development milestone before repository initialization）

本版本在仓库 `git init` 之前开发完成，未作为独立 Git 提交发布；其能力全部包含在
v0.2.0 中，此处如实记录历史。

- **Profile Runtime Snapshot**：`.dshpack` 保存可验证的 DSH Profile 运行时快照
  （bundles + profile patch 的 Portable Profile Scope），两层语义：可复现承诺
  （Portable Snapshot）与诊断信息（排除的 home/`--patch` 层）。
- **Secret Redaction**：组合树扫描、高置信命中 redact 为 `${VAR}`、生成
  `env/.env.example`，包内永不出现明文 secret（D9）。
- **双哈希**：`configHash`（可移植配置复现锚，公式 `dshpack-config-v1`）与
  `contentHash`（完整性锚，无自引用）分离。
- **确定性归档**：tar.gz 条目排序、mtime=0、规范化 mode、YAML/JSON canonicalization。
- **命令面**：`/pack`、`/pack inspect`、`/pack verify`、`/pack install`，纯 Human
  Command，不消耗 LLM turn（D12）。
- **install 管线**：verify → 安全解包（路径逃逸/symlink 防护，MUST-4）→ staging
  原子物化 → `pnpm install --frozen-lockfile`（MUST-1）→ bundle reconcile → atomic
  swap（MUST-3）；runtime 精确版本匹配（D15）。
- **Release Gate（2026-08-29）**：D1–D17 协议一致性 Review 无未关闭 blocker + 全量测试 + typecheck + clean-room North-Star E2E（真实 dsh CLI
  `--dump-config` 归一化一致 + configHash 相等）全部 PASS（当时 39 测试，后随 v0.2 新增增至 54）。
