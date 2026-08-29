# dsh-pack

> **A reproducible, portable and verifiable artifact format for DSH runtime profiles.**

dsh-pack 把一个可运行的 **DSH Profile**（有序 bundles + 自定义 `cordis.patch.yml` +
模型/Sandbox 配置）打成可迁移、可复现、可校验的 **`.dshpack`**，在另一台机器上
一步恢复，并以 `configHash` 为判据保证恢复后的配置与打包时**完全一致**。

```text
DSH A（已调好：8 个 bundle + 自定义 patch）
      │  /pack web
      ▼
web-YYYYMMDD.dshpack
      │  /pack install（另一台机器，全新 DSH_HOME）
      ▼
DSH B  →  dsh --profile web  直接启动
```

## 定位演进

```text
v0.1  Profile Snapshot        —— 可复现的 Profile 配置快照
v0.2  Portable Runtime Artifact —— 连本地依赖一起可移植
v0.3  Trusted Runtime Artifact —— 可签名、可验证来源（Signing 已实现；Encryption / Agent Image 后续）
```

## 命令面（全部为 Human Command，不经过 LLM、不消耗 turn）

| 命令 | 作用 |
|------|------|
| `/pack [name]` | 打包当前 Profile（`--strict` / `--out` / `--allow-secrets` / `--allow-nonportable`） |
| `/pack <name> --portable` | 连本地 `file:`/`link:` 依赖一起 vendoring 打包 |
| `/pack inspect <file>` | 查看包内容摘要（`--json`） |
| `/pack verify <file>` | 校验完整性：Manifest / Config / Packages / Checksums / DSH Version / Signature（`--json`、`--require-signature`） |
| `/pack install <file>` | 恢复到 `$DSH_HOME/profiles/<name>`（staging + 原子 swap + frozen-lockfile） |
| `/pack diff <a> <b>` | 两包配置漂移对比：Manifest / Bundles / Config / Dependencies + configHash |
| `/pack keygen [--out <dir>]` | 生成 ed25519 密钥对（v0.3：私钥 chmod 600 + 公钥 + keyId） |
| `/pack sign <file> --key <pem> [--signer <name>]` | 嵌入签名 + provenance，产出 `<name>.signed.dshpack`（v0.3） |

## 版本历史

- **v0.1**（2026-08-28，**仓库初始化前**完成开发与验证）：Runtime Snapshot、Secret
  Redaction、configHash/contentHash 双锚、确定性归档、frozen-lockfile install、
  原子 staging 安装、archive 提取安全、clean-room North-Star E2E。
- **v0.2.0**（2026-08-29，**首个公开 Git 版本**）：`/pack diff` + `--portable`。
- **v0.3.0**（2026-08-29，**开发中**）：Artifact Signing / Provenance 已实现
  （`/pack keygen` + `/pack sign` + verify Signature 分节 + `DSH_PACK_TRUSTED_KEYS`
  信任白名单）；Encryption / Agent Image 后续。

> v0.1 was developed and validated before repository initialization; the first
> public Git release is v0.2.0.（不伪造指向当前代码的 v0.1.0 tag。）

## Known Limitations

1. **pnpm v11 虚拟存储布局**：`--portable` 恢复后，传递的 `file:` 依赖可能位于
   `.pnpm` 虚拟存储（`node_modules/.pnpm/@xp+b-lib@.../node_modules/@xp/b-lib`）
   而非顶层 `node_modules/@xp/b-lib`。**功能与 frozen install 闭环成立**（依赖
   可解析、configHash 一致）；若要求 node_modules 布局与打包机逐字节一致，受
   pnpm 行为差异限制，不属于包缺陷。
2. **`--portable` 实现中修复的三个真实工程坑**（均已补回归测试，详见
   `DESIGN.md` Appendix D 与 `TRACEABILITY.md`）：
   - 异步 staging 竞态：未 `await` 的 `return createPackageTgz(...)` 导致
     `finally` 提前删除 staging 目录 → 间歇性 ENOENT；
   - 重写后的 `package.json` 被 copy 步骤用源文件覆盖；
   - pnpm lockfile 的**项目相对路径语义**：`file:` 依赖按项目根寻址，与声明处的
     相对 spec 不同，重写必须同时覆盖两种形式。
3. **不可复现项**：floating git 分支（无 `#commit` 锚点，`--strict` 下失败）；
   home 层与 `--patch` overlay（machine/invocation-local，不打包但记录告警）；
   `--allow-nonportable` 产物 `installable:false` 且 install 默认拒绝。
4. **安全边界**：`.dshpack` 内禁止真实 secret（组合树扫描 + redact 为 `${VAR}` +
   `.env.example`，install 永不恢复 secret）；archive 提取防路径逃逸与
   symlink/hardlink/device 条目。

## 验证状态

- **54 个测试全绿**（含 2 个真实 pnpm E2E：v0.1 roundtrip + `--portable` 全链路）
- **clean-room North-Star E2E**：真实 dsh CLI `--dump-config` 归一化一致 +
  install 侧 configHash == manifest.configHash
- typecheck（`tsc -b`）通过

## 文档

- `DESIGN.md` —— 协议冻结（格式、哈希算法、安全模型、命令行为）
- `TRACEABILITY.md` —— D1–D17 冻结决策 → 源文件 → 测试用例逐条追踪
- `LICENSE` —— MIT
