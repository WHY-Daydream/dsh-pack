# dsh-pack v0.1 Traceability

> DESIGN.md 冻结决策（D1–D17）→ 实现（源文件）→ 验证（测试用例）的逐条映射。
> 用途：协议一致性审查、开源展示、回归时快速定位。

## D1–D17 追踪表

| 决策 | 一句话 | 实现（源文件） | 测试用例 |
|------|--------|----------------|----------|
| D1 | 包容器 = 确定性 tar.gz（排序/mtime=0/gzip mtime=0） | `pack-builder.ts` `buildTarGz`/`createArchive` | `tests/pack-builder.spec.ts` `is byte-deterministic` |
| D2 | `schemaVersion=1`，reader 拒绝未知 major、只加可选字段 | `manifest.ts` `SCHEMA_VERSION`/`validateManifest` | `tests/manifest.spec.ts` `rejects unknown schema majors` |
| D3 | 两层 Snapshot：Portable Scope = 可复现承诺；home/`--patch` 排除但记录 | `config-snapshot.ts` `buildSnapshot`；`service.ts` `excludedLayersPresent` | `tests/e2e.spec.ts`（manifest 快照语义间接覆盖） |
| D4 | effective config = Portable Profile Scope | `config-snapshot.ts` `composition`/`renderEffective` | `tests/e2e.spec.ts`（composition 重算哈希） |
| D5 | 组合树复用 `dsh-app-boot`，进程内组合 | `config-snapshot.ts`（import `loadProfile`/`composeEntries`/`loadOptionalPatches`） | `tests/e2e.spec.ts`（`buildSnapshot` 重算哈希） |
| D6 | 依赖事实来源 = `pnpm-lock.yaml`，不重新 resolve | `dependency-resolver.ts` `resolveDependencies` | `tests/dependency-resolver.spec.ts` `builds the closure from pnpm-lock.yaml` |
| D7 | `file:`/`link:` 目录依赖默认 FAIL；`--allow-nonportable` → `installable:false` | `service.ts` preflight；`install.ts` installable 门禁 | `tests/service.spec.ts`（D7 三个用例） |
| D8 | Secret 扫描对象 = 组合树 | `secret-scanner.ts` `scanAndRedact(rows)` | `tests/secret-scanner.spec.ts` |
| D9 | Redact 为 `${VAR}` + `.env.example`；install 永不恢复 | `secret-scanner.ts`；`install.ts` `copyPackProfile` | `tests/secret-scanner.spec.ts` + `tests/e2e.spec.ts`（包内无明文断言） |
| D10 | configHash（复现锚）/ contentHash（完整性锚）分离 | `manifest.ts` `computeConfigHash`；`pack-builder.ts` `computeContentHash` | `tests/manifest.spec.ts` + `tests/canonical.spec.ts` + `tests/pack-builder.spec.ts` |
| D11 | verify 分节（Manifest/Config/Packages/Checksums/DSH Version） | `verify.ts` `verifyPack` | `tests/e2e.spec.ts` + `tests/service.spec.ts`（DSH Version 分节） |
| D12 | 命令面纯 Human Command，无 LLM Tool | `index.ts` `ctx.commands.register`；`commands.ts` | —（命令层由 E2E 间接覆盖） |
| D13 | install = staging + atomic swap + `--frozen-lockfile` + 官方 reconcile | `install.ts` `installPack` | `tests/e2e.spec.ts`（install 全流程） |
| D14 | E2E 北极星：①可移植哈希判据 ②clean-room dump-config 判据 | `tests/e2e.spec.ts`；`scripts/clean-room-e2e.mjs` | 两者均已 PASS（2026-08-29） |
| D15 | Runtime 精确版本匹配，`--ignore-runtime-version` 放行 | `verify.ts` + `install.ts` 门禁 | `tests/service.spec.ts`（D15 两个用例） |
| D16 | Archive 提取安全：路径归一化 + 禁 symlink/hardlink/device | `pack-builder.ts` `extractTarGz`（filter + UNSAFE_TYPES） | `tests/pack-builder.spec.ts` `rejects a symlink entry` |
| D17 | contentHash 无自引用（checksums.json 不入 files 映射） | `pack-builder.ts` `checksumsJson`；`service.ts` 两步 buildTarGz | `tests/pack-builder.spec.ts` `non-self-referential` |

## 9 项安全关注点检查结论（2026-08-29 Review）

| # | 关注点 | 结论 |
|---|--------|------|
| 1 | configHash 只含 portable scope（无 home/overlay/路径/mtime） | ✅ `config-snapshot.ts` composition 排除 home/overlay |
| 2 | contentHash 无自引用、无 archive metadata 漂移 | ✅ files 映射不含 checksums.json；mtime=0 |
| 3 | Secret Scanner 嵌套对象 / `${VAR}` 替换 | ✅ `walk` 递归；F4 修复后字段名含 `.` 也可精确定位 |
| 4 | `--allow-nonportable` 写 `installable:false` | ✅ 且 F1 修复后 `portable:false` 同步 |
| 5 | `install --force` 原子 swap | ✅ rename target→backup 后再 rename staging→target，失败回滚 |
| 6 | tar 解包防 `../`、绝对路径、symlink/hardlink traversal | ✅ filter 拒绝 + UNSAFE_TYPES；有测试 |
| 7 | frozen-lockfile 失败旧 profile 不受影响 | ✅ install 全部发生在 staging，失败 `rmSync(staging)` |
| 8 | manifest/schemaVersion/runtimeVersion 在 install 前校验 | ✅ `validateManifest` + D15 门禁在物化之前 |
| 9 | `ctx.packager` Service Seam 不泄露内部实现 | ✅ 对外只暴露接口类型 |

## 审查发现与修复（2026-08-29）

| # | 级别 | 问题 | 修复 |
|---|------|------|------|
| F1 | MAJOR | `service.ts` `portable:true` 恒真，违反 DESIGN §3.3/§5.2（`--allow-nonportable` 产物应为 `portable:false`） | 改为 `portable: installable` |
| F2 | BLOCKER | staged lockfile 只重写 importer `version`，遗漏 `specifier` 与 `packages:` 键，且 importer 目标应为 install 端 `file:vendor/<tgz>` → tarball 依赖在 B 机 frozen install 必失败 | `rewriteLockfileForStaging` 同时重写 specifier/version/packages 键（含 scoped `/` 前缀变体） |
| F4 | MINOR(安全) | secret 路径用 `.` 连接，字段名含 `.` 时 redact 定位错位 → secret 静默漏改留在包内 | `SecretHit.segments` 数组精确定位（`walk`/`redactAt`/`redactPatchText` 全链路） |

## Release Gate（2026-08-29）

- ✅ Review 无未关闭 blocker（F1/F2/F4 已修复并有测试）
- ✅ 单元测试 38 passed（+E2E roundtrip 真实执行通过）
- ✅ typecheck（`tsc -b`）通过
- ✅ North-Star E2E：vitest roundtrip（判据①）+ `scripts/clean-room-e2e.mjs`（判据②，真实 dsh CLI `--dump-config` 归一化一致 + configHash 相等）全部 PASS
- ✅ lib 产物可直接被 node 执行（`rewriteRelativeImportExtensions` 全量重建）
- ⚠️ 仓库尚未 `git init`/打 tag —— 封版判定成立，版本号 `0.1.0` 已在 package.json
