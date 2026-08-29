# Changelog

本项目的版本历史。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- **v0.4.2 规划**：trust.yaml 细粒度策略；image lock（tag → digest 固定）；
  registry 引用计数 / GC；GHCR 真实凭据验证（CI/手动）。
- **v0.5 规划**：Encryption（私密插件源码 / 企业离线分发场景才需要）。
  Signing 已知边界（吊销 / 轮换 / 多签名 / 过期）同列后续。

## [v0.4.1] - 2026-08-29

### Remote Distribution（OCI push/pull，D32–D40 冻结）

定位演进：v0.4.0 回答"Agent Image 是什么、怎么在本地运行"；v0.4.1 回答
"Agent Image 怎么跨机器分发"。只实现 OCI Distribution Spec 最小子集
（D40），复用 GHCR/Harbor/Docker Registry/ECR 现有 API，**不自建 DSH
Registry Server**。

### Added

- **三种 Digest 分离**（D32/D33）：`contentHash`（DSH 语义身份，Signing/
  Trust 锚点不变）/ OCI `blobDigest`（SHA256 over raw archive bytes）/
  OCI `manifestDigest`（SHA256 over manifest JSON）；类型层面三个独立
  alias 强制区分，杜绝 `verifyContentHash(manifestDigest)` 类 bug。
- **OCI 顶层标准 Envelope**（D34–D37）：`application/vnd.oci.image.
  manifest.v1+json` + `artifactType=vnd.dsh.agent.image.v1`；DSH Image
  Manifest 作为 **config blob**，`.dshpack` 作为**单 layer**——不在 Registry
  顶层发布自定义 manifest media type（旧 Registry 兼容性）。
- **`src/image/registry/`**：reference（local/remote 区分 + 端点）、
  descriptor（digest/size 按实际字节重算）、manifest（envelope
  build/parse）、auth（anonymous / username+token / Bearer challenge，
  凭据来自 env 或 `~/.dsh/registry-auth.json`，**永不入包**）、client
  （HTTP 原语 + Docker-Content-Digest 校验）、push（§4）、pull（§5）。
- **`/pack push <localRef> <remoteRef>`**：resolve → verifyPack 自证 →
  blob/config 上传 → PUT manifest。
- **`/pack pull <remoteRef>`**（digest-first，D38/D39）：OCI Transport →
  DSH Artifact（contentHash == config）→ Signature → Trust → LocalStore。
- **`/pack run <remoteRef>`**：本地无则先拉（cache-only 策略），trust 强制
  仍在 boot 前（D29 延续）。
- **恶意 Registry 边界**：registry 返回的 annotations/metadata 全部忽略，
  信任只来自包内 v0.3 验签（VALID ≠ TRUSTED 不变）。

### 工程笔记

- **local-store putManifest 幂等 bug（真 bug）**：写入带 `\n` 尾缀、幂等
  比较却不带 → 同 digest 二次 import 必抛 "already exists with different
  content"。被 criterion 3 的重复导入路径抓到并修复（比较改用同一序列化
  常量）。
- **mock registry 三坑**（E2E 基建，协议层验证价值）：① 多段 repo 路径
  正则（`[^/]+` → `(.+?)`）；② client 对 digest 做 `encodeURIComponent`
  → mock 需 `decodeURIComponent`（manifest 分支有、blob 分支漏）；③
  正则改多段后 group 索引位移（repo=1/ref=2），mock 误用 group 1 当 ref
  ——tag 拉取"恰好"命中 repo 键而通过、digest 拉取必挂。
- **测试基建**：pack 输出确定性文件名（`<profile>-<date>.dshpack`）→
  同 outDir 二次调用覆盖，criterion 3 需唯一 pack 目录。

### 发布前 OCI 分发不变量审查（2026-08-29，8 项专项）

按 OCI 分发不变量清单逐项审查 `main..v0.4.1-oci`：

| # | 不变量 | 结论 |
|---|--------|------|
| 1 | 三种 Digest 无混用（contentHash / blobDigest / manifestDigest） | ✅ 审查 + **类型收紧**：digests.ts 抽离三 alias（无依赖，registry/types 转导出），ImageStore blob 键 / `ImageManifest.artifact.digest` / `ResolvedImage.artifactDigest` 全部改为 `DshContentDigest`——语义边界显式化，grep 可审计 |
| 2 | Pull 验证顺序不可退化（manifest → config → blob → contentHash → Signature → Trust → import） | ✅ 代码顺序确认；"先 import 再 verify trust" 被设计禁止（D39） |
| 3 | `run(remote)` cache 语义：**缓存策略 ≠ 执行信任策略** | ✅ signed-but-untrusted 可 pull 缓存，`run --require-trusted` boot 前拒绝（E2E 判据 6）——下载与执行是两个安全边界 |
| 4 | Remote tag mutable / digest immutable | ✅ E2E 判据 3：tag 更新后旧 manifest digest 仍可精确 pull——**冻结为发布 invariant** |
| 5 | Registry ≠ Trust Authority（annotations/signer/metadata 全部忽略） | ✅ pull 不读任何 registry 提供的信任字段；Trust 只来自包内 v0.3 验签 + keyId 白名单 |
| 6 | Auth secret 不进入日志/错误消息/Artifact | ✅ grep 确认 credentials 只出现在 auth.ts（解析/加载）与 client.ts（Authorization 头）；所有错误消息仅含 method/URL/status，无 headers |
| 7 | Blob upload 幂等（HEAD 命中跳过；中断重试不影响 blobDigest） | ✅ 新增 E2E：同 image 重复 push → 第二次 HEAD 命中跳过上传，blobDigest 不变，registry 仅存一份 |
| 8 | Local Store 幂等（同 digest+同内容 = 成功；同 digest+异内容 = FAIL） | ✅ putManifest `\n` 幂等 bug 已修复；新增单测固化（幂等成功 + 分歧报 digest mismatch） |

发布 invariants（随 v0.4.1 冻结）：**digest 恒等 / pull 顺序不可退化 / cache≠trust /
remote digest immutable / Registry≠Trust Authority / secret 不泄露 / 双幂等**
（blob 上传幂等 + local store 幂等）。

### 验收（2026-08-29，本地 OCI mock registry，协议与 GHCR 相同子集）

- **北极星 E2E 6 条判据全过**：
  1. push → 删本地 store → pull → **contentHash 相同** + Signature VALID +
     Trust VERIFIED
  2. tag 更新 → 新 manifest；**旧 digest 仍可精确 pull**（tag mutable /
     digest immutable）
  3. registry 返回篡改 blob → **OCI transport integrity FAIL**，DSH verify
     不执行（判据 4/5 可区分）
  4. 合法 blob 但 config contentHash 不符 → **DSH artifact integrity FAIL**
     （transport 已过）
  5. signed but untrusted → pull 可缓存 → `run --require-trusted` **boot 前
     FAIL**（VALID ≠ TRUSTED 跨机器成立）
  6. Bearer challenge → token fetch → 重试成功（auth 最小子集）
- 全量 **101 测试**（16 文件，+13 registry）+ typecheck + signing CLI E2E
  通过（v0.1–v0.4.0 无回归）
- 真实 GHCR 验证（需 `DSH_REGISTRY_USERNAME/TOKEN`）留作手动/CI 步骤

## [v0.4.0] - 2026-08-29

### Named + Versioned + Runnable Agent Image（Local Image Model）

定位演进：v0.1 可验证快照 → v0.2 可移植 Artifact → v0.3 可信 Artifact →
**v0.4 可命名、可版本化、可运行的 Image**。第一次把
Artifact / Identity / Version / Trust / Distribution / Runtime 六件事串成
一个完整模型。`.dshpack` v1 包格式**不变**（D23）——Image 只是它的分发视图。

### Added

- **Image Reference**（D21/D22）：`[registry/][namespace/]name[:tag][@digest]`
  Docker 兼容语法；**Tag mutable、Digest immutable**（digest = `sha256:` + 64 hex）。
- **digest = contentHash**（D21）：不发明新哈希——Image Digest 直接映射
  v0.3 的 contentHash 锚点，Pack/Verify/Sign/Import/Run 共用同一个 immutable identity。
- **Image Manifest**（D24）：独立于 `.dshpack` 的分发元数据
  （`application/vnd.dsh.image.manifest.v1+json`），含 artifact digest/size、
  configHash、platform（dsh/node/pnpm）、OCI 兼容 annotations（D31）。
- **Local Image Store**（D25）：`$DSH_HOME/images/` 内容寻址存储
  （blobs/sha256 + manifests/sha256 + refs/，原子写）。
- **`/pack image` 命令面**：`import`（blob + manifest + tag）、`ls`、`inspect`、
  `tag`（mutable 别名）、`rm`（tag / digest 形态）。
- **`/pack run <ref>`**（D27）：resolve → v0.3 全量 verify（integrity + signature +
  D15 版本门禁）→ trust policy → 物化**临时 runtime profile**（`.run-<uuid>`，
  不触碰现有 Profile，D26/D27）→ boot 交接；`--require-signature` /
  `--require-trusted` / `--profile <name>`（持久化 install）。
- **Trust 桥接 v0.3**（D29）：不重复实现验签；VALID ≠ TRUSTED 延续（D19）。

### 工程笔记

- **digest 语义澄清**：blob digest = contentHash **锚点**（排除 checksums/
  signature/provenance 的复合哈希），不是原始 archive 字节的 sha256——两者
  不同。store 只校验 digest 格式与"同 digest 同内容"一致性；锚点↔字节的对应
  由 import 的 `computePackContentHash` 与 run 的 verify 保证（单测曾把两者
  混淆，已修正并固化断言）。

### 发布前 Image Model 不变量审查（2026-08-29，8 项专项）

按 Image Model 不变量清单逐项审查 `main..v0.4-image`，确认 6 项成立、
修复 3 个问题：

| 不变量 | 结论 |
|---|---|
| 1. digest 恒等（digest == contentHash，全系统单一 Artifact Identity） | ✅ verify 重算与 import 锚点同算法，E2E 闭环实证 |
| 2. Tag mutable / Digest immutable，rm 不产生 dangling ref | ❌ **F-A 修复** |
| 3. CAS 原子性（可脏不可坏：refs 最后写，不允许 dangling ref） | ✅ import 顺序 blob→manifest→refs；tag() 先 resolve |
| 4. run 不污染 Profile（失败无残留，现有 profile 原样） | ✅ install 管线 try/finally 清理 staging |
| 5. Trust 顺序（untrusted 必须在物化/pnpm 之前失败） | ✅ run：verify → policy → installPack |
| 6. require-signature / require-trusted 正交（4×4 矩阵） | ✅ 两个检查独立，VALID ≠ TRUSTED 保留 |
| 7. Reference Parser 严格性（never guess） | ❌ **F-B / F-B2 修复** |
| 8. 存储隔离（只有 LocalImageStore 知道磁盘布局） | ✅ grep 确认无泄漏（index.ts 组合根除外） |

修复：

- **F-A（不变量 2）**：`image rm <digest 形态>` 在仍有其他 tag 引用该
  manifest 时拒绝删除（"CAS 可以脏，但引用图不能坏"）；引用计数/GC 留
  v0.4.1。
- **F-B（不变量 7）**：reference parser 拒绝前导/双/尾斜杠
  （`/foo`、`foo//bar`、`foo/`），不再静默归一化。
- **F-B2（不变量 7）**：`. / ..` 路径段在任何启发式之前拒绝——`..` 原会
  被 registry 判定（含 `.`）吞掉变成 traversal 向量（store 层 `..` 守卫
  兜底，parser 层补强）。

新增不变量测试：parser 恶意/边界输入（9 种）、traversal 守卫、trust 4×4
正交矩阵、rm dangling-ref 守卫、digest 恒等（import digest == 包内
checksums.json contentHash）、run 失败不污染 Profile、trust 拒绝后无物化。

### 验收（2026-08-29）

- 24 个 image 测试全绿（reference/manifest/local-store/resolver/trust 单测 +
  DefaultImageService 服务层 + 北极星 E2E + 不变量测试）
- **北极星 E2E（DESIGN-v0.4.md §17，真实 pnpm frozen install）**：
  1. run 闭环：pack --portable → sign → import --tag agent:v1 → 删原 Profile →
     run → 临时 runtime 的 configHash == 原始 + Signature VALID + Trust VERIFIED
  2. tag agent:latest → 与 v1 同一 digest
  3. 篡改本地 blob → run **boot 前 FAIL**
  4. 未在白名单的 key 签名 → run --require-trusted FAIL（Signature 仍 VALID）
- 全量 **88 测试** + typecheck + signing CLI E2E（23 断言）通过（v0.1–v0.3
  无回归）

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
