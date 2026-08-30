# Changelog

本项目的版本历史。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [Unreleased]

- **v0.5.0-beta.1（Runtime Attestation，D89–D97 冻结，DESIGN-v0.5.0.md §9）**：
  冷启 seam 调研结论：harness `boot()`（dsh-app-boot）→ cordis Context，cold
  boot 后从服务注册表 seam 收集 observed capabilities（不引入 OS-level
  tracing）。subject 绑定实际 contentHash（D89）；Observed 与 Declared 分离并
  输出结构化 diff，observedButNotDeclared 只报告不 DENY（D90/D91）；所有执行
  在 disposable isolated DSH_HOME/profile 中，env allowlist 只给
  PATH/临时 HOME/TMPDIR/必要 DSH vars，secrets 默认不可见（D92/D93）；cold
  boot 与主动 tool invocation 分开，Phase A 只启动-注册-初始化-shutdown
  （D94）；effects 来自 observation，未测 = NOT_PROBED 而非 false（D95）；
  不要求 byte-identical，normalized result → deterministic resultDigest
  （D96）；cleanup 本身是 Evidence（D97）；Observed 必须来自运行时注册表
  观察——真实 cold boot → 正常注册 → 只读观察，禁 monkey-patch
  register()/provide() 改变插件语义、禁 grep 源码猜 observed（D98）；
  Observation Coverage 显式声明 complete|partial|unknown，root observer
  无法完整观察 child-context 服务时如实 partial、cold boot 失败 unknown，
  partial 不得被解释为权威缺失（comparison.authoritative=false，D99）。
  R0–R16 测试矩阵。明确不做：
  OS-level tracing、allow/deny、Phase B probe（后半段）、按名称推断 effects。
- **v0.5.0-alpha.4（Declared Capability Manifest，D81–D88 冻结，DESIGN-v0.5.0.md §8）**：
  纯 artifact inspection、无 cold boot（绝不为生成 declared manifest 执行插件
  代码）。调研结论：harness profile schema（app-boot）只有 bundles 字段，
  providers/services 可从 composition/patch 行静态发现（行 id=稳定 capability
  id），tools/skills 只能运行时注册 → 静态不可发现（D86/C10）。subject 绑定
  实际 contentHash（D82）；Declared 与 Observed 永久分离，只生成 declared
  （D83）；稳定 id/kind/declaredBy 结构化 identity（D84/D85）；manifest 只
  描述能力不做 allow/deny（D87）；deterministic（D88）。C0–C10 测试矩阵。
  明确不做：observed/effects（beta.1）、trust.yaml v2（beta.2）、cold boot、
  按名称推断权限。
- **v0.5.0-alpha.3（SBOM Evidence，D73–D80 冻结，DESIGN-v0.5.0.md §7）**：
  CycloneDX 1.7 JSON 为唯一 canonical SBOM format（D73）；SBOM 只消费
  artifact/staged lockfile + vendored + embedded metadata + dependency
  closure，禁止扫描当前 node_modules / Git workspace / 重新 resolve（D74）；
  SBOM 文档（`documents/<sbomDigest>.cdx.json`）与 Signed Evidence
  （`sbom/<statementDigest>.json`，subject=contentHash，statement 携带
  sbomDigest）分离（D75/D73）；registry 依赖带 PURL/resolved/integrity、
  file:/link:/vendored 带 contentDigest 且无绝对机器路径（D76）；lifecycle
  scripts 记录 existence+digest（D77）；native 只记 indicator 不推
  compatibility（D78）；license 缺失一律 UNKNOWN（D79）；deterministic
  byte-identical（D80）。S0–S13 测试矩阵。明确不做 vulnerability/CVE/
  license policy/trust.yaml v2/OCI/SPDX/CycloneDX 2.0。
- **v0.5.0-alpha.2（Build Provenance v2，D68–D72 冻结，DESIGN-v0.5.0.md §6）**：
  provenance 在 `/pack` **构建现场**采集，绝不事后根据当前 Git HEAD 推测。
  新增 `src/evidence/build-record.ts`：Git source（完整 commit SHA / dirty /
  sourceTreeDigest，D68）、materials digests（profile manifest / bundle patch /
  source 与 artifact lockfile 分开 / canonical dependency closure 带 file:link:
  contentDigest，D69）、environment（D71）。`/pack` 总是写
  `<name>.dshpack.build-receipt.json`；`--evidence-key` 构建时签名
  build-provenance Evidence（dirty 默认 FAIL，`--allow-dirty` 记录
  sourceTreeDigest）；`/pack evidence provenance <file>` 只消费 receipt
  （校验 schema + subject == 实际 contentHash，篡改拒绝）。**D72 origin
  语义**：`/pack --evidence-key` 构建时签名 = build-time attestation
  （`capture.mode=build-time`）；`/pack evidence provenance` 消费未签名
  receipt 只能标记 post-build-receipt（endorsement），不得冒充构建瞬间证明；
  receipt 及其 digest 不进 artifact contentHash。P0–P12 测试矩阵
  （clean/dirty/commit 切换/lockfile 变化/file-link contentDigest/configHash≠
  code identity/statement tamper/subject swap/modified receipt 只能
  endorsement/build-time attestation 不受后续 receipt 修改影响）。
- **v0.5.0-alpha.1（Evidence Foundation，D64–D67 + Protocol Hardening H1–H3 冻结，
  DESIGN-v0.5.0.md）**：Signed Evidence Envelope（`src/evidence/`）——独立证据对象，
  subject 绑定 immutable contentHash（D64）、Evidence 与 Artifact 分离不进
  contentHash 也不改 Artifact Signature anchor（D65）、domain-separated
  canonical 签名认证（D66，`domain="dsh-pack:evidence:v1"`）、Policy 只消费
  已验证 Evidence（D67 前置）。Protocol Hardening：H1 domain separation
  （跨协议签名不可重放）、H2 verifiedKeyId（keyId 永远从内嵌 public key 重算，
  绝不消费声明值）、H3 Evidence Collection（`<name>.dshpack.evidence/<type>/
  <statementDigest hex>.json`，同 contentHash 可绑定 N 份证据、禁止覆盖）。
  命令：`/pack evidence sign|verify`（`--against` / `--key-id`）。负例矩阵：
  tamper / subject substitution / wrong signer / stale evidence / cross-protocol
  replay / overwrite refusal。
- **v0.4.2 剩余**：image lock（`/pack image lock <ref>` → 真实 manifestDigest +
  dsh-lock.json）；trust.yaml（registries 级 requireSignature/requireTrusted/
  trustedKeys）；local image prune（mark-and-sweep reachability GC：
  只删不可达 manifest/blob，默认 dry-run、`--apply` 才删除；runtime cache
  保守报告不删除（D62）；不做 Registry GC——那是 Registry Server 的职责）。
- **v0.5 规划**：Encryption（私密插件源码 / 企业离线分发场景才需要）。
  Signing 已知边界（吊销 / 轮换 / 多签名 / 过期）同列后续。

## [v0.4.2] - 2026-08-29（第一阶段：Real GHCR Protocol Acceptance）

### Distribution Governance 第一阶段（D41–D45 冻结）

目的：**不是再证明业务逻辑**，而是验证"我们的 OCI 客户端真的能和 GHCR
对话"——从协议兼容升级为真实公共 OCI Registry 实证兼容。暂不实现
image lock / trust.yaml / prune（跑通真实 GHCR 后再做，顺序见 DESIGN
§8）。

### Added

- **D41–D45 冻结**（DESIGN-v0.4.2.md）：
  - D41 Real GHCR E2E 属于协议验收，不替代 mock registry 单测（两层并存）
  - D42 GitHub Actions 默认 `GITHUB_TOKEN`，不要求长期 PAT（本地 CLI 才用
    PAT classic）
  - D43 CI GHCR E2E 不在 fork PR 执行（不向不可信代码暴露 package write）
  - D44 Real registry 成功必须 OCI integrity + DSH integrity +
    Signature/Trust 三成兼须
  - D45 Remote Registry credentials 永远不属于 Artifact / Provenance /
    Image Manifest
- **GHCR 8 项协议验收清单**（冻结入 DESIGN §3）：401+Bearer challenge /
  token scope=pull,push / blob HEAD 404→200 / POST uploads/ → Location →
  PUT ?digest → 201 / OCI manifest PUT Content-Type / tag pull
  Content-Type+Docker-Content-Digest / digest pull 一致性 / DSH 层
  contentHash+Signature+Trust+run configHash。
- **CI 两层模型**：
  - `.github/workflows/pr-ci.yml`：普通 PR CI（typecheck + 103 测试含
    mock registry + signing E2E，**不碰真实 GHCR**；fork 安全，最小权限
    `contents: read`）。
  - `.github/workflows/ghcr-e2e.yml`：`workflow_dispatch` 手动触发（初期），
    `packages: write` + `GITHUB_TOKEN`（job 级 env 注入，结束即消失），
    测试 namespace `ghcr.io/<owner>/dsh-pack-e2e:run-<run_id>`（正式包
    与测试包隔离，新 package 默认 private 正好覆盖认证 E2E）。
- **`scripts/ghcr-e2e.mjs`**：Internet North-Star 脚本——8 项协议断言全
  覆盖（raw probe 验证 ① 401+challenge、② token scope、⑥ Content-Type+
  Docker-Content-Digest==bytes；服务层验证 ③④⑤⑦⑧），env 凭据，日志纪律
  （只记 method/host/repo/status/scope，永不记 token）。缺 env 时 exit 2
  明确退出。

### image lock（D46–D49 冻结，与真实 GHCR 验收并行开发）

- **`/pack image lock <remoteRef> [--file <path>]`**：mutable remote tag →
  immutable OCI manifest digest（D46/D48；锁对象是 **manifestDigest**，非
  contentHash/blobDigest）。输出 `Resolved: <ref> ↓ <repo@sha256:...>` +
  `Lock written: dsh-lock.json`。
- **`dsh-lock.json` 最小 schema**（D47）：`{ schemaVersion: 1, images: {
  "<mutable ref>": { "resolved": "repo@sha256:<manifestDigest>",
  "manifestDigest": "sha256:..." } } }`——只钉版本，**不承载 Signature/
  Trust**；contentHash/blobDigest/signature/trust/configHash 一律不塞
  （都可从 immutable manifest 再解析）。
- **`src/image/lockfile.ts`**：load/save/addLock/validate（broken file
  loudly FAIL）；`service.lock()` resolve 远程 manifest（OCI envelope 校验）
  后写入；digest 形态输入也做 transport digest 校验。
- **Lock ≠ Trust（D49）**：locked image 运行时仍完整执行 OCI → DSH →
  Signature → Trust 验证链（不因来自 lockfile 跳过 v0.3/v0.4 安全链）。
- **验收判据（mock registry）**：T0 tag 漂移后 locked digest 仍拉旧
  artifact ✓；T1 锁文件不存在 digest → pull FAIL（404，nothing imported）✓；
  T2 registry 返回与 locked digest 不匹配的 manifest → transport
  integrity FAIL ✓（mock 新增 manifest-swap tamper 模拟恶意 registry）。

### trust.yaml（D50–D56 冻结，Remote Image Execution Policy）

- **定位**：Trust Policy ≠ "trusted keys 配置文件"——是 `$DSH_HOME/trust.yaml`
  的**本地执行策略**（Host/Environment Policy，不进 `.dshpack`/OCI
  manifest/provenance/registry metadata，D50）；与 `image lock` 分层：
  lock 解决"运行哪个版本"，trust.yaml 解决"这个版本允不允许运行"。
- **最小 schema**（version 1 + registries map）：`requireSignature` /
  `requireTrusted` / `trustedKeys`（keyId fingerprint，D55，**不用 signer
  label**）；按 **remote repository pattern** 匹配（D51），
  **most-specific-match wins**（最长 pattern，等长字典序，与文件行序无关，
  D52）；无匹配规则 → 保持 v0.4.1 行为（D53，backward-compatible）。
- **CLI 只能收紧不能放宽**（D54）：effective = Policy OR CLI；
  `--require-*` 永远无法被策略中的 false 降级。
- **Pull 与 Run 分离**（D56，cache ≠ trust）：pull 只做 OCI+DSH integrity
  + Signature metadata → 允许进 cache；run 才评估 trust.yaml → FAIL 在
  materialize/pnpm 前（`allowPull` 留待以后）。
- **`src/image/trust-policy.ts`**：Policy Engine（load/validate/glob 匹配/
  most-specific/mergeCli 决策）；`image/trust.ts` 扩展 trustedKeys 指纹
  检查（D55）；`service.run` 对 remote ref 应用策略（local ref 保持 CLI
  语义）。**验签复用 v0.3/v0.4 现有实现，未重新实现。**
- **测试**（mock registry）：T0 无策略保持 v0.4.1 ✓ / T1 unsigned run FAIL
  ✓ / T2 signed unknown key PASS ✓ / T3-T4 trustedKeys 拒/放 ✓ / T5
  most-specific ✓ / T6 CLI 收紧 ✓ / T7 策略独立生效 ✓ / T8 signer label
  无关 ✓ / T9 untrusted pull cache 成功 + run boot 前 FAIL ✓ /
  **lock×trust 组合**：同一 lock 版本不变，trustedKeys 移除签名者后
  trust FAIL（Version identity 与 Trust policy 正交）✓。

### 工程笔记（trust.yaml 阶段抓到 3 个真问题）

- **run() digest 形态 remote ref 无法本地解析**（真 bug）：本地 store 以
  DSH manifest digest 为键，OCI manifest digest 查不到——`ensureLocal`
  吞掉 resolve 错误后 run 再 resolve 仍失败（会连带挂掉 ghcr-e2e.mjs 的
  `run(digestRef)`）。修复：ensureLocal 返回 PullResult，digest 形态经
  `local@<dshManifestDigest>` 解析。
- **trust-policy glob 通配符失效**（真 bug）：escapeRegExp 转义类漏 `*`，
  `replaceAll('\\*', '.*')` 找不到转义形式，裸 `*` 被当作量词 → 所有含
  `*` 的 pattern 不匹配。
- **putManifest 幂等比较误报**（真 bug，与 \n 那次同类）：字节级比较对
  import（插入序）与 pull（canonical 排序序）构造的同一语义 manifest
  误报 "already exists"。修复：canonicalJson 归一化后**语义比较**。

### 验收状态

- 本地验证：`node --check` 语法 OK；lib 导入路径全部存在；本地测试套件
  **138 全绿**（20 文件，+6 lock +20 trust +9 prune +2 fixture 测试）。
- **真实 GHCR 运行须在 GitHub Actions `workflow_dispatch` 执行**（需
  `GITHUB_TOKEN` + `packages: write`，此环境无凭据不可本地运行真协议）——
  **Release Gate（§10）：GHCR 8/8 全过后才允许 v0.4.2 merge/tag**。
  GHCR Gate 现场记录（2026-08-30，详见 DESIGN §13）：
  - run #1 BLOCKED（pnpm 未入 PATH → pnpm/action-setup 修复）
  - run #2 BLOCKED（CI 缺 deepseek-harness sibling → 双 checkout + pin +
    build:lib:host 修复）
  - run #3 **PARTIAL**：① GET /v2/ → 401 + Bearer challenge ✅、② Bearer
    token 获取 ✅；push 前客户端 ImageReference 校验拦截 uppercase
    namespace（fixture 用 `WHY-Daydream`，OCI 只允许小写）——GHCR 未收到
    push，⑥⑦⑧ 及其余项 NOT RUN。修复：`scripts/ghcr-fixture.mjs`
    canonical lowercase（`why-daydream/dsh-pack-e2e`），target/URL/scope
    共用同一字符串；Parser 不放宽（回归测试钉死）。
  - run #4 **8/8 PASS ✅**（run 33292227705，head 5139074）：真实 GHCR
    协议 8 项全部通过——① Bearer challenge ② token（pull,push）③ blob
    HEAD 404→200 ④ POST uploads/ → PUT ?digest → 201 ⑤ OCI manifest PUT
    Content-Type ⑥ tag pull Content-Type + Docker-Content-Digest == bytes
    ⑦ digest pull 与 tag 一致 ⑧ DSH contentHash + Signature VALID + Trust
    VERIFIED + run configHash 一致。
  - **Release Gate PASS → v0.4.2 允许 merge/tag**（原 §10 硬 Gate 解锁）。

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
