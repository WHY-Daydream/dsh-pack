# dsh-pack v0.4.2 Design — Distribution Governance（第一阶段：Real GHCR Protocol Acceptance）

> **dsh-pack v0.4.2 — Real GHCR protocol acceptance + CI credential model.**
> v0.4.1 已在 mock registry 上封死三 Digest、digest-first、Registry≠Trust、
> 双幂等等核心不变量（103 测试全绿）。v0.4.2 第一阶段的目的**不是再证明业务
> 逻辑**，而是验证"我们的 OCI 客户端真的能和 GHCR 对话"——从**协议兼容**
> 升级为**真实公共 OCI Registry 实证兼容**。

- 状态：**v0.4.2 第一阶段设计定稿（2026-08-29，D41–D45 冻结，见 §2）**
- 前置：v0.4.1（D32–D40：三 Digest / OCI envelope / digest-first pull / Registry≠Trust / 双幂等）已封版
- 范围：**暂不实现 image lock / trust.yaml / prune**（跑通真实 GHCR 后再做）

---

## 1. 定位与边界

**一句话**：真实 GHCR E2E 属于**协议验收**（D41），不替代 mock registry 单测。

**明确不做**（第一阶段）：

- ❌ image lock / trust.yaml / local prune（功能顺序 §8）
- ❌ fork PR 上的真实 GHCR 测试（D43）
- ❌ 长期 PAT 作为 CI 默认凭据（D42）
- ❌ 任何"把凭据写进包"的路径（D45）

---

## 2. 冻结决策（D41–D45）

| ID | 决策 | 一句话 |
|----|------|--------|
| D41 | Real GHCR E2E 属于协议验收，不替代 mock registry 单测 | 两层测试并存：mock = 业务逻辑回归；GHCR = 真实协议验证 |
| D42 | GitHub Actions 默认使用 `GITHUB_TOKEN`，不要求长期 PAT | job 运行时生成的 installation token，权限受 workflow 仓库限制，比长期 PAT 更适合自动化 E2E；仅本地人工 CLI 验证才用 PAT classic（push 需 `write:packages`，SSO 组织需授权） |
| D43 | CI GHCR E2E 不在 fork PR 执行 | fork 不暴露 package write；真实 GHCR 测试只经 `workflow_dispatch`（初期手动）与 main/release 触发 |
| D44 | Real registry 成功必须同时满足 OCI integrity + DSH integrity + Signature/Trust | 三层独立验证全部通过才算 E2E 成功（与 pull 四段顺序一致，D39 延续） |
| D45 | Remote Registry credentials 永远不属于 Artifact / Provenance / Image Manifest | 凭据只存在于进程环境（env）或 `~/.dsh/registry-auth.json`；日志/错误/包内均不可出现（延续 v0.4.1 审查项 6） |

---

## 3. GHCR 协议验收清单（冻结，8 项）

```text
GHCR Protocol E2E

1. GET /v2/
   → 401 + WWW-Authenticate Bearer challenge

2. Bearer token acquisition
   → scope=repository:<owner>/<repo>:pull,push

3. HEAD blob
   → missing = 404
   → existing = 200
   → Docker-Content-Digest 可校验

4. Blob upload
   POST /blobs/uploads/
        ↓
   Location
        ↓
   PUT <Location>?digest=sha256:...
        ↓
   201 Created

5. OCI manifest PUT
   Content-Type: application/vnd.oci.image.manifest.v1+json

6. Tag pull
   → Content-Type 与 manifest.mediaType 一致
   → Docker-Content-Digest 与实际 manifest bytes 一致

7. Digest pull
   repo@sha256:<manifestDigest>
   → 与 tag resolve 的 manifest 完全一致

8. DSH Layer
   OCI blob digest PASS
        ↓
   DSH contentHash PASS
        ↓
   Signature VALID
        ↓
   Trust VERIFIED
        ↓
   run configHash 一致
```

这些正是真实 Registry 与 mock 最容易分歧的差异点：
`Docker-Content-Digest`、manifest `Content-Type`、upload `Location`。

---

## 4. CI 两层模型（冻结）

### A. 普通 PR CI（不碰真实 GHCR）

```text
unit tests（103 个，含 mock OCI registry）
signing E2E
typecheck
```

理由：外部网络增加 flaky；fork PR 不应获得 packages write；无需每个 commit
向 GHCR 堆测试 artifact。

### B. Real GHCR E2E（workflow_dispatch 优先）

```yaml
on:
  workflow_dispatch:        # 初期手动跑
  push:
    tags: ["v*"]            # 稳定后再挂 release
```

v0.4.2 初期**先 `workflow_dispatch` 手动跑**，稳定后挂 release tag。

---

## 5. 凭据模型（冻结，D42/D45）

### GitHub Actions

```yaml
permissions:
  contents: read
  packages: write

env:
  DSH_REGISTRY_USERNAME: ${{ github.actor }}
  DSH_REGISTRY_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

- CI **不生成持久 `registry-auth.json`**，走 env（job 结束即消失）
- pull 的 `packages:read` 被 `packages:write` 覆盖
- 新发布的 GHCR package 默认 private——认证访问正好覆盖 E2E，无需调 visibility

### 本地人工

```text
Developer local → PAT classic（pull: read:packages；push: write:packages；SSO 需授权）
GitHub Actions  → GITHUB_TOKEN
```

### 日志纪律（延续 v0.4.1 审查项 6，冻结）

```text
可以记录：method / registry host / repo / status / scope
禁止记录：Authorization / raw token / Basic credentials / Bearer token response
```

---

## 6. 测试 namespace 策略（冻结）

正式包与测试包隔离：

```text
正式：ghcr.io/<owner>/<agent-name>:<tag>
测试：ghcr.io/<owner>/dsh-pack-e2e:run-<github.run_id>
```

每次 `run_id` 唯一 → 可追溯、可对比、不污染正式 namespace。

---

## 7. 推荐 CI 流程（冻结，Real GHCR E2E）

```text
Checkout
  → Install Node / pnpm（corepack）
  → Build dsh-pack
  → Run 103 local tests（先证明业务逻辑）
  → Generate E2E signing key
  → Build portable .dshpack
  → Sign artifact
  → Image import
  → Push: ghcr.io/$OWNER/dsh-pack-e2e:run-$RUN_ID
  → Delete LocalImageStore entry
  → Pull tag
      assert: contentHash same / signature VALID / trust VERIFIED
  → Delete local again
  → Pull @manifestDigest
      assert: 同一 artifact
  → run --require-trusted
      assert: configHash same
```

即 **Internet North-Star E2E**（§3 清单 8 项全覆盖，D44 三成兼须）。

---

## 8. v0.4.2 功能顺序（冻结，真实 GHCR 跑通之后）

```text
① Real GHCR E2E（本阶段）
      ↓
② image lock      /pack image lock ghcr.io/org/agent:prod
                  → ghcr.io/org/agent@sha256:<real-manifest-digest>
                  → dsh-lock.json（Human-friendly tag → Deployment lock → Immutable digest）
                  —— 直接复用本轮真实 GHCR 得到的 manifestDigest
      ↓
③ trust.yaml     registries 级 requireSignature/requireTrusted/trustedKeys
      ↓
④ local prune    /pack image prune（未引用 blob/manifest + 旧 runtime cache；
                  **不做 Registry GC**——那是 Registry Server 的职责）
```

---

## 9. image lock（冻结，D46–D49）

**定位**：`image lock` 只做一件事——把 **mutable remote tag** 解析为
**immutable OCI manifest digest**（远程分发身份的钉死），与真实 GHCR 验收
并行开发，不依赖 GHCR 运行结果。

### 冻结决策

| ID | 决策 |
|----|------|
| D46 | image lock 将 mutable remote tag 解析为 immutable OCI manifest digest |
| D47 | `dsh-lock.json` 只负责版本钉死，**不表示 Signature/Trust**（Lock ≠ Trust） |
| D48 | lock 解析结果必须是 `repo@sha256:<manifestDigest>`（对象是 **OCI manifestDigest**，不是 DSH contentHash，也不是 blobDigest） |
| D49 | 使用 lock 运行时**仍完整执行** OCI integrity → DSH integrity → Signature → Trust 验证（不因来自 lockfile 而跳过 v0.3/v0.4 安全链） |

### 命令形态（v0.4.2 第一版只生成 lockfile，不增加消费命令）

```bash
/pack image lock ghcr.io/org/agent:prod
/pack image lock ghcr.io/org/agent:prod --file dsh-lock.json
```

输出：

```text
Resolved:

ghcr.io/org/agent:prod
        ↓
ghcr.io/org/agent@sha256:8a19...

Lock written: dsh-lock.json
```

（`run --lock` / `pull --locked` 等消费命令留待后续版本；lockfile 的消费
即标准 digest-form pull——不可变性由 OCI 协议保证。）

### dsh-lock.json 最小 schema（冻结）

```json
{
  "schemaVersion": 1,
  "images": {
    "ghcr.io/org/agent:prod": {
      "resolved": "ghcr.io/org/agent@sha256:abc123...",
      "manifestDigest": "sha256:abc123..."
    }
  }
}
```

**最小字段原则**：不塞 contentHash / blobDigest / signature / trust /
configHash / runtime versions——这些都能通过 immutable manifest 再解析
出来。Lockfile 唯一职责：**Mutable Reference → Immutable Reference**。

### 语义边界

```text
Lock
  ↓
immutable manifest digest
  ↓
pull
  ↓
OCI integrity
  ↓
DSH integrity
  ↓
Signature
  ↓
Trust Policy
  ↓
Run
```

lock 只能证明"部署后不会因 `prod` tag 漂移而换版本"，**不能证明 digest 可信**
（D47/D49）。

### 验收判据（mock registry，冻结）

```text
T0（核心价值）：
  agent:prod → manifest A
  image lock → lock = @sha256:A
  后来：agent:prod → manifest B
  使用 lock（pull @sha256:A）→ 仍然拉 A

T1：锁文件写的是不存在的 digest → pull FAIL
T2：Registry 返回与 locked digest 不匹配的 manifest → Transport Integrity FAIL
```

---

## 10. Release Gate（冻结）

```text
v0.4.2 可以开发（image lock 等）
  但 merge/tag 的硬门槛：
    ① Real GHCR E2E 8/8 PASS（workflow_dispatch，GITHUB_TOKEN）
    ② image lock E2E PASS（mock registry）
  两者全过才允许 v0.4.2 merge/tag + CHANGELOG 验收状态改 PASS
```

**可以开发，不可以在真实 GHCR 通过之前宣布 v0.4.2 完成。**

---

## 11. trust.yaml（冻结，D50–D56）

**定位**：Trust Policy ≠ "保存 trusted keys 的配置文件"——它是 **Remote Image
Execution Policy**：回答"这个 registry/namespace 下的 image，是否必须有签名？
签名是否必须来自受信任 Key？允许哪些 Key？不满足时允许 pull/run 吗？"

与 `image lock` 分层（Lock ≠ Trust，D47/D49 延续）：

```text
image lock    解决"到底运行哪个版本？"（immutable pinning）
trust.yaml    解决"这个版本允许不允许运行？"（execution policy）
```

### 冻结决策

| ID | 决策 |
|----|------|
| D50 | Trust Policy 是**本地策略**，不属于 Artifact（trust.yaml ∉ `.dshpack` / OCI manifest / provenance / registry metadata）——生产与开发可对同一 image 不同策略 |
| D51 | 策略匹配对象是 **Remote Repository Pattern**（如 `ghcr.io/company/prod-*`），不只看 registry host（粒度太粗） |
| D52 | **Most-specific-match wins**（最长 pattern 优先；等长按 pattern 字典序——确定性、与文件行序无关）；**不用 first match**（换行序不应改变安全策略） |
| D53 | 无匹配规则 → **保持 v0.4.1 语义**（unsigned/signed-untrusted 默认允许 WARN；CLI `--require-*` 显式收紧）——backward-compatible |
| D54 | Policy 与 CLI 关系**只能越叠越严**（Effective = Policy OR CLI tightening；CLI 永远不能放宽管理员策略） |
| D55 | `trustedKeys` 只认 **keyId fingerprint**（`SHA256:<hex>`）；**不用 signer label**（`--signer` 只是 display label，D19 延续，绝不倒退） |
| D56 | **Pull 与 Run 的 Policy 边界分开**（cache ≠ trust）：pull 只做 OCI+DSH integrity + Signature metadata → 允许进 cache；run 才评估 trust.yaml → PASS 才 materialize，FAIL 在 pnpm 前（`allowPull: false` 留待以后，v0.4.2 不做） |

### 配置文件位置（冻结）

```text
$DSH_HOME/trust.yaml        ← Host / Environment Policy
```

**不是** `profile/trust.yaml`——Trust Policy 更接近本机"允不允许这个 Agent
运行"（Host policy），而 Profile 是"Agent 要怎么运行"，层级不同。

### 最小 Schema（冻结）

```yaml
version: 1

registries:
  "ghcr.io/company/prod-*":
    requireSignature: true
    requireTrusted: true
    trustedKeys:
      - SHA256:AAAA
      - SHA256:BBBB

  "ghcr.io/company/*":
    requireSignature: true

  "localhost:5000/*":
    requireSignature: false
    requireTrusted: false
```

**不加**（范围控制）：expiry / key rotation / deny / allow list / time
constraints / signer names / certificate chains。

### 内部架构（冻结）

```text
src/image/trust-policy.ts（Policy Engine，纯策略解析）
  ├── schema/load/validate（$DSH_HOME/trust.yaml）
  ├── glob 匹配 + most-specific 排序（D51/D52）
  ├── mergeCli（D54：只能收紧）
  └── Decision: { requireSignature, requireTrusted, trustedKeys?, matchedRule? }

Remote Ref → TrustPolicy.resolve(repository) → Decision
          → 现有 verify/trust machinery（D55 指纹检查并入 applyTrustPolicy）
```

Policy Engine 只解析策略；**验签仍复用 v0.3/v0.4 现有实现，不重新实现**
（D55 的 fingerprint 检查作为 trustedKeys 分支并入 `image/trust.ts`）。

### 测试判据（冻结）

```text
T0 无 trust.yaml → 完全保持 v0.4.1 行为
T1 ghcr.io/company/* requireSignature=true → unsigned run FAIL
T2 requireSignature=true + signed unknown key → PASS（无 requireTrusted）
T3 requireTrusted=true + signed unknown key → FAIL
T4 requireTrusted=true + trusted key → PASS
T5 父规则宽松、子规则严格 → 最具体规则生效（ghcr.io/company/prod-* 胜 ghcr.io/*）
T6 CLI --require-trusted + policy requireTrusted=false → effective=true
T7 policy requireTrusted=true + CLI 无额外约束 → 仍 true
T8 signer label 匹配但 key fingerprint 不匹配 → UNTRUSTED
T9 untrusted pull → cache 成功；run → policy FAIL before materialization
```

（T5/T6/T9 最重要。）

### lock × trust 组合 E2E（冻结）

```text
prod tag → manifest A → image lock → @sha256:A
prod tag 后来 → manifest B
trust.yaml: prod 规则 requireTrusted（A 的 key 在 trustedKeys）
运行 lock → 仍拉 A → 验证 A 签名 → Trust policy → PASS

然后：A 的 signer 从 trustedKeys 删除
同一个 lock → 版本没变 → Trust policy changed → FAIL
```

说明 **Version identity 与 Trust policy 正交**：lock 钉版本，trust.yaml
管准入；策略变更只影响准入，不改变版本身份。

---

## 12. local image prune（冻结，D57–D63）

**定位**：Local CAS Garbage Collection——**不是** `rm -rf ~/.dsh/images`。
核心原则：**只删除"不可达"的对象，永远不根据"看起来旧"直接删除仍被引用的
对象**。v0.4.2 最后一块功能；完成后停止新增功能，等 GHCR 8/8 Release
Gate。

### 冻结决策

| ID | 决策 |
|----|------|
| D57 | prune 只管理 Local Image Store / runtime cache，**不操作远程 Registry**（不做 Registry GC——那是 Registry Server 的职责，延续 v0.4.2 冻结） |
| D58 | GC 使用 **reachability**，而不是时间作为主要删除依据（ref count 会因 crash / 手工改文件漂移；reachability 每次重算是真相） |
| D59 | 所有 refs 指向的 manifests/digests 都属于 **GC Root** |
| D60 | manifest 可达则其 `.dshpack` blob **必须保留**（blob 可能被多个 manifest/ref 间接引用——不能因删一个 tag 就删 blob，延续 v0.4.0 F-A 不变量） |
| D61 | **默认 dry-run**（完整列出删除计划）；破坏性删除必须显式 `--apply` |
| D62 | runtime cache 与 Image CAS **分开清理**，运行中的 runtime 永远不能 prune——v0.4.2 无活跃 marker/pid lease → **保守策略：runtime cache 只报告（条目+字节），永不自动删除**（宁可保守；未来引入 lease 后再启用自动清理） |
| D63 | `dsh-lock.json` 与 `trust.yaml` **都不是 Local GC Root**（lock 是 remote immutable reference，不代表本地存在；trust.yaml 是执行治理不是本地保存治理）——需要时 `pull locked digest` 重新拉回 |

### 四层架构（互不混淆，冻结）

```text
Image Ref         → Local reachability / lifecycle（prune 管这层）
Image Lock        → Version governance（D46–D49）
trust.yaml        → Execution governance（D50–D56）
Registry          → Distribution（不操作，D57）
```

### Mark-and-Sweep（冻结实现结构）

```text
Phase 1 — Mark：遍历 refs → 标记 manifest reachable → 读取 manifest →
              标记 artifact blob reachable（D59/D60）

Phase 2 — Sweep：all manifests − marked = orphan manifests
                 all blobs − marked = orphan blobs
```

```ts
const reachableManifests = new Set<string>()
const reachableBlobs = new Set<string>()
for (const ref of store.listTags()) {
  const manifestDigest = store.getTag(ref)          // resolve ref (GC Root)
  reachableManifests.add(manifestDigest)
  const manifest = store.getManifest(manifestDigest)
  reachableBlobs.add(manifest.artifact.digest)      // D60
}
const orphanManifests = store.listManifests().filter((m) => !reachableManifests.has(m))
const orphanBlobs = store.listBlobs().filter((b) => !reachableBlobs.has(b))
```

### 命令面（冻结）

```bash
/pack image prune           # dry-run：只扫描
/pack image prune --apply   # 真正删除
```

输出（dry-run 示例）：

```text
Local Image Prune

Reachable manifests   8
Reachable blobs       6

Unreferenced manifests
  sha256:AAA
  sha256:BBB

Unreferenced blobs
  sha256:CCC   12.4 MB

Runtime cache (conservative, not deleted)
  3 entries
  184 MB

Reclaimable (dry-run): 196.4 MB
```

`--apply` 时输出 `Reclaimed: <bytes>`（扫描阶段记录每个对象大小）。

### 验收判据（冻结）

```text
T0 无 orphan → prune 0 items
T1 删除唯一 tag 后 manifest + blob 成为 unreachable → prune 删除
T2 两个 tag 指向同 digest，删其中一个 → manifest/blob 保留
T3 两个 manifests 共用同 blob，其中一个 orphan → manifest 删，blob 保留（D60）
T4 orphan manifest 指向 orphan blob → 两者一起删除
T5 dry-run → 结果正确，但磁盘完全不改变（D61）
T6 prune 中途失败 → refs 永不损坏 → 可再次安全执行（二次 --apply 幂等 no-op）
T7 .run-* 存在（active/unknown）→ 永不删除（D62 保守）
T8 runtime cache 报告正确（条目+字节）+ D63：locked 但本地无 ref 的 image → prune 删除
```

---

## 13. v0.4.2 路线收口（冻结）

```text
image lock       ✅
trust.yaml       ✅
local prune      ✅
GHCR 8/8         ⏳（硬 Release Gate）
        ↓
真实 GHCR workflow_dispatch → 8/8 PASS
        ↓
CHANGELOG 回填 → Release Review → --no-ff merge → annotated v0.4.2
```

**GHCR Gate 状态记录（2026-08-30，两次 workflow_dispatch 前置失败）**：

```text
run #1：BLOCKED — setup-node cache 阶段找不到 pnpm（corepack enable 在
        setup-node 之后才运行，且 package.json 无 packageManager 字段）。
        修复：pnpm/action-setup@v4（version 11）置于 setup-node 之前。
run #2：BLOCKED — CI 只 checkout dsh-pack，devDependencies 通过
        link:../deepseek-harness/<pkg> 依赖 sibling DeepSeek Harness 源码树，
        runner 上 ../deepseek-harness 不存在 → tsc 无法 resolve @deepseek-ai/*。
        修复：双 checkout（dsh-pack + deepseek-ai/deepseek-harness@
        47f943859b，pin release dsh@0.1.0-rc.5）+ working-directory=dsh-pack
        + dependency preflight + build:lib:host（lib/ 被 harness .gitignore
        忽略，checkout 后无构建产物）。
run #3：PARTIAL — 真实 GHCR 协议已开始：① GET /v2/ → 401 + Bearer
        challenge ✅、② Bearer token 获取（scope pull,push）✅；③ 之前
        push 前的客户端 ImageReference 校验拦截：fixture 用了 GitHub
        owner 原始大小写（ghcr.io/WHY-Daydream/dsh-pack-e2e），而 OCI
        repository <name> 只允许小写 [a-z0-9...] → Parser 正确拒绝
        （invalid namespace component）。不是 GHCR 拒绝请求——GHCR 根本
        没收到 push。修复：scripts/ghcr-fixture.mjs 将 owner 映射为
        canonical lowercase repository（why-daydream/dsh-pack-e2e），
        target ref / registry URL / Bearer scope 共用同一字符串；通用
        Parser 不放宽（回归测试钉死）。⑥⑦⑧ 及其余项 NOT RUN。

前两轮 BLOCKED（CI environment parity failure / NOT RUN）；run #3 为
PARTIAL（2 项真实 PASS，push 未进入）——均不是 8 项协议 FAIL。修复后
重新 workflow_dispatch 才进入真实 Registry push/pull 核心阶段。
```

**完成 prune 后不再新增 v0.4.2 功能。**

---

*本文档 v0.4.2 设计定稿（2026-08-29）。冻结 D41–D63；v0.4.1 的
D32–D40 与 `.dshpack` v1 协议不受影响。实现顺序：DESIGN 冻结（本文）→
PR CI workflow → GHCR E2E workflow → `scripts/ghcr-e2e.mjs`（8 项断言）→
本地验证脚本语法 → CHANGELOG。真实 GHCR 运行须在 GitHub Actions
`workflow_dispatch` 中执行（需 GITHUB_TOKEN + packages:write）。*
