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

*本文档 v0.4.2 第一阶段设计定稿（2026-08-29）。冻结 D41–D45；v0.4.1 的
D32–D40 与 `.dshpack` v1 协议不受影响。实现顺序：DESIGN 冻结（本文）→
PR CI workflow → GHCR E2E workflow → `scripts/ghcr-e2e.mjs`（8 项断言）→
本地验证脚本语法 → CHANGELOG。真实 GHCR 运行须在 GitHub Actions
`workflow_dispatch` 中执行（需 GITHUB_TOKEN + packages:write）。*
