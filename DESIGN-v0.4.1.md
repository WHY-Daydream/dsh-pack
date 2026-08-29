# dsh-pack v0.4.1 Design — OCI push/pull（Remote Distribution）

> **dsh-pack v0.4.1 — Distributed Image.** v0.4.0 回答"Agent Image 是什么、
> 怎么在本地运行"；v0.4.1 回答"Agent Image 怎么跨机器分发"。
> 只实现 OCI Distribution Spec 的最小子集，复用现有 Registry API
> （GHCR / Harbor / Docker Registry / ECR），**不自建 DSH Registry Server**。

- 状态：**v0.4.1 设计定稿（2026-08-29，D32–D40 冻结，见 §12）**
- 前置：v0.4.0（D20–D31：Image Reference / Local CAS Store / Image Manifest /
  `ctx.images` / run 临时 runtime / Trust 桥接）已封版；`.dshpack` v1 与
  DSH Image Manifest v1 协议**均不修改**
- 关系：v0.4.1 是 **Transport 层**，不是新包格式——DSH 语义身份与 OCI
  Transport 身份明确分离（D32/D33）

---

## 1. 定位与边界

**一句话**：让本地 Image（`$DSH_HOME/images/`）可以 push 到 / pull 自任意
OCI Registry，且 pull 全程 digest-first 验证（D38/D39）。

**明确不做**（D40 最小子集）：

- ❌ multi-platform manifest / cross-repo mount / referrers API / registry GC
- ❌ cosign / OCI artifact 自定义顶层 manifest / OAuth device flow
- ❌ login/logout/registry ls/delete/copy/mirror
- ❌ 不把 registry 返回的任何 metadata 当作信任依据（§6）

---

## 2. 三种 Digest 分离（冻结，D32/D33）

**关键问题**：OCI descriptor 的 `digest` 是**目标内容原始字节**的
collision-resistant hash（拉取后按实际字节重新验证）；而 DSH `contentHash`
是排除派生元数据文件（checksums/signature/provenance）的**语义锚点**。
一个已签名包几乎必然满足 `contentHash = sha256:AAA` 而
`SHA256(pack bytes) = sha256:BBB`——两者不同。

因此 v0.4.1 **正式引入三种 Digest，禁止合并**（D32）：

```text
DSH Artifact
│
├── contentHash     DSH semantic identity（Signing/Trust anchor，v0.3 不变）
│
├── blobDigest      SHA256(.dshpack raw bytes)——OCI layer descriptor
│
└── manifestDigest  SHA256(OCI manifest JSON bytes)——OCI registry/tag 解析
```

类型层面强制区分（即使 runtime 都是 string，**不得共用 alias**，防止
`verifyContentHash(manifestDigest)` 这类 bug）：

```ts
/** DSH semantic identity — signature/trust anchor (D33, unchanged). */
type DshContentDigest = string
/** OCI layer descriptor digest — SHA256 over the raw archive bytes. */
type OciBlobDigest = string
/** OCI manifest digest — SHA256 over the canonical OCI manifest JSON. */
type OciManifestDigest = string
```

- **D33**：DSH `contentHash` 继续作为 Signing/Trust/Local Image Identity，
  v0.4.0 语义零变化。

---

## 3. OCI 顶层 Envelope（冻结，D34–D37）

Registry 顶层 **不使用自定义 DSH manifest media type**（未知 media type 在旧
Registry 上兼容性差）——复用标准 OCI Image Manifest（D34）：

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.dsh.agent.image.v1",
  "config": {
    "mediaType": "application/vnd.dsh.image.manifest.v1+json",
    "digest": "sha256:<configBlobDigest>",
    "size": 1234
  },
  "layers": [
    {
      "mediaType": "application/vnd.dsh.pack.v1+gzip",
      "digest": "sha256:<packBlobDigest>",
      "size": 123456
    }
  ]
}
```

映射（D35/D36/D37）：

```text
OCI Image Manifest
├── config ──► DSH Image Manifest（DSH contentHash/configHash/runtime/provenance 元数据）
└── layer  ──► 实际 .dshpack（单层，raw bytes）
```

- **D35**：`artifactType = application/vnd.dsh.agent.image.v1`
- **D36**：DSH Image Manifest（v0.4 定义）作为 OCI config blob
- **D37**：`.dshpack` 作为单 OCI layer blob（mediaType
  `application/vnd.dsh.pack.v1+gzip`，与包内自描述一致）

---

## 4. Push 顺序（冻结）

```text
Local Image Ref
  → resolve → DSH contentHash（本地 store）
  → load .dshpack bytes
  → verifyPack（DSH integrity，上推前先自证）
  → blobDigest = SHA256(raw bytes)
  → build DSH config blob（DSH Image Manifest）→ configBlobDigest
  → Registry HEAD blob（存在？）
      ├─ 不存在 → POST upload → PUT blob（monolithic）
      └─ 存在   → 跳过
  → build canonical OCI manifest → manifestDigest
  → PUT /v2/<repo>/manifests/<tag>
  → 校验响应 Docker-Content-Digest == manifestDigest
```

Tag 更新语义（D22 延续）：`repo:tag` 可重指向（新 manifestDigest 覆盖）；
`repo@<manifestDigest>` 永远指向同一 manifest。

---

## 5. Pull 顺序（冻结，digest-first，D38/D39）

```text
ghcr.io/org/agent:v1
  → GET manifest → 校验 manifest bytes == manifestDigest（tag 形态先 resolve）
  → validate：mediaType / artifactType / descriptor sizes
  → GET config blob → 校验 configBlobDigest → 读出 DSH contentHash
  → GET .dshpack blob → 校验 blobDigest（**按实际字节重算**）
  → verifyPack() → 重算 DSH contentHash → 必须 == config.contentHash
  → Signature VALID？（v0.3，包内）
  → Trust Policy？（v0.4，keyId 白名单）
  → LocalImageStore.import（content-addressed 落库）
```

四段顺序固定（D39）：

```text
OCI Transport Integrity（manifest/blob digest）
        ↓
DSH Artifact Integrity（contentHash / verifyPack）
        ↓
Signature Authenticity（v0.3 包内验签）
        ↓
Trust Policy（keyId 白名单）
        ↓
Local Image Store
```

**Trust 永不依赖 Registry 提供的 metadata**（§6）。OCI 验证通过后才执行
DSH 验证——transport 失败时 DSH verify **不执行**（E2E 判据 4/5 区分）。

---

## 6. 恶意 Registry 边界（冻结）

Registry 可能恶意/被篡改。**全部忽略** registry 返回的任何
annotations/metadata：

```json
{ "annotations": { "dsh.trust": "VERIFIED", "dsh.signer": "WHY-Daydream" } }
```

真实的 Signature / Signer keyId / Trust **只来自包内**：

```text
.dshpack → actual bytes/contentHash → v0.3 signature verification
         → local trusted-key policy（VALID ≠ TRUSTED，D19 延续）
```

v0.4.1 只复用 v0.3/v0.4 语义，不重新解释；Trust 仍在 materialize/pnpm 前
执行（v0.4.0 已验证的顺序）。

---

## 7. Remote `@digest` 语义（冻结）

```text
Local:   agent@sha256:<contentHash>          （DSH 语义身份，D21）
Remote:  ghcr.io/org/agent@sha256:<ociManifestDigest>（OCI transport 身份，D32）
```

**不强行让两者一致**。pull `repo@sha256:ABC` 时 `ABC` = OCI manifest digest
（经 §5 全链路验证后落库，落库后的本地 digest 仍是 DSH contentHash）。

---

## 8. Auth 范围（冻结）

v0.4.1 支持：

- **anonymous pull**
- **username/token**（Basic 或 Bearer challenge）
- **Bearer challenge**：`WWW-Authenticate: Bearer realm/service/scope` →
  按 scope 取 token → 重放请求

凭据来源（按序）：

```text
DSH_REGISTRY_USERNAME / DSH_REGISTRY_TOKEN（环境变量）
~/.dsh/registry-auth.json（{ "registry": { "username": "...", "token": "..." } }）
```

**绝对禁止**：token 写入 `.dshpack` / Image Manifest / provenance。
（GHCR 个人 CLI：PAT classic，scope `read:packages` / `write:packages`。）

---

## 9. 命令面（v0.4.1 冻结）

| 命令 | 行为 |
|------|------|
| `/pack push <localRef> <remoteRef>` | 本地 Image → OCI Registry（§4） |
| `/pack pull <remoteRef>` | digest-first 拉取 → LocalImageStore（§5） |
| `/pack run <remoteRef>` | **本地无则先 pull** → verify/trust → run（复用 v0.4.0 run 语义） |

`run` remote 内部：

```text
local exists? ──否──► pull → verify/trust → LocalImageStore
   └─是─► 直接 resolve
        → run（v0.4.0 临时 runtime）
```

---

## 10. 内部模块结构

```text
src/image/registry/
├── reference.ts    local/remote ref 区分（registry 缺省=local；remote=local ref + 远端 registry）
├── client.ts       OCI HTTP 原语（GET/PUT/HEAD blob、GET/PUT manifest、Docker-Content-Digest 校验、错误映射）
├── auth.ts         WWW-Authenticate / Bearer / Basic / token 凭据解析（token 不入包）
├── descriptor.ts   digest + size 验证（sha256 按字节重算）
├── manifest.ts     OCI envelope build/parse（schemaVersion 2 + artifactType + config/layers）
├── push.ts         §4 上传流水线
├── pull.ts         §5 digest-first 下载流水线
└── ghcr.ts         GHCR 便利封装（可选，v0.4.1 骨架）
```

```text
ImageService
    ├── LocalImageStore（本地内容层）
    └── RegistryClient（传输层）
```

**runtime.ts 不知道 HTTP**（D40 结构纪律，延续不变量 8）。

---

## 11. 北极星 E2E（v0.4.1 验收判据，冻结）

对**本地 OCI mock registry**（实现与 GHCR 相同的 Distribution 协议子集，
测试可注入篡改模式）执行 6 条：

| # | 判据 | 验证点 |
|---|------|--------|
| 1 | 本地签名 Image → push → **删本地 store** → pull → contentHash 相同 | 传输闭环，DSH 身份保持 |
| 2 | push → pull → Signature VALID + Trust VERIFIED | 包内签名/信任跨机器成立 |
| 3 | tag v1 → manifest A；更新 v1 → manifest B；`@A` 仍可精确 pull | tag mutable、digest immutable |
| 4 | registry 返回**篡改 blob** → OCI blobDigest FAIL → **DSH verify 不执行** | transport integrity 失败定位 |
| 5 | registry 返回合法 blob 但 **config.contentHash 与包不符** → DSH integrity FAIL | artifact semantic integrity 失败定位 |
| 6 | signed but untrusted → pull 可缓存 → `run --require-trusted` boot 前 FAIL | Trust 跨机器成立（VALID≠TRUSTED） |

判据 4/5 必须**可区分**：4 = OCI transport 层错误（blobDigest 不符）；
5 = DSH 语义层错误（contentHash 不符）。

真实 GHCR 验证（需 `DSH_REGISTRY_USERNAME/TOKEN`）留作手动/CI 步骤，
自动化 E2E 走本地 mock registry（协议相同）。

---

## 12. 冻结决策清单（D32–D40）

| ID | 决策 | 章节 |
|----|------|------|
| D32 | `contentHash` / OCI `blobDigest` / OCI `manifestDigest` 三种身份明确分离 | §2 |
| D33 | DSH `contentHash` 继续作为 Signing/Trust/Local Identity，v0.4 语义不变 | §2 |
| D34 | OCI 顶层使用标准 `application/vnd.oci.image.manifest.v1+json` | §3 |
| D35 | `artifactType = application/vnd.dsh.agent.image.v1` | §3 |
| D36 | DSH Image Manifest 作为 OCI config blob | §3 |
| D37 | `.dshpack` 作为单 OCI layer blob | §3 |
| D38 | tag resolve 得 OCI manifest digest；pull 必须先验证 manifest/blob digest | §5 |
| D39 | blob OCI 验证通过后，再执行 DSH contentHash + Signature + Trust 验证 | §5 |
| D40 | Registry Client 只实现最小 OCI Distribution 子集（无 multi-platform/referrers/cosign/GC/device flow） | §1, §10 |

---

*本文档 v0.4.1 设计定稿（2026-08-29）。冻结 D32–D40；v0.4.0 的 D20–D31 与
`.dshpack` v1 协议不受影响。实现顺序：registry 基础（reference/descriptor/
manifest/auth）→ client → push/pull → ImageService 集成 + 命令 → mock
registry E2E（§11 六条）。*
