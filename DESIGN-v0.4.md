# dsh-pack v0.4 Design — Agent Image / Distribution Model

> **dsh-pack v0.4 — Named + Versioned + Runnable DSH Agent Image.**
>
> v0.4 不做"新的包格式"，而是让 `.dshpack` 从本地 Artifact 变成**可命名、可版本化、
> 可推送、可拉取、可运行的发布单元**。这是第一次把
> **Artifact / Identity / Version / Trust / Distribution / Runtime** 六件事串成
> 一个完整模型。

- 状态：**v0.4 设计定稿（2026-08-29，D20–D31 冻结，见 §18）**
- 前置：v0.1 可验证快照（configHash/contentHash）→ v0.2 可移植 Artifact（`/pack diff` + `--portable`）→ v0.3 可信 Artifact（ed25519 签名 / provenance / Trust，D18/D19）
- 关系：**`.dshpack` v1 包格式不因 v0.4 修改**（D23）；Image Manifest 是独立于包之外的分发元数据（D24）
- 关联官方现状：DSH 官方仍为 Profile + Bundle + `dsh plugin --profile` 模型，无 "Agent Image push/pull/run" 抽象——本方向不重复造轮子

---

## 1. 定位与边界

**一句话**：v0.4 让 `.dshpack` 从"文件"变成"可寻址、可信任、可运行的发布对象"。

**明确不是**：

- ❌ 不是 "DSH Docker"——不打包 OS / Node / pnpm / DSH Runtime（D30）。
- ❌ 不是新的 Pack 格式——`.dshpack` v1 冻结不动（D23）。
- ❌ v0.4.0 不实现完整 OCI Registry——只做 Local Image Model（D31 方向兼容）。

**DSH Agent Image 的准确定义**（D20）：

```text
DSHPack Artifact（.dshpack）
  + Repository Name
  + Tag（mutable alias）
  + Digest（immutable content identity = contentHash）
  + Signature / Provenance（v0.3）
  = DSH Agent Image
```

**概念链**（Image ≠ Pack，D20）：

```text
Profile → Pack → Artifact → Image Reference → Distribution → Runtime
```

`.dshpack` 是 **Artifact Format**；Agent Image 是**被赋予 Name + Tag/Digest + Distribution Identity 的 Artifact**——类似 "tar layers ≠ docker image reference"。

---

## 2. 核心概念冻结

| 概念 | 定义 | 可变性 | 归属 |
|------|------|:------:|------|
| Pack / Artifact | `.dshpack` 文件（v1 格式，含 manifest/resolved/packages/metadata） | immutable | 本地文件 |
| Image | 被命名 + 版本化的 Artifact（store 中的对象） | immutable（内容寻址） | `$DSH_HOME/images/` |
| Image Reference | `[registry/][namespace/]name[:tag][@digest]`（§3） | — | 字符串 |
| Tag | mutable 人类别名（latest/prod/v1） | **mutable**（D22） | store refs |
| Digest | immutable 内容身份 = contentHash（§5） | **immutable**（D22） | store blobs |
| Profile | 可运行组合（bundles + patch + node_modules） | **mutable、用户可编辑** | `$DSH_HOME/profiles/` |
| Runtime Instance | `run` 产生的临时可运行 profile | 瞬态 | `$DSH_HOME/runs/<uuid>/` |

---

## 3. Image Reference Grammar（冻结，D21 关联）

借鉴容器镜像命名，**v0.4 冻结**：

```text
[registry/][namespace/]name[:tag][@digest]
```

合法示例：

```text
why-daydream/procurement-agent:v1.0
ghcr.io/why-daydream/procurement-agent:v1.0
ghcr.io/why-daydream/procurement-agent@sha256:abcd...（64 hex）
ghcr.io/why-daydream/procurement-agent:v1.0@sha256:abcd...（tag+digest 并存合法）
```

解析结果（内部结构）：

```text
{ registry?: "ghcr.io", namespace: "why-daydream", name: "procurement-agent",
  tag?: "v1.0", digest?: "sha256:abcd..." }
```

约束（冻结）：

- `name`：小写字母/数字/`-`/`_`/`.`，每段 `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`，段间 `/`。
- `tag`：`[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127}`（非空、最长 128）。
- `digest`：`sha256:` + 64 hex（**仅支持 sha256**，与 contentHash 对齐）。
- `registry`：含 `.` 或 `:` 或 `localhost` 的 host 段视为 registry（区分 `org/name` 与 `host/name` 的歧义规则与 Docker 一致）。
- **解析失败 → 明确报错（exit 1）**，绝不静默猜测。

---

## 4. Tag vs Digest（冻结，D22）

```text
Tag    = mutable human alias（latest/prod/v1）   —— 今天指 A，明天指 B
Digest = immutable content identity（sha256:...）—— 永远指向同一 Artifact
```

原则：

- `agent:latest` 允许重指向（push 新版本时 tag 更新，UI 明确显示 `agent:latest → sha256:B`，不隐藏 digest）。
- `agent@sha256:A` 永不变化；resolve 到同一 digest 的引用等价。
- 该原则决定：**Caching / Rollback / Supply-chain trust / Deployment reproducibility**。
- `run`/`pull` 一律 **digest-first**（§12）：tag 只是入口，解析后锁定 digest。

---

## 5. Identity 链：digest = contentHash（冻结，D21/D23）

**不发明新哈希**。v0.3 的 contentHash 直接升级为 Image Digest：

```text
Portable Config  →  configHash（可移植配置复现锚）
Artifact         →  contentHash（完整性锚，排除 checksums/signature/provenance）
Distribution     →  digest = contentHash
Trust            →  signature(contentHash)
```

因此 `Pack / Verify / Sign / Import / Push / Pull / Run` 全部围绕**同一个 immutable identity**。`imageDigest` 一词在 v0.4 中即 `contentHash` 的别名（同一字符串，`sha256:<64 hex>`）。

---

## 6. Image Manifest（冻结，D24——独立于 `.dshpack` v1）

`.dshpack` v1 保持 **Runtime Artifact**；Image Manifest 是 **Distribution metadata**，存于 store 的 `manifests/`，**不进入包内**。

```json
{
  "schemaVersion": 1,
  "mediaType": "application/vnd.dsh.image.manifest.v1+json",

  "artifact": {
    "digest": "sha256:...",
    "size": 1839201,
    "mediaType": "application/vnd.dsh.pack.v1+gzip"
  },

  "configHash": "sha256:...",

  "platform": {
    "dshVersion": "0.1.0-rc.5",
    "node": ">=24",
    "pnpm": ">=10"
  },

  "annotations": {
    "org.opencontainers.image.title": "procurement-agent",
    "org.opencontainers.image.version": "1.0.0"
  }
}
```

字段规则（冻结）：

| 字段 | 必选 | 语义 |
|------|:----:|------|
| `schemaVersion` | ✓ | = 1 |
| `mediaType` | ✓ | 固定 `application/vnd.dsh.image.manifest.v1+json` |
| `artifact.digest` | ✓ | **= 包 contentHash**（唯一身份锚） |
| `artifact.size` | ✓ | 包字节数 |
| `artifact.mediaType` | ✓ | 固定 `application/vnd.dsh.pack.v1+gzip` |
| `configHash` | ✓ | 包 manifest.configHash（配置可移植锚） |
| `platform.dshVersion` | ✓ | 构建时 dsh 精确版本（run 兼容性检查，§14） |
| `platform.node` / `platform.pnpm` | — | semver 范围（默认 `>=24` / `>=10`） |
| `annotations.*` | — | 尽量兼容 OCI `org.opencontainers.image.*`（D31） |

manifest 的 digest = `sha256:<manifest 内容 JSON 的 sha256>`（规范序列化：键排序、紧凑 JSON——沿用 v0.1 canonical 规则）。

---

## 7. Local Image Store（冻结，D25）

路径：`$DSH_HOME/images/`（`$DSH_HOME` 解析复用 `@deepseek-ai/dsh-home-paths`）。

```text
$DSH_HOME/images/
├── blobs/
│   └── sha256/
│       └── <contentHash>          ← .dshpack 字节（内容寻址）
├── manifests/
│   └── sha256/
│       └── <manifestDigest>       ← Image Manifest JSON
└── refs/
    └── why-daydream/
        └── procurement-agent/
            ├── v1.0               ← 内容 = manifestDigest（一行 sha256:...）
            └── latest             ← 内容 = manifestDigest
```

规则（冻结）：

- **blob 文件 = 包字节，文件名 = 其 sha256**（content-addressed）；写入后内容不可变（同名文件已存在且一致 → 幂等；不一致 → FAIL——防止碰撞/损坏覆盖）。
- refs 是 tag → manifestDigest 的**一行文本文件**（可原子替换 = tag 更新，§15）；digest 引用（`name@sha256:...`）不写 refs，直接查 manifests。
- 写入原子性：先写临时文件再 rename（同一文件系统原子）。
- **store 是纯本地内容层**：不含网络/认证/registry 语义（§10 设计动机）。
- `.dshpack` → store 的入口：`image import`（§15），import 时同时写 blob + manifest + refs。

---

## 8. Image vs Profile 边界（冻结，D26）

```text
Image   = immutable / content-addressed / signed / versioned / distribution object
Profile = mutable / user editable / local / can patch / can add-remove plugins
```

关系：**Image --instantiate--> Profile**，绝不等同：

```bash
/pack run agent:v1                    # 临时实例：不污染当前环境（D27）
/pack install agent:v1 --profile my-agent   # 从 immutable image 创建 mutable profile
```

- `run` 生成**临时 runtime profile**（§9），生命周期与运行绑定，结束清理。
- `install --profile` 才把 image 物化为**持久可编辑** profile（复用 v0.1 install 管线：verify → frozen install → atomic swap）。

---

## 9. `run` 语义（冻结，D27）

```text
resolve tag → digest
  → blob 本地存在？（无则 FAIL——v0.4.0 无远程拉取，D28 见 v0.4.1）
  → verify contentHash（blob 字节重算 == digest）
  → verify signature（v0.3 Signature 分节；缺失按 policy）
  → trust policy（§11；policy 拒绝 → FAIL）
  → 兼容性检查（§14：dsh 精确版本 + node/pnpm 范围）
  → materialize 临时 runtime：$DSH_HOME/runs/<uuid>/
  → pnpm install --frozen-lockfile（复用 v0.1 MUST-1）
  → dsh --profile <uuid-profile> 启动
  → 退出后 cleanup（成功与失败都清理；失败保留 <uuid> 目录供排障，输出路径）
```

要点（冻结）：

- `run` **默认不覆盖/不创建持久 profile**（D27）；临时目录 `$DSH_HOME/runs/<uuid>/`，由工具拥有。
- `--profile <name>` 显式传参时退化为**持久 install + 提示**（等价 `image install`），此时走 v0.1 install 原子管线。
- 任意 verify/trust/兼容性失败 → **boot 前 FAIL**（exit 非 0），绝不带病启动。

---

## 10. `ctx.images` Service Seam（冻结接口）

v0.4 新增服务缝（与 `ctx.packager` 同构，Everything is a Plugin）：

```ts
interface ImageService {
  import(packPath: string, options?: ImportOptions): Promise<ImageRef>     // 入 store
  inspect(ref: string): Promise<ImageMetadata>                            // 查元数据
  tag(source: string, target: string): Promise<void>                      // 加别名（mutable）
  remove(ref: string): Promise<void>                                      // 删 tag / digest（blob 引用计数见 §19 预留）
  resolve(ref: string): Promise<ResolvedImage>                            // tag/digest → { manifest, digest }
  run(ref: string, options?: RunOptions): Promise<RunResult>              // §9
  // v0.4.1：
  pull(ref: string): Promise<ResolvedImage>
  push(ref: string): Promise<void>
}
```

实现可替换：`LocalImageStore`（v0.4.0）→ `OCIImageStore / GHCRImageStore / EnterpriseRegistry`（v0.4.1+，D31）。Remote 只是 Store 的另一个 Provider。

---

## 11. Trust Policy 桥接 v0.3（冻结，D29）

**不重复实现**验签逻辑——直接复用 v0.3 verify（`verifySignatureValue` + keyId 白名单）。

v0.4.0 policy 规则（env 起步，未来 `trust.yaml`）：

| 来源 | 默认策略 | 说明 |
|------|---------|------|
| local image（import 自本机） | signature optional | 与 v0.3 verify 一致（缺失 WARN） |
| `run --require-signature` | signature required | 缺失/无效 → FAIL |
| `run --require-trusted` | trusted key required | 不在 `DSH_PACK_TRUSTED_KEYS` → FAIL（复用 v0.3 白名单 + `SHA256:` 归一化） |

预留（v0.4.1+）：

```yaml
# $DSH_HOME/images/trust.yaml（未来）
trust:
  "ghcr.io/company/*":
    requireSignature: true
    trustedKeys: ["SHA256:ABC..."]
```

**Trust 判定只基于 keyId 指纹**（D19 延续），与 signer 标签无关。

---

## 12. Pull 必须 Digest-first（冻结，D28——v0.4.1 生效，语义现在冻结）

```text
agent:v1 → resolve → manifest digest → artifact digest
  → download blob → SHA256 重算 == artifact digest（Transport + Artifact Integrity）
  → signature verify（Authenticity）
  → trust policy（Trust）
```

顺序固定：**Transport Integrity → Artifact Integrity → Authenticity → Trust**。
绝不 "pull tag → blind trust"。

---

## 13. OCI 兼容方向（冻结，D31）

OCI-compatible ≠ v0.4 实现完整 OCI Registry。冻结：

- 命名：`repo:tag` / `repo@sha256:digest`（Docker 兼容语法，§3）。
- Digest：`sha256`（与 contentHash 同族）。
- Media Type：`application/vnd.dsh.pack.v1+gzip`、`application/vnd.dsh.image.manifest.v1+json`（vnd.dsh 命名空间，不与 OCI 标准类型冲突）。
- Annotation：尽量复用 `org.opencontainers.image.*`。
- 演进：v0.4.0 = Local Image Model；v0.4.1 = OCI push/pull（push = .dshpack → OCI blob + DSH manifest → OCI manifest/tag → registry；pull 反向 + §12 digest-first）。**不需要自建 DSH Registry Server**——复用 GHCR/Harbor/Docker Registry/ECR 现有 API。

---

## 14. 边界声明（冻结，D30）

- **不打 OS / Node / pnpm / DSH runtime**：DSH Image 是 **application-level Agent image**（类比 Python wheel / npm package / WASM component），依赖宿主环境。
- **不自动下载/启动不同版本 runtime**：`run` 只做兼容性检查——

```text
current runtime → compatible? → yes: run / no: FAIL
```

- `platform.dshVersion` 精确匹配（沿用 D15 原则）；`node`/`pnpm` semver 范围检查（默认 `>=24` / `>=10`）。
- 不在 v0.4：容器化、运行时自动升级、KMS/HSM。

---

## 15. 命令面（v0.4.0 冻结）

| 命令 | 行为 | 关键参数 |
|------|------|---------|
| `/pack image import <file.dshpack> [--tag <ref>]` | 入本地 store（blob + manifest + refs），返回 digest | `--tag` |
| `/pack image ls` | 列出 refs（REPOSITORY / TAG / DIGEST） | — |
| `/pack image inspect <ref>` | 查 Image Manifest + 签名状态 | `--json` |
| `/pack image tag <src> <dst>` | 加 tag（mutable 别名） | — |
| `/pack image rm <ref>` | 删 tag 或 digest 引用 | — |
| `/pack run <ref>` | §9 临时 runtime | `--require-signature`、`--require-trusted`、`--profile <name>`（持久化） |
| v0.4.1：`/pack push <ref>`、`/pack pull <ref>` | OCI push/pull（digest-first） | — |

`image ls` 输出示例：

```text
REPOSITORY             TAG      DIGEST
why-daydream/agent     v1       sha256:a82...
why-daydream/agent     latest   sha256:a82...
```

---

## 16. 内部模块结构

```text
src/image/
├── reference.ts      §3  repo/tag/digest 解析与校验
├── manifest.ts       §6  Image Manifest schema（生成/校验/digest）
├── store.ts          ImageStore 接口（§10）
├── local-store.ts    §7  内容寻址本地存储（blobs/manifests/refs，原子写）
├── resolver.ts       §10 tag/digest → manifest + artifact digest
├── runtime.ts        §9  image → 临时 profile → pnpm frozen → dsh 启动 → cleanup
├── trust.ts          §11 桥接 v0.3 verify（require-signature / require-trusted / 白名单）
└── commands.ts       §15 image import/ls/inspect/tag/rm + run
```

依赖：复用 `@deepseek-ai/dsh-home-paths`（`$DSH_HOME`）、v0.1 `verify.ts`/`install.ts` 管线、v0.3 `sign.ts`（signature 校验）、canonical 序列化。新增依赖：无（Node 原生 crypto + 现有 tar/yaml）。

---

## 17. 北极星 E2E（v0.4 验收判据，冻结）

**第一条（模型成立的唯一判据）**——Image 闭环：

```text
Profile A
  → pack --portable
  → sign（ed25519，keyId K）
  → image import --tag agent:v1
  → 删除原 Profile（模拟干净机器）
  → run agent:v1
  → temporary runtime
  → configHash == original
  → Signature VALID
  → Trust VERIFIED（DSH_PACK_TRUSTED_KEYS=K）
```

**第二条**——tag 语义：

```text
image tag agent:v1 agent:latest → ls 显示同一 digest
```

**第三条**——tamper 拒绝：

```text
篡改本地 blob 字节 → run → boot 前 FAIL（digest 重算不一致）
```

**第四条**——untrusted 拒绝：

```text
未在白名单的 key 签名 → run --require-trusted → FAIL（Signature 仍 VALID，Trust UNTRUSTED）
```

---

## 18. 冻结决策清单（D20–D31）

| ID | 决策 | 章节 | 一句话 |
|----|------|------|--------|
| D20 | Agent Image = 被命名/版本化的 `.dshpack` Artifact | §1, §2 | Image ≠ Pack；概念链 Profile→Pack→Artifact→Reference→Distribution→Runtime |
| D21 | Image identity = content digest | §3, §5 | 内容寻址，身份与路径无关 |
| D22 | Tag mutable，Digest immutable | §4 | tag 可重指向；digest 永不变化 |
| D23 | `.dshpack` v1 不因 Image 功能修改 | §1, §6 | 兼容 v0.1–v0.3 包格式 |
| D24 | 新增独立 Image Manifest（dist 元数据） | §6 | media type `application/vnd.dsh.image.manifest.v1+json`，不入包 |
| D25 | Local Store 内容寻址 | §7 | `$DSH_HOME/images/`：blobs/sha256 + manifests/sha256 + refs/；原子写 |
| D26 | Image 与 Profile 分离：immutable → mutable instantiate | §8 | run=临时实例；install --profile=持久物化 |
| D27 | `run` 默认临时 runtime，不覆盖现有 Profile | §9 | `$DSH_HOME/runs/<uuid>/`，失败保留供排障 |
| D28 | Remote pull 必须 digest verify | §12 | Transport→Artifact→Authenticity→Trust 顺序冻结 |
| D29 | Trust 直接复用 v0.3 keyId policy | §11 | require-signature / require-trusted；signer 非信任根（D19 延续） |
| D30 | v0.4 不包含 OS/Node/DSH runtime image | §14 | application-level image；只做兼容性检查 |
| D31 | Distribution protocol 朝 OCI compatibility 设计 | §13 | 命名/digest/media-type/annotation 兼容；v0.4.0 Local / v0.4.1 OCI |

---

## 19. 预留（不在 v0.4.0 实现）

- **`image lock`**：`why-daydream/agent:prod` → `why-daydream/agent@sha256:abc...`（部署可复现，企业场景；与 `lockfile` 同精神）。
- **blob 引用计数 / GC**：`image rm` 的孤儿 blob 回收。
- **Registry Provider 抽象**：OCIImageStore / GHCRImageStore / EnterpriseRegistry（v0.4.1+）。
- **Encryption**：v0.5（私密插件源码 / 企业离线分发；`.dshpack` 默认 safe to distribute）。
- **`trust.yaml`**：按命名空间/仓库的细粒度 trust policy（v0.4.1+）。

---

*本文档 v0.4 设计定稿（2026-08-29）。冻结 D20–D31；`.dshpack` v1 协议（DESIGN.md）不受影响。实现顺序：Local Image Store（§7/§10）→ 命令面（§15）→ run 语义（§9）→ 北极星 E2E（§17）。*
