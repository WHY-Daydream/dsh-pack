# dsh-pack v0.5.0 Design — Verifiable Agent Artifact（第一阶段：Evidence Foundation）

## 1. 定位与边界

v0.4.2 的 Identity（contentHash anchor）/ Trust（trust.yaml + trustedKeys）/
Distribution（OCI + image lock）基线已经成立。v0.5 在其上补 **Evidence /
Attestation 层**，目标是把社区反馈的五点（mutable `latest` 漂移、supply-chain
风险、configHash ≠ 代码内容、isolated runtime、negative test matrix）变成
可验证的产品能力：

```text
Artifact Identity
        +
Signed Build Evidence
        +
Runtime Evidence
        +
Trust Policy
        ↓
    ALLOW / DENY
```

### 1.1 冻结的架构原则（v0.5 全程）

```text
Artifact ≠ Trust Policy
Artifact Identity ≠ Runtime Compatibility
Signature VALID ≠ Least Privilege
configHash ≠ Code Identity
Lock ≠ Trust
```

这些原则决定本阶段的一切取舍：Evidence 只描述 Artifact，不代替 Policy 做决定。

### 1.2 本轮范围（v0.5.0-alpha.1：Evidence Foundation）

**只实现 Evidence Foundation**，不修改已发布的 v0.4.2：

- 新增独立 **Signed Evidence Envelope**（`src/evidence/`）
- 所有 Evidence 必须以 immutable DSH `contentHash` 为 subject
- Evidence 不进入 artifact `contentHash`，不修改现有 Artifact Signature anchor
- Evidence 通过 canonical statement digest + Ed25519 签名认证
- 冻结 D64–D67
- 增加 tamper / subject substitution / wrong signer / stale evidence 负例测试

## 2. 优先级：先解决"Evidence 本身是否可信"

现状（v0.4.2）：

```text
contentHash      — artifact 完整性 anchor（已签名覆盖）
Signature        — ed25519 签名 contentHash anchor
Provenance       — 未签名的构建元数据（仅展示）
```

问题：如果后续 `trust.yaml` 要依据 provenance / SBOM / runtime matrix 做决策，
这些 Evidence 必须**不可被随意篡改**——否则 Policy 是在消费不可信输入。
因此第一阶段不碰 SBOM UI / trust.yaml v2，先统一证据的"防伪封装"。

关键区分（冻结）：

```text
Artifact signature  → 证明 artifact 没变（v0.3 既有）
Evidence signature  → 证明关于 artifact 的这份证据没变（v0.5 新增）
```

两者不混：Evidence 是独立对象，通过 subject 指向 Artifact，而不是塞进
Artifact 内部。

## 3. Signed Evidence Envelope（冻结，D64–D67）

### 3.1 Schema（冻结）

Evidence 是独立 sidecar 文件 `<name>.dshpack.evidence.json`，自包含可验证：

```json
{
  "schemaVersion": 1,
  "type": "build-provenance",
  "subject": {
    "contentHash": "sha256:<64 hex>"
  },
  "statement": { "……": "证据载荷，envelope 对其 opaque" },
  "statementDigest": "sha256:<64 hex>",
  "signing": {
    "algorithm": "ed25519",
    "keyId": "<sha256 of public key DER>",
    "publicKey": "<PEM SPKI — 自包含验证>",
    "signature": "<base64 ed25519>",
    "createdAt": "<ISO 8601>"
  }
}
```

- `subject.contentHash`：必须形如 `sha256:<64 hex>`（D64），且由服务层
  **重算** artifact anchor 填入，绝不接受调用方声明值。
- `statement`：envelope 对载荷 opaque，只做 canonical 哈希。
- `statementDigest`：`sha256:` + `canonicalJson(statement)` 的 hex（D66）。
- `signing.publicKey` 嵌入 envelope 使其自包含；`keyId` 必须是该 public key
  DER 的 sha256（防 keyId/publicKey 拼接伪造）。

### 3.2 签名对象（冻结，v0.5 Protocol Hardening 后）

签名只覆盖 **domain-separated canonical 对象**，**不覆盖 raw envelope JSON**：

```json
{
  "domain": "dsh-pack:evidence:v1",
  "schemaVersion": 1,
  "type": "build-provenance",
  "subject": {
    "contentHash": "sha256:..."
  },
  "statementDigest": {
    "algorithm": "sha256",
    "value": "..."
  }
}
```

即 `canonicalJson({ domain, schemaVersion, type, subject: { contentHash },
statementDigest: { algorithm, value } })`（复用 DESIGN.md §7.2 的 canonical
规则，全仓库唯一的哈希输入序列化）。

**Domain separation（冻结）**：`domain = "dsh-pack:evidence:v1"` 是证据协议的
固定域标签。同一把 Ed25519 key 未来可能签名不同协议对象（Artifact Signature /
Evidence / Runtime Attestation / OCI Attestation）——每个协议必须有独立 domain，
签名才互不可重放。v0.3 Artifact Signature 签裸 contentHash 字符串；Evidence
Signature 签这个带 domain 的 canonical 对象；二者永不混淆，non-domain 签名
一律 FAIL。

由此得到三重绑定：

| 攻击/漂移                     | 签名三元组变化 | 结果 |
| ---------------------------- | ------------- | ---- |
| statement 字段被改            | 否（digest 重算不符） | FAIL（digest mismatch） |
| subject.contentHash 被替换    | 是            | FAIL（签名不匹配） |
| type 被改写                   | 是            | FAIL（签名不匹配） |
| signature 字节被翻转          | —             | FAIL（验签失败） |

### 3.3 内部架构（冻结）

```text
src/evidence/
  envelope.ts   — 纯函数：signEvidence / verifyEvidenceEnvelope /
                  verifyEvidenceSubject / verifyEvidenceSigner /
                  evidenceSigningInput / statementDigestOf
                  （EVIDENCE_DOMAIN = "dsh-pack:evidence:v1"）
  service.ts    — DefaultEvidenceService：对 .dshpack 重算 contentHash 作
                  subject（D64），写入 Evidence Collection，verify
                  --against / --key-id
```

**Evidence Collection（冻结，Protocol Hardening）**——同一 contentHash 可绑定
**N 份独立 Evidence，同一种 Evidence 也允许 N 份**，任何新证据都不覆盖旧证据：

```text
<name>.dshpack.evidence/
  <type>/                         # build-provenance / sbom / runtime-attestation/...
    <statementDigest hex>.json    # 内容唯一 ⇒ 文件名唯一
```

statementDigest-hex 文件名使碰撞不可能：同一 statement → 同一文件（幂等
re-sign）；不同 statement → 新文件；`sign` 对已存在且内容不同的文件
**拒绝覆盖**（报错）。SBOM 永远不可能覆盖 provenance。

- **验证三问**（envelope.ts 的回答，不是 Policy 的回答）：
  1. 这份 evidence 是否完好？（statement→digest 绑定 + 签名）——D66
  2. 它是否指向这个 artifact？（subject binding）——D64
  3. 签它的人是不是策略预期的人？（keyId 匹配）——D67 前置
- **verifiedKeyId（冻结，Protocol Hardening）**：验证时 keyId **永远从内嵌
  verification public key 重算**（`sha256(SPKI DER)`）并与声明 keyId 比对，
  不匹配即 FAIL。verify 返回的 keyId 即 verifiedKeyId——Trust Policy 只能消费
  verifiedKeyId，绝不消费 claimedKeyId。
- **VALID ≠ TRUSTED**：envelope 验证通过只证明"证据真实完整"；签名者是否可
  信由后续 trust.yaml v2 的 keyId 白名单决定（沿用 v0.3 语义）。

### 3.4 冻结决策（D64–D67）

| # | 决策 |
|---|------|
| D64 | Evidence 必须明确绑定 immutable `contentHash`：`subject.contentHash` 只能是 `sha256:<64 hex>`，由服务层从 artifact 重算，不接受声明值 |
| D65 | Evidence 与 Artifact **分离**：Evidence 是独立 sidecar 对象，不进入 artifact `contentHash`，不改现有 Artifact Signature anchor；`.dshpack` 字节永不因签名证据而变化 |
| D66 | Evidence 自身必须**可验证签名**：签名覆盖 domain-separated canonical 对象 `{domain, schemaVersion, type, subject.contentHash, statementDigest}`，statement 通过 canonical digest 锚定，publicKey 自包含且 keyId=DER hash（重算比对，verifiedKeyId） |
| D67 | Trust Policy **只能消费已验证 Evidence**：policy 入口必须经过 envelope 验证（完好 + subject 绑定 + signer 匹配）；未验证的 evidence 不得进入决策（本轮实现验证原语，policy 消费在 trust.yaml v2 阶段接入） |

### 3.5 Protocol Hardening 冻结（v0.5.0-alpha.1 补强）

| # | 决策 |
|---|------|
| H1 | **Domain separation**：evidence signing input 携带固定 `domain = "dsh-pack:evidence:v1"` + `schemaVersion`；同一 key 签其他协议对象（Artifact Signature / Runtime Attestation / OCI Attestation）必须用各自独立 domain，non-domain 签名一律 FAIL |
| H2 | **verifiedKeyId**：验证时 keyId 永远从内嵌 verification public key 重算并与声明值比对，不匹配即 FAIL；verify/Policy 只消费 verifiedKeyId，绝不消费 claimedKeyId（防 `trustedKeys` 白名单被 envelope 自声明 keyId 绕过） |
| H3 | **Evidence Collection**：同一 contentHash 可绑定 N 份独立 Evidence、同一种 Evidence 也允许 N 份；文件按 `<type>/<statementDigest hex>.json` 布局，statement 唯一 ⇒ 文件名唯一；已存在且内容不同的文件拒绝覆盖；SBOM/Attestation 永远不可能覆盖 provenance |

### 3.6 命令面（冻结）

```text
/pack evidence sign <file.dshpack> --type <type> --statement-file <statement.json>
    --key <private.pem> [--signer <name>] [--out <dir>]
    → <name>.dshpack.evidence/<type>/<statementDigest hex>.json
      （Evidence Collection，subject = 重算 contentHash；同 statement 幂等，
        不同内容拒绝覆盖）

/pack evidence verify <evidence.json> [--against <file.dshpack>] [--key-id <sha256hex>]
    → ✓ VERIFIED / ✗ FAILED + 有序错误列表
```

`--against` 触发 D64 subject 绑定检查（重算 artifact anchor 对比）；
`--key-id` 触发 D67 前置 signer 检查（verifiedKeyId 比对）。

### 3.7 验收判据（冻结，负例矩阵）

| 场景 | 预期 |
| ---- | ---- |
| 正例：sign → verify --against + --key-id | PASS |
| statement 被篡改（如 gitCommit 改写） | statementDigest mismatch FAIL |
| signature 字节翻转 | 验签 FAIL |
| subject.contentHash 被替换 | 签名不匹配 FAIL |
| 证据签给 A，用 B 的 keyId 期望 | keyId mismatch（VALID ≠ TRUSTED）DENY |
| keyId 与内嵌 publicKey 不一致（伪造） | FAIL（keyId/publicKey 一致性，verifiedKeyId） |
| 同一 key 的非 domain 签名冒充 Evidence（跨协议重放，H1） | 验签 FAIL（domain separation） |
| artifact 重建后 contentHash 变化，旧证据 --against | subject binding FAIL（stale evidence） |
| 同一 artifact 签证据前/后 | artifact contentHash 与 v0.3 签名均不变（D65） |
| 同 statement 重复 sign（H3） | 幂等：同一文件，不覆盖 |
| 不同 statement / 不同类型 sign（H3） | 各自新文件共存（SBOM 不覆盖 provenance） |
| 已存在 evidence 被改动后重 sign（H3） | 拒绝覆盖（refusing to overwrite） |
| 非 JSON evidence 文件 | 明确错误（not valid JSON） |

**North-Star 断言（本阶段必须成立）：**

```text
contentHash 一样
+
Evidence 被篡改
→ DENY
```

## 4. 后续阶段路线（冻结：分阶段独立 PR）

以下为 v0.5 全程规划，**每个阶段独立 feature 分支 + PR**，不合并巨型分支：

| 版本 | 内容 |
| ---- | ---- |
| v0.5.0-alpha.1（已冻结） | Evidence Foundation：Signed Evidence Envelope、D64–D67、负例矩阵 + **Protocol Hardening**（H1 domain separation / H2 verifiedKeyId / H3 Evidence Collection） |
| v0.5.0-alpha.2（本阶段） | **Build Provenance v2**（D68–D72 冻结，§6）：构建时采集 / Git source identity / materials digests / dependency closure / environment matrix + **D72 origin 语义**（build-time attestation vs post-build endorsement） |
| v0.5.0-alpha.3（本阶段） | **SBOM Evidence**（D73–D80 冻结，§7）：CycloneDX 1.7 JSON canonical；只消费 artifact closure（禁扫当前机器）；独立文档 + signed envelope；deterministic；UNKNOWN 语义 |
| v0.5.0-alpha.4（本阶段） | **Declared Capability Manifest**（D81–D88 冻结，§8）：纯 artifact inspection，只声明"能做什么"；Observed 归 beta.1 |
| v0.5.0-beta.1 | Isolated Runtime Attestation（cold boot / effects / cleanup / rollback）+ **Observed Capability**（declared vs observed 对比） |
| v0.5.0-beta.2 | trust.yaml v2（requireEvidence / runtime matrix / capability policy） |
| v0.5.0-rc.1 | 供应链负例矩阵（cache / latest / prepare / native / tampering / dependency re-resolution / cross-platform） |
| v0.5.0 | OCI Evidence Distribution（provenance/sbom/attestation 作为 subject 指向 artifact 的独立对象） |

### 4.1 阶段决策索引

- D64–D67 + H1–H3：Evidence Foundation + Protocol Hardening（§3，已冻结）
- D68–D72：Build Provenance v2 + D72 origin 语义（§6，已冻结，v0.5.0-alpha.2）
- D73–D80：SBOM Evidence（§7，已冻结，v0.5.0-alpha.3）
- D81–D88：Declared Capability Manifest（§8，已冻结，v0.5.0-alpha.4）
- 后续阶段决策（Runtime Attestation / trust.yaml v2）：阶段开始前另行冻结

## 5. 范围外（本轮不做）

- Observed Capability / network-filesystem-process effects（beta.1 Runtime Attestation）
- trust.yaml v2（requireEvidence / runtime / capabilities / allow-deny）（beta.2）
- OCI Referrers / Evidence 挂载（v0.5.0 收尾）
- vulnerability scanning / CVE lookup / license policy / capability policy / runtime permissions（明确不做，§7.7/§8.6）
- SPDX exporter / CycloneDX 2.0（future）
- 修改 v0.4.2 任何已冻结行为（sign / verify / trust-policy / image 语义不变）

## 6. Build Provenance v2（冻结，D68–D71，v0.5.0-alpha.2）

### 6.1 核心原则（冻结）

> **Build Provenance 不是"给已经生成的 artifact 补一些环境信息"，而是
> "记录这个 artifact 当时到底是怎么被构建出来的"。**

```text
Build starts
    ↓
Capture Build Inputs（构建现场：git / profile / patch / lockfile / closure / 版本 / OS）
    ↓
Build artifact
    ↓
Calculate contentHash
    ↓
Create BuildRecord —— subject = contentHash（构建完成后再绑定）
    ↓
Write build receipt（<name>.dshpack.build-receipt.json，sidecar）
    ↓
（可选）Sign as build-provenance Evidence（D64 subject 绑定 + D66 签名）
```

**禁止事后推测**：`/pack evidence provenance` 只能消费 `/pack` 当时留下的
build receipt，绝不重新读当前 Git HEAD 伪造历史现场；receipt 的 subject 必须
等于 artifact 实际重算的 contentHash，被替换/篡改的 receipt 直接拒绝。

### 6.2 BuildRecord schema（冻结）

```json
{
  "schemaVersion": 1,
  "subject": { "contentHash": "sha256:..." },
  "source": {
    "repository": "https://github.com/company/app.git",
    "gitCommit": "<完整 40/64 位 SHA>",
    "dirty": false
  },
  "materials": {
    "profileManifestDigest": "sha256:...",
    "bundlePatchDigests": ["sha256:..."],
    "sourceLockfileDigest": "sha256:...",
    "artifactLockfileDigest": "sha256:...",
    "dependencyClosureDigest": "sha256:..."
  },
  "environment": {
    "dshPack": "0.5.0-alpha.2",
    "dsh": "0.1.0-rc.5",
    "node": "24.6.0",
    "pnpm": "10.15.0",
    "os": "linux",
    "arch": "x64"
  },
  "capture": {
    "mode": "build-time"
  },
  "createdAt": "2026-08-30T00:00:00Z"
}
```

- `source.gitCommit`：完整 SHA（非短 hash）；非 git 构建现场不虚构 source
  （`gitCommit` 缺省，不伪造）。
- `source.dirty=true` 时必须存在 `sourceTreeDigest`（对 dirty 条目做 canonical
  inventory digest）——commit 已不能唯一描述实际输入，不许只写 commit。
- `materials.dependencyClosureDigest`：`sha256(canonicalJson(closure))`；
  registry 条目带 name/version/resolved/integrity；`file:`/`link:` 依赖带
  **contentDigest**（路径没变、内容变了，digest 必须变）。

### 6.3 冻结决策（D68–D71）

| # | 决策 |
|---|------|
| D68 | Provenance source 必须在 `/pack` 构建现场采集：完整 Git commit SHA；dirty 默认 FAIL（除非显式 `--allow-dirty`，且必须记录 `sourceTreeDigest`）；不允许事后根据当前 Git HEAD 推测构建输入 |
| D69 | Materials 分别计算 identity：profile manifest、bundle patch、**source lockfile 与 artifact/staged lockfile 分开**（v0.2 portable 会 rewrite）、canonical dependency closure；`file:`/`link:` 依赖必须含内容 digest |
| D70 | `configHash` 永远不能替代 source/code/dependency identity：configHash→runtime composition 语义、sourceTreeDigest→code source、lockfileDigest→dependency 输入、contentHash→artifact identity；Profile 配置不变 + 代码变 ⇒ configHash 可相同但 contentHash/provenance 必变 |
| D71 | DSH/dsh-pack/Node/pnpm/OS/arch 只作为**构建环境 Evidence**，不声明运行兼容性（运行兼容是未来 Runtime Attestation 的职责，两个不同 Evidence） |
| D72 | **Build-time Attestation 与 Post-build Endorsement 分离**：`/pack --evidence-key` 在构建现场基于当时采集的 BuildRecord 与最终实际 contentHash **立即签名** → `capture.mode=build-time`（Build-time Provenance Attestation）；事后 `/pack evidence provenance` 消费未签名 receipt → **只能** `capture.mode=post-build-receipt`（Post-build Provenance Endorsement），不得声称密码学证明构建瞬间现场；build receipt 或其 digest **不进入 artifact contentHash**（Artifact Identity 与 Evidence 保持分离） |

### 6.4 命令面（冻结）

```text
/pack <profile> --provenance --evidence-key <private.pem> [--allow-dirty] [--signer <name>]
    → <name>.dshpack                       （artifact）
    → <name>.dshpack.build-receipt.json    （build receipt，总是写入）
    → <name>.dshpack.evidence/build-provenance/<digest>.json（构建时签名，可选）

/pack evidence provenance <file.dshpack> --key <private.pem> [--allow-dirty] [--signer <name>]
    → 只消费 build receipt：校验 schema + subject == 实际 contentHash；
      dirty 默认 FAIL，--allow-dirty 用记录的 sourceTreeDigest；绝不读当前 HEAD
```

**D72 语义（冻结）**：前者 = **Build-time Provenance Attestation**
（`capture.mode=build-time`，签名在构建瞬间完成，密码学证明构建现场）；
后者 = **Post-build Provenance Endorsement**（`capture.mode=post-build-receipt`，
未签名 receipt 事后可能被修改，只证明签名者背书 artifact，不构成构建瞬间证明）。
`trust.yaml v2` 可要求 `provenance.origin: build-time`，生产策略拒绝
post-build endorsement。

### 6.5 验收判据（冻结，P0–P12）

| # | 场景 | 预期 |
|---|------|------|
| P0 | clean repo pack | provenance PASS（receipt 写入 + 可签名） |
| P1 | subject.contentHash | == 实际 artifact 重算值（非声明值） |
| P2 | git commit | 完整 SHA |
| P3 | dirty repo | 默认 FAIL（evidence-key 时） |
| P4 | --allow-dirty | dirty=true + sourceTreeDigest，签名成功 |
| P5 | pack 后再切换 git commit | provenance 仍记录构建时 commit（不读当前 HEAD） |
| P6 | 修改 lockfile | sourceLockfileDigest / closureDigest 改变 |
| P7 | file:/link: 内容改变 | dependencyClosureDigest 改变（路径不变也变） |
| P8 | configHash 相同、代码不同 | contentHash / provenance 不同（D70） |
| P9 | 修改 provenance statement | Evidence signature FAIL |
| P10 | Artifact A 的 provenance 替换 subject 为 B | 签名 FAIL（端到端 subject substitution） |
| P11 | pack 后修改 unsigned receipt（gitCommit/material） | post-build provenance 允许生成，但 origin 必须 `post-build-receipt`，绝不显示 `build-time`（D72） |
| P12 | `/pack --evidence-key` 构建时签名后再修改 receipt | 原 build-time attestation 仍 VALID、subject 正确、statement 不变（不受后续 receipt 修改影响，D72） |

## 7. SBOM Evidence（冻结，D73–D80，v0.5.0-alpha.3）

### 7.1 关键选择（冻结）：CycloneDX 1.7 JSON 为唯一 canonical SBOM format

```text
format      = CycloneDX
specVersion = 1.7
mediaType   = application/vnd.cyclonedx+json
```

- CycloneDX 1.7 是当前稳定版本；**不追 CycloneDX 2.0**（2026-08 公布路线、
  秋季才发布，未稳定）。
- SPDX 3.0 也能支持 SBOM，但 alpha.3 **不做双输出**（SPDX export 与
  CycloneDX 2.0 列为 future）。

### 7.2 数据来源边界（冻结，D74）：SBOM 描述 Artifact，不是"当前机器"

**禁止**：扫描当前 node_modules、扫描当前 Git workspace、重新 pnpm resolve。

**只消费**已经属于 artifact identity / build receipt 的材料：

```text
.dshpack
   ↓
artifact/staged lockfile（profile/pnpm-lock.yaml：packages map 的
                          resolution.integrity / tarball）
vendored packages（packages/*.tgz 内 package.json）
embedded package metadata（profile/package.json、resolved/dependency-tree.json
                          的 closure / localDeps / direct）
dependency closure
   ↓
SBOM
```

**dependency edges（D73/D74）**：根组件 → direct deps（来自
`resolved/dependency-tree.json`）；vendored 组件 → 其 artifact 内
`package.json` 声明的 deps（ref 可解析时才输出，不做重新 resolve）。
Components 回答"有哪些包"，dependencies 回答"谁依赖谁"。

> 否则会重蹈 provenance 的问题：T0 构建 artifact → T1 workspace 变化 →
> T2 生成 SBOM 描述的是 T2，而不是 artifact。

### 7.3 目录布局（冻结）：SBOM 文档与 Signed Evidence Envelope 分离

```text
agent.dshpack.evidence/
├── build-provenance/
│   └── <statementDigest>.json
├── sbom/
│   └── <statementDigest>.json        ← Signed Evidence（证明"这份 SBOM 属于 artifact A"）
└── documents/
    └── <sbomDigest>.cdx.json         ← CycloneDX 1.7 文档（标准工具直接消费）
```

**不要把完整 CycloneDX 文档内嵌进 Evidence statement**（几千行 JSON），否则
dependency / license / vulnerability scanner 与 SBOM viewer 消费起来都很别扭。
Document 给标准工具，Envelope 证明归属。

### 7.4 冻结决策（D73–D80）

| # | 决策 |
|---|------|
| D73 | SBOM 使用标准格式，**不自创 BOM Schema**：CycloneDX 1.7 JSON（format/specVersion/mediaType 三要素），PURL 作为标准软件包身份 |
| D74 | SBOM 必须描述 Artifact 而非"当前机器"：只消费 artifact/staged lockfile、vendored packages、embedded package metadata、dependency closure；**禁止**扫描当前 node_modules / Git workspace / 重新 resolve |
| D75 | SBOM 自身必须有**独立 identity**：`sbomDigest`（deterministic canonical bytes）≠ artifact `contentHash`（A≠B 正常）；Signed Evidence Envelope `subject.contentHash=A`，statement 携带 format/specVersion/mediaType/sbomDigest=B，由 `dsh-pack:evidence:v1` 签名 |
| D76 | Dependency Identity 按来源区别：registry → name/version/**PURL**/resolved/integrity（closure 已采集不丢弃）；file:/link:/vendored → name/version/sourceType/**contentDigest**（properties: `dsh-pack:source-type` / `dsh-pack:content-digest`）；**绝对机器路径禁止进入 SBOM**（防环境泄漏 + 保 reproducibility） |
| D77 | npm lifecycle scripts 成为**显式供应链事实**：识别 preinstall/install/postinstall/prepare/prepublish/prepack/postpack；记录 existence + scriptDigest（`dsh-pack:npm-lifecycle:<name>` = `sha256:...`）；**不写 script 原文**（防绝对路径 / 凭据插值 / 私有 registry URL 泄漏） |
| D78 | Native 只记录 **Indicator** 不推出结论：检测 binding.gyp / gypfile / node-gyp / prebuild / prebuildify / node-pre-gyp / os / cpu / optionalDependencies 中 native package；`nativeIndicator {detected, reasons}`；**不声明** runtime compatible/incompatible（兼容性留给 beta.1 Runtime Attestation） |
| D79 | **不知道就是 UNKNOWN，禁止猜**：license 未声明 → UNKNOWN（不按 repo 外观猜、不联网补全）；resolved / lifecycle / native 元数据不可得 → unknown |
| D80 | SBOM 必须 **deterministic**：相同 .dshpack → byte-for-byte identical + sbomDigest identical；components/dependencies/properties/hashes 全排序；UTF-8 canonical JSON；**无 random serialNumber、无当前时间戳** |

### 7.5 命令面（冻结）

```text
/pack evidence sbom <file.dshpack> --key <private.pem> [--signer <name>] [--out <dir>]
    → documents/<sbomDigest>.cdx.json（CycloneDX 1.7 文档，deterministic）
    → sbom/<statementDigest>.json（Signed Evidence，subject = 重算 contentHash）

验证复用统一入口：
/pack evidence verify <sbom-envelope.json> --against <file.dshpack> [--key-id <sha256hex>]
```

不新增 `/pack sbom inspect | diff | audit`（留后续）。

### 7.6 验收判据（冻结，S0–S13）

| # | 场景 | 预期 |
|---|------|------|
| S0 | 相同 artifact 生成两次 SBOM | byte identical + sbomDigest identical |
| S1 | subject.contentHash | == 实际 artifact 重算值 |
| S2 | registry dependency | name/version/purl/resolved/integrity 正确 |
| S3 | file:/link:/vendored dependency | contentDigest 存在 |
| S4 | local dep 路径不变、内容改变 | contentDigest / SBOM digest 改变 |
| S5 | license 已声明 / 未声明 | 正确记录 / UNKNOWN |
| S6 | prepare/install/postinstall 存在 | lifecycle indicator 存在 |
| S7 | native package | native indicator 存在，**不产生 compatibility 结论** |
| S8 | 篡改 .cdx.json | sbomDigest mismatch → Evidence FAIL |
| S9 | Artifact A 的 SBOM 挂到 Artifact B | subject verification FAIL |
| S10 | artifact 构建后修改当前 node_modules/workspace | 对 artifact 重新生成 SBOM **不变**（只消费 artifact） |
| S11 | SBOM 不出现绝对机器路径 | 无 `/home/...`、`C:\...` |
| S12 | build-provenance + sbom | 同一 evidence collection 共存、不覆盖 |
| S13 | configHash 相同、dependency/code 不同 | SBOM/contentHash 不同 |

### 7.7 明确不做（scope guard）

```text
❌ vulnerability scanning / CVE lookup / license policy
❌ capability policy / runtime permissions
❌ trust.yaml v2 / OCI referrers
❌ SPDX exporter / CycloneDX 2.0
```

SBOM 只回答：**"这个 artifact 里面/依赖了什么？"**
不回答："它安全吗？它能运行吗？我应该信任吗？"（后续层职责）

## 8. Declared Capability Manifest（冻结，D81–D88，v0.5.0-alpha.4）

### 8.1 静态来源调研结论（冻结）

> alpha.4 只回答 **"artifact 声明要向 DSH 暴露什么能力"**，不回答"运行时实际
> 做了什么"。**纯 artifact inspection，无 cold boot**——绝不为生成 declared
> manifest 而执行插件代码（static evidence 一旦变成 runtime observation，边界就混了）。

对 deepseek-harness profile schema（app-boot `profile.ts`）的调研结论：

- `DshProfileManifest` 只有 `bundles?: string[]`——**没有** tools/skills/services/
  providers 静态声明字段。
- **providers / services 可静态发现**：composition / patch 行
  （`insert: [{ id, provider, config }]`）就是静态声明；行 id 即稳定 capability
  id（非显示名）；`provider` 字段区分 provider 类。
- **tools / skills 只能运行时注册**（插件代码 `ctx.commands.register` / tool
  registration）→ 静态不可发现 → 记录 UNKNOWN + reason（C10），不执行代码、
  不按名称猜。
- **来源追溯**（D85）：id 命中 `profile/cordis.patch.yml` 的 insert 行 →
  `declaredBy.layer = profile:cordis.patch.yml`；其余行只能归属 bundle layer
  （bundle patch 文本不在 artifact 内，per-bundle 归属如实 UNKNOWN，D86）。

### 8.2 Schema（冻结）

```json
{
  "schemaVersion": 1,
  "subject": {
    "contentHash": "sha256:..."
  },
  "declared": {
    "providers": [
      { "id": "llm-deepseek", "kind": "provider", "declaredBy": { "layer": "profile:cordis.patch.yml" } }
    ],
    "services": [],
    "tools": [],
    "skills": []
  },
  "undiscoverable": {
    "tools": { "reason": "requires runtime registration (no cold boot, D86)" },
    "skills": { "reason": "requires runtime registration (no cold boot, D86)" }
  }
}
```

- 每个 capability：稳定 `id`（行 id）+ `kind`（provider | service）+ `declaredBy`
- 空集合是**事实**（C5），`undiscoverable` 是**原因**（C10）——两者都不猜

### 8.3 冻结决策（D81–D88）

| # | 决策 |
|---|------|
| D81 | Capability Manifest **独立于 SBOM**（SBOM=软件构成，Capability=Agent/runtime surface，两个证据域；不塞进 CycloneDX properties） |
| D82 | subject **绑定实际 artifact contentHash**；不绑 configHash / tag / profile name / package version |
| D83 | **Declared 与 Observed 永久分离**：alpha.4 只生成 `declared`，禁止出现 `observed`（防止污染 beta.1 Runtime Attestation 边界） |
| D84 | capability 用**稳定结构化 identity**：id/kind/source；显示名可变，identity 不靠 UI 文案 |
| D85 | **来源可追溯**：declaredBy 至少记录 source layer / registration path；静态不可得的 per-bundle 归属如实 UNKNOWN |
| D86 | 静态无法证明的能力 = **UNKNOWN**：不按名称/代码语义猜（tool 名叫 fetch ≠ network=true）；不执行 runtime code 来发现 |
| D87 | Manifest **只描述能力集合，不做权限判断**：无 safe/unsafe/allowed/denied/least-privilege（留给 trust.yaml v2） |
| D88 | **deterministic**：同 artifact → byte-identical；排序覆盖 kind/id/declaredBy 等全部 key |

### 8.4 命令面（冻结）

```text
/pack evidence capability <file.dshpack> --key <private.pem> [--signer <name>] [--out <dir>]
    → documents/<capabilityDigest>.capability.json（declared manifest 文档）
    → capability/<statementDigest>.json（Signed Evidence，subject = 重算 contentHash）

验证复用统一入口：/pack evidence verify <capability-envelope.json> --against <file.dshpack>
```

### 8.5 验收判据（冻结，C0–C10）

| # | 场景 | 预期 |
|---|------|------|
| C0 | 同一 artifact 生成两次 | byte identical + digest identical |
| C1 | subject.contentHash | == 实际 artifact 重算值 |
| C2 | 明确声明 provider/service 行 | manifest 出现稳定 id（非显示名） |
| C3 | provider/service 分类正确 | kind 正确（按行 `provider` 字段） |
| C4 | 同名 capability 不同 source | 不错误合并（各自 declaredBy 保留） |
| C5 | artifact 无 capability 声明 | 空集合（不猜） |
| C6 | 修改当前 workspace | 已有 artifact manifest 不变（只消费 artifact） |
| C7 | 篡改 capability document | digest mismatch → Evidence FAIL |
| C8 | Artifact A capability evidence 挂到 B | subject FAIL |
| C9 | SBOM + provenance + capability | evidence collection 三者共存、不覆盖 |
| C10 | 静态不可发现（tools/skills） | UNKNOWN + reason，不执行 runtime code |

### 8.6 明确不做（scope guard）

```text
❌ observed capability / network-filesystem-process effects（beta.1）
❌ allow/deny / safe / least-privilege 判断（beta.2 trust.yaml v2）
❌ cold boot / 执行插件代码发现能力
❌ 从能力名称推断权限（tool 名叫 fetch ≠ network=true）
```

---

*本文档 v0.5.0 设计阶段定稿（2026-08-30）。本阶段冻结 D64–D88（+ H1–H3）；
v0.4.2 的 D41–D63 不受影响。实现顺序：DESIGN 冻结（本文）→ `src/evidence/`
模块（envelope / service / build-record / sbom / capability）→ pack 构建时采集
→ CLI 接线 → P0–P12 + S0–S13 + C0–C10 负例测试 → typecheck + vitest 全绿 →
CHANGELOG。*
