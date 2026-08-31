# dsh-pack v0.6.0 Design Spike — Distributed Verifiable Evidence

> 状态：**design spike，非实现**。本文件是 v0.6 的设计输出，不含 production code。
> v0.5.0 已永久冻结（tag `v0.5.0` @ `09f7f27`，npm `@why-daydream/dsh-pack@0.5.0`）。

## 1. 定位与边界

v0.5 建立了**本地** evidence collection 的可信链（Provenance / SBOM / Capability /
Runtime Attestation → Trust Policy v2）。v0.6 把这条链延伸进 OCI Registry：
让四类 Evidence 跟随 Agent Image 被远程**发现、分发、缓存、验证**。

核心不变量（继承 v0.4 / v0.5，D147）：

```text
OCI ManifestDigest M  = OCI distribution identity（registry 层）
DSH contentHash C     = semantic artifact identity（DSH 层）
M ≠ C，永远不合并，任何一层都不允许用相等省略另一层验证
```

Registry 永远只是 **discovery / transport**，不是 trust authority（D141）。
Strong Runtime Isolation（v0.7）、Encryption（v0.8）、Evidence GC/revocation、
新 trust policy features：全部 out of scope。

## 2. Evidence OCI Manifest Schema（D152 载体）

Evidence Object 直接使用**标准 OCI Image Manifest** 作为 carrier（`application/vnd.oci.image.manifest.v1+json`），
不发明任何私有 registry 协议。

### 2.1 结构

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",

  "artifactType": "application/vnd.dsh.evidence.runtime-attestation.v1+json",

  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:<OCI_MANIFEST_M>",
    "size": 1234
  },

  "config": {
    "mediaType": "application/vnd.oci.empty.v1+json",
    "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
    "size": 2
  },

  "layers": [
    {
      "mediaType": "application/vnd.dsh.evidence.envelope.v1+json",
      "digest": "sha256:<signed envelope digest>",
      "size": 5678
    },
    {
      "mediaType": "application/vnd.dsh.evidence.document.v1+json",
      "digest": "sha256:<evidence document digest>",
      "size": 9012
    }
  ]
}
```

### 2.2 字段语义（锚定 OCI 官方规范）

| 字段 | 取值 | 规范依据 |
|------|------|----------|
| `artifactType` | per-type media type（2.3） | image-spec：artifact 用法；`config.mediaType` 为 empty 时 **MUST** 设置；unknown artifactType 不得报错 |
| `subject` | descriptor 指向 Agent Image manifest（`digest = M`） | image-spec：subject = 到另一 manifest 的**弱关联**，供 Referrers API 收录进 subject digest 的响应 |
| `config` | `application/vnd.oci.empty.v1+json`（`{}`，size 2，digest `sha256:44136fa3…`） | image-spec empty descriptor guidance（`DescriptorEmptyJSON`） |
| `layers[0]` | **signed evidence envelope**（v0.5 同格式） | v0.5 evidence envelope 原样复用，不重设计 |
| `layers[1]` | **可选** external evidence document（SBOM 文档 / attestation 文档等） | 与本地 collection 的 `envelope + documents/` 结构对齐 |

### 2.3 Media type proposal（四个独立 artifactType）

```text
application/vnd.dsh.evidence.provenance.v1+json
application/vnd.dsh.evidence.sbom.v1+json
application/vnd.dsh.evidence.capability.v1+json
application/vnd.dsh.evidence.runtime-attestation.v1+json

application/vnd.dsh.evidence.envelope.v1+json   （layer 0，signed envelope）
application/vnd.dsh.evidence.document.v1+json   （layer 1，optional external document）
```

四个独立 `artifactType` 支持 registry 按类型过滤（end-12b `?artifactType=`），
不采用统一 `application/vnd.dsh.evidence.v1`。
信封的 `mediaType`（layer 0）与 document 的 `mediaType`（layer 1）均为描述层，不代表信任。

### 2.4 `artifactType` 只是 discovery hint（D152）

```text
OCI artifactType
        ↓ hint（不可信，可被伪造）
Signed Envelope.type
        ↓ verified fact（唯一信任来源）
```

下载并验证后必须校验 `envelope.type == 期望 evidence 类型`；不一致 → invalid candidate（DENY）。
Registry 返回的 `annotations`（含 `org.opencontainers.*`）同样**不可信**，不参与判定。

### 2.5 双层绑定（D150）

```text
OCI subject.digest = M
        → distribution binding（registry 层：这份 OCI 对象关联到 manifest M）

Envelope statement.subject.contentHash = C
        → semantic binding（DSH 层：证据说的是 artifact C）
```

两层都必须成立，任一失败都不能进入 Policy：
`OCI referrer subject ≠ Evidence subject.contentHash` 不是缺点，而是正确设计
（`subject.digest` 管分发关系，`contentHash` 管语义关系，互不替代）。

## 3. 冻结决策 D149–D156

| Decision | 语义 |
|----------|------|
| **D149** | Remote Evidence discovery 必须锚定 immutable `OciManifestDigest`，不得直接锚定 mutable tag（继承 N1：`tag ≠ identity`） |
| **D150** | OCI `subject = M` 与 DSH Evidence `subject.contentHash = C` 必须同时成立；任一失败都不能进入 Policy |
| **D151** | Native Referrers API preferred；只使用 OCI 1.1 标准 referrers-tag fallback，不发明 DSH 私有 discovery scheme |
| **D152** | `artifactType` 仅为 untrusted discovery hint；实际 Evidence type 必须从 verified envelope 获得 |
| **D153** | Remote candidates 全量收集后复用 D110/D124–D128 ambiguity 语义；Registry 返回顺序永远不是 selector |
| **D154** | Remote Evidence cache 只能缓存 bytes/object identity，不能缓存 `TRUSTED` / `ALLOW` verdict |
| **D155** | Evidence publication 是**附加关系**，不得改变已有 Agent Image 的 `contentHash` 或 OCI manifest M |
| **D156** | Discover / pull / verify Evidence 永远不得 materialize 或执行 Agent/package code |
| **D157** | Remote discovery locator 是 `(registry, repository, OciManifestDigest)`，裸 digest 不是完整远程定位身份；标准 Referrers discovery 与 subject 位于同一 repository namespace |
| **D158** | Referrers API 的所有 `Link rel=next` 页面必须**完整消费**后，才能进行 semantic dedup / ambiguity / policy；partial enumeration ≠ complete Evidence set |
| **D159** | OCI Evidence carrier 必须 **exactly-one** Signed Evidence Envelope；external document 是否存在由 verified Evidence schema 决定，需要时 must exactly-one 且同时通过 OCI descriptor digest/size 与 DSH document digest 校验；禁止 `.find()`/first-layer-wins，重复/歧义 carrier 无效 |

**D151 注释（design review 2026-08-31 精确化）**：
`OCI-Subject` 是 **push-time acknowledgement**——PUT 带 `subject` 的 manifest 时 Registry 处理了该 subject 才必须返回该 header；
它不是 discovery capability probe。Discovery 能力以 `GET /v2/<name>/referrers/<digest>` 的响应决定：
`200` → native Referrers API；`404` → MUST 进入标准 referrers-tag fallback（D151）。

**D152 注释（design review 2026-08-31 精确化）**：
`?artifactType=` 过滤是 Registry 的 **SHOULD**，不是无条件 MUST；只有响应包含
`OCI-Filters-Applied: artifactType` header 才能认为过滤真正生效；无该 header 必须视为**未过滤**
（本地按 artifactType 过滤仅作优化，不作为正确性依据）。`artifactType` 永远只是 hint，
最终 Evidence 类型来自 verified `Envelope.type`。

## 4. 协议流程

### 4.1 Discovery order（先 resolve immutable M，再 discover；read path）

```text
1. resolve tag → OCI ManifestDigest M        （locator = (registry, repository, M)，D157）
2. verify / pull Agent Image M（OCI integrity）
3. recompute DSH contentHash C
4. GET referrers(M)                          [end-12a]
     ├── 200 → image index（?artifactType= 过滤仅在 OCI-Filters-Applied 确认时视为生效 [end-12b]）
     └── 404 → referrers-tag fallback（sha256-<64hex> tag → image index）（D151）
5. follow ALL Link rel=next pages            （D158：pagination 完整消费，partial ≠ complete）
6. referrer descriptors = UNTRUSTED enumeration metadata
     （descriptor 的 digest/size/artifactType/annotations 均不可信，只作为获取依据）
7. fetch candidate manifest by digest        （recompute/verify OCI digest + size）
8. verify manifest.subject.digest == M       （D150：foreign subject 拒绝）
9. fetch layers by descriptor                （verify each OCI descriptor digest/size）
10. verify DSH Evidence（envelope.type / signature / issuer / subject.contentHash==C
      / D159 严格 cardinality：exactly-one envelope，required document exactly-one）
11. merge into existing Evidence Collection semantics（D153：复用 D110/D124–D128）
12. evaluate Trust Policy v2
```

**禁止** `discover evidence for :prod`：tag 会漂移（T0→M1, T1→M2），Evidence 必须
明确属于 M1 还是 M2（D149，天然继承 N1 的 `tag ≠ identity`）。

**禁止**把 referrer descriptor 直接变成 candidate（`referrer list says
artifactType=runtime-attestation → create candidate immediately` ❌）——
必须走 6→10 的硬顺序：fetch manifest → verify digest/size → verify subject=M →
fetch layers → verify descriptors → 才进入 DSH Evidence verification。

### 4.2 Push sequence（Evidence Publication，alpha.2）

```text
1. 生成证据（envelope + optional document），计算各层 blob digest
2. PUT blobs（envelope layer / document layer）          [end-4a/4b + end-6，或 mount end-11]
3. PUT evidence manifest（Content-Type = manifest mediaType）[end-7a]
     ├── 响应含 OCI-Subject: <M> → registry 支持 Referrers API（索引已建立）
     └── 无 OCI-Subject → client 维护 referrers-tag（sha256-<64hex>）：
          拉取 → 校验是合法 image index → 检查重复 descriptor → append
          （artifactType 必须设置，缺省回退 config.mediaType）
          → 有条件推送（conditional HTTP / ETag，防并发覆盖）
4. 发布后 M 与 C 均不变（D155：Evidence attached to artifact，不是 embedded into artifact）
```

registry **MUST** 接受 subject 指向尚不存在的 manifest（允许 manifest 与 referrers
任意顺序推送）——spec 已明确，作为 alpha.2 的互操作断言。

### 4.3 验证链（Remote Evidence 全链，D142）

```text
Agent Image pull（复用 v0.4 链路，锚定 M）
        ↓
OCI integrity          （manifest + blob digest 校验；Content-Type/mediaType 一致性）
        ↓
Evidence envelope integrity（envelope JSON digest）
        ↓
subject.contentHash == C
        ↓
Evidence signature VALID
        ↓
Evidence issuer TRUSTED（trustedKeys / evidenceTrustedKeys）
        ↓
D110/N5 ambiguity handling（复用，D153）
        ↓
Trust Policy v2 → ALLOW / DENY
```

## 5. Registry compatibility matrix（D151）

| Registry 能力 | 行为 | DSH client 处理 |
|---------------|------|------------------|
| Native Referrers API（end-12a/12b + `OCI-Subject`） | PUT subject manifest 返回 `OCI-Subject: <M>`；GET referrers(M) → 200 image index | **preferred**：discovery 直接走 referrers API；`?artifactType=` 过滤（end-12b） |
| 无 Referrers API | PUT 无 `OCI-Subject`；GET referrers → 404 | **fallback**：referrers-tag（`sha256-<64hex>`）维护——拉 index → 校验合法 → 去重 append → 有条件推送（conditional HTTP / ETag） |
| fallback 并发发布 | 多 client 同时更新 tag → race / lost update | spec 明示 race 无法完全避免；最坏 = evidence missing → required missing → **DENY**（availability 损失，绝非 trust 绕过） |
| 只读 / 删除禁用 | DELETE 不支持 | 正确性不依赖删除 |
| Proxy registry | `ns` query / `OCI-Namespace` header | 不跨 host 转发 Authorization（spec 要求） |

## 6. Failure semantics（fail-closed）

| 失败场景 | 语义 | 结果 |
|----------|------|------|
| referrers API 404 + fallback tag 404 / 非合法 image index | 假设无 referrers（spec 要求） | required evidence missing → **DENY** |
| referrers API 400 | registry 拒绝请求 | 同缺失处理 → **DENY**（required） |
| candidate manifest digest 不符 | OCI integrity 失败 | invalid candidate，不进入 Policy |
| envelope digest 不符 / JSON 非法 | envelope integrity 失败 | invalid candidate |
| `subject.contentHash ≠ C` | 语义绑定失败（D150） | **DENY**（foreign subject） |
| `envelope.type` ≠ 期望类型 / 与 artifactType 冲突 | D152 | invalid candidate → **DENY** |
| signature 非法 / issuer untrusted | D110 | UNTRUSTED → **DENY** |
| 多候选语义冲突 | D124–D128 | **AMBIGUOUS → DENY** |
| fallback race 缺一份 evidence | 证据缺失 | required missing → **DENY** |

核心属性：**registry 层任何异常的最坏结果都是 missing → DENY，永远不是错误 ALLOW**。

## 7. Cache model（D154，继承 N1 / D112 / D129）

```text
可缓存：OCI manifest bytes / envelope bytes / document bytes
        （CAS / content-addressable，以 digest 为 key）

不可缓存：issuerTrusted=true / policy=ALLOW / TRUSTED verdict
```

原因：`trustedKeys` / `trust.yaml` / `executionTarget` / `coverage` / `denyObserved`
随时会变，缓存 verdict 复用会产生 stale-trust。**Remote Evidence Cache ≠ Remote
Evidence Trust Cache**——与 N1 的"cache 只存 bytes，不存 decisions"（D112/D129）同一原则。

## 8. Threat model + North-Star

### 8.1 North-Star NS-1/2/3（spike 必须回答，已冻结）

**NS-1 — Remote Evidence follows immutable artifact**

```text
prod → M1，Evidence → M1
prod 后来 → M2
repo@M1 只能发现/验证 M1 的 Evidence；不能跟着 tag 拿到 M2 的 Evidence（D149）
```

**NS-2 — Registry cannot manufacture trust**

```text
Registry 返回攻击者 Evidence：
  subject=M，subject.contentHash=C，signature VALID，issuer UNTRUSTED
→ DENY
Registry discovery ≠ Registry endorsement（D141）
```

**NS-3 — Remote ambiguity remains fail-closed**

```text
Registry 同时返回：
  Trusted Attestation A observed=[]
  Trusted Attestation B observed=[process.exec]
→ AMBIGUOUS → DENY
不受 registry order / push order / manifest digest / createdAt 影响（D153）
```

### 8.2 Adversarial matrix（v0.6 rc.1 攻击面清单）

| 攻击 | 防线 |
|------|------|
| 恶意 enumeration / 伪造 referrers 列表 | referrers 只是候选；全量收集 + D110 验证；registry 数据不可信（D141） |
| missing referrer（删除/漏发布） | required evidence missing → DENY |
| foreign subject（referrer 指向别的 M'） | `OCI subject.digest == M` 校验（D150） |
| wrong contentHash（envelope subject ≠ C） | `subject.contentHash == C` 校验 |
| tampered layer（blob 篡改） | OCI digest 校验 |
| untrusted issuer（伪签） | signature VALID + issuer TRUSTED（D110） |
| conflicting remote attestations | D124–D128 → AMBIGUOUS → DENY |
| tag drift（:prod 指向新 M，证据仍属旧 M） | D149：锚定 immutable M，不锚定 tag |
| cache stale（旧 bytes 复用） | CAS digest 校验；verdict 永不缓存（D154） |
| fallback race（并发丢 referrers 项） | 最坏 missing → DENY（fail-closed） |
| artifactType 伪装（SBOM 标成 attestation） | envelope.type 为准（D152） |
| evidence pull 执行代码 | D156：pull/verify 永不 materialize / 永不 exec |

## 9. v0.6 Roadmap（alpha → beta → rc，每个阶段有明确协议边界）

```text
v0.6.0-alpha.1  Remote Evidence Discovery
─────────────────────────────────────────
GET referrers（end-12a）+ referrers-tag fallback
artifactType filtering（end-12b，hint only）
OCI integrity（manifest/blob digest）
remote → local Evidence Collection merge
D149 / D150 / D152 / D153

v0.6.0-alpha.2  Evidence Publication
─────────────────────────────────────────
push evidence OCI object（blobs → manifest）
subject = M（OCI-Subject 支持探测：响应含 header → 原生索引；否则 fallback 维护）
标准 referrers-tag fallback（去重 append + conditional push）
D151 / D155
（断言：registry MUST 接受 subject 指向尚不存在的 manifest）

v0.6.0-alpha.3  Remote Evidence Cache
─────────────────────────────────────────
CAS / content-addressable 缓存
offline cached discovery
cache ≠ trust（verdict 永不缓存）
D154

v0.6.0-beta.1   Remote Trust Integration
─────────────────────────────────────────
image pull/run → remote evidence discovery → Trust Policy v2
D140–D156 全链
（NS-1/2/3 全绿为 beta.1 出口标准）

v0.6.0-beta.2   Registry Interoperability
─────────────────────────────────────────
GHCR / 本地 mock registry / Referrers API registry / fallback-only registry
ORAS 作为 interop oracle 交叉验证

v0.6.0-rc.1     Adversarial Distribution Matrix
─────────────────────────────────────────
malicious enumeration / missing referrer / foreign subject /
wrong contentHash / tampered layer / untrusted issuer /
conflicting remote attestations / tag drift / cache stale / fallback race
```

### alpha.1 — Remote Evidence Discovery（scope 冻结，design review 已批准）

**只实现（read path）**：

```text
fully-qualified remote image reference
  → resolve mutable tag → immutable M
  → GET referrers(M)（404 → 标准 referrers-tag fallback）
  → follow ALL Link pagination（D158）
  → collect descriptors（untrusted enumeration metadata，D157/D150）
  → fetch manifest by digest（OCI manifest / subject integrity）
  → fetch envelope / document blobs（OCI blob integrity）
  → DSH envelope validation（envelope.type / signature / issuer）
  → subject.contentHash == actual C
  → produce verified remote Evidence candidates
```

**不做**：push Evidence（alpha.2）/ cache（alpha.3）/ Trust Policy 集成（beta.1）/
remote run 集成 / GHCR acceptance / ORAS E2E（beta.2）。

**alpha.1 冻结测试 A1–A10**（★ = North-Star regression）：

| ID | 场景 | 关键决策 |
|----|------|----------|
| A1 | native Referrers API 发现合法 Evidence | D151 |
| A2 | tag 先 resolve 为 M；discovery 永不直接使用 tag | D149 |
| A3 | foreign OCI subject M2 拒绝 | D150 |
| A4 | OCI M 正确但 DSH contentHash C2 错误 → 拒绝 | D150 ★ |
| A5 | artifactType 撒谎，verified Envelope.type 胜出 | D152 |
| A6 | 请求过滤但无 OCI-Filters-Applied → 视为未过滤 | D152 注释 |
| A7 | 多页 referrers → 全部页面收集后才出结果 | D158 ★ |
| A8 | 重复/歧义 envelope layer 拒绝 | D159 |
| A9 | required external document 缺失 / digest 不符 → 拒绝 | D159 ★ |
| A10 | referrers 404 → 标准 tag-schema fallback | D151 |

## 10. 实现原则：ORAS 只是 interop oracle，不是 runtime 依赖

```text
dsh-pack runtime
  → 自己遵循 OCI Distribution protocol（HTTP + digest 校验）

ORAS CLI
  → 仅作为互操作 oracle / E2E fixture（测试期交叉验证 referrers API 与 fallback）

禁止：dsh-pack spawn("oras discover ...")
```

理由：保持与 v0.4 OCI Distribution 相同的工程层级（协议直接实现），
避免把外部 CLI 变成运行时依赖；`oras discover` 在 ORAS 文档中仍标为 preview，
只用于验证我们的 client 行为与生态一致。

## 11. Spike 出口标准（design review 结论：Conditional PASS → 4/4 PASS）

**design review（2026-08-31）结论：**

| Section 11 Exit | 结果 |
|-----------------|------|
| NS-1 / NS-2 / NS-3 无异议 | ✅ PASS |
| D149–D156 无方向性争议 | ✅ PASS（补充 **D157–D159** + D151/D152 精确化注释，均为实现契约级收紧，非新 feature） |
| Schema / protocol 可直接作为编码契约 | ✅ PASS（4 个协议级契约已冻结：**D157** repository-scoped locator / **D158** pagination 完整消费 / **D159** 严格 carrier cardinality / referrer descriptor = untrusted enumeration metadata 硬顺序） |
| Out-of-scope 不扩大 | ✅ PASS（revocation / delete-GC / retention / timestamp authority / transparency log / Sigstore-Rekor / Encryption / sandbox / 新 trust selector 一律不进入 v0.6） |

> **结论：`v0.6.0-alpha.1 Remote Evidence Discovery` = GO。**
> scope 与冻结测试见第 9 节（仅 discovery/read path；pagination 完整性 A7、
> contentHash 绑定 A4、document cardinality A9 为 North-Star regression）。

复核说明：review 前的四条原始出口标准（NS 无异议 / D149–D156 无争议 /
schema 可作契约 / out-of-scope 不扩大）经本轮 docs-only protocol tightening
后**全部满足**；本文件未含任何 production code，v0.5.0 资产未触碰。
