# dsh-pack Design

> **dsh-pack — Portable, reproducible and safe DSH profiles.**
>
> `.dshpack` 保存的不是"几个配置文件"，而是一个 **Verifiable DSH Profile Runtime Snapshot**
> （可验证的 DSH Profile 运行时快照）。注意中间有 **Profile**：快照承诺的对象是
> **Portable Profile Scope**（bundles + profile patch），不是包含 machine-local 层的完整 Runtime——
> home 层与 `--patch` 属于 **Machine / Invocation State**，可迁移时被排除（§4.2）。
> 这一条是本文档的顶层原则：后续所有技术选择（哈希算法、包含范围、依赖策略、安全边界）都从这里推导。

- 状态：**v0.1 定稿**（2026-08-28，已并入 Conditional Review：BLOCKER D3/D7 + MUST-1~5 + D15）
- 关联仓库：`@why-daydream/dsh-pack`（本设计对应独立插件仓库，与 `dsh-chaos` 同构）
- 依赖的 DSH 官方机制（均已核实）：
  - Profile 组合层序：`apps/cli/src/profile-boot.ts`（bundles 按 `dsh.profile.bundles` 序 → profile `cordis.patch.yml` → `$DSH_HOME/cordis.patch.yml` → `--patch`）
  - Human Command：`ctx.commands.register()`，UI 直派、不经 LLM（`packages/interaction/commands/src/index.ts`）
  - 组合树获取：`dsh --profile <name> --dump-config`，底层 `@deepseek-ai/dsh-app-boot` 的 `loadProfile` / `loadOptionalPatches` / `composeEntries`
  - Bundle 声明：`package.json` 的 `dsh.bundle.patch` 字段；CLI 按已安装状态 reconcile（`apps/cli/src/plugin.ts`）

---

## 1. Motivation

DSH 里 **Profile 才是真正可启动的组合**：它维护有序的 bundles、树外插件依赖和自己的 `cordis.patch.yml`。一个人把 DSH 调好（装 8 个插件、配一堆参数、写模型/Sandbox 配置）之后，这个"工作状态"目前无法整体迁移——官方 `pnpm pack` + `dsh plugin add` 只解决单插件分发，不解决"整个可运行环境"的复制、校验与复现。

dsh-pack 填补的正是这个空缺：**把一个可运行的 DSH Profile 打成可迁移、可复现、可校验的 `.dshpack`，在另一台机器上一步恢复**，并保证恢复后的配置与打包时一致（以 configHash 为判据）。

目标用户场景：

```text
DSH A  (已调好: 8 个 bundle + 自定义 patch + 模型配置)
        │  /pack web
        ▼
web-20260828.dshpack
        │  /pack install  (另一台机器, DSH_HOME=/tmp/new-dsh)
        ▼
DSH B  →  dsh --profile web  直接启动
```

设计原则（与 DSH 官方能力边界划清）：

- **不做**单插件打包（`pnpm pack` / `dsh plugin add` 已覆盖）。
- **不做**注册表/云/UI（长期 Non-Goal）。
- **只用 Human Command**，不暴露 LLM Tool——打包是"用户明确要求的控制操作"，不该消耗 LLM turn。
- **复用官方组合引擎**，不自己发明配置合并。

---

## 2. Goals & Non-Goals

### 2.1 v0.1 Goals

| # | 目标 | 验收标准 |
|---|------|---------|
| G1 | 读取 Profile | 能定位并解析 `$DSH_HOME/profiles/<name>/` 的 `package.json`、`cordis.patch.yml`、`cordis.yml` |
| G2 | 解析 bundles + dependencies | 产出有序 bundle 列表与依赖闭包（来源：profile `package.json` + `pnpm-lock.yaml`） |
| G3 | Secret Scan / Redact | 扫描组合树，敏感值 redact 为 `${VAR}`，生成 `env/.env.example`，记录告警 |
| G4 | 生成 manifest + effective config | 产出 `manifest.json`、`resolved/cordis.effective.yml`、`resolved/layers.json`、`resolved/dependency-tree.json` |
| G5 | Pack / Inspect / Verify / Install | 四个命令可用；Install 后 `dsh --profile <name> --dump-config` 与打包机 configHash 一致 |
| G6 | 确定性 | 相同 Profile + 相同版本 → 相同 configHash（`createdAt` 不影响 configHash） |

### 2.2 v0.1 Non-Goals（明确不做）

| 项 | 说明 | 排期 |
|----|------|------|
| `--portable`（file:/link: 依赖 vendoring） | v0.1 只检测 + 告警，不打包本地依赖源码 | v0.2 |
| `/pack diff` | 两个包的配置漂移对比 | v0.2 |
| 签名 / 加密 | 包内容签名、secrets 加密 | v0.3 |
| Registry / Cloud / UI | 长期不做 | — |
| node_modules、会话/工作区数据、日志 | 永不打包（见 §6.4） | 永不 |
| `!!js` 求值 | 快照与 dump 一样不执行任何代码（安全 + 确定性） | 永不 |

---

## 3. DSHPack Format

### 3.1 容器

- `.dshpack` = **tar.gz**：tar 条目 + zlib gzip。
- **确定性规则**（冻结，见 §7.2）：条目按路径字典序排列；mtime=0；uid/gid=0；mode 规范化为 0644/0755；gzip 头部 mtime=0（Node zlib gzip 默认即 0）。
- 禁止条目：`.DS_Store`、`node_modules/**`、空目录（可省略）。

### 3.2 文件布局（v1）

```text
web-20260828.dshpack
│
├── manifest.json              MUST    包的核心：Runtime Snapshot 的元数据与哈希锚
│
├── profile/                   MUST
│   ├── package.json           MUST    含 dependencies + dsh.profile.bundles（可打包组合）
│   ├── cordis.patch.yml       MUST    用户层 patch（若为空文件也保留）
│   └── cordis.yml             MUST    空根 entry list（固定内容，install 时重建）
│
├── resolved/                  MUST
│   ├── cordis.effective.yml   MUST    组合树：bundles + profile patch（见 §4.4）
│   ├── layers.json            MUST    有序 layer 清单（含被排除层的行数）
│   └── dependency-tree.json   MUST    依赖闭包（lockfile 解析结果）
│
├── env/
│   └── .env.example           MUST（有 redact 时）；否则可选
│
├── metadata/
│   ├── checksums.json         MUST    逐文件 sha256 + contentHash
│   └── warnings.json          MUST    告警清单（可为空数组）
│
└── README.md                  MUST    人类可读的包说明（自动生成）
```

`packages/` 目录（tgz vendoring）为 **v0.2 portable 预留**：v0.1 包中不存在，manifest 不引用。

### 3.3 manifest.json（schema v1）

```json
{
  "format": "dshpack",
  "schemaVersion": 1,
  "profile": { "name": "web" },
  "snapshot": { "scope": "profile", "excludedLayersPresent": true },
  "runtime": {
    "dshVersion": "0.1.0-rc.5",
    "nodeVersion": "24.6.0",
    "pnpmVersion": "10.15.0",
    "platform": "linux-x64"
  },
  "installable": true,
  "portable": true,
  "bundles": [
    "@deepseek-ai/dsh-base",
    "@deepseek-ai/dsh-web-app",
    "dsh-tool-bulkhead",
    "dsh-tool-idempotency"
  ],
  "dependencies": {
    "@deepseek-ai/dsh-base": "0.1.0-rc.5",
    "dsh-tool-bulkhead": "0.1.0",
    "dsh-tool-idempotency": "github:WHY-Daydream/dsh-tool-idempotency#abc1234"
  },
  "secrets": { "redacted": 2 },
  "configHash": "sha256:<64 hex>",
  "createdAt": "2026-08-28T00:00:00Z",
  "packager": { "name": "@why-daydream/dsh-pack", "version": "0.1.0" }
}
```

字段规则（冻结）：

| 字段 | 必选 | 语义 |
|------|------|------|
| `format` | ✓ | 固定字符串 `"dshpack"`；不符即拒绝 |
| `schemaVersion` | ✓ | 必须等于 1；**reader 拒绝未知 major，只允许新增可选字段**（minor 兼容） |
| `profile.name` | ✓ | 源 profile 名；install 默认目标名 |
| `runtime.dshVersion` | ✓ | 打包机安装的 dsh **精确版本**（读安装 anchor 的 `package.json`）；install 端默认要求一致（D15） |
| `runtime.nodeVersion` / `runtime.pnpmVersion` | ✓ | 打包机版本（`process.versions.node` / `pnpm --version`，后者失败则 `"unknown"` 并告警） |
| `runtime.platform` | ✓ | `${process.platform}-${process.arch}` |
| `bundles` | ✓ | **有序**，与 reconcile 后的 `dsh.profile.bundles` 一致；包含每个 bundle 的解析版本见 `dependencies` |
| `dependencies` | ✓ | profile `package.json.dependencies` 的完整快照（含非 bundle 依赖），spec 原样保留 |
| `snapshot.scope` | ✓ | 固定 `"profile"`（v0.1 唯一 scope，见 §4.2） |
| `snapshot.excludedLayersPresent` | ✓ | 打包时是否存在被排除的 home/`--patch` 层（诊断信号） |
| `installable` | ✓ | 该包是否可被 `/pack install` 恢复；`--allow-nonportable` 产物为 `false`（D7） |
| `portable` | ✓ | v0.1 light pack 恒为 `true`；非 portable 包为 `false` |
| `secrets.redacted` | — | 被 redact 的字段数（0 时字段可省略） |
| `configHash` | ✓ | §7.3 算法，**可复现锚** |
| `createdAt` | ✓ | ISO 8601 UTC；**不参与 configHash**（只影响包级内容） |
| `packager` | ✓ | 生成包的工具名 + 版本（诊断用） |

### 3.4 兼容规则（schemaVersion 演进）

- major 变化（`schemaVersion=2`）：包格式或字段语义不兼容 → reader 必须拒绝并给出明确错误。
- minor 变化（同 major 内）：只允许**新增可选字段**；所有已有字段的语义不得改变。
- 未来可能的新字段（v0.2/v0.3 预留，不在 v1 定义）：`packages`（tgz 清单，v0.2）、`signature`（v0.3）。

---

## 4. Profile Snapshot Semantics

### 4.1 Layer 顺序（冻结，与官方一致）

Profile 的实际启动配置按以下顺序组合，**后层覆盖前层**：

```text
1. bundle 层     —— dsh.profile.bundles 中每个依赖（声明 dsh.bundle.patch 者），按列表顺序
2. profile 层    —— profiles/<name>/cordis.patch.yml
3. home 层       —— $DSH_HOME/cordis.patch.yml
4. overlay 层    —— 启动时 --patch 传入的临时 patch
```

### 4.2 两层 Snapshot 语义（冻结——Review BLOCKER-1 修改后定稿）

`.dshpack` 的 Snapshot 分两层，**可复现承诺只覆盖第一层**：

```text
DSHPack Snapshot
│
├── Portable Snapshot        ← 可复现承诺（configHash / effective 只含这一层）
│   ├── Bundles
│   └── Profile patch
│
└── Observed Runtime Layers  ← 诊断信息，不承诺恢复
    ├── Home patch           (machine-local)
    └── CLI --patch          (invocation-local)
```

| Layer | 打入包 | 计入 effective/configHash | 处理 |
|-------|:------:|:-------------------------:|------|
| bundle 层 | ✓ | ✓ | 完整收集 patch + 依赖声明 |
| profile 层 | ✓ | ✓ | 原样复制 `cordis.patch.yml` |
| home 层 | ✗ | ✗ | `included: false, reason: "machine-local"`，行数记入 `layers.json` + `warnings.json` 告警 |
| overlay 层 | ✗ | ✗ | `included: false, reason: "invocation-local"`，同上（`--patch` 是瞬态参数） |

理由：

- 官方将 Home 层定义为机器本地用户偏好（`.env`、`.credentials.yaml` 同属 machine-local 状态），直接迁移到另一台机器既不可复现也危险。
- 可复现性要求"install 出来的组合 == 打包时的组合"；home 层打进包会在 B 机产生 A 机没有的配置覆盖。
- 诊断不丢：`layers.json` 完整记录所有观测层（含排除层及行数、原因），"为什么 A 机正常 B 机不正常"的差异会被明确标记为"打包机独有的 machine-local 行"。
- 包级标记：manifest 的 `snapshot.excludedLayersPresent` 如实反映是否存在被排除层。

### 4.3 layers.json（schema v1）

```json
{
  "schemaVersion": 1,
  "layers": [
    { "type": "bundle",  "id": "@deepseek-ai/dsh-base", "included": true,  "rows": 12 },
    { "type": "bundle",  "id": "dsh-tool-bulkhead",     "included": true,  "rows": 1 },
    { "type": "profile", "id": "profile:cordis.patch.yml", "included": true, "rows": 3 },
    { "type": "home",    "id": "home:cordis.patch.yml", "included": false, "reason": "machine-local", "rows": 2 },
    { "type": "cli-overlay", "id": "cli-overlay:0",     "included": false, "reason": "invocation-local", "rows": 1 }
  ]
}
```

- `rows` = 该层 patch 操作数；`included: false` 仅出现在未打入包的层，必须带 `reason`。
- **不使用文件系统绝对路径**（Review 点 8）：层身份用逻辑标识（`bundle:<pkg>` / `profile:cordis.patch.yml` / `home:cordis.patch.yml` / `cli-overlay:<n>`），避免 A/B 机路径不同造成的机器漂移。

### 4.4 effective config（冻结）

- `resolved/cordis.effective.yml` = **Portable Profile Scope**（bundle 层 + profile 层）的合并结果，即 install 后能复现的配置；**不含 home/overlay**。
- 生成方式：**在进程内复用 `@deepseek-ai/dsh-app-boot` 的组合引擎**（`loadProfile` / `loadOptionalPatches` / `composeEntries`），不 shell 出去抓 `--dump-config` 文本。
- 同时产出两份形态：
  - 人类可读 YAML（`cordis.effective.yml`，带每层来源注释，等价于官方 dump 风格）；
  - canonical JSON（仅用于 §7.3 哈希，不落盘为单独文件，由 `config-snapshot` 模块内存持有）。
- **不执行 `!!js`**：与官方 dump 相同，快照永不求值。

### 4.5 profile/ 目录内容（install 的还原输入）

- `package.json`：dependencies（来自 manifest）+ `dsh.profile.bundles`（来自 manifest.bundles）。
- `cordis.patch.yml`：profile 层原样。
- `cordis.yml`：固定空根内容（install 时重建，与官方 `prepareProfile` 行为一致，注释说明"编辑 cordis.patch.yml，不要编辑此文件"）。

---

## 5. Dependency Resolution

### 5.1 事实来源

| 来源 | 用途 | 优先级 |
|------|------|--------|
| profile `package.json.dependencies` | 直接依赖声明（含 spec 原文） | 必须 |
| profile 目录 `pnpm-lock.yaml` | **依赖闭包 + 锁定版本**（事实来源） | 必须（缺失则告警降级，见下） |
| `dsh.profile.bundles`（package.json） | 有序 bundle 层列表 | 必须 |
| 已安装的 `node_modules/<pkg>/package.json` | bundle 解析版本补充（lockfile 缺失时） | 兜底 |

- profile 本质是 pnpm workspace：v0.1 **要求** `pnpm-lock.yaml` 存在；缺失时只记录 package.json 声明并打 `unverified closure` 告警，install 端因无锁版本而**降级为"不可验证"**（verify 报告该项为 warning）。
- 不重新 resolve 版本：锁定版本一律来自 lockfile（可复现性要求）。
- **MUST-1（v0.1 内，不推到 v0.2）**：install 必须执行 `pnpm install --frozen-lockfile`——任何 lock 与 package.json 不一致 → **FAIL**，绝不静默升级（防 `^1.2.0` 在恢复时解析出 1.2.4 破坏可复现性）。DSH 官方 CI 亦采用 immutable/frozen 安装。

### 5.2 spec 类型与 v0.1 策略（冻结）

| spec 类型 | 示例 | v0.1 策略 |
|-----------|------|-----------|
| npm registry | `^0.1.0` / `0.1.0` | 原样记录进 manifest.dependencies；闭包版本取 lockfile |
| github | `github:owner/repo#sha` | 原样记录（含 #sha 锚点）；未锚定分支 → **告警**（floating branch 不可复现；`--strict` 下失败） |
| tarball（本地相对路径 `.tgz`） | `file:../dist/x.tgz` | vendor 拷贝进包 `packages/`，**staged spec 重写为 `file:./packages/<name>.tgz`**（MUST-2，见 §8.4）；configHash 不受重写影响（身份基于 name+内容哈希，非路径） |
| file:（目录） | `file:../dsh-bulkhead` | **默认 FAIL**（BLOCKER-2，见下）；`--allow-nonportable` 显式放行 → 生成 `installable:false` 包 |
| link: | `link:../dsh-bulkhead` | 同上，默认 FAIL / `--allow-nonportable` 放行 |

- **D7 默认行为（Review BLOCKER-2 修改后定稿）**：`file:`/`link:` **目录**依赖 = 非 portable → `/pack` **默认失败**（退出码 1），绝不默认产出一个"能打包但不能安装"的包：

```text
Non-portable dependency detected:
  dsh-foo -> link:../../dsh-foo
v0.1 cannot create an installable snapshot containing directory dependencies.
Use --allow-nonportable, or wait for v0.2 --portable.
```

- `--allow-nonportable` 显式放行：产物 manifest 必须带 `"installable": false, "portable": false`；`/pack install` 对 `installable:false` 的包**默认直接拒绝**（退出码 1），强制用户显式认知这是降级产物。
- `--strict` 预检失败条件（任一即 abort，退出码 3）：floating git 分支、lockfile 缺失、`dsh.bundle` manifest 非法、schema 校验失败、检测到 secret 但 `--allow-secrets` 未开（见 §6.3）。

### 5.3 dependency-tree.json（schema v1）

```json
{
  "schemaVersion": 1,
  "lockfile": "pnpm-lock.yaml (lockfileVersion 9.0)",
  "direct": { "dsh-tool-bulkhead": "0.1.0", "@deepseek-ai/dsh-base": "0.1.0-rc.5" },
  "closure": { "@deepseek-ai/dsh-base": "0.1.0-rc.5", "undici": "7.0.0", "...": "..." },
  "localDeps": [
    { "name": "dsh-tool-local", "spec": "file:../dsh-tool-local", "resolved": "/home/user/projects/dsh-tool-local", "portable": false }
  ],
  "warnings": []
}
```

`closure` = 全部直接 + 传递依赖（lockfile importers → packages 全量），按名称排序。`localDeps` 列出所有 file:/link: 依赖及其打包机路径（**仅存路径用于诊断，不打包内容**；层身份与 configHash 均不依赖该路径）。

---

## 6. Security Model

### 6.1 扫描目标（冻结）

扫描对象是 **§4.4 的组合树（最终生效值）**，不是单个 patch 文件——secret 可能来自任意 layer（bundle patch、profile patch、甚至未来 home 层）。`config-snapshot` 产物是唯一扫描输入。

### 6.2 检测规则

| 类别 | 规则 | 示例 |
|------|------|------|
| 键名启发式 | key 匹配 `apiKey|token|secret|password|passwd|authorization|cookie|privateKey|accessKey|credential`（不区分大小写） | `config.apiKey` |
| 值启发式 | 值匹配 `sk-`、`ghp_`、`xoxb-`、`AKIA[0-9A-Z]{16}`、超长 base64/hex、`eyJ...`（JWT） | `sk-123456` |
| 环境变量名 | key 匹配 `DEEPSEEK_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|AWS_*|AZURE_*` | `DEEPSEEK_API_KEY` |
| 引用型 | 值形如 `${VAR}` 且 VAR 在已知敏感名单内 | `apiKey: ${DEEPSEEK_API_KEY}` |

阈值：**不误伤**优先于**不漏检**——只对"高置信"命中 redact；低置信命中只进 `warnings.json`（`suspected` 列表），不 redact。

### 6.3 Redaction（冻结）

- 命中值替换为 `${VAR}` 占位：`apiKey: sk-123456` → `apiKey: ${DEEPSEEK_API_KEY}`。
- 生成 `env/.env.example`：每个被 redact 的变量一行（`VAR=` 空值），注释标注**来源 layer 与字段路径**，如 `# dsh-tool-x/cordis.patch.yml → config.apiKey`。
- `metadata/warnings.json` 记录 `{ field, layer, var }` 明细。
- **install 永不恢复 secret**：install 只落 `${VAR}` 占位 + `.env.example`，由用户自行注入环境变量（见 §8.4）。`.dshpack` 内禁止出现真实 secret。
- `--strict` 下：任何高置信 secret 命中 → pack 中止（除非显式 `--allow-secrets`，该选项会同时向 stdout 打印醒目警告）。

### 6.4 永不打包清单

`node_modules/**`、会话/工作区数据（`ctx.sessions` 等）、日志、真实的 `.env`、DSH credentials store 内容（`packages/credentials`）、`$DSH_HOME/cordis.patch.yml`（home 层，§4.2）、`--patch` 临时文件、`.git/**`、`.DS_Store`、任何二进制产物（v0.1 无 `packages/`）。

---

## 7. Reproducibility & Integrity

### 7.1 两个哈希的分工（冻结）

| 哈希 | 定义 | 角色 |
|------|------|------|
| `configHash` | Portable Profile Scope 的规范化哈希（公式见 §7.3） | **可复现锚（Portable Profile Configuration Hash）**：同 Profile 同版本 → 跨机器/跨时间恒等。`createdAt`、home/`--patch`、绝对路径、mtime 一律不参与 |
| `contentHash` | 包内全部文件的路径+字节哈希（§7.4） | **完整性锚**：单包内校验，verify 用。只表示 artifact integrity，**不承诺跨创建时间的 byte-identical archive** |

原则：**configHash 承诺"可移植配置等价"，contentHash 承诺"文件完好"**——不要把时间戳塞进复现锚。
CLARIFY（Review 点）：确定性声明严格写作——

```text
Deterministic serialization:                YES
Byte-identical archive across build times:  NOT guaranteed in v0.1
```

（`manifest.createdAt` 与 README 日期会随打包时间变化，两个不同时刻的 `.dshpack` 允许字节不同；`sha256sum a.dshpack b.dshpack` 不同是预期行为。）

### 7.2 Canonicalization 规则（冻结）

- JSON：键按字典序排序、无尾随空白、`JSON.stringify` 稳定序列化（2 空格缩进落盘；哈希用紧凑序列化）。
- YAML：解析后重排（键排序、标量规范化）；**落盘的 effective.yml 为人类可读形式，哈希用的 canonical JSON 由组合树对象直接派生**，两者不互为转换来源（避免 YAML 解析器差异破坏哈希）。
- 包内容：archive 条目按路径字典序；mtime=0；uid/gid=0；mode 0644/0755；gzip 头部 mtime=0。
- 不引入任何构建期时间戳进 configHash 输入。

### 7.3 configHash 算法（冻结——Review BLOCKER-1 修改后定稿）

**命名**：这是 **Portable Profile Configuration Hash**（可移植 Profile 配置哈希），不是"当前 Runtime 的 Effective Config Hash"。

```
configHash = "sha256:" + hex(
  SHA256(
    "dshpack-config-v1\0"
    + canonical(profileComposition)   // bundles + profile patch（Portable Profile Scope）
    + "\0"
    + canonical(bundleIdentities)     // [ {name, version}, ... ] 有序, 与 dsh.profile.bundles 一致
    + "\0"
    + canonical(dependencyClosure)    // { name: lockedVersion, ... } 全量闭包, 键排序
  )
)
```

- `profileComposition`：§4.4 的组合树对象（bundles + profile 层，**不含 home/overlay**）。
- `bundleIdentities[].version`：来自 lockfile（兜底：已安装包 `package.json`）。
- `dependencyClosure`：§5.3 的 dependency-tree.json 中 `closure` 对象；**身份基于 name + resolved version/commit + integrity（内容哈希）**，不使用机器路径。
- **不参与**：home patch、`--patch`、`createdAt`、archive metadata、绝对路径、机器名、DSH_HOME 路径、mtime、secret 值。
- **vendor 重写不变性**：tarball spec 从 `file:../foo.tgz` 重写为 `file:./packages/foo.tgz` 后，逻辑 configHash **不得变化**（闭包身份按 name + 内容哈希，而非 spec 原文路径）。

### 7.4 checksums.json（schema v1）

```json
{
  "schemaVersion": 1,
  "contentHash": "sha256:<hex>",
  "files": {
    "manifest.json": "sha256:<hex>",
    "profile/package.json": "sha256:<hex>",
    "resolved/cordis.effective.yml": "sha256:<hex>",
    "...": "sha256:<hex>"
  }
}
```

`contentHash` = `sha256( 排序后的 "path:fileSha256" 逐行拼接 )`。

- **自引用处理（Review 点，方案 B）**：`files` 映射**不含 `checksums.json` 自身**；verify 时从其余成员重算全部文件哈希并与 `files` 逐项比对，再重算 `contentHash` 比对——checksums.json 由其他文件确定性派生，无需自校验。

### 7.5 verify 规则（冻结）

| 检查项 | 规则 | 失败级别 |
|--------|------|---------|
| Manifest | `format`/`schemaVersion` 合法、必需字段齐全、类型正确 | FAIL |
| Config | 从包内 `profile/` + `resolved/` 重算 configHash == manifest.configHash | FAIL |
| Packages | v0.1 无 `packages/` 时 trivially OK；有则校验 tgz checksum | FAIL |
| Checksums | 逐文件 sha256 == checksums.json；contentHash 一致 | FAIL |
| DSH Version | manifest.runtime.dshVersion 与安装的 dsh **精确匹配**（v0.1 不做 `^0.x` semver 范围，DSH 仍为 Developer Preview，可能 breaking） | FAIL（install 默认拒绝；`--ignore-runtime-version` 显式放行） |
| Redaction | `secrets.redacted` 与 warnings.json 记录一致；包内无高置信 secret 残留 | FAIL |

verify 输出分节：`Manifest / Config / Packages / Checksums / DSH Version`，全部 OK → 退出码 0；任一 FAIL → 非零（退出码 2）；WARN 不影响退出码。

### 7.6 Deterministic Pack 声明

同一 Profile + 同一版本集，任意时间/机器打包：`configHash` 恒等；`contentHash` 在 `createdAt`/README 日期相同的条件下恒等。文档与 README 中的日期不承诺确定性。

---

## 8. Commands & Lifecycle

### 8.1 命令面（v0.1，全部为 Human Command，无 LLM Tool）

| 命令 | 作用 | 关键参数 |
|------|------|---------|
| `/pack [name]` | 打包当前 Profile（省略 name 时取当前活跃 profile） | `--strict`、`--out <dir>`、`--allow-secrets`、`--allow-nonportable` |
| `/pack inspect <file>` | 查看包内容摘要 | `--json` |
| `/pack verify <file>` | 校验完整性（§7.5） | `--json` |
| `/pack install <file>` | 恢复到 `$DSH_HOME/profiles/<name>` | `--profile <name>`、`--force` |
| `/pack diff <a> <b>` | 两包配置漂移对比（v0.2 已实现：4 域 + configHash 判定） | `--json` |
| `/pack <name> --portable` | 连本地 `file:`/`link:` 依赖一起 vendoring 打包（v0.2 已实现） | `--out <dir>` 等同上 |

命令名 `pack` 满足官方注册约束（`^[a-z][a-z0-9_-]*$`）。v0.2 追加：`/pack <name> --portable`（**已实现，2026-08-29**）、`/pack diff <a> <b>`（**已实现，2026-08-29**）。

### 8.2 输出约定

- 默认人类可读：`✓`（成功项）/ `⚠`（告警）/ `✗`（失败）逐行 + 末尾摘要块（与提案 demo 风格一致）。
- `--json`：stdout 输出单个 JSON 文档（inspect / verify 可用），供脚本消费。
- 退出码：`0` 成功；`1` 运行/用户错误（如 profile 不存在）；`2` 校验失败（verify）；`3` `--strict` 预检中止。

### 8.3 /pack 行为（冻结）

1. 定位 Profile：`$DSH_HOME/profiles/<name>`（`$DSH_HOME` 解析复用 `@deepseek-ai/dsh-home-paths`）。
2. **Preflight**（`--strict` 下任一失败即中止，退出码 3；BLOCKER-2 项默认即失败，退出码 1）：
   - Profile 存在；`package.json` 合法；`dsh.profile.bundles` 可解析；每个 bundle 的 `dsh.bundle.patch` 指向真实可解析文件；
   - `pnpm-lock.yaml` 存在；
   - **`file:`/`link:` 目录依赖 → 默认 FAIL**（D7），除非显式 `--allow-nonportable`（此时产物 `installable:false`）；
   - 无 floating git 分支（`--strict`）；
   - 组合树通过 Schemastery schema 校验（复用 DSH 插件配置校验）；
   - Secret 扫描无高置信命中（或显式 `--allow-secrets`）。
3. 收集：bundles（有序）、dependencies、lockfile 闭包、profile patch、组合树。
4. Secret Scan / Redact → `env/.env.example` + `metadata/warnings.json`。
5. 生成 `manifest.json`（含 configHash）→ 组装全部条目 → 确定性 tar.gz。
6. 产物：`<out>/<name>-<YYYYMMDD>.dshpack`（默认当前目录）。
7. 摘要输出，如：

```text
Analyzing profile "web"...
✓ 9 bundles
✓ 14 dependencies
✓ effective config generated
⚠ 2 home-layer rows excluded
✓ 2 secrets redacted
✓ configuration validated
Created: web-20260828.dshpack
```

### 8.4 /pack install 行为（冻结——Review MUST-1/2/3/4 修改后定稿）

**install 管线（原子性，MUST-3）**：

```text
verify archive → verify manifest → verify checksums → verify schema
  → extract 到 staging（防 traversal / symlink，MUST-4）
  → 物化 profile 文件
  → pnpm install --frozen-lockfile（MUST-1）
  → bundle reconcile
  → validate profile
  → atomic swap（旧目录不动，直到全部成功）
```

1. **入口校验**：manifest 合法 + verify（§7.5）通过；`installable === false` 的包**默认直接拒绝**（退出码 1，提示"该包含非 portable 依赖，属于降级产物"）；`runtime.dshVersion` 与安装的 dsh **精确匹配**，不一致 → FAIL（除非 `--ignore-runtime-version`，D15）。
2. 目标 profile 名：`--profile` 覆盖，否则取 `manifest.profile.name`。
3. 已存在同名 profile → fail loud（退出码 1），除非 `--force`。
4. **Staging（MUST-3）**：解包到 `$DSH_HOME/profiles/.dsh-pack-staging-<UUID>/`，全部成功后才 swap；失败时旧 profile **完全不动**。`--force` 的替换流程：`old → backup → staging → final`，最后删 backup；中途任何一步失败即回滚。
5. **Archive 提取安全（MUST-4）**：
   - 每个条目路径 `normalize` 后**必须仍位于 staging root 之下**，否则 FAIL（防 `../../.ssh/authorized_keys` 逃逸）；
   - **v0.1 禁止 symlink / hardlink / device / FIFO 条目**（发现即 FAIL）；内部 `packages/*.tgz` 交给 pnpm 自行处理。
6. 物化（写入 staging 内的 `profiles/<name>/`）：
   - `package.json`（dependencies + `dsh.profile.bundles`）；
   - `cordis.patch.yml`（原样）；
   - `cordis.yml`（固定空根）；
   - `.env.example`（来自包内 env/，**只提示不应用**）；
   - `.dshpack/` 收据目录：`manifest.json` + `resolved/`（快照参照，供日后 diff/排障；工具拥有，不参与启动）。
7. 依赖落地：
   - npm/github spec → 原样写入 package.json，由 pnpm 解析；
   - **tarball vendor（MUST-2）**：包内 `packages/<name>.tgz` → 复制到 profile 目录 `vendor/`，**staged spec 重写**为 `file:vendor/<name>.tgz`（pack 时已把原 `file:../x.tgz` 规范化为 `file:./packages/x.tgz`，install 端再落到 `file:vendor/...`，保证 B 机不指向不存在的位置）；
   - `file:`/`link:` **目录**依赖（仅 `--allow-nonportable` 包可能出现）→ **fail loud**（installable:false 已在上游拒绝）。
8. **pnpm install --frozen-lockfile（MUST-1）**：在 profile 目录 spawn，非零退出即 FAIL（含 lock 不一致）；绝不静默升级。
9. **Bundle reconcile**：复用官方 `apps/cli/src/plugin.ts` 的算法——按已安装状态把声明 `dsh.bundle` 的依赖收敛进层栈，写回 `dsh.profile.bundles`。
10. 输出：`✓ profile "web" restored` + 下一步提示（`dsh --profile web`）。

**E2E 验收判据**（本设计的北极星，Review 修改后定稿）——两部分：

1. **可移植哈希判据**：pack 侧 Portable configHash == install 后重算的 Portable configHash（不受 A 机 home 层干扰）。
2. **Clean-room 判据**：在**无 excluded machine-local 层干扰的干净环境**中，`DSH_HOME=/tmp/A-clean` pack → `DSH_HOME=/tmp/B-clean` install → `dsh --profile web --dump-config` 重算哈希与包内 manifest.configHash 相同。

---

## Appendix A. Packager Service API（`ctx.packager`，Service Seam）

模块以 `ctx.packager` 暴露为 **Service Seam**（冻结接口，v0.1 仅实现 in-process 后端），第三方可基于同一接口做 `dsh-pack-s3` / `dsh-pack-github` / `dsh-pack-sign` / `dsh-pack-encrypt` / `dsh-pack-ui`。

```ts
// src/service.ts —— 冻结 v0.1 接口
export interface PackagerService {
  pack(opts: PackOptions): Promise<PackResult>
  inspect(file: string): Promise<PackInspection>
  verify(file: string): Promise<VerificationReport>
  install(file: string, opts: InstallOptions): Promise<InstallResult>
}

export interface PackOptions {
  profile: string              // $DSH_HOME/profiles/<profile>
  strict?: boolean             // preflight 任一失败即中止（退出码 3）
  outDir?: string              // 默认 cwd
  allowSecrets?: boolean       // 默认 false
  allowNonportable?: boolean   // 默认 false：file:/link: 目录依赖放行 → installable:false（D7）
  portable?: boolean           // v0.2 预留
}

export interface InstallOptions {
  profile?: string             // 覆盖 manifest.profile.name
  force?: boolean              // 覆盖已存在的同名 profile（staging + atomic swap）
  ignoreRuntimeVersion?: boolean // 默认 false：跳过 dshVersion 精确匹配（D15）
}
```

模块映射（实现时按此拆分，用户已确认无需重新做架构设计）：

```text
src/index.ts              apply(ctx): 注册命令 + ctx.packager 装配
src/commands.ts           /pack 子命令解析、参数校验、输出渲染（✓/⚠/✗、--json）
src/service.ts            ctx.packager 接口（上）
src/profile-reader.ts     §4  §5  Profile 定位与解析（package.json / cordis.patch.yml / lockfile）
src/config-snapshot.ts    §4.4 组合树（复用 dsh-app-boot）→ effective.yml + layers.json + canonical JSON
src/dependency-resolver.ts §5  lockfile 闭包 / spec 分类 / localDeps 检测
src/secret-scanner.ts     §6  组合树扫描 → redact + .env.example + warnings
src/manifest.ts           §3.3 manifest.json 生成 / 读取 / schema 校验
src/pack-builder.ts       §3  确定性 tar.gz 组装（排序、mtime=0、checksums）
src/verify.ts             §7.5 verify 管线
src/install.ts            §8.4 物化 + pnpm install + bundle reconcile
src/inspect.ts            §8.3/8.4 摘要渲染
tests/                    单元 + E2E（vitest）
```

依赖选择：`@deepseek-ai/dsh-app-boot`（组合引擎）、`@deepseek-ai/dsh-home-paths`（`$DSH_HOME` 解析）、`@deepseek-ai/schemastery`（schema 校验）、`@deepseek-ai/cordis`（context/commands）、`yaml`（解析）、`tar`（确定性归档）、Node `zlib`/`crypto`（gzip/sha256）。

---

## Appendix B. Roadmap

| 版本 | 内容 |
|------|------|
| **v0.1** | light pack（pack / inspect / verify / install）、secret redaction、configHash、确定性归档、frozen-lockfile install、原子 staging 安装、archive 提取安全。**2026-08-29 封版**（Review 无 blocker + North-Star E2E PASS，见 Appendix D） |
| **v0.2** | `--portable`（**已实现 2026-08-29**：`src/portable.ts` 本地依赖图 DFS 闭包（含 cycle 检测）→ `pnpm pack` 式确定性 tgz vendoring（`package/` 前缀 + mtime=0）→ 传递 spec 重写（`file:/link:` → `file:vendor/<tgz>`）→ lockfile 目录形态→tarball 形态重写（importer + `packages:` 键 + `snapshots:` 值，覆盖声明形式与 pnpm 项目相对形式）；manifest 新增可选 `packages` 字段（§3.4 minor 扩展）；verify Packages 分节支持 vendored tgz；North-Star E2E：pack --portable → 干净 home frozen install → install 侧 configHash == manifest 一致）。`/pack diff`（**已实现 2026-08-29**：Manifest/Bundles/Config/Dependencies 4 域 + configHash 判定，`src/diff.ts` + `tests/diff.spec.ts`） |
| **v0.3** | 包签名（ed25519）、secrets 加密支持、对接 DSH credentials 注入、`dsh pull/run` Agent Image 实验（Profile → .dshpack → Agent Runtime 的 OCI 类似物） |
| 长期 | Registry / Cloud / UI（明确不做） |

---

## Appendix C. 冻结决策清单（review 重点）

| # | 决策 | 章节 | 一句话 |
|---|------|------|--------|
| D1 | 包容器 = 确定性 tar.gz（排序/mtime=0/gzip mtime=0） | §3.1, §7.2 | 同输入同字节（不含跨创建时间的 byte-identical 承诺） |
| D2 | `schemaVersion=1`，reader 拒绝未知 major、只加可选字段 | §3.3, §3.4 | 前向兼容规则写死 |
| D3 | **两层 Snapshot 语义**：Portable Snapshot（bundles+profile patch）= 可复现承诺；Home/`--patch` 排除但记录（`excludedLayersPresent` 标记） | §4.2, §4.3 | 复现承诺限定到 Portable Profile Scope（BLOCKER-1 后定稿） |
| D4 | effective config = Portable Profile Scope（bundles + profile patch） | §4.4 | install 后能复现的组合才是快照对象 |
| D5 | 组合树复用 `dsh-app-boot`，进程内组合，不 shell 抓 dump | §4.4 | 不发明合并算法、不执行 `!!js` |
| D6 | 依赖事实来源 = `pnpm-lock.yaml`；不重新 resolve | §5.1 | 锁定版本才可复现 |
| D7 | **`file:`/`link:` 目录依赖默认 FAIL**；`--allow-nonportable` 放行 → `installable:false` 且 install 默认拒绝；tarball vendor + spec 重写 | §5.2, §8.4 | fail loud + 显式 opt-in 降级产物（BLOCKER-2 后定稿） |
| D8 | Secret 扫描对象 = **组合树**，不是单个 patch | §6.1 | 防"从 bundle 层漏进来的 secret" |
| D9 | Redact 为 `${VAR}` + `.env.example`；**install 永不恢复 secret** | §6.3, §8.4 | `.dshpack` 内禁止真实 secret |
| D10 | `configHash` = "dshpack-config-v1" 公式（§7.3），`createdAt`/路径/mtime 不参与；contentHash 只表完整性 | §7.1, §7.3, §7.4 | 复现锚 vs 完整性锚分离（含自引用处理） |
| D11 | verify 分节（Manifest/Config/Packages/Checksums/DSH Version），FAIL 级别含 DSH 精确版本匹配 | §7.5 | 失败才非零；版本不一致 = FAIL |
| D12 | 命令面 = `/pack` `/pack inspect` `/pack verify` `/pack install`，纯 Human Command | §8.1 | 不消耗 LLM turn |
| D13 | install = staging + atomic swap + `pnpm install --frozen-lockfile` + 官方 reconcile；同名 profile 默认拒写，`--force` 原子替换 | §8.4 | 破坏性操作 safe-by-default（MUST-1/3 后定稿） |
| D14 | E2E 北极星 = ①可移植哈希判据 + ②clean-room dump-config 判据 | §8.4 | 一票否决的验收判据 |
| D15 | **Runtime 精确版本匹配**：install 时 dshVersion 不一致默认 FAIL，`--ignore-runtime-version` 放行（v0.1 不做 `^0.x` semver 范围） | §7.5, §8.4 | DSH 为 Developer Preview，防 breaking |
| D16 | **Archive 提取安全**：路径归一化必须留在 staging root 内；禁止 symlink/hardlink/device/FIFO 条目 | §8.4 | 防恶意包路径逃逸 |
| D17 | **contentHash 无自引用**：checksums.json 不入 files 映射，verify 重算比对 | §7.4 | 哈希与归档互不依赖 |

---

*本文档 v0.1 定稿（2026-08-28）。已并入 Conditional Review：BLOCKER-1（D3 两层 Snapshot 语义）、BLOCKER-2（D7 默认 fail）、MUST-1（frozen-lockfile）、MUST-2（tarball spec 重写）、MUST-3（原子 staging 安装）、MUST-4（archive 提取安全）、MUST-5/D15（runtime 精确版本）、CLARIFY（contentHash 完整性语义 + 无自引用）。*

## Appendix D. v0.1 代码审查记录（2026-08-29）

按 DESIGN.md 冻结协议对实现做了逐条一致性 + 安全性 review（追踪表见 `TRACEABILITY.md`），发现并修复 3 项：

| # | 级别 | 问题 | 修复落点 |
|---|------|------|---------|
| F1 | MAJOR | `service.ts` 恒写 `portable:true`，违反 §3.3/§5.2（`--allow-nonportable` 产物必须 `installable:false, portable:false`） | `portable: installable` |
| F2 | BLOCKER | **MUST-2 锁文件重写不完整**：`rewriteLockfileForStaging` 只重写 importer `version`，遗漏 `specifier` 与 `packages:` 解析键；且 importer 目标应为 install 端 `file:vendor/<tgz>`（§8.4 物化后的最终 spec），否则 tarball 依赖在 B 机 `pnpm install --frozen-lockfile` 必然失败 | 同时重写 specifier/version/`packages:` 键（含 scoped `/` 前缀变体），目标统一为 `file:vendor/<tgz>` |
| F4 | MINOR(安全) | Secret 定位用 `.` 拼接路径，字段名含 `.`（如 `auth.apiKey`）时 redact 落点错位 → 明文 secret 静默留在包内（违反 D9 承诺） | `SecretHit.segments` 数组精确定位，`walk`/`redactAt`/`redactPatchText` 全链路改走 segments |

补测试：`tests/service.spec.ts`（D7 默认 fail / `--allow-nonportable` → `installable:false`+`portable:false` / tarball 保持 portable；D15 verify 分节 fail + install 拒绝 + `--ignore-runtime-version` 放行）、`tests/dependency-resolver.spec.ts`（MUST-2 packages 键与 scoped 变体重写）、`tests/secret-scanner.spec.ts`（F4 dotted-key 用例）。

**Release Gate（2026-08-29）**：Review 无未关闭 blocker + 38 单测通过 + typecheck 通过 + North-Star E2E 判据①（vitest roundtrip configHash 相等）与判据②（`scripts/clean-room-e2e.mjs`：真实 dsh CLI `--dump-config` 归一化一致 + install 侧 configHash == manifest.configHash）全部 PASS → **v0.1 封版判定成立**（package.json `0.1.0`；仓库尚未 git init，打 tag 待用户操作）。



