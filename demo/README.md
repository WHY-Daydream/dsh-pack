# Quick Start Demo

可复现的 dsh-pack Happy Path 演示 —— **与 README 命令、CI 完全同一流程**。

## 运行

```bash
bash demo/quickstart.sh
```

前提：

- `node` ≥ 22
- `pnpm`（pack 需要它生成 lockfile）
- `lib/` 已构建（`pnpm build` 一次即可）

## 覆盖的流程

```text
DSH Profile
  ↓ /pack --portable
.dshpack
  ↓ /inspect
artifact summary
  ↓ /verify
integrity baseline
  ↓ /keygen + /sign
Trusted Artifact（ed25519）
  ↓ /verify
Signature VALID + Trust VERIFIED
  ↓ image import
Agent Image（Local Image Store）
  ↓ image ls / inspect / tag
named + versioned image
  ↓ image prune（dry-run）
mark-and-sweep GC
  ↓（可选）push + lock
OCI Registry + immutable digest
```

## 可选：真实 push + lock

脚本默认只跑本地链路（不碰网络）。要触发真实 OCI push + lock：

```bash
DEMO_REMOTE_REF=ghcr.io/<owner>/demo-agent:v1 \
DSH_REGISTRY_USERNAME=<your-user> \
DSH_REGISTRY_TOKEN=<your-token> \
bash demo/quickstart.sh
```

## 安全说明

- 脚本**不含真实 secret**：API key 用 `DEMO_API_KEY` 环境变量占位；registry 凭据从
  `DSH_REGISTRY_USERNAME` / `DSH_REGISTRY_TOKEN` 读取。
- demo key 是临时生成的 ed25519 测试密钥（临时目录，运行结束即清理），不是真实签名密钥。
