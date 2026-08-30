#!/usr/bin/env bash
# dsh-pack Quick Start Demo —— 可复现 Happy Path（pack → inspect → verify →
# sign → image import → tag → prune；可选 push/lock 需 registry 环境变量）。
#
# 本脚本驱动 REAL /pack 命令路径（makeHandler → parseCommand → runCommand），
# 与 README / CI 共用同一流程 —— 演示能跑 = 文档命令能跑。
#
# 用法：
#   bash demo/quickstart.sh
#
# 可选环境变量（不设置则跳过对应步骤）：
#   DEMO_REMOTE_REF        e.g. ghcr.io/<owner>/demo-agent:v1（触发 push + lock）
#   DSH_REGISTRY_USERNAME / DSH_REGISTRY_TOKEN    registry 认证（push/lock 需要）
#
# 注意：所有密钥/token 仅通过环境变量注入，脚本不包含真实 secret。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== dsh-pack Quick Start Demo =="

# 1. 前置检查
command -v node >/dev/null 2>&1 || { echo "✗ node 未安装"; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo "✗ pnpm 未安装（pack 需要 pnpm 生成 lockfile）"; exit 1; }
[ -f "$ROOT/lib/index.js" ] || { echo "✗ lib/ 未构建，先执行：cd $ROOT && pnpm build"; exit 1; }

# 2. 运行可复现 Happy Path（node 脚本驱动真实命令路径）
echo "== 运行 demo/quickstart.mjs =="
cd "$ROOT"
node demo/quickstart.mjs

echo ""
echo "✔ Quick Start Demo finished (exit $?)"
