#!/usr/bin/env bash
# dsh-pack Demo 录制驱动 —— 复用 demo/quickstart.mjs 的真实 makeHandler 命令路径，
# 不复制第二套业务逻辑。
#
# 两种模式：
#   DEMO_MODE=local（默认）—— 无网络凭据即可完成 pack/sign/import/verify/run
#   DEMO_MODE=ghcr        —— 显式提供 Registry 凭据时展示真实 push + lock
#
# 用法：
#   bash demo/recording/demo.sh                    # local 模式
#   DEMO_MODE=ghcr \
#   DEMO_REMOTE_REF=ghcr.io/<owner>/demo-agent:v1 \
#   DSH_REGISTRY_USERNAME=<user> \
#   DSH_REGISTRY_TOKEN=<token> \
#   bash demo/recording/demo.sh                    # ghcr 模式
#
# 安全：脚本/日志/录屏不含真实 secret；token 仅经环境变量注入，结束后即失效。
# 录制用临时 Ed25519 key，进程退出后临时目录自动清理。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
MODE="${DEMO_MODE:-local}"
OUT_DIR="$ROOT/demo/recording/output"
mkdir -p "$OUT_DIR"

echo "== dsh-pack Demo Recording (mode: $MODE) =="

# 前置检查
command -v node >/dev/null 2>&1 || { echo "✗ node 未安装"; exit 1; }
command -v pnpm >/dev/null 2>&1 || { echo "✗ pnpm 未安装"; exit 1; }
[ -f "$ROOT/lib/index.js" ] || { echo "✗ lib/ 未构建，先执行：cd $ROOT && pnpm build"; exit 1; }

# ghcr 模式校验
if [ "$MODE" = "ghcr" ]; then
  [ -n "${DEMO_REMOTE_REF:-}" ] || { echo "✗ DEMO_MODE=ghcr 需要 DEMO_REMOTE_REF"; exit 1; }
  [ -n "${DSH_REGISTRY_USERNAME:-}" ] || { echo "✗ DEMO_MODE=ghcr 需要 DSH_REGISTRY_USERNAME"; exit 1; }
  [ -n "${DSH_REGISTRY_TOKEN:-}" ] || { echo "✗ DEMO_MODE=ghcr 需要 DSH_REGISTRY_TOKEN"; exit 1; }
fi

cd "$ROOT"

# 用 `script` 记录一次完整会话（确定性的终端输出日志，供后续渲染 GIF/MP4）。
# 若环境安装了 VHS，也可改用 demo/recording/demo.tape 做像素级确定性录制。
STAMP="$(date +%Y%m%d-%H%M%S)"
if command -v script >/dev/null 2>&1; then
  echo "== 录制会话（script typescript）… =="
  # 注入 DEMO_MODE 相关 env，驱动 quickstart.mjs（它内部读取 DEMO_REMOTE_REF/
  # DSH_REGISTRY_* 决定是否 push+lock）
  export DEMO_MODE="$MODE"
  script -q -e -c "node demo/quickstart.mjs" "$OUT_DIR/session-$MODE-$STAMP.typescript"
  echo "✔ 会话已记录: demo/recording/output/session-$MODE-$STAMP.typescript"
else
  echo "（无 script 工具，直接运行，不落盘日志）"
  node demo/quickstart.mjs
fi

echo ""
echo "✔ Demo recording finished (mode=$MODE)"
echo "  下一步：用 VHS/agg 将 typescript 渲染为 docs/assets/dsh-pack-demo.gif（目标 ≤3–5MB）"
echo "  参考 demo/recording/README.md"
