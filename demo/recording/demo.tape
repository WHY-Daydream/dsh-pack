# dsh-pack Demo — VHS tape（像素级确定性终端录制）
# 需要 vhs（https://github.com/charmbracelet/vhs）环境。若未安装 vhs，
# 可改用 demo/recording/demo.sh（script typescript 日志）后经 agg/ffmpeg 渲染。
#
# 目标：20–30 秒突出价值链（不含 pnpm/install/test 日志）。
# 运行（local 模式）：
#   vhs demo/recording/demo.tape
# ghcr 模式：先在 Shell 里 export DEMO_MODE=ghcr 等 env，再 vhs 录制。
Output docs/assets/dsh-pack-demo.gif

Set Width 900
Set Height 600
Set FontSize 18
Set Padding 20
Set Margin 20
Set Theme "OneDark"
Set Framerate 60
Set PlaybackSpeed 1.0
Set TypingSpeed 25ms
Set WindowBar "dsh-pack — Artifact Supply Chain"

# 前置：构建 lib
Type "cd dsh-pack"
Enter
Type "pnpm build"
Enter
Sleep 2s

# 1. pack → .dshpack（contentHash）
Type "node demo/quickstart.mjs"
Enter
Sleep 3s
# 脚本按 section 输出，关键瞬间：contentHash / Signature VALID / Trust VERIFIED
# / tag → @sha256:manifestDigest / Agent image started

# 收尾
Sleep 1s
Enter
