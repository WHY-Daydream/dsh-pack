# Demo Recording

dsh-pack 的价值链终端演示（约 20–30 秒）——**不是录完整日志**，突出最有辨识度的瞬间：

```text
Profile
  ↓ PACK
.dshpack + contentHash
  ↓ SIGN
Signature: VALID
  ↓ image import
Agent Image
  ↓ OCI push（可选）
ghcr.io/.../repo:tag
  ↓ image lock
tag → repo@sha256:<manifestDigest>
  ↓ verify
Trust: VERIFIED
  ↓ run
Agent image started
```

## 文件

| 文件 | 作用 |
|------|------|
| `demo.sh` | 录制驱动：复用 `demo/quickstart.mjs` 真实命令路径，支持 `DEMO_MODE=local\|ghcr` |
| `demo.tape` | VHS 像素级确定性录制配置（需 vhs；未安装时可忽略，用 `demo.sh` 的 script 日志代替） |
| `output/` | 录制产物（typescript 日志 / GIF / MP4），不提交 |

## 运行

### local 模式（默认，无网络凭据即可）

```bash
bash demo/recording/demo.sh
```

覆盖：pack → inspect → verify → keygen+sign → verify(signed) → image import → ls → inspect → tag → prune。

### ghcr 模式（有 Registry 凭据时展示真实 push + lock）

```bash
DEMO_MODE=ghcr \
DEMO_REMOTE_REF=ghcr.io/<owner>/demo-agent:v1 \
DSH_REGISTRY_USERNAME=<user> \
DSH_REGISTRY_TOKEN=<token> \
bash demo/recording/demo.sh
```

## 生成 GIF

优先用 [VHS](https://github.com/charmbracelet/vhs)（像素级确定性，可复现）：

```bash
vhs demo/recording/demo.tape
# → docs/assets/dsh-pack-demo.gif
```

无 VHS 时：先跑 `demo.sh` 得到 `output/session-<mode>-<stamp>.typescript`，再用
[agg](https://github.com/asciinema/agg) 或 `script` + `ffmpeg` 渲染。

**GIF 体积目标 ≤ 3–5 MB**（README 加载体验）；高清 MP4/WebM 留给 Release/Discussion。

## 安全约束

- 任何 token / private key / registry credential **不进入** GIF、日志、脚本、仓库。
- 录制用临时 Ed25519 key，进程结束即删除（quickstart.mjs 的临时目录在 `finally` 清理）。
- 检查产物的铁律：GIF 里出现 `sk-`、`BEGIN PRIVATE KEY`、`Bearer` 均视为泄漏，丢弃重录。
