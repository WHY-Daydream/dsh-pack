# Architecture — Artifact Supply Chain

> 本文档是 **README 架构图的 Mermaid 可编辑源图**（`README.md` 默认展示
> `docs/assets/dsh-pack-architecture.svg`，本文件为维护用源）。
> 修改流程：改 Mermaid → 重新生成/同步 SVG → 更新 README 引用。

## Mermaid（可编辑源）

```mermaid
flowchart LR
    P["DSH Profile"] --> PACK["/pack"]

    PACK --> A[".dshpack Artifact"]

    A --> CH["configHash<br/>Reproducibility"]
    A --> DH["contentHash<br/>DSH Identity"]

    A --> SIGN["Ed25519 Sign"]
    SIGN --> SA["Signed Artifact"]

    SA --> IMG["Image Import"]
    IMG --> LS["Local Image Store<br/>Content Addressed"]

    LS --> PUSH["OCI Push"]
    PUSH --> REG["OCI Registry / GHCR"]

    REG --> LOCK["dsh-lock.json<br/>Version Governance"]
    REG --> PULL["OCI Pull"]

    PULL --> VERIFY["OCI Integrity<br/>↓<br/>DSH Integrity<br/>↓<br/>Signature<br/>↓<br/>Trust"]

    LOCK --> VERIFY
    TP["trust.yaml<br/>Execution Governance"] --> VERIFY

    VERIFY --> RUN["Runnable Agent Image"]
    RUN --> RT["Temporary Runtime"]

    LS --> GC["Mark-and-Sweep Prune<br/>Local Lifecycle"]
```

## Identity Model — Four Layers

```text
configHash
    ↓
Profile reproducibility

contentHash
    ↓
DSH artifact identity / signing

OCI blobDigest
    ↓
Transport bytes integrity

OCI manifestDigest
    ↓
Remote immutable image identity
```

## Core Invariants

```text
Lock ≠ Trust               — Version governance ≠ execution governance
Cache ≠ Trust              — A cached image is not automatically trusted
Registry ≠ Trust Authority — The registry is a distribution channel, not a trust source
VALID ≠ TRUSTED            — A valid signature from an unknown key is still untrusted
OCI Digest ≠ DSH contentHash — Transport identity ≠ artifact identity
CLI can tighten policy, never weaken it
```
