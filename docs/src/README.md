# agent-assembly

**agent-assembly** is the open-source core of the AI Agent Assembly governance platform. It enforces policy on AI agents — what they may call, spend, and connect to — and records every decision in an immutable audit trail.

This book is the contributor and operator reference for the core. If you build *with* a language SDK instead, read the per-SDK guides below.

New here? Start with the **[Introduction](introduction/README.md)** — it explains what Agent Assembly is, the problem it solves, the core concepts, and the three-layer interception model. Then move on to the [Quick Start](quick-start/requirements.md).

> **Other docs:** [Docs Hub](https://docs.agent-assembly.com/stable/) · [Python SDK](https://ai-agent-assembly.github.io/python-sdk/stable/) · [Node SDK](https://ai-agent-assembly.github.io/node-sdk/stable/) · [Go SDK](https://ai-agent-assembly.github.io/go-sdk/stable/)

## Run it locally

Point the gateway at a bundled reference policy and you have a governing daemon listening on `127.0.0.1:50051`:

```bash
git clone https://github.com/ai-agent-assembly/agent-assembly.git
cd agent-assembly
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml
```

From there, attach an SDK shim, the `aa-proxy` sidecar, or the eBPF layer to start intercepting agent actions. The [Architecture](architecture/README.md) chapter explains how those three layers fit together.

## Where to go next

| You want to… | Read |
|---|---|
| Understand what this is and why | [Introduction](introduction/README.md) |
| Get a gateway running quickly | [Quick Start](quick-start/requirements.md) |
| Look up an `aasm` command | [CLI Reference](cli/overview.md) |
| Follow a task end-to-end | [Usage Guide](usage-guide/overview.md) |
| Understand the threat model and defenses | [Security Model](security/overview.md) |
| See how the crates fit together | [Architecture](architecture/README.md) |
| Check which SDK versions are compatible | [Compatibility matrix](compatibility.md) |
| Read the wire-protocol contract | [Protocol changelog](protocol/CHANGELOG.md) |
| See latency and build-time numbers | [Benchmarks — baseline](benchmarks/BASELINE.md) |

## Audience

This book targets contributors and operators of `agent-assembly`. SDK users (Python, TypeScript, Go) should refer to the per-SDK guides in the sibling repositories.

## See also

- [README](https://github.com/ai-agent-assembly/agent-assembly/blob/master/README.md) — top-level project overview, prerequisites, quickstart
- [CONTRIBUTING](https://github.com/ai-agent-assembly/agent-assembly/blob/master/CONTRIBUTING.md) — development workflow, branch naming, PR rules
- API reference — generate locally with `cargo doc --workspace --no-deps --open`

## Diagram rendering

This book renders Mermaid diagrams via the `mdbook-mermaid` preprocessor:

```mermaid
graph LR
    SDK[SDK shim] --> Gateway[aa-gateway]
    Proxy[aa-proxy] --> Gateway
    eBPF[aa-ebpf] --> Gateway
    Gateway --> Audit[(Audit log)]
```
