# Local Development

This page covers the from-clone development loop for the `agent-assembly`
monorepo. For contribution conventions (commit style, PR process) see
[`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/CONTRIBUTING.md).

## Prerequisites

- Rust stable (≥ 1.75) via [rustup](https://rustup.rs/)
- `protoc` — Protocol Buffers compiler (`brew install protobuf` /
  `apt-get install protobuf-compiler`); required by the `aa-proto` and
  `aa-gateway` build scripts
- [`cargo-nextest`](https://nexte.st/), [`cargo-deny`](https://embarkstudios.github.io/cargo-deny/),
  and [Lefthook](https://github.com/evilmartians/lefthook)
- **Linux only** for the proxy / eBPF layers — see
  [Supported platforms](https://github.com/ai-agent-assembly/agent-assembly#supported-platforms).

## Bootstrap

```bash
git clone https://github.com/ai-agent-assembly/agent-assembly.git
cd agent-assembly

# Installs toolchains, clones the SDK polyrepos as siblings, installs git
# hooks, and builds the workspace.
make dev-setup

# Smoke-tests each SDK repo in parallel, then checks gateway health.
make dev-verify
```

## Everyday loop

```bash
cargo build --workspace --exclude aa-ebpf   # build (skip the BPF-target crate off Linux)
cargo nextest run --workspace               # full test suite
cargo nextest run -p aa-core                # one crate
cargo fmt --all                             # format
cargo clippy --all-targets -- -D warnings   # lint
cargo deny check                            # dependency / license audit
```

The eBPF crates compile with a target-specific toolchain; on non-Linux hosts
`cargo check -p aa-ebpf` is sufficient.

## Git hooks

Hooks are managed by [Lefthook](https://github.com/evilmartians/lefthook)
(`lefthook.toml`). Install them once with `lefthook install`. The **pre-commit**
hook runs `fmt`, `clippy`, and `deny` scoped by file glob; the **pre-push** hook
runs `cargo doc --workspace --no-deps`.

## Running locally

Point the gateway at a bundled reference policy and connect a sidecar:

```bash
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml
```

See the [CLI](../cli/overview.md) page for `aasm` operator commands and the README
"Running with Docker Compose" section for the sidecar stack.

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `protoc` / "Could not find protoc" build error | Protocol Buffers compiler missing | Install it (`brew install protobuf` or `apt-get install protobuf-compiler`) — `aa-proto` and `aa-gateway` need it |
| `cargo build` fails on `aa-ebpf*` off Linux | eBPF crates target the BPF toolchain | Build with `--exclude aa-ebpf`; use `cargo check -p aa-ebpf` on non-Linux hosts |
| Pre-commit hook does not run | Lefthook hooks not installed | Run `lefthook install` once in the repo |
| Pre-push fails on `cargo doc` | A doc comment has a broken intra-doc link | Run `cargo doc --workspace --no-deps` locally and fix the reported link |
| `make dev-verify` skips the Go smoke test | `go-sdk` checkout is missing or has no `internal/smoke/` | Expected when the Go SDK sibling repo is absent; clone it next to `agent-assembly` to enable it |
