# Building & contributing

This page is the short version of building, testing, and linting the workspace.
The authoritative source is
[`CONTRIBUTING.md`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/CONTRIBUTING.md)
at the repo root; read it before opening a pull request.

## Prerequisites

- **Rust stable** (≥ 1.75) — install via [rustup](https://rustup.rs/).
- **cargo-nextest** — `cargo install cargo-nextest` (the test runner).
- **cargo-deny** — `cargo install cargo-deny` (license / advisory checks).
- **Lefthook** — `brew install lefthook` (macOS) or see the
  [Lefthook install guide](https://github.com/evilmartians/lefthook/blob/master/docs/install.md).
  The hook configuration lives in
  [`lefthook.toml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/lefthook.toml).

## Setup

```bash
git clone https://github.com/ai-agent-assembly/agent-assembly.git
cd agent-assembly

# Install git hooks (fmt, clippy, deny on commit; doc on push)
lefthook install

# Verify the workspace builds
cargo build --workspace

# Run the full test suite
cargo nextest run --workspace
```

## Common commands

| Task | Command |
|---|---|
| Build everything | `cargo build --workspace` |
| Full test suite | `cargo nextest run --workspace` |
| Tests for one crate | `cargo nextest run -p aa-gateway` |
| A single test | `cargo nextest run -p aa-gateway budget::types::tests::provider_variants_are_distinct` |
| Format | `cargo fmt --all` |
| Lint | `cargo clippy --all-targets -- -D warnings` |
| License / advisory check | `cargo deny check` |
| Docs | `cargo doc --workspace --no-deps` |

Notes:

- **eBPF crates** (`aa-ebpf*`) compile with target-specific toolchains;
  `cargo check -p aa-ebpf` is sufficient on non-Linux environments. The
  out-of-workspace BPF crates (`aa-ebpf-probes`, `aa-ebpf-programs`) are built by
  `aa-ebpf/build.rs` via `aya-build` and cannot be selected with `cargo -p`.
- **The CLI binary** is `aasm` (shipped by `aa-cli`); smoke-test it with
  `./target/debug/aasm <subcommand>`.

## Faster builds (optional)

The dev profile already builds dependencies at `opt-level = 1` with
`line-tables-only` debuginfo, so warm rebuilds link faster while backtraces stay
readable — no setup needed. A faster **linker** is opt-in: install it and
uncomment the block for your platform in
[`.cargo/config.toml`](https://github.com/ai-agent-assembly/agent-assembly/blob/master/.cargo/config.toml)
(mold + clang on Linux, lld via `brew install llvm` on macOS).

## Commit & branch conventions

- **Branches:** `<version>/<ticket-number>/<short-summary>`, e.g.
  `v0.0.1/AAASM-42/add_agent_registry`.
- **Commits:** Gitmoji-prefixed, `<emoji> (<scope>): <imperative summary>`, one
  logical unit per commit, bisectable. Example:
  `✨ (aa-core): Add AgentId newtype wrapper`.

## Adding a new crate

1. `cargo new --lib aa-<name>` from the repo root.
2. Add `aa-<name>` to the `members` array in the top-level `Cargo.toml`.
3. Inherit workspace metadata (`version.workspace = true`, etc.) and use the
   shared `[workspace.lints.clippy]` rather than redefining clippy lints
   per-crate.
