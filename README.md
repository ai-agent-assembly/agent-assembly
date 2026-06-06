# agent-assembly

> Governance-native runtime for AI agents — open-source core.

[![CI](https://github.com/AI-agent-assembly/agent-assembly/actions/workflows/ci.yml/badge.svg)](https://github.com/AI-agent-assembly/agent-assembly/actions/workflows/ci.yml)
[![Docs](https://github.com/AI-agent-assembly/agent-assembly/actions/workflows/docs.yml/badge.svg)](https://github.com/AI-agent-assembly/agent-assembly/actions/workflows/docs.yml)
[![codecov](https://codecov.io/gh/AI-agent-assembly/agent-assembly/branch/master/graph/badge.svg)](https://codecov.io/gh/AI-agent-assembly/agent-assembly)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/AI-agent-assembly/agent-assembly?include_prereleases&sort=semver)](https://github.com/AI-agent-assembly/agent-assembly/releases)


## Install the CLI

```sh
curl -sSf https://install.ai-agent-assembly.dev | sh
```

This downloads and installs the `aasm` binary to `~/.local/bin`. Requires a
[published release](https://github.com/AI-agent-assembly/agent-assembly/releases).
The installer script lives at [`scripts/install-cli.sh`](scripts/install-cli.sh).

```sh
# Pin a specific version
AASM_VERSION=v0.1.0 curl -sSf https://install.ai-agent-assembly.dev | sh

# Custom install directory
AASM_INSTALL_DIR=/usr/local/bin curl -sSf https://install.ai-agent-assembly.dev | sh
```

### Homebrew (macOS / Linux)

```sh
brew install ai-agent-assembly/homebrew-agent-assembly/aasm
```

Installs the latest tagged `aasm` release from the
[Homebrew tap](https://github.com/AI-agent-assembly/homebrew-agent-assembly).
During the `v0.0.1` alpha series the published releases are pre-releases — see
[Project Status](#project-status).

## Overview

`agent-assembly` is the core runtime that brings governance to AI agents at
scale. It provides a three-layer interception model — eBPF kernel hooks, a
sidecar proxy, and an SDK shim — backed by a policy engine and audit trail.

## Ecosystem

`agent-assembly` is the open-source core of a larger governance platform. The
table below maps each production repository to its role and entry point, so you
can move from this repo to the SDKs, the install tap, or the canonical docs.

| Repository | Role | Status |
|---|---|---|
| **agent-assembly** (this repo) | Core runtime — gateway, policy engine, eBPF / proxy / SDK interception | Public · Alpha |
| [python-sdk](https://github.com/AI-agent-assembly/python-sdk) | Python SDK (PyO3 native + pure-Python client) | Public · Alpha |
| [node-sdk](https://github.com/AI-agent-assembly/node-sdk) | TypeScript / Node.js SDK (napi-rs native + JS client) | Public · Alpha |
| [go-sdk](https://github.com/AI-agent-assembly/go-sdk) | Go SDK | Public · Alpha |
| [homebrew-agent-assembly](https://github.com/AI-agent-assembly/homebrew-agent-assembly) | Homebrew tap for the `aasm` CLI | Public |
| [agent-assembly-docs](https://ai-agent-assembly.github.io/agent-assembly-docs/) | Canonical documentation site | Public |
| agent-assembly-cloud | Hosted SaaS control plane | Private · in development |
| agent-assembly-enterprise | Enterprise extensions (delivered via SaaS) | Private · in development |

> The protocol specification is maintained **inside this monorepo** under
> [`proto/`](proto/) and [`docs/src/protocol/`](docs/src/protocol/CHANGELOG.md) —
> there is no separate spec package.

## Crate Map

The Cargo workspace declares **14 members** in the top-level `Cargo.toml`. Two additional eBPF-target crates live alongside but are intentionally outside the workspace because they compile for the `bpfel-unknown-none` target.

### Workspace members

| Crate | Role |
|---|---|
| `aa-core` | Pure logic, `no_std`-compatible domain types and traits |
| `aa-proto` | Protobuf message types — single source of truth for the wire format |
| `aa-runtime` | Tokio async runtime wrapper and agent lifecycle |
| `aa-ebpf` | eBPF orchestrator (loads probes/programs via `aya-build`) |
| `aa-ebpf-common` | Shared types between user-space and eBPF programs |
| `aa-proxy` | Sidecar HTTPS interception proxy (MitM with per-host CA) |
| `aa-ffi-go` | Go FFI bindings via cgo (C-ABI staticlib artifact for the Go SDK) |
| `aa-sdk-client` | Shared SDK runtime-client (UDS transport, codec, lifecycle) the language shims wrap |
| `aa-wasm` | WebAssembly target via wasm-bindgen |
| `aa-gateway` | Control plane — policy enforcement, agent registry, budget tracking |
| `aa-api` | HTTP presentation layer with OpenAPI spec generation (utoipa) |
| `aa-cli` | `aasm` command-line tool |
| `conformance` | Cross-SDK protocol conformance test harness |

### Out-of-workspace eBPF target crates

These two are built by `aa-ebpf/build.rs` (via `aya-build`) for the BPF target — they are not part of the host workspace and cannot be selected with `cargo -p`:

| Crate | Role |
|---|---|
| `aa-ebpf-probes` | Userspace probe loaders (uprobes for SSL libraries) |
| `aa-ebpf-programs` | eBPF programs compiled to BPF bytecode (`bpfel-unknown-none`) |

## Project Status

🚧 **Alpha — `v0.0.1` pre-release series** _(status as of 2026-06-06)_. The
public API and wire protocol are **not** stable; do not use in production.

Releases are published as GitHub pre-releases — latest
[`v0.0.1-alpha.5`](https://github.com/AI-agent-assembly/agent-assembly/releases/tag/v0.0.1-alpha.5)
(2026-06-03). The coordinated release tag also publishes the CLI, crates, SDK
packages, and container image:

| Channel | Status |
|---|---|
| GitHub Releases | ✅ Pre-releases published (`v0.0.1-alpha.1` … `alpha.5`) |
| crates.io | ✅ Workspace crates published at the pre-release version |
| Homebrew tap | ✅ `aasm` formula published for tagged releases |
| PyPI / npm | ✅ SDK pre-releases published from the release tag |
| GHCR image | ✅ Published from the release tag |

See [`docs/release/`](docs/release/) for the per-tag release notes and the
[release runbook](docs/release/RUNBOOK.md).

## Requirements

- Rust stable (≥ 1.75)
- `protoc` — Protocol Buffers compiler (`brew install protobuf` on macOS, `apt-get install protobuf-compiler` on Debian/Ubuntu); required by `aa-proto` and `aa-gateway` build scripts
- [cargo-nextest](https://nexte.st/) for running tests
- [cargo-deny](https://embarkstudios.github.io/cargo-deny/) for dependency checks
- [Lefthook](https://github.com/evilmartians/lefthook) for git hooks
- **Linux only**: `pkg-config` and `libssl-dev` (or `openssl-devel` on RHEL-family) for native TLS in `aa-proxy`; eBPF crates additionally require a recent kernel with BTF and a nightly Rust toolchain (see `aa-ebpf/README.md`)

## Supported platforms

The interception layers have different platform reach. The SDK shim and sidecar
proxy run anywhere the runtime builds; kernel-level eBPF interception is
Linux-only.

| Platform | Runtime / CLI | Sidecar proxy (`aa-proxy`) | eBPF interception |
|---|---|---|---|
| Linux (x86_64 / arm64) | ✅ | ✅ | ✅ — kernel with BTF + nightly toolchain |
| macOS (Apple Silicon / Intel) | ✅ | ✅ | ❌ — Linux-only |
| Windows | ⚠️ via WSL2 | ⚠️ via WSL2 | ⚠️ via WSL2 |

On macOS, governance is enforced through the SDK and proxy layers; the eBPF
layer is unavailable. See [`aa-ebpf/README.md`](aa-ebpf/README.md) for kernel
requirements.

## Quickstart

<!-- docs-site: <asciinema-player src="quickstart.cast" cols="220" rows="50" preload="true"></asciinema-player> -->

> **Demo recording:** `asciinema play docs/quickstart.cast`
>
> **Prefer Codespaces?** [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/AI-agent-assembly/agent-assembly)
> The `.devcontainer/` config installs all dependencies automatically.

Get from a fresh clone to a verified local environment in under 10 minutes.

### 1. Clone the repository

```bash
git clone https://github.com/AI-agent-assembly/agent-assembly.git
cd agent-assembly
```

### 2. Bootstrap the development environment

```bash
make dev-setup
```

Installs required toolchains, clones the SDK polyrepos as siblings, installs
git hooks, and builds the workspace. Expected output (abbreviated):

```text
  Cloning python-sdk ...
  Cloning node-sdk ...
  Cloning go-sdk ...
pre-commit installed at .git/hooks/pre-commit
   Compiling aa-core v0.0.1 ...
    Finished `dev` profile target(s) in 167s

dev-setup complete. Run 'make dev-verify' to validate.
```

### 3. Verify the installation

```bash
make dev-verify
```

Runs smoke tests across all SDK repos in parallel then checks gateway health.
Expected output:

```text
dev-verify: running SDK smoke tests in parallel ...
[1/4] python smoke ... OK (2s)
[2/4] node smoke   ... OK (18s)
[3/4] go smoke     ... SKIP (internal/smoke/ not found in go-sdk)
[4/4] gateway health ... OK (1s)

dev-verify passed (22s total)
```

> **Timing:** ~4 minutes on a 2024 MacBook Pro M3 (first run; subsequent runs
> skip already-installed tools).

### Next steps

- [SDK repositories](#ecosystem) — Python, Node.js, and Go SDK guides
- [Architecture Overview](docs/src/architecture.md) — three-layer interception model
- [Policy examples](policy-examples/) — reference governance policies

## Running with Docker Compose

Run `aa-runtime` as a sidecar against a placeholder agent using the
[`examples/docker-compose`](examples/docker-compose/) stack:

```bash
# 1. Build the workspace (first time only)
cargo build --workspace --exclude aa-ebpf

# 2. Launch the sidecar + a stub agent container
cd examples/docker-compose
AA_API_KEY=dev-local-key docker compose up
```

The sidecar exposes:

- The agent IPC socket at `/tmp/aa-runtime-my-agent-001.sock`
- Readiness probe at `http://localhost:8080/ready`

To run only the governance gateway (without Docker), point it at one of the
bundled YAML policies:

```bash
# Listens on 127.0.0.1:50051 by default; SDK shims and aa-proxy connect over gRPC.
cargo run -p aa-gateway -- --policy policy-examples/low-risk.yaml
```

`policy-examples/{low,medium,high}-risk.yaml` are reference policies — pick one
or write your own following the same schema.

Replace the `agent-stub` service in
`examples/docker-compose/docker-compose.yml` with your own SDK-based agent
image once `python-sdk`, `node-sdk`, or `go-sdk` is wired into your project.

## Repository Layout

```
agent-assembly/
├── aa-core/             # Domain types (no_std)
├── aa-proto/            # Protobuf message types (wire format)
├── aa-runtime/          # Async runtime + agent lifecycle
├── aa-ebpf/             # eBPF orchestrator (workspace member)
├── aa-ebpf-common/      # Shared user/kernel types (workspace member)
├── aa-ebpf-probes/      # Userspace probe loaders (out-of-workspace, BPF target)
├── aa-ebpf-programs/    # eBPF programs (out-of-workspace, BPF target)
├── aa-proxy/            # Sidecar HTTPS proxy
├── aa-ffi-go/           # Go bindings (cgo C-ABI staticlib)
├── aa-sdk-client/       # Shared SDK runtime-client (Python/Node shims live in their own repos)
├── aa-wasm/             # WASM target
├── aa-gateway/          # Control plane (policy, registry, budget)
├── aa-api/              # HTTP API + OpenAPI
├── aa-cli/              # CLI tool (aasm)
├── conformance/         # Protocol conformance test harness
├── proto/               # Protobuf source (.proto files)
├── openapi/             # Generated OpenAPI v1 spec
├── schemas/             # JSON schemas (compatibility matrix)
├── dashboard/           # Community web UI (React + TypeScript)
├── docs/                # mdBook contributor documentation
└── policy-examples/     # Reference governance policies
```

## Documentation

📖 **Canonical docs site:** <https://ai-agent-assembly.github.io/agent-assembly-docs/>

The contributor-facing documentation is also published as an [mdBook](https://rust-lang.github.io/mdBook/). Sources live under `docs/src/`. Build it locally with:

```bash
cargo install --locked --version 0.5.2 mdbook
cargo install --locked --version 0.17.0 mdbook-mermaid
mdbook serve docs --open
```

| Chapter | Description |
|---|---|
| [Introduction](docs/src/README.md) | Book overview and audience |
| [Architecture Overview](docs/src/architecture.md) | Crate dependency graph, three-layer interception, IPC, sidecar lifecycle, policy evaluation |
| [API Reference](docs/src/api-reference.md) | rustdoc generation flow and per-crate API surface map |
| [Compatibility Matrix](docs/src/compatibility.md) | Which `aa-runtime` versions work with which SDK versions |
| [Versioning Policy](docs/src/versioning.md) | Protocol semver rules, breaking-change classification, deprecation lifecycle |
| [Protocol Changelog](docs/src/protocol/CHANGELOG.md) | Wire-protocol change log |
| [Migration Template](docs/src/migration/template.md) | Guidance for moving between protocol versions |
| [Benchmarks — Baseline](docs/src/benchmarks/BASELINE.md) | Performance baseline numbers |
| [Benchmarks — Policy Check p99](docs/src/benchmarks/policy-check-p99.md) | Latency SLA evidence |

## Security & Support

- **Security:** Report vulnerabilities **privately** via
  [GitHub Security Advisories](https://github.com/AI-agent-assembly/agent-assembly/security)
  or email `security@agent-assembly.dev`. Please do not open public issues for
  security reports. See [`SECURITY.md`](SECURITY.md) for the disclosure policy
  and response SLA.
- **Bugs & features:** Open an issue using the
  [bug report](.github/ISSUE_TEMPLATE/bug_report.md) or
  [feature request](.github/ISSUE_TEMPLATE/feature_request.md) template.
- **Contributing:** See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the development
  setup, commit conventions, and PR process.
- **Changelog:** [`CHANGELOG.md`](CHANGELOG.md).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
