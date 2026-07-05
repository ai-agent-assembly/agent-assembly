# agent-assembly

> Governance-native runtime for AI agents — open-source core.

[![CI](https://img.shields.io/github/actions/workflow/status/ai-agent-assembly/agent-assembly/ci.yml?branch=master&logo=githubactions&logoColor=white&label=CI)](https://github.com/ai-agent-assembly/agent-assembly/actions/workflows/ci.yml)
[![Docs](https://img.shields.io/github/actions/workflow/status/ai-agent-assembly/agent-assembly/docs.yml?branch=master&logo=githubactions&logoColor=white&label=docs)](https://github.com/ai-agent-assembly/agent-assembly/actions/workflows/docs.yml)
[![GitHub release](https://img.shields.io/github/v/release/ai-agent-assembly/agent-assembly?include_prereleases&sort=semver&logo=github&label=release)](https://github.com/ai-agent-assembly/agent-assembly/releases)
[![crates.io](https://img.shields.io/crates/v/aa-cli?logo=rust&label=crates.io)](https://crates.io/crates/aa-cli)
[![Coverage](https://img.shields.io/codecov/c/github/ai-agent-assembly/agent-assembly?logo=codecov&logoColor=white)](https://codecov.io/gh/ai-agent-assembly/agent-assembly)
[![Quality Gate](https://img.shields.io/sonar/quality_gate/ai-agent-assembly_agent-assembly?server=https%3A%2F%2Fsonarcloud.io&logo=sonarcloud)](https://sonarcloud.io/project/overview?id=ai-agent-assembly_agent-assembly)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.75-orange?logo=rust)](https://www.rust-lang.org)
[![Style](https://img.shields.io/badge/style-rustfmt-000?logo=rust)](https://github.com/rust-lang/rustfmt)
[![Lints](https://img.shields.io/badge/lints-clippy-blue?logo=rust)](https://github.com/rust-lang/rust-clippy)


## Install the CLI

```sh
curl -fsSL https://agent-assembly.com/install.sh | sh
```

This downloads and installs the `aasm` binary to `~/.local/bin`. Requires a
[published release](https://github.com/ai-agent-assembly/agent-assembly/releases).
The installer script lives at [`scripts/install-cli.sh`](scripts/install-cli.sh).
The alternate host `https://tool.agent-assembly.dev` serves the same script.

```sh
# Pin a specific version
AASM_VERSION=v0.0.1-rc.3 curl -sSf https://agent-assembly.com/install.sh | sh

# Custom install directory
AASM_INSTALL_DIR=/usr/local/bin curl -sSf https://agent-assembly.com/install.sh | sh
```

> The raw `raw.githubusercontent.com/.../install-cli.sh` URL also works if you
> prefer to fetch the script directly from GitHub.

The default install is **CLI-only** — it installs the `aasm` command and never
starts a background service.

### Install additional components

`aasm` is the CLI. The runtime, proxy, and eBPF layers are separate components.
Select them by passing options **to the script** via `sh -s --` (not to `curl`):

```sh
# CLI + local runtime
curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --components cli,runtime

# Full local profile (cli + runtime + proxy)
curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --profile full
```

Installing `runtime` does **not** start it — start it yourself afterwards.

### Review-first install

Prefer to read the script before running it:

```sh
curl -fsSL https://agent-assembly.com/install.sh -o install.sh
less install.sh
sh install.sh --components cli,runtime
```

### Homebrew (macOS / Linux)

```sh
brew install ai-agent-assembly/tap/aasm
```

Or tap once, then install by short name (add components as separate formulae):

```sh
brew tap ai-agent-assembly/tap
brew install aasm            # CLI only
brew install aasm-runtime    # runtime (start with: brew services start aasm-runtime)
```

Installs the latest tagged `aasm` release from the
[Homebrew tap](https://github.com/ai-agent-assembly/homebrew-tap). See the tap
README for the full component matrix (`aasm-runtime`, `aasm-proxy`, `aasm-ebpf`,
`aasm-bundle`). During the `v0.0.1` series the published releases are
pre-releases — see [Project Status](#project-status).

> [!NOTE]
> **Deprecated command:** `brew install ai-agent-assembly/agent-assembly/aasm`
> (repo `homebrew-agent-assembly`) still works via a GitHub redirect but is
> deprecated — use `ai-agent-assembly/tap/aasm`.

## Uninstall

For **curl** installs, the default uninstall removes the tools and **keeps your
local data** (config, policies, state, logs):

```sh
aasm uninstall                          # remove tools; preserve data
aasm uninstall --components cli,runtime # remove only these components
```

To also remove Agent Assembly-owned local data, opt in explicitly (prompts for
confirmation; preview with `--dry-run`):

```sh
aasm uninstall --all --purge            # remove tools + config + state
aasm uninstall --all --purge --dry-run  # show what would be removed
```

If `aasm` is missing or broken, the installer provides the same uninstall engine
as a fallback:

```sh
curl -fsSL https://agent-assembly.com/install.sh | sh -s -- --uninstall
```

**Homebrew** installs are detected and left untouched by the above — remove them
with Homebrew instead:

```sh
brew uninstall aasm            # plus aasm-runtime / aasm-proxy if installed
```

## Overview

`agent-assembly` brings governance to AI agents at scale. It intercepts what an
agent tries to do — call a tool, reach the network, spend budget — at three
independent layers, sends each action to a central **gateway** for a
**policy** decision, and records the outcome in an immutable audit trail.

The three interception layers, lowest-latency first:

- **SDK shim** (in-process) — fastest path; requires the agent to adopt an SDK.
- **Sidecar proxy** (`aa-proxy`) — intercepts outbound HTTPS without code changes.
- **eBPF** (Linux kernel) — catches everything else, including bypass attempts.

Each layer reports to the same gateway, so you get one unified view no matter
which layers a deployment runs. See the [Architecture overview](docs/src/architecture.md)
for the full picture, or jump straight to the [Quickstart](#quickstart).

## Ecosystem

`agent-assembly` is the open-source core of a larger governance platform. The
table below maps each production repository to its role and entry point, so you
can move from this repo to the SDKs, the install tap, or the canonical docs.

| Repository | Role | Status |
|---|---|---|
| **agent-assembly** (this repo) | Core runtime — gateway, policy engine, eBPF / proxy / SDK interception | [![release](https://img.shields.io/github/v/release/ai-agent-assembly/agent-assembly?include_prereleases&sort=semver&label=release&logo=rust&logoColor=white)](https://github.com/ai-agent-assembly/agent-assembly/releases) |
| [python-sdk](https://github.com/ai-agent-assembly/python-sdk) | Python SDK (PyO3 native + pure-Python client) | [![release](https://img.shields.io/github/v/release/ai-agent-assembly/python-sdk?include_prereleases&sort=semver&label=release&logo=python&logoColor=white)](https://github.com/ai-agent-assembly/python-sdk/releases) |
| [node-sdk](https://github.com/ai-agent-assembly/node-sdk) | TypeScript / Node.js SDK (napi-rs native + JS client) | [![release](https://img.shields.io/github/v/release/ai-agent-assembly/node-sdk?include_prereleases&sort=semver&label=release&logo=nodedotjs&logoColor=white)](https://github.com/ai-agent-assembly/node-sdk/releases) |
| [go-sdk](https://github.com/ai-agent-assembly/go-sdk) | Go SDK | [![release](https://img.shields.io/github/v/release/ai-agent-assembly/go-sdk?include_prereleases&sort=semver&label=release&logo=go&logoColor=white)](https://github.com/ai-agent-assembly/go-sdk/releases) |
| [homebrew-tap](https://github.com/ai-agent-assembly/homebrew-tap) | Homebrew tap for the `aasm` CLI | [![Homebrew tap](https://img.shields.io/badge/homebrew-tap-FBB040?logo=homebrew&logoColor=white)](https://github.com/ai-agent-assembly/homebrew-tap) |
| [agent-assembly-docs](https://docs.agent-assembly.com/) | Canonical documentation site | [![docs](https://img.shields.io/badge/docs-live-2088FF)](https://docs.agent-assembly.com/) |
| agent-assembly-cloud | Hosted SaaS control plane | ![coming soon](https://img.shields.io/badge/SaaS-coming_soon-8957E5) |
| agent-assembly-enterprise | Enterprise extensions (delivered via SaaS) | ![coming soon](https://img.shields.io/badge/enterprise-coming_soon-8957E5) |

> The protocol specification is maintained **inside this monorepo** under
> [`proto/`](proto/) and [`docs/src/protocol/`](docs/src/protocol/CHANGELOG.md) —
> there is no separate spec package.

## Crate Map

The Cargo workspace declares **28 members** in the top-level `Cargo.toml`. The table below lists the core architectural crates; storage drivers, dev-tool adapters, and test harnesses are omitted for brevity. Two additional eBPF-target crates live alongside but are intentionally outside the workspace because they compile for the `bpfel-unknown-none` target.

### Workspace members (core)

| Crate | Role |
|---|---|
| `aa-core` | Pure logic, `no_std`-compatible domain types and traits |
| `aa-proto` | Protobuf message types — single source of truth for the wire format |
| `aa-runtime` | Tokio async runtime wrapper and agent lifecycle |
| `aa-ebpf` | eBPF orchestrator (loads probes/programs via `aya-build`) |
| `aa-ebpf-common` | Shared types between user-space and eBPF programs |
| `aa-proxy` | Sidecar HTTPS interception proxy (MitM with per-host CA) |
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

🚧 **Alpha — `v0.0.1` pre-release series** _(status as of 2026-06-13)_. The
public API and wire protocol are **not** stable; do not use in production.

Releases are published as GitHub pre-releases — latest
[`v0.0.1-rc.3`](https://github.com/ai-agent-assembly/agent-assembly/releases/tag/v0.0.1-rc.3)
(2026-06-20). The coordinated release tag also publishes the CLI, crates, SDK
packages, and container image:

| Channel | Status |
|---|---|
| GitHub Releases | ✅ Pre-releases published (`v0.0.1-alpha.1` … `alpha.9`) |
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
> **Prefer Codespaces?** [![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/ai-agent-assembly/agent-assembly)
> The `.devcontainer/` config installs all dependencies automatically.

Get from a fresh clone to a verified local environment in under 10 minutes.

### 1. Clone the repository

```bash
git clone https://github.com/ai-agent-assembly/agent-assembly.git
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
- [Runnable examples](https://github.com/ai-agent-assembly/agent-assembly-examples) — learn the runtime, CLI, and policy behavior by running small, framework-specific examples for Python, Node.js/TypeScript, Go, policy enforcement, approvals, audit, trace, and runtime workflows

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
├── aa-sdk-client/       # Shared SDK runtime-client (Python/Node/Go shims live in their own repos)
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

📖 **Canonical docs site:** <https://docs.agent-assembly.com/>

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
| [Command-Line Interface](docs/src/cli.md) | `aasm` global flags, command groups, and examples |
| [Policy YAML Reference](docs/src/policy-reference.md) | Complete per-section policy field reference, `requires_approval_if` expression syntax, and example policies |
| [Dashboard](docs/src/dashboard.md) | Web console and terminal (TUI) governance dashboards |
| [Local Development](docs/src/development/local-development.md) | From-clone setup, everyday build/test loop, git hooks |
| [Releases](docs/src/releases.md) | Release state, distribution channels, and process |
| [Compatibility Matrix](docs/src/compatibility.md) | Which `aa-runtime` versions work with which SDK versions |
| [Versioning Policy](docs/src/versioning.md) | Protocol semver rules, breaking-change classification, deprecation lifecycle |
| [Protocol Changelog](docs/src/protocol/CHANGELOG.md) | Wire-protocol change log |
| [Migration Template](docs/src/migration/template.md) | Guidance for moving between protocol versions |
| [Benchmarks — Baseline](docs/src/benchmarks/BASELINE.md) | Performance baseline numbers |
| [Benchmarks — Policy Check p99](docs/src/benchmarks/policy-check-p99.md) | Latency SLA evidence |

## Security & Support

- **Security:** Report vulnerabilities **privately** via
  [GitHub Security Advisories](https://github.com/ai-agent-assembly/agent-assembly/security)
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
