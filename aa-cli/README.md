# aa-cli

`aasm` — the command-line tool for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-cli?logo=rust&label=crates.io)](https://crates.io/crates/aa-cli)
[![docs.rs](https://img.shields.io/docsrs/aa-cli?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-cli)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](../LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.75-orange?logo=rust)](https://www.rust-lang.org)

## What is this

`aa-cli` is the operator front-end for [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly),
the governance-native runtime for AI agents. It ships the **`aasm`** binary — the
terminal entry point for inspecting agent topology, managing policies, watching
the audit trail, and driving the governance gateway.

Agent Assembly enforces governance across three independently-deployable
interception layers (in-process SDK shim, sidecar proxy, and eBPF). `aasm` is how
an operator observes and controls that system from the command line, talking to
the gateway over its HTTP/OpenAPI surface.

## Install

The recommended way to get the `aasm` binary is the one-line installer, which
downloads the matching pre-built release tarball, verifies its checksum, and
installs to `~/.local/bin`:

```sh
curl -fsSL https://agent-assembly.com/install.sh | sh
```

Pin a specific version with `AASM_VERSION`:

```sh
AASM_VERSION=v0.0.1-beta.4 curl -sSf https://agent-assembly.com/install.sh | sh
```

Or build/install from source via cargo:

```sh
cargo install aa-cli
```

Then confirm the install:

```sh
aasm --help
```

## Usage

```sh
# Show the agent topology
aasm topology

# Manage governance policies
aasm policy --help

# Launch the operator dashboard (TUI)
aasm dashboard

# Tail the audit log
aasm audit
```

Run `aasm <command> --help` for the full set of subcommands (`agent`, `policy`,
`audit`, `budget`, `cost`, `gateway`, `proxy`, `sandbox`, `topology`, and more).

## Links

- Documentation: <https://ai-agent-assembly.github.io/agent-assembly-docs/>
- Source: <https://github.com/ai-agent-assembly/agent-assembly>
- License: [Apache-2.0](../LICENSE)
