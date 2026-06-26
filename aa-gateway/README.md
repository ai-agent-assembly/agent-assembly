# aa-gateway

Control plane — policy enforcement engine and agent registry for Agent Assembly.

[![crates.io](https://img.shields.io/crates/v/aa-gateway?logo=rust&label=crates.io)](https://crates.io/crates/aa-gateway)
[![docs.rs](https://img.shields.io/docsrs/aa-gateway?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-gateway)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](../LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.75-orange?logo=rust)](https://www.rust-lang.org)

## What is this

`aa-gateway` is the brain of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly),
the governance-native runtime for AI agents. It is the central coordination point:
it maintains the **agent registry**, evaluates **governance policies**, tracks
**per-team budgets**, routes enforcement decisions back to the proxy and SDK
shims, and writes the audit trail.

Agent Assembly enforces governance through three independently-deployable
interception layers (in-process SDK shim, sidecar proxy, eBPF). The gateway sits
behind all of them — exposing **gRPC** for the SDK shims and an **HTTP/OpenAPI**
surface (via `aa-api`) for the dashboard and operator tooling.

The crate ships both a library and the `aa-gateway` binary.

## Install

```sh
cargo add aa-gateway
```

The Redis-backed policy cache is behind an off-by-default feature:

```sh
cargo add aa-gateway --features redis-cache
```

## Usage

```rust
use aa_gateway::{AgentRegistry, PolicyEngine};
```

`PolicyEngine` loads and evaluates governance policies; `AgentRegistry` tracks
registered agents and their status. See the [API documentation](https://docs.rs/aa-gateway)
for how to construct and wire them, and the project docs for running the gateway
as a service.

## Links

- Documentation: <https://docs.agent-assembly.com/>
- Source: <https://github.com/ai-agent-assembly/agent-assembly>
- License: [Apache-2.0](../LICENSE)
