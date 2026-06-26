# aa-sdk-client

Shared SDK runtime-client for Agent Assembly — UDS transport, IPC wire codec,
`AssemblyClient` lifecycle, and advisory credential preflight.

[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](../LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.75-orange?logo=rust)](https://www.rust-lang.org)

> **Not published to crates.io.** This crate is distributed to the external SDK
> shims as a **git-SHA pin** (ADR 0002), so it is `publish = false`. Add it as a
> git dependency rather than via `cargo add`.

## What is this

`aa-sdk-client` is the single, FFI-agnostic implementation of the agent-side SDK
runtime client for [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly),
the governance-native runtime for AI agents. It provides the Unix-domain-socket
transport, the IPC wire codec, the `AssemblyClient` lifecycle, and event
capture/shipping to the runtime.

It is Layer 1 (the in-process SDK layer) of the three-layer interception model.
The thin per-language FFI shims (`aa-ffi-python`, `aa-ffi-node`, `aa-ffi-go`) are
wrappers over this crate, so the transport/codec/lifecycle logic lives in exactly
one place and cannot drift between languages.

### Trust model

The SDK is **untrusted** and is **not** a security boundary. Authoritative
credential scanning, redaction, and normalization happen at the mandatory runtime
chokepoint (`aa-runtime`), which re-scans every event unconditionally. Any
credential preflight this crate performs (behind the default `preflight` feature)
is **advisory, best-effort only**.

## Install

Because the crate is git-pinned, depend on it from a Git revision:

```toml
[dependencies]
aa-sdk-client = { git = "https://github.com/ai-agent-assembly/agent-assembly", rev = "<commit-sha>" }
```

Disable the advisory preflight (drops the `aa-security` dependency) with
`default-features = false`.

## Usage

```rust
use aa_sdk_client::{AssemblyClient, AssemblyConfig};
```

`AssemblyConfig` resolves the socket/transport configuration and `AssemblyClient`
drives the connection lifecycle and ships governance events to the runtime. See
the crate's API docs and the language SDKs for end-to-end usage.

## Links

- Documentation: <https://ai-agent-assembly.github.io/agent-assembly-docs/>
- Source: <https://github.com/ai-agent-assembly/agent-assembly>
- License: [Apache-2.0](../LICENSE)
