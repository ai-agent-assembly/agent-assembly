# aa-core

Pure domain logic for Agent Assembly — `no_std` compatible.

[![crates.io](https://img.shields.io/crates/v/aa-core?logo=rust&label=crates.io)](https://crates.io/crates/aa-core)
[![docs.rs](https://img.shields.io/docsrs/aa-core?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-core)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](../LICENSE)
[![Rust](https://img.shields.io/badge/rust-%E2%89%A51.75-orange?logo=rust)](https://www.rust-lang.org)

## What is this

`aa-core` is the foundational crate of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly),
the governance-native runtime for AI agents. It holds the shared domain types,
traits, and pure logic that every other layer of the system depends on — agent
identity, policy decisions, risk tiers, capabilities, and the audit model.

It has **no runtime or I/O dependencies** and is `no_std` compatible, so the same
types flow unchanged through the gateway, the runtime, the FFI shims the language
SDKs bind to, and the operator CLI. Anything used across layers lives here.

## Install

```sh
cargo add aa-core
```

### Feature flags

| Feature | Default | Purpose |
|---|---|---|
| `std` | yes | `std`-dependent convenience impls and types (config, storage, scanner) |
| `alloc` | via `std` | heap types (`String`, `Vec`, `BTreeMap`) for `no_std` builds |
| `serde` | no | `Serialize`/`Deserialize` derives on the core types |
| `schemars` | no | `JsonSchema` derives |
| `test-utils` | no | exposes `PermitAllEvaluator` / `DenyAllEvaluator` for downstream tests |

For a `no_std` build, disable default features and opt back into `alloc`:

```sh
cargo add aa-core --no-default-features --features alloc
```

## Usage

```rust
use aa_core::{AgentId, PolicyDecision, RiskTier};

// AgentId is an opaque 16-byte (UUID v4) identifier.
let agent = AgentId::from_bytes([0u8; 16]);
let tier = RiskTier::default();
let decision = PolicyDecision::Allow;
```

See the [API documentation](https://docs.rs/aa-core) for the full set of domain
types (`agent`, `policy`, `capability`, `audit`, `identity`, `risk_tier`, …).

## Links

- Documentation: <https://ai-agent-assembly.github.io/agent-assembly-docs/>
- Source: <https://github.com/ai-agent-assembly/agent-assembly>
- License: [Apache-2.0](../LICENSE)
