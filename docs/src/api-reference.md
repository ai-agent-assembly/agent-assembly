# API Reference

Authoritative API documentation for the Rust crates lives in rustdoc, generated directly from source. This chapter explains how to produce and browse it.

## Generating rustdoc locally

The whole-workspace rustdoc is built with `cargo doc`. The pre-push lefthook hook also runs this command, so the docs are guaranteed to compile on `master`.

```bash
# Build rustdoc for every workspace member without recursing into transitive deps.
cargo doc --workspace --no-deps

# Same, but also opens the index page in the default browser.
cargo doc --workspace --no-deps --open

# Document private items too — useful when working inside a single crate.
cargo doc -p aa-gateway --no-deps --document-private-items --open
```

The HTML output lands in `target/doc/`. Open `target/doc/aa_core/index.html` (or any other crate's index) directly if you'd rather not use `--open`.

> **Note on eBPF crates** — `aa-ebpf*` requires a nightly toolchain to build the BPF target. CI excludes these crates from the standard build matrix and validates them in a dedicated job. For rustdoc on macOS or non-Linux machines, run `cargo doc --workspace --no-deps --exclude aa-ebpf` to skip them.

## Per-crate API surface

Once rustdoc is built (`target/doc/<crate>/index.html`), the most-frequented entry points are:

| Crate | rustdoc entry | Highlights |
|---|---|---|
| [`aa-core`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-core) | `target/doc/aa_core/index.html` | Domain newtypes (`AgentId`, `TeamId`), `ActionType` enum, common traits |
| [`aa-proto`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-proto) | `target/doc/aa_proto/index.html` | Generated protobuf message types — wire format source of truth |
| [`aa-runtime`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-runtime) | `target/doc/aa_runtime/index.html` | Tokio runtime wrapper, agent lifecycle hooks |
| [`aa-proxy`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-proxy) | `target/doc/aa_proxy/index.html` | MitM HTTPS proxy primitives |
| [`aa-gateway`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-gateway) | `target/doc/aa_gateway/index.html` | Policy engine, agent registry, budget tracker |
| [`aa-api`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-api) | `target/doc/aa_api/index.html` | HTTP layer with `utoipa`-generated OpenAPI spec |
| [`aa-cli`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-cli) | `target/doc/aa_cli/index.html` | `aasm` operator binary surface (clap commands) |
| [`aa-sdk-client`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-sdk-client) | `target/doc/aa_sdk_client/index.html` | Shared SDK runtime-client (UDS transport, codec, lifecycle) the Python/Node/Go shims wrap |
| [`aa-wasm`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/aa-wasm) | `target/doc/aa_wasm/index.html` | wasm-bindgen surface for in-browser embedding |
| [`conformance`](https://github.com/AI-agent-assembly/agent-assembly/tree/master/conformance) | `target/doc/conformance/index.html` | Cross-SDK protocol vector harness |

The HTTP API (served by `aa-api`) additionally publishes a generated [OpenAPI v1 spec](https://github.com/AI-agent-assembly/agent-assembly/tree/master/openapi). Validate the spec with `npx @stoplight/spectral-cli lint openapi/v1.yaml`.

## Hosted documentation (deferred)

Publishing rustdoc to [docs.rs](https://docs.rs/) and the mdBook to GitHub Pages is **out of scope for v0.0.1**. Both are tracked as follow-up Stories under Epic [AAASM-13](https://lightning-dust-mite.atlassian.net/browse/AAASM-13). Until then, run `cargo doc --workspace --no-deps --open` and `mdbook serve docs --open` locally.
