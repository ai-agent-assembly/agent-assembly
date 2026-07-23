# aa-sandbox

WebAssembly/WASI sandbox runtime for Agent Assembly tool execution.

[![crates.io](https://img.shields.io/crates/v/aa-sandbox?logo=rust&label=crates.io)](https://crates.io/crates/aa-sandbox)
[![docs.rs](https://img.shields.io/docsrs/aa-sandbox?logo=docsdotrs&label=docs.rs)](https://docs.rs/aa-sandbox)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue?logo=apache)](https://github.com/ai-agent-assembly/agent-assembly/blob/HEAD/LICENSE)

Hosts a `wasmtime`-based runtime that executes WASM-marked tools registered with
the gateway, enforcing three independent isolation surfaces — filesystem allowlist
(WASI preopened directories), CPU budget (instruction fuel), and memory ceiling —
each surfaced as a deterministic `SandboxError`.

Part of [Agent Assembly](https://github.com/ai-agent-assembly/agent-assembly) — [documentation](https://docs.agent-assembly.com/) · [monorepo](https://github.com/ai-agent-assembly/agent-assembly).
