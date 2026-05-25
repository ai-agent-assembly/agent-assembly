//! Tool registry — maps `tools/call` names to either a native upstream
//! forward or a sandboxed WASM execution.
//!
//! Consumed by `aa-proxy::wasm_dispatch` (AAASM-2019). The registry lives
//! in `aa-sandbox` (rather than `aa-core::tool_registry` as the AAASM-2019
//! ticket text proposed) because the [`ToolKind::Wasm`] variant references
//! [`crate::policy::SandboxConfig`] directly and the registry uses
//! `std::sync::Arc<RwLock<...>>` — both of which would require lifting
//! `aa-core` out of its `no_std` posture.
//!
//! The registry is intentionally minimal: in-memory, no persistence, no
//! HTTP CRUD surface. Persistent storage + management APIs are out of
//! scope for AAASM-2019 (see the sub-task's explicit out-of-scope
//! section).

use crate::policy::SandboxConfig;

/// Whether a registered tool is forwarded upstream as-is or executed
/// inside the WASM sandbox.
#[derive(Debug, Clone)]
pub enum ToolKind {
    /// Forward the `tools/call` envelope to the upstream MCP server.
    /// Equivalent to "tool is not WASM" — the existing aa-proxy
    /// upstream-forward path handles it unchanged.
    Native,
    /// Execute the tool inside the `aa-sandbox` WASI runtime.
    Wasm {
        /// Raw WebAssembly module bytes (the output of `wat::parse_str`
        /// or `wasm-opt`) loaded into wasmtime via `Module::from_binary`
        /// on every invocation.
        module_bytes: Vec<u8>,
        /// Per-invocation sandbox configuration — preopened-dir
        /// allowlist + fuel / memory / wall-clock budgets. Fed into
        /// `SandboxRuntime::new` and then consumed per `run_tool`.
        config: SandboxConfig,
    },
}
