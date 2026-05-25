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

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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

/// In-memory `tools/call` → [`ToolKind`] map shared across the proxy's
/// per-connection tasks.
///
/// Backed by `Arc<RwLock<HashMap<String, ToolKind>>>` so the proxy's
/// async data path can `.read()` per `tools/call` without contending
/// with rare `.write()`s from registry-management code paths.
/// `ToolRegistry` is `Clone` (just bumps the `Arc`'s refcount) so it
/// can be handed to as many tasks as the proxy spawns.
///
/// The registry is intentionally empty by default; consumers register
/// tools at proxy boot or via the management surface that lands in a
/// later sub-task.
#[derive(Clone, Default)]
pub struct ToolRegistry {
    inner: Arc<RwLock<HashMap<String, ToolKind>>>,
}

impl ToolRegistry {
    /// Construct an empty registry. Equivalent to `ToolRegistry::default()`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `kind` under `name`, returning the previously-registered
    /// [`ToolKind`] (if any). Useful for hot-swap semantics.
    pub fn register(&self, name: impl Into<String>, kind: ToolKind) -> Option<ToolKind> {
        self.inner
            .write()
            .expect("ToolRegistry lock poisoned")
            .insert(name.into(), kind)
    }

    /// Look up `name`. Returns a cloned [`ToolKind`] so callers don't
    /// hold the registry's `RwLock` across `await` points (the WASM
    /// dispatch helper does its `SandboxRuntime::run_tool` invocation
    /// outside of any registry lock).
    pub fn get(&self, name: &str) -> Option<ToolKind> {
        self.inner
            .read()
            .expect("ToolRegistry lock poisoned")
            .get(name)
            .cloned()
    }

    /// Number of currently-registered tools.
    pub fn len(&self) -> usize {
        self.inner.read().expect("ToolRegistry lock poisoned").len()
    }

    /// `true` iff no tools are registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_is_empty_and_len_zero() {
        let reg = ToolRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        assert!(reg.get("anything").is_none());
    }

    #[test]
    fn register_native_then_lookup_returns_native() {
        let reg = ToolRegistry::new();
        let prev = reg.register("forward_to_upstream", ToolKind::Native);
        assert!(prev.is_none(), "first register should return no previous entry");
        assert_eq!(reg.len(), 1);
        match reg.get("forward_to_upstream") {
            Some(ToolKind::Native) => {}
            other => panic!("expected ToolKind::Native, got {:?}", other.map(|_| "Wasm")),
        }
    }

    #[test]
    fn register_wasm_then_lookup_returns_wasm_with_bytes() {
        let reg = ToolRegistry::new();
        let module_bytes = b"\x00asm\x01\x00\x00\x00".to_vec(); // minimal WASM magic + version
        reg.register(
            "run_in_sandbox",
            ToolKind::Wasm {
                module_bytes: module_bytes.clone(),
                config: SandboxConfig::default(),
            },
        );
        match reg.get("run_in_sandbox") {
            Some(ToolKind::Wasm { module_bytes: got, .. }) => {
                assert_eq!(got, module_bytes, "registered module bytes must round-trip on lookup");
            }
            other => panic!("expected ToolKind::Wasm, got {:?}", other.map(|_| "Native")),
        }
    }

    #[test]
    fn register_replaces_existing_entry() {
        let reg = ToolRegistry::new();
        reg.register("same_name", ToolKind::Native);
        let prev = reg.register(
            "same_name",
            ToolKind::Wasm {
                module_bytes: vec![0, 1, 2],
                config: SandboxConfig::default(),
            },
        );
        assert!(
            matches!(prev, Some(ToolKind::Native)),
            "register should return the previous entry on replace"
        );
        assert_eq!(reg.len(), 1, "len stays at 1 after a replace");
        assert!(matches!(reg.get("same_name"), Some(ToolKind::Wasm { .. })));
    }
}
