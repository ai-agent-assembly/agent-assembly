//! WebAssembly/WASI sandbox runtime for Agent Assembly tool execution.
//!
//! `aa-sandbox` hosts a wasmtime-based runtime that executes WASM-marked
//! tools registered with the gateway. The runtime enforces three independent
//! isolation surfaces — filesystem allowlist (WASI preopened directories),
//! CPU budget (wasmtime instruction fuel), and memory ceiling (wasmtime
//! `Store::limiter`) — each surfaced as a deterministic `SandboxError`
//! variant.
//!
//! The crate is workspace-internal and consumed by `aa-proxy` via the
//! `ToolRegistry` dispatch surface introduced in F116 ST-W S5. See the
//! parent Story AAASM-1965 for scope and acceptance criteria.

#![forbid(unsafe_code)]

pub mod error;
pub mod host_fn;
pub mod policy;
pub mod registry;
pub mod runtime;
pub mod wasm_dispatch;
