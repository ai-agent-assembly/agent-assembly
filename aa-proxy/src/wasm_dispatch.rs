//! WASM tool dispatch — consults [`ToolRegistry`] and routes WASM-marked
//! `tools/call` requests through [`SandboxRuntime`] instead of forwarding
//! upstream.
//!
//! The proxy data path calls [`dispatch_wasm_tool`] after the gateway's
//! `CheckAction` returns `McpDecision::Allow`. If the named tool is
//! [`ToolKind::Wasm`], this helper runs it in the sandbox and reports the
//! outcome alongside the audit-event sequence the data path should write.
//! If the tool is missing from the registry or registered as
//! [`ToolKind::Native`], the helper returns [`WasmDispatchResult::NotWasm`]
//! and the data path falls through to its existing upstream-forward
//! pipeline unchanged.
//!
//! ## Audit-event lifecycle
//!
//! Every WASM dispatch emits a paired event sequence — a
//! [`AuditEventType::SandboxStarted`] at the start, then exactly one
//! outcome event ([`SandboxFilesystemBlocked`], [`SandboxCpuTimeout`],
//! [`SandboxOomKilled`], or [`SandboxTerminated`]). Wall-clock breaches
//! and InvalidWasm / generic wasmtime errors are folded into
//! `SandboxCpuTimeout` and `SandboxTerminated` respectively (see the
//! per-variant doc-comments on `AuditEventType` for the rationale).
//!
//! [`AuditEventType::SandboxStarted`]: aa_core::audit::AuditEventType::SandboxStarted
//! [`SandboxFilesystemBlocked`]: aa_core::audit::AuditEventType::SandboxFilesystemBlocked
//! [`SandboxCpuTimeout`]: aa_core::audit::AuditEventType::SandboxCpuTimeout
//! [`SandboxOomKilled`]: aa_core::audit::AuditEventType::SandboxOomKilled
//! [`SandboxTerminated`]: aa_core::audit::AuditEventType::SandboxTerminated
//! [`ToolRegistry`]: aa_sandbox::registry::ToolRegistry
//! [`ToolKind`]: aa_sandbox::registry::ToolKind
//! [`ToolKind::Wasm`]: aa_sandbox::registry::ToolKind::Wasm
//! [`ToolKind::Native`]: aa_sandbox::registry::ToolKind::Native
//! [`SandboxRuntime`]: aa_sandbox::runtime::SandboxRuntime

use aa_core::audit::AuditEventType;
use aa_sandbox::error::SandboxError;
use aa_sandbox::registry::{ToolKind, ToolRegistry};
use aa_sandbox::runtime::{SandboxOutput, SandboxRuntime};

/// Outcome of a single `tools/call` dispatch attempt.
#[derive(Debug)]
pub enum WasmDispatchResult {
    /// The named tool is missing from the registry, or registered as
    /// [`ToolKind::Native`]. The caller should fall through to the
    /// existing upstream-forward pipeline.
    NotWasm,
    /// The named tool is [`ToolKind::Wasm`]; it ran (or failed to
    /// instantiate) inside the sandbox. The caller must NOT forward
    /// upstream — `result` is the final outcome the client receives.
    Wasm {
        /// The sandbox runtime's verdict — `Ok` on clean exit (the
        /// guest's `proc_exit(0)` or a `_start` return), `Err` on any
        /// isolation kill or wasmtime error.
        result: Result<SandboxOutput, SandboxError>,
        /// Ordered sequence of audit events that describe the
        /// invocation's lifecycle. Always begins with
        /// [`AuditEventType::SandboxStarted`] and ends with exactly one
        /// outcome event.
        audit_events: Vec<AuditEventType>,
    },
}

/// Dispatch `tool_name` against the [`ToolRegistry`].
///
/// Returns [`WasmDispatchResult::NotWasm`] for unknown tools and
/// [`ToolKind::Native`] entries. Otherwise constructs a
/// [`SandboxRuntime`] from the registered [`SandboxConfig`], invokes
/// `run_tool(module_bytes, args)`, and packages the verdict + lifecycle
/// audit events.
///
/// `args` is forwarded to `SandboxRuntime::run_tool` unchanged; in
/// AAASM-2019 the sandbox runtime ignores it (no WASI args wiring yet),
/// but the parameter is kept so the caller doesn't need to change shape
/// when the dispatch glue lands in AAASM-2020.
///
/// [`SandboxConfig`]: aa_sandbox::policy::SandboxConfig
pub fn dispatch_wasm_tool(tool_name: &str, args: &[u8], registry: &ToolRegistry) -> WasmDispatchResult {
    let kind = match registry.get(tool_name) {
        Some(k) => k,
        None => return WasmDispatchResult::NotWasm,
    };
    let (module_bytes, config) = match kind {
        ToolKind::Native => return WasmDispatchResult::NotWasm,
        ToolKind::Wasm { module_bytes, config } => (module_bytes, config),
    };

    let mut audit_events = vec![AuditEventType::SandboxStarted];
    let result = match SandboxRuntime::new(config) {
        Ok(runtime) => runtime.run_tool(&module_bytes, args),
        Err(e) => Err(e),
    };
    audit_events.push(outcome_event(&result));

    WasmDispatchResult::Wasm { result, audit_events }
}

/// Map the sandbox verdict to its terminal audit event.
///
/// * `Ok(_)` and `InvalidWasm` / generic `Wasmtime` errors → `SandboxTerminated`
///   (lifecycle ended without being killed by an isolation primitive).
/// * `FilesystemBlocked` → `SandboxFilesystemBlocked`.
/// * `CpuTimeout` and `WallClockTimeout` → `SandboxCpuTimeout` (the audit
///   variant's doc-comment explicitly covers both fuel and wall-clock
///   kills).
/// * `MemoryExhausted` → `SandboxOomKilled`.
fn outcome_event(result: &Result<SandboxOutput, SandboxError>) -> AuditEventType {
    match result {
        Ok(_) => AuditEventType::SandboxTerminated,
        Err(SandboxError::FilesystemBlocked { .. }) => AuditEventType::SandboxFilesystemBlocked,
        Err(SandboxError::CpuTimeout) | Err(SandboxError::WallClockTimeout) => AuditEventType::SandboxCpuTimeout,
        Err(SandboxError::MemoryExhausted) => AuditEventType::SandboxOomKilled,
        Err(SandboxError::InvalidWasm(_)) | Err(SandboxError::Wasmtime(_)) => AuditEventType::SandboxTerminated,
    }
}
