//! WASM tool dispatch — consults [`ToolRegistry`] and routes WASM-marked
//! `tools/call` requests through [`SandboxRuntime`] instead of forwarding
//! upstream.
//!
//! Originally shipped in `aa-proxy::wasm_dispatch` under AAASM-2019;
//! relocated to `aa-sandbox::wasm_dispatch` under AAASM-2033 so the
//! `aa-api` `/dispatch_tool` HTTP route can consume it without reversing
//! the workspace dep direction (`aa-api → aa-proxy` would be a layer
//! inversion; `aa-api → aa-sandbox` is a clean primitive dep).
//!
//! Callers — either the proxy data path or the `aa-api` dispatch route —
//! invoke [`dispatch_wasm_tool`] after the gateway's `CheckAction`
//! returns `Allow`. If the named tool is [`ToolKind::Wasm`], this helper
//! runs it in the sandbox and reports the outcome alongside the
//! audit-event sequence the caller should write. If the tool is missing
//! from the registry or registered as [`ToolKind::Native`], the helper
//! returns [`WasmDispatchResult::NotWasm`] and the caller falls through
//! to its existing pipeline unchanged.
//!
//! ## Audit-event lifecycle
//!
//! Every WASM dispatch emits a paired event sequence — a
//! [`AuditEventType::SandboxStarted`] at the start, then exactly one
//! outcome event ([`AuditEventType::SandboxFilesystemBlocked`],
//! [`AuditEventType::SandboxCpuTimeout`],
//! [`AuditEventType::SandboxOomKilled`], or
//! [`AuditEventType::SandboxTerminated`]). Wall-clock breaches and
//! `InvalidWasm` / generic `Wasmtime` errors are folded into
//! `SandboxCpuTimeout` and `SandboxTerminated` respectively (see the
//! per-variant doc-comments on `AuditEventType` for the rationale).

use aa_core::audit::AuditEventType;

use crate::error::SandboxError;
use crate::registry::{ToolKind, ToolRegistry};
use crate::runtime::{SandboxOutput, SandboxRuntime};

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
/// `args` is forwarded to `SandboxRuntime::run_tool` unchanged; the
/// sandbox runtime currently ignores it (no WASI args wiring yet), but
/// the parameter is kept so the caller's shape stays stable once WASI
/// args land.
///
/// [`SandboxConfig`]: crate::policy::SandboxConfig
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{SandboxConfig, SandboxLimits};

    /// Minimal `_start` that returns cleanly (empty body). Used to
    /// assert the happy-path `SandboxTerminated` lifecycle event.
    /// Avoids `proc_exit(0)` because the wasmtime-wasi backtrace
    /// wrapper around an `I32Exit(0)` doesn't downcast through
    /// `wasmtime::Error::downcast_ref::<I32Exit>` cleanly on every
    /// path; a body-less `_start` is the canonical clean-exit shape.
    const NOOP_WAT: &str = r#"
        (module
          (func (export "_start"))
        )
    "#;

    /// Same `path_open("/etc/passwd")` probe as AAASM-2017's runtime
    /// fixture — confirms `FilesystemBlocked` round-trips through the
    /// dispatch helper.
    const PATH_OPEN_PROBE_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "path_open"
            (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $proc_exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "/etc/passwd")
          (func (export "_start")
            (call $proc_exit
              (call $path_open
                (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 11)
                (i32.const 0) (i64.const 0) (i64.const 0) (i32.const 0)
                (i32.const 100)
              )
            )
          )
        )
    "#;

    /// Same runaway loop as AAASM-2018's runtime fixture.
    const RUNAWAY_LOOP_WAT: &str = r#"
        (module
          (func (export "_start")
            (loop $infinite (br $infinite))
          )
        )
    "#;

    /// Same memory bomb as AAASM-2018's runtime fixture.
    const MEMORY_BOMB_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "_start")
            (drop (memory.grow (i32.const 100)))
          )
        )
    "#;

    fn registry_with(name: &str, wat_source: &str) -> ToolRegistry {
        registry_with_config(name, wat_source, SandboxConfig::default())
    }

    fn registry_with_config(name: &str, wat_source: &str, config: SandboxConfig) -> ToolRegistry {
        let module_bytes = wat::parse_str(wat_source).expect("test WAT fixture must parse");
        let reg = ToolRegistry::new();
        reg.register(name, ToolKind::Wasm { module_bytes, config });
        reg
    }

    #[test]
    fn dispatch_unknown_tool_returns_not_wasm() {
        let reg = ToolRegistry::new();
        assert!(matches!(
            dispatch_wasm_tool("never_registered", &[], &reg),
            WasmDispatchResult::NotWasm
        ));
    }

    #[test]
    fn dispatch_native_tool_returns_not_wasm() {
        let reg = ToolRegistry::new();
        reg.register("forward_upstream", ToolKind::Native);
        assert!(matches!(
            dispatch_wasm_tool("forward_upstream", &[], &reg),
            WasmDispatchResult::NotWasm
        ));
    }

    #[test]
    fn dispatch_wasm_tool_emits_started_then_terminated_on_success() {
        let reg = registry_with("noop", NOOP_WAT);
        match dispatch_wasm_tool("noop", &[], &reg) {
            WasmDispatchResult::Wasm { result, audit_events } => {
                assert!(result.is_ok(), "noop must succeed, got {:?}", result);
                assert_eq!(
                    audit_events,
                    vec![AuditEventType::SandboxStarted, AuditEventType::SandboxTerminated],
                );
            }
            WasmDispatchResult::NotWasm => panic!("expected Wasm outcome, got NotWasm"),
        }
    }

    #[test]
    fn dispatch_wasm_tool_emits_started_then_filesystem_blocked() {
        let reg = registry_with("fs_probe", PATH_OPEN_PROBE_WAT);
        match dispatch_wasm_tool("fs_probe", &[], &reg) {
            WasmDispatchResult::Wasm { result, audit_events } => {
                assert!(
                    matches!(result, Err(SandboxError::FilesystemBlocked { .. })),
                    "expected FilesystemBlocked, got {:?}",
                    result,
                );
                assert_eq!(
                    audit_events,
                    vec![AuditEventType::SandboxStarted, AuditEventType::SandboxFilesystemBlocked],
                );
            }
            WasmDispatchResult::NotWasm => panic!("expected Wasm outcome, got NotWasm"),
        }
    }

    #[test]
    fn dispatch_wasm_tool_emits_started_then_cpu_timeout_on_runaway_loop() {
        let config = SandboxConfig {
            limits: SandboxLimits {
                fuel: 1_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let reg = registry_with_config("runaway", RUNAWAY_LOOP_WAT, config);
        match dispatch_wasm_tool("runaway", &[], &reg) {
            WasmDispatchResult::Wasm { result, audit_events } => {
                assert!(
                    matches!(result, Err(SandboxError::CpuTimeout)),
                    "expected CpuTimeout, got {:?}",
                    result,
                );
                assert_eq!(
                    audit_events,
                    vec![AuditEventType::SandboxStarted, AuditEventType::SandboxCpuTimeout],
                );
            }
            WasmDispatchResult::NotWasm => panic!("expected Wasm outcome, got NotWasm"),
        }
    }

    #[test]
    fn dispatch_wasm_tool_emits_started_then_oom_killed_on_memory_bomb() {
        let reg = registry_with("mem_bomb", MEMORY_BOMB_WAT);
        match dispatch_wasm_tool("mem_bomb", &[], &reg) {
            WasmDispatchResult::Wasm { result, audit_events } => {
                assert!(
                    matches!(result, Err(SandboxError::MemoryExhausted)),
                    "expected MemoryExhausted, got {:?}",
                    result,
                );
                assert_eq!(
                    audit_events,
                    vec![AuditEventType::SandboxStarted, AuditEventType::SandboxOomKilled],
                );
            }
            WasmDispatchResult::NotWasm => panic!("expected Wasm outcome, got NotWasm"),
        }
    }
}
