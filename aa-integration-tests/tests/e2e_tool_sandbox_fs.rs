//! AAASM-2020 / F116 ST-W E2E — WASM/WASI sandbox tool execution.
//!
//! Three scenarios covering both halves of F116 ST-W (parent Story
//! AAASM-1965):
//!
//! * **Scenario 1 — Filesystem isolation** (AAASM-2017).
//!   `sandbox_blocks_etc_passwd_read` registers a WASM tool that calls
//!   `path_open("/etc/passwd")` with an empty preopen allowlist;
//!   asserts the dispatch helper returns
//!   [`SandboxError::FilesystemBlocked`] AND emits the audit-event
//!   sequence `[SandboxStarted, SandboxFilesystemBlocked]`.
//! * **Scenario 2a — CPU timeout** (AAASM-2018). `sandbox_kills_runaway_loop`
//!   registers a runaway-loop WASM tool with a 1 000-unit fuel budget;
//!   asserts [`SandboxError::CpuTimeout`] AND audit
//!   `[SandboxStarted, SandboxCpuTimeout]`.
//! * **Scenario 2b — Memory exhaustion** (AAASM-2018).
//!   `sandbox_kills_memory_bomb` registers a `memory.grow(100)` WASM
//!   tool under the default 16-page (1 MiB) cap; asserts
//!   [`SandboxError::MemoryExhausted`] AND audit
//!   `[SandboxStarted, SandboxOomKilled]`.
//!
//! # Scope note
//!
//! The AAASM-2020 ticket text proposed using `TopologyTestEnv` (the
//! pattern from `e2e_secret_injection.rs`) for "audit-sink readback".
//! That pattern works when the dispatch lives behind an HTTP route
//! (the secret-injection case fronts `/dispatch_tool`). The
//! AAASM-2019 dispatch helper
//! ([`aa_proxy::wasm_dispatch::dispatch_wasm_tool`]) is currently a
//! synchronous pure function not yet wired into any HTTP route — its
//! audit-event sink IS the `audit_events: Vec<AuditEventType>` field
//! on the returned [`WasmDispatchResult::Wasm`]. These tests inspect
//! that field directly, which is the canonical "audit-sink readback"
//! at the helper's contract boundary. Wiring the helper into a
//! production HTTP endpoint is the right scope for a follow-up
//! sub-task once an external surface needs it.

use aa_core::audit::AuditEventType;
use aa_proxy::wasm_dispatch::{dispatch_wasm_tool, WasmDispatchResult};
use aa_sandbox::error::SandboxError;
use aa_sandbox::policy::{SandboxConfig, SandboxLimits};
use aa_sandbox::registry::{ToolKind, ToolRegistry};

const FS_PROBE_WAT: &str = include_str!("../fixtures/wasm/fs_probe.wat");
const RUNAWAY_WAT: &str = include_str!("../fixtures/wasm/runaway.wat");
const MEM_BOMB_WAT: &str = include_str!("../fixtures/wasm/mem_bomb.wat");

/// Build a [`ToolRegistry`] containing a single WASM tool compiled
/// from `wat_source` at test time and registered under `name`.
fn registry_with(name: &str, wat_source: &str, config: SandboxConfig) -> ToolRegistry {
    let module_bytes = wat::parse_str(wat_source).expect("fixture WAT must parse");
    let reg = ToolRegistry::new();
    reg.register(name, ToolKind::Wasm { module_bytes, config });
    reg
}

#[tokio::test]
async fn sandbox_blocks_etc_passwd_read() {
    let reg = registry_with("fs_probe", FS_PROBE_WAT, SandboxConfig::default());

    // The dispatch helper is synchronous wasmtime work; wrap with
    // `spawn_blocking` so the runtime's executor isn't held up by
    // the sandbox call. This mirrors how the proxy data path will
    // host the helper once it lands behind an HTTP endpoint.
    let outcome = tokio::task::spawn_blocking(move || dispatch_wasm_tool("fs_probe", &[], &reg))
        .await
        .expect("dispatch task must not panic");

    match outcome {
        WasmDispatchResult::Wasm { result, audit_events } => {
            assert!(
                matches!(result, Err(SandboxError::FilesystemBlocked { .. })),
                "expected SandboxError::FilesystemBlocked, got {:?}",
                result,
            );
            assert_eq!(
                audit_events,
                vec![AuditEventType::SandboxStarted, AuditEventType::SandboxFilesystemBlocked,],
            );
        }
        WasmDispatchResult::NotWasm => panic!("registered Wasm tool must dispatch as Wasm"),
    }
}

#[tokio::test]
async fn sandbox_kills_runaway_loop() {
    // Tight 1 000-unit fuel budget so the runaway loop trips
    // `Trap::OutOfFuel` within microseconds; default memory + wall-clock
    // budgets are kept (irrelevant — fuel exhausts first under any
    // non-zero budget on a pure-CPU runaway).
    let config = SandboxConfig {
        limits: SandboxLimits {
            fuel: 1_000,
            ..Default::default()
        },
        ..Default::default()
    };
    let reg = registry_with("runaway", RUNAWAY_WAT, config);

    let outcome = tokio::task::spawn_blocking(move || dispatch_wasm_tool("runaway", &[], &reg))
        .await
        .expect("dispatch task must not panic");

    match outcome {
        WasmDispatchResult::Wasm { result, audit_events } => {
            assert!(
                matches!(result, Err(SandboxError::CpuTimeout)),
                "expected SandboxError::CpuTimeout, got {:?}",
                result,
            );
            assert_eq!(
                audit_events,
                vec![AuditEventType::SandboxStarted, AuditEventType::SandboxCpuTimeout],
            );
        }
        WasmDispatchResult::NotWasm => panic!("registered Wasm tool must dispatch as Wasm"),
    }
}

#[tokio::test]
async fn sandbox_kills_memory_bomb() {
    // Default `SandboxLimits::memory_pages = 16` (1 MiB). The fixture
    // declares 1 page and immediately tries to grow by 100 pages
    // (~6.4 MiB), well past the cap — the limiter returns
    // `Err(MemoryExhaustedMarker)` which the runtime surfaces as
    // `SandboxError::MemoryExhausted`.
    let reg = registry_with("mem_bomb", MEM_BOMB_WAT, SandboxConfig::default());

    let outcome = tokio::task::spawn_blocking(move || dispatch_wasm_tool("mem_bomb", &[], &reg))
        .await
        .expect("dispatch task must not panic");

    match outcome {
        WasmDispatchResult::Wasm { result, audit_events } => {
            assert!(
                matches!(result, Err(SandboxError::MemoryExhausted)),
                "expected SandboxError::MemoryExhausted, got {:?}",
                result,
            );
            assert_eq!(
                audit_events,
                vec![AuditEventType::SandboxStarted, AuditEventType::SandboxOomKilled],
            );
        }
        WasmDispatchResult::NotWasm => panic!("registered Wasm tool must dispatch as Wasm"),
    }
}
