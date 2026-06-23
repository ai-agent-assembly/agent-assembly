//! Sandbox policy configuration — filesystem allowlist + CPU/memory limits.
//!
//! [`SandboxConfig`] carries the data that a single
//! [`crate::runtime::SandboxRuntime::run_tool`] invocation needs:
//!
//! * `preopened_dirs` — WASI filesystem allowlist (AAASM-2017).
//! * `limits` — per-invocation CPU + memory budget (AAASM-2018), fed
//!   into wasmtime `Store::set_fuel`, `Store::limiter`, and the
//!   wall-clock watchdog thread.

use std::path::PathBuf;

/// Mapping of one host directory into the WASI sandbox.
///
/// Each entry becomes a single
/// [`wasmtime_wasi::WasiCtxBuilder::preopened_dir`] call on the guest's
/// `WasiCtx`. The guest sees `host_path` mounted at `guest_path` and can
/// only resolve WASI `path_open` calls within that subtree; anything else
/// surfaces as `errno` `ENOTCAPABLE` and bubbles up as
/// [`crate::error::SandboxError::FilesystemBlocked`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreopenedDir {
    /// Real path on the host filesystem.
    pub host_path: PathBuf,
    /// Path the guest sees this directory mounted at (e.g. `"."` for the
    /// guest's working directory or `"/data"` for a labelled mount).
    pub guest_path: String,
}

/// Per-invocation CPU + memory budget for a sandboxed tool.
///
/// Each call to [`crate::runtime::SandboxRuntime::run_tool`] is bounded
/// by all three of these limits independently:
///
/// * `fuel` exhaustion surfaces as
///   [`crate::error::SandboxError::CpuTimeout`].
/// * `memory_pages` exhaustion (the guest tried to grow linear memory
///   beyond `memory_pages * 64 KiB`) surfaces as
///   [`crate::error::SandboxError::MemoryExhausted`].
/// * `wall_clock_ms` elapsed before the guest returned surfaces as
///   [`crate::error::SandboxError::WallClockTimeout`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxLimits {
    /// Wasmtime instruction-fuel budget (units of `Store::set_fuel`).
    /// One unit ≈ one instruction; runaway loops drain this quickly.
    pub fuel: u64,
    /// Maximum linear-memory pages the guest can grow to. One WASM page
    /// is 64 KiB so the byte cap is `memory_pages * 65_536`.
    pub memory_pages: u32,
    /// Wall-clock deadline in milliseconds. Enforced by a watchdog
    /// thread that calls `Engine::increment_epoch` after this delay; the
    /// runtime arms `Store::set_epoch_deadline(1)` and
    /// `epoch_deadline_trap` so the tick fires a trap.
    pub wall_clock_ms: u64,
}

impl Default for SandboxLimits {
    /// Safe-by-default budget. All three values are intentionally modest
    /// so a misconfigured tool fails fast instead of running unbounded:
    /// 10 million fuel units, 16 pages (1 MiB) of memory, 5 seconds
    /// wall-clock.
    fn default() -> Self {
        Self {
            fuel: 10_000_000,
            memory_pages: 16,
            wall_clock_ms: 5_000,
        }
    }
}

/// Per-tenant call budget for host-function imports.
///
/// Host functions are the classic sandbox-escape conduit: an attacker fuzzes
/// a weakly-validated import until it yields a memory-safety or
/// path-traversal primitive. A per-tenant call rate-limit caps how many times
/// a single invocation can drive any one host-function import, so a fuzzing
/// loop cannot brute-force a weakness or DoS the host. The limit is enforced
/// per [`crate::runtime::SandboxRuntime::run_tool`] call (AAASM-3617); this
/// struct is the policy half (AAASM-3613).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostFnRateLimit {
    /// Maximum number of host-function calls a single
    /// [`crate::runtime::SandboxRuntime::run_tool`] invocation may make.
    /// Counted across all validated host-function imports; the
    /// `max_calls_per_call + 1`-th call is denied with
    /// [`crate::error::SandboxError::HostFnRateLimited`].
    pub max_calls_per_call: u32,
    /// Optional finer-grained per-window cap. `None` (the [`Default`]) means
    /// only `max_calls_per_call` applies; `Some(n)` reserves a tighter
    /// rolling-window budget for a future windowed counter. Carried on the
    /// policy now so the on-disk contract is stable before the windowed
    /// enforcement lands.
    pub window_calls: Option<u32>,
}

impl Default for HostFnRateLimit {
    /// Conservative default: at most 1024 host-function calls per invocation,
    /// no extra window cap. Modest enough that a fuzzing loop trips the limit
    /// quickly, generous enough that a legitimate tool's handful of host-fn
    /// calls is never throttled.
    fn default() -> Self {
        Self {
            max_calls_per_call: 1_024,
            window_calls: None,
        }
    }
}

/// Sandbox configuration consumed by [`crate::runtime::SandboxRuntime`].
///
/// An empty `preopened_dirs` list is the most-restrictive case: the guest
/// cannot open any file via WASI — every `path_open` returns `EBADF`
/// because there is no preopen handle to resolve paths against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SandboxConfig {
    /// WASI preopened-directory allowlist. Each entry is presented to the
    /// guest as one mount point with full `DirPerms` / `FilePerms`. Empty
    /// (the [`Default`]) means "no filesystem visibility" — every WASI
    /// `path_open` returns `EBADF`.
    pub preopened_dirs: Vec<PreopenedDir>,
    /// CPU + memory + wall-clock budget. See [`SandboxLimits`] for the
    /// per-field semantics; the [`Default`] is a safe-by-default budget
    /// (10M fuel, 16 pages = 1 MiB memory, 5s wall-clock).
    pub limits: SandboxLimits,
    /// Tenant the sandboxed tool runs on behalf of. Carried so the
    /// host-function rate-limit and its audit events are attributable to a
    /// tenant. The [`Default`] is the empty string (unattributed).
    pub tenant_id: String,
    /// Per-tenant host-function call budget. See [`HostFnRateLimit`]; the
    /// [`Default`] caps a single invocation at 1024 host-function calls.
    pub host_fn_rate_limit: HostFnRateLimit,
}
