//! Deterministic error types surfaced by the sandbox runtime.
//!
//! The [`SandboxError`] enum maps each WASI denial or wasmtime trap to a
//! distinct variant so call-sites can branch on the failure mode without
//! parsing wasmtime's internal trap codes. Additional variants land
//! alongside the code paths that produce them:
//!
//! * [`SandboxError::FilesystemBlocked`] — AAASM-2017 (WASI preopened-dir
//!   allowlist).
//! * `CpuTimeout` / `WallClockTimeout` / `MemoryExhausted` — AAASM-2018
//!   (wasmtime fuel + `Store::limiter`).

use thiserror::Error;

/// Failure modes surfaced by [`crate::runtime::SandboxRuntime::run_tool`].
///
/// All variants are deterministic — the same WASI denial or wasmtime trap
/// always maps to the same variant so downstream audit consumers (see
/// `aa-core::audit::AuditEventType::Sandbox*`, AAASM-2016) and the
/// `aa-proxy` dispatch glue (AAASM-2019) can branch on outcome without
/// inspecting trap internals.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// WASI denied a filesystem operation — either the requested path fell
    /// outside every directory passed to
    /// [`wasmtime_wasi::WasiCtxBuilder::preopened_dir`] (`errno`
    /// `ENOTCAPABLE` / `76`) or the guest tried to use a directory fd not
    /// backed by a preopen (`errno` `EBADF` / `8`). Carries the raw WASI
    /// errno surfaced by the guest via `proc_exit`.
    #[error("sandbox filesystem access denied (WASI errno {errno})")]
    FilesystemBlocked {
        /// WASI preview1 errno value as surfaced via the guest's
        /// `proc_exit` exit code.
        errno: u32,
    },
    /// The supplied WASM module bytes could not be parsed or validated by
    /// wasmtime.
    #[error("invalid WASM module: {0}")]
    InvalidWasm(String),
    /// A wasmtime-level error that does not yet have a deterministic
    /// variant. Carries the wasmtime error's `Display` representation.
    #[error("wasmtime error: {0}")]
    Wasmtime(String),
    /// The guest exhausted its wasmtime instruction-fuel budget — typically
    /// a runaway loop. Mapped from a `Trap::OutOfFuel` wasmtime error.
    /// (AAASM-2018 / F116 ST-W Scenario 2 — CPU half.)
    #[error("sandbox CPU budget exhausted (fuel ran out)")]
    CpuTimeout,
    /// The wall-clock deadline (`SandboxLimits::wall_clock_ms`) elapsed
    /// before the guest returned. Mapped from a wasmtime epoch-interrupt
    /// trap fired by a watchdog thread. Distinguished from
    /// [`SandboxError::CpuTimeout`] so audit consumers can tell whether
    /// the kill was driven by instruction fuel (`CpuTimeout`) or by
    /// real-time stalls in non-fuel-instrumented code paths
    /// (`WallClockTimeout`). (AAASM-2018 / F116 ST-W Scenario 2.)
    #[error("sandbox wall-clock deadline exceeded")]
    WallClockTimeout,
    /// The guest attempted to grow linear memory beyond
    /// `SandboxLimits::memory_pages * 64 KiB`. Mapped from
    /// [`wasmtime::ResourceLimiter::memory_growing`] returning `Err`
    /// with the crate-internal marker error. (AAASM-2018 / F116 ST-W
    /// Scenario 2 — memory half.)
    #[error("sandbox memory store limit exhausted")]
    MemoryExhausted,
}
