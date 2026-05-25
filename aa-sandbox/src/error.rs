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
    /// variant. Placeholder for the fuel / limiter mappings landing in
    /// AAASM-2018; carries the wasmtime error's `Display` representation.
    #[error("wasmtime error: {0}")]
    Wasmtime(String),
}
