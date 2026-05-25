//! Sandbox policy configuration — filesystem allowlist + (in AAASM-2018)
//! CPU/memory limits.
//!
//! [`SandboxConfig`] carries the data that a single
//! [`crate::runtime::SandboxRuntime::run_tool`] invocation needs. In this
//! sub-task it carries only the filesystem allowlist; the
//! `SandboxLimits { fuel, memory_pages, wall_clock_ms }` field lands in
//! AAASM-2018 (fuel + `Store::limiter`).

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
}
