//! Sandbox policy configuration — filesystem allowlist + CPU/memory limits.
//!
//! `SandboxConfig` carries the data that a [`runtime`] invocation needs:
//!
//! * `preopened_dirs` — F116 ST-W S3 (WASI `WasiCtxBuilder::preopened_dir`
//!   allowlist; arbitrary reads outside the listed roots surface as
//!   `error::SandboxError::FilesystemBlocked`).
//! * `limits` — F116 ST-W S4 (`SandboxLimits { fuel, memory_pages,
//!   wall_clock_ms }`, fed into wasmtime `Store::set_fuel` and
//!   `Store::limiter`).
//!
//! This module ships as a doc-only scaffold under AAASM-2015 (S1); the
//! types land in S3 and S4.
//!
//! [`runtime`]: crate::runtime
