//! Deterministic error types surfaced by the sandbox runtime.
//!
//! The `SandboxError` enum maps each wasmtime trap or WASI denial to a
//! distinct variant so call-sites can branch on the failure mode without
//! parsing wasmtime's internal trap codes. Variants are intentionally added
//! in later sub-tasks alongside the code paths that produce them:
//!
//! * `FilesystemBlocked` — F116 ST-W S3 (WASI preopened-dir allowlist).
//! * `CpuTimeout` / `WallClockTimeout` — F116 ST-W S4 (wasmtime fuel).
//! * `MemoryExhausted` — F116 ST-W S4 (wasmtime `Store::limiter`).
//!
//! This module ships as a doc-only scaffold under AAASM-2015 (S1); the enum
//! itself lands in S3.
