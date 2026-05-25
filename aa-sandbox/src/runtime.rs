//! Sandbox runtime — wasmtime engine + per-invocation store wiring.
//!
//! `SandboxRuntime` owns a long-lived [`wasmtime::Engine`] configured with
//! `consume_fuel(true)` and instantiates a fresh `Store` per `run_tool`
//! call. The store is wired with:
//!
//! * WASI preview 1 host handlers built from a [`policy::SandboxConfig`]
//!   `preopened_dirs` allowlist (F116 ST-W S3).
//! * `Store::set_fuel(...)` + `Store::limiter(...)` from the same config's
//!   `limits` field (F116 ST-W S4).
//!
//! Each invocation surfaces a deterministic
//! [`error::SandboxError`](crate::error) variant on failure; success
//! returns a wasmtime [`Trap`]-free completion plus the audit lifecycle
//! events emitted by `aa-proxy` in F116 ST-W S5.
//!
//! This module ships as a doc-only scaffold under AAASM-2015 (S1); the
//! `SandboxRuntime` type lands in S3.
//!
//! [`Trap`]: https://docs.rs/wasmtime/latest/wasmtime/struct.Trap.html
//! [`policy::SandboxConfig`]: crate::policy
