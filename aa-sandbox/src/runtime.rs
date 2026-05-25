//! Sandbox runtime — wasmtime engine + per-invocation store wiring.
//!
//! [`SandboxRuntime`] owns a long-lived [`wasmtime::Engine`] and a
//! [`wasmtime::Linker`] pre-populated with WASI preview 1 host functions.
//! [`SandboxRuntime::run_tool`] instantiates a fresh
//! [`wasmtime::Store`] per call, builds a
//! [`wasmtime_wasi::WasiCtx`] from the [`SandboxConfig`]'s
//! `preopened_dirs` allowlist, instantiates the WASM module, and invokes
//! the conventional `_start` entry point.
//!
//! WASI's preview 1 file-system handlers (`fd_open`, `fd_read`, `fd_write`,
//! `path_open`) are responsible for enforcing the allowlist: paths outside
//! every preopened directory surface as `errno` `ENOTCAPABLE` (`76`) or
//! `EBADF` (`8`) to the guest. The runtime maps any non-zero WASI exit
//! code from the guest's `proc_exit` into
//! [`SandboxError::FilesystemBlocked`].
//!
//! Fuel + memory-store limits land in AAASM-2018; ToolRegistry dispatch +
//! audit-event emission land in AAASM-2019.

use wasmtime::{Engine, Linker, Module, Store};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtx};

use crate::error::SandboxError;
use crate::policy::SandboxConfig;

/// Successful sandboxed-tool invocation outcome.
///
/// In AAASM-2017 this carries only the WASI exit code; structured tool
/// output (stdout capture, return value decoding) lands in AAASM-2019
/// alongside the `ToolRegistry` dispatch glue that knows the call's
/// semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxOutput {
    /// WASI exit code surfaced by the guest. Zero indicates a clean
    /// `_start` return (or an explicit `proc_exit(0)`); any non-zero
    /// value would have been mapped to a `SandboxError` variant by
    /// [`SandboxRuntime::run_tool`] before reaching this struct.
    pub exit_code: i32,
}

/// Sandbox host runtime — owns the wasmtime [`Engine`] and the
/// WASI-populated [`Linker`].
///
/// One runtime instance can service many `run_tool` invocations; each
/// invocation gets a fresh [`Store`] + [`WasiCtx`] so per-call state never
/// leaks between tools.
pub struct SandboxRuntime {
    engine: Engine,
    linker: Linker<WasiP1Ctx>,
    config: SandboxConfig,
}

impl SandboxRuntime {
    /// Build a runtime with a default wasmtime [`Engine`] and a
    /// [`Linker`] pre-populated with WASI preview 1 host functions.
    ///
    /// Returns [`SandboxError::Wasmtime`] if WASI registration fails (in
    /// practice this only happens on a programming error — duplicate
    /// import name).
    pub fn new(config: SandboxConfig) -> Result<Self, SandboxError> {
        let engine = Engine::default();
        let mut linker: Linker<WasiP1Ctx> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |cx| cx).map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        Ok(Self { engine, linker, config })
    }

    /// Instantiate the supplied WASM module under WASI preview 1 and
    /// invoke its `_start` entry point.
    ///
    /// A fresh [`Store`] + [`WasiCtx`] is built per call; the WASI ctx
    /// only sees directories listed in [`SandboxConfig::preopened_dirs`].
    /// `args` is accepted as part of the AAASM-2017 signature contract
    /// (see parent Story AAASM-1965) but is unused until the
    /// `ToolRegistry` dispatch glue lands in AAASM-2019 — the guest sees
    /// an empty WASI args vector for now.
    ///
    /// Returns:
    /// * `Ok(SandboxOutput { exit_code: 0 })` if `_start` returns
    ///   cleanly or the guest calls `proc_exit(0)`.
    /// * [`SandboxError::FilesystemBlocked`] if the guest calls
    ///   `proc_exit(n)` with non-zero `n` (the WASI FS handlers surface
    ///   `ENOTCAPABLE`/`EBADF` via the exit code in AAASM-2017's WAT
    ///   fixtures).
    /// * [`SandboxError::InvalidWasm`] if wasmtime cannot parse/validate
    ///   the module bytes.
    /// * [`SandboxError::Wasmtime`] for any other trap; this is the
    ///   fallback bucket that AAASM-2018 (fuel/limiter) narrows into
    ///   `CpuTimeout` and `MemoryExhausted`.
    pub fn run_tool(&self, wasm_bytes: &[u8], _args: &[u8]) -> Result<SandboxOutput, SandboxError> {
        let module =
            Module::from_binary(&self.engine, wasm_bytes).map_err(|e| SandboxError::InvalidWasm(e.to_string()))?;

        let mut builder = WasiCtx::builder();
        for preopen in &self.config.preopened_dirs {
            builder
                .preopened_dir(
                    &preopen.host_path,
                    &preopen.guest_path,
                    DirPerms::all(),
                    FilePerms::all(),
                )
                .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        }
        let wasi = builder.build_p1();
        let mut store = Store::new(&self.engine, wasi);

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;

        match start.call(&mut store, ()) {
            Ok(()) => Ok(SandboxOutput { exit_code: 0 }),
            Err(trap) => {
                if let Some(I32Exit(code)) = trap.downcast_ref::<I32Exit>() {
                    if *code == 0 {
                        Ok(SandboxOutput { exit_code: 0 })
                    } else {
                        Err(SandboxError::FilesystemBlocked { errno: *code as u32 })
                    }
                } else {
                    Err(SandboxError::Wasmtime(trap.to_string()))
                }
            }
        }
    }
}
