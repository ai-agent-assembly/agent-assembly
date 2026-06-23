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

use std::sync::mpsc;
use std::time::Duration;

use wasmtime::{Caller, Config, Engine, Linker, Module, ResourceLimiter, Store, Trap};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtx};

use crate::error::SandboxError;
use crate::host_fn::HostFnCounter;
use crate::policy::SandboxConfig;

/// Sentinel error type the [`MemoryLimit`] [`ResourceLimiter`] returns
/// when a `memory.grow` would exceed the configured byte cap. The
/// runtime's call-result branch downcasts to this type to surface
/// [`SandboxError::MemoryExhausted`].
#[derive(Debug)]
struct MemoryExhaustedMarker;

impl std::fmt::Display for MemoryExhaustedMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sandbox memory store limit exceeded")
    }
}

impl std::error::Error for MemoryExhaustedMarker {}

/// Sentinel error a counted host-function import returns when the per-tenant
/// host-function rate limit is exhausted. Like [`MemoryExhaustedMarker`], it
/// rides the `wasmtime::Error` channel out of the guest call and the runtime's
/// call-result branch downcasts to it to surface
/// [`SandboxError::HostFnRateLimited`].
#[derive(Debug)]
struct HostFnRateLimitMarker;

impl std::fmt::Display for HostFnRateLimitMarker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sandbox host-function rate limit exceeded")
    }
}

impl std::error::Error for HostFnRateLimitMarker {}

/// Per-store linear-memory cap enforced via [`Store::limiter`].
///
/// `memory_growing` denies any grow that would push the guest above
/// `max_bytes` by returning [`MemoryExhaustedMarker`] inside the
/// `wasmtime::Error` channel — the wasmtime runtime then surfaces that
/// error from the call's `start.call(...)` return value, which the
/// runtime maps to [`SandboxError::MemoryExhausted`].
struct MemoryLimit {
    max_bytes: usize,
}

impl ResourceLimiter for MemoryLimit {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        if desired > self.max_bytes {
            Err(wasmtime::Error::new(MemoryExhaustedMarker))
        } else {
            Ok(true)
        }
    }

    fn table_growing(&mut self, _current: usize, _desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        Ok(true)
    }
}

/// Per-store state combining the WASI context with the memory limiter.
///
/// Wraps the [`WasiP1Ctx`] previously held directly by the store; the
/// linker's WASI projection closure now returns `&mut state.wasi`, and
/// `Store::limiter` projects to `&mut state.limiter`.
struct StoreState {
    wasi: WasiP1Ctx,
    limiter: MemoryLimit,
    /// Per-invocation host-function call budget (AAASM-3617). Seeded from
    /// [`SandboxConfig::host_fn_rate_limit`] for each `run_tool` call so the
    /// budget is never shared across invocations or tenants. Every counted
    /// host-function import charges this before doing work.
    host_fn_counter: HostFnCounter,
}

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
    linker: Linker<StoreState>,
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
        let mut engine_config = Config::new();
        engine_config.consume_fuel(true);
        engine_config.epoch_interruption(true);
        let engine = Engine::new(&engine_config).map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        let mut linker: Linker<StoreState> = Linker::new(&engine);
        p1::add_to_linker_sync(&mut linker, |s: &mut StoreState| &mut s.wasi)
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        Self::register_host_fns(&mut linker)?;
        Ok(Self { engine, linker, config })
    }

    /// Register the sandbox's custom (non-WASI) host-function imports under the
    /// `aa_sandbox` module namespace.
    ///
    /// Every import registered here is *counted* against the per-tenant
    /// host-function rate limit (AAASM-3617) by charging
    /// [`StoreState::host_fn_counter`] before doing any work, and any guest
    /// memory it reads MUST go through
    /// [`crate::host_fn::read_guest_bytes`] (AAASM-3614). `aa_host_noop` is the
    /// first such import: a minimal counted no-op that exists so the
    /// rate-limit + audit machinery is exercised end-to-end and so future
    /// imports have a worked example of the counted+validated contract.
    fn register_host_fns(linker: &mut Linker<StoreState>) -> Result<(), SandboxError> {
        linker
            .func_wrap("aa_sandbox", "aa_host_noop", |mut caller: Caller<'_, StoreState>| {
                // Charge the per-invocation host-fn budget BEFORE doing work.
                // On breach, return the rate-limit marker through the
                // wasmtime::Error channel so run_tool can map it to
                // SandboxError::HostFnRateLimited.
                caller
                    .data_mut()
                    .host_fn_counter
                    .charge()
                    .map_err(|_| wasmtime::Error::new(HostFnRateLimitMarker))
            })
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        Ok(())
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
    /// * [`SandboxError::CpuTimeout`] if the guest exhausts its fuel
    ///   budget (`Trap::OutOfFuel`).
    /// * [`SandboxError::Wasmtime`] for any other trap (further
    ///   narrowed by `MemoryExhausted` / `WallClockTimeout` mappings
    ///   landing on this branch).
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
        let limiter = MemoryLimit {
            max_bytes: (self.config.limits.memory_pages as usize) * 65_536,
        };
        // Fresh per-invocation host-fn budget so it is never shared across
        // calls or tenants (AAASM-3617).
        let host_fn_counter = HostFnCounter::new(self.config.host_fn_rate_limit.max_calls_per_call);
        let mut store = Store::new(
            &self.engine,
            StoreState {
                wasi,
                limiter,
                host_fn_counter,
            },
        );
        store.limiter(|s| &mut s.limiter);
        store
            .set_fuel(self.config.limits.fuel)
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        // Wall-clock watchdog — spawn a thread that fires
        // `Engine::increment_epoch` after `wall_clock_ms` unless the call
        // completes first. `Engine::increment_epoch` ticks the global
        // counter; since this store armed `set_epoch_deadline(1)` against
        // the engine's current epoch + 1, that single tick trips the
        // deadline and traps the guest with `Trap::Interrupt`.
        //
        // The watchdog blocks on an mpsc channel with `recv_timeout` so
        // the main thread can wake it early — keeps fast-completing
        // calls from paying the full `wall_clock_ms` latency.
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let watchdog = {
            let engine = self.engine.clone();
            let wall_clock_ms = self.config.limits.wall_clock_ms;
            std::thread::spawn(move || {
                if matches!(
                    cancel_rx.recv_timeout(Duration::from_millis(wall_clock_ms)),
                    Err(mpsc::RecvTimeoutError::Timeout)
                ) {
                    engine.increment_epoch();
                }
            })
        };

        let instance = self
            .linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        let start = instance
            .get_typed_func::<(), ()>(&mut store, "_start")
            .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;

        let call_result = start.call(&mut store, ());

        // Cancel the watchdog and reap it. Sending on the cancel channel
        // wakes the watchdog's `recv_timeout` immediately so `join()`
        // returns without paying the remaining `wall_clock_ms`.
        let _ = cancel_tx.send(());
        let _ = watchdog.join();

        match call_result {
            Ok(()) => Ok(SandboxOutput { exit_code: 0 }),
            Err(trap) => {
                if let Some(I32Exit(code)) = trap.downcast_ref::<I32Exit>() {
                    if *code == 0 {
                        Ok(SandboxOutput { exit_code: 0 })
                    } else {
                        Err(SandboxError::FilesystemBlocked { errno: *code as u32 })
                    }
                } else if matches!(trap.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)) {
                    Err(SandboxError::CpuTimeout)
                } else if matches!(trap.downcast_ref::<Trap>(), Some(Trap::Interrupt)) {
                    Err(SandboxError::WallClockTimeout)
                } else if trap.downcast_ref::<MemoryExhaustedMarker>().is_some() {
                    Err(SandboxError::MemoryExhausted)
                } else if trap.downcast_ref::<HostFnRateLimitMarker>().is_some() {
                    Err(SandboxError::HostFnRateLimited)
                } else {
                    Err(SandboxError::Wasmtime(trap.to_string()))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-authored WAT fixture that probes the WASI filesystem
    /// allowlist. The guest:
    ///
    /// 1. Places the literal `/etc/passwd` at memory offset 0.
    /// 2. Invokes `path_open` with `fd = 3` — the first non-stdio fd,
    ///    which is unbound when [`SandboxConfig::preopened_dirs`] is
    ///    empty.
    /// 3. Surfaces the returned errno via `proc_exit`. WASI returns
    ///    `EBADF` (8) when the dir fd is unmapped (the AAASM-2017
    ///    empty-allowlist case) or `ENOTCAPABLE` (76) when a path
    ///    escapes the preopen tree.
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
                (i32.const 3)
                (i32.const 0)
                (i32.const 0)
                (i32.const 11)
                (i32.const 0)
                (i64.const 0)
                (i64.const 0)
                (i32.const 0)
                (i32.const 100)
              )
            )
          )
        )
    "#;

    #[test]
    fn run_tool_blocks_path_open_outside_allowlist() {
        let runtime =
            SandboxRuntime::new(SandboxConfig::default()).expect("SandboxRuntime with empty allowlist must construct");
        let wasm = wat::parse_str(PATH_OPEN_PROBE_WAT).expect("WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        match result {
            Err(SandboxError::FilesystemBlocked { errno }) => {
                assert_ne!(errno, 0, "WASI must surface a non-zero errno for the blocked path_open");
            }
            other => panic!("expected SandboxError::FilesystemBlocked, got {:?}", other),
        }
    }

    /// Hand-authored WAT fixture exercising the fuel budget. `_start`
    /// enters an infinite WebAssembly loop (`(loop (br 0))`); every
    /// iteration consumes ~1 unit of wasmtime instruction fuel, so a
    /// small `SandboxLimits::fuel` budget trips `Trap::OutOfFuel`
    /// within microseconds.
    const RUNAWAY_LOOP_WAT: &str = r#"
        (module
          (func (export "_start")
            (loop $infinite (br $infinite))
          )
        )
    "#;

    #[test]
    fn run_tool_kills_runaway_loop_with_cpu_timeout() {
        let config = SandboxConfig {
            limits: crate::policy::SandboxLimits {
                fuel: 1_000,
                ..Default::default()
            },
            ..Default::default()
        };
        let runtime = SandboxRuntime::new(config).expect("SandboxRuntime with low fuel must construct");
        let wasm = wat::parse_str(RUNAWAY_LOOP_WAT).expect("runaway-loop WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        assert!(
            matches!(result, Err(SandboxError::CpuTimeout)),
            "expected SandboxError::CpuTimeout, got {:?}",
            result,
        );
    }

    /// Hand-authored WAT fixture exercising the memory-store limiter.
    /// `_start` declares a 1-page initial memory and immediately tries
    /// to grow it by 100 pages (= 6.4 MiB), well past the default
    /// `SandboxLimits::memory_pages = 16` (1 MiB) cap. The
    /// `MemoryLimit` `ResourceLimiter` returns `Err(MemoryExhaustedMarker)`
    /// for the grow, which wasmtime surfaces as a trap.
    const MEMORY_BOMB_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (func (export "_start")
            (drop (memory.grow (i32.const 100)))
          )
        )
    "#;

    #[test]
    fn run_tool_kills_memory_bomb_with_memory_exhausted() {
        let runtime = SandboxRuntime::new(SandboxConfig::default())
            .expect("SandboxRuntime with default memory cap must construct");
        let wasm = wat::parse_str(MEMORY_BOMB_WAT).expect("memory-bomb WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        assert!(
            matches!(result, Err(SandboxError::MemoryExhausted)),
            "expected SandboxError::MemoryExhausted, got {:?}",
            result,
        );
    }
}
