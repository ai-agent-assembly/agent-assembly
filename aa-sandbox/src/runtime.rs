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
use std::time::{Duration, Instant};

use wasmtime::{Caller, Config, Engine, Linker, Module, ResourceLimiter, Store, Trap, UpdateDeadline};
use wasmtime_wasi::p1::{self, WasiP1Ctx};
use wasmtime_wasi::{DirPerms, FilePerms, I32Exit, WasiCtx};

use crate::error::SandboxError;
use crate::host_fn::HostFnCounter;
use crate::policy::{PreopenAccess, SandboxConfig};

/// Sentinel error type the [`StoreLimits`] [`ResourceLimiter`] returns
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

/// Maximum number of elements any single guest table may grow to.
///
/// `table.grow` is one non-fuel-metered instruction that forces the host to
/// eagerly allocate `delta` fresh table slots, so an uncapped grow is an
/// OOM-DoS primitive the linear-memory cap ([`StoreLimits::max_bytes`]) does
/// not cover. This constant bounds the worst-case eager table allocation to a
/// value far above any legitimate tool's dynamic table growth. (AAASM-3990.)
///
/// It is a compile-time constant rather than a [`crate::policy::SandboxLimits`]
/// field only because promoting it to the public config would break
/// out-of-crate callers that build `SandboxLimits` with every field enumerated;
/// a config field can follow once those call sites adopt `..Default::default()`.
const MAX_TABLE_ELEMENTS: usize = 10_000;

/// Per-store resource caps enforced via [`Store::limiter`].
///
/// `memory_growing` denies any grow that would push the guest above
/// `max_bytes` by returning [`MemoryExhaustedMarker`] inside the
/// `wasmtime::Error` channel — the wasmtime runtime then surfaces that
/// error from the call's `start.call(...)` return value, which the
/// runtime maps to [`SandboxError::MemoryExhausted`].
///
/// `table_growing` caps table-element growth at `max_table_elements`. Unlike
/// the memory path it rejects *gracefully* (`Ok(false)`) rather than trapping:
/// that yields the standard WASM `table.grow` failure sentinel (`-1`) to the
/// guest while still preventing the eager host allocation an uncapped grow
/// would force. (AAASM-3990.)
struct StoreLimits {
    max_bytes: usize,
    max_table_elements: usize,
}

impl ResourceLimiter for StoreLimits {
    fn memory_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        if desired > self.max_bytes {
            Err(wasmtime::Error::new(MemoryExhaustedMarker))
        } else {
            Ok(true)
        }
    }

    fn table_growing(&mut self, _current: usize, desired: usize, _maximum: Option<usize>) -> wasmtime::Result<bool> {
        // Reject growth past the element cap gracefully: `Ok(false)` makes
        // `table.grow` return -1 to the guest (well-defined WASM semantics)
        // without the host eagerly allocating the requested slots — closing
        // the uncapped-`table.grow` OOM-DoS gap. (AAASM-3990.)
        Ok(desired <= self.max_table_elements)
    }
}

/// Whether a store's own wall-clock budget has elapsed.
///
/// The epoch-deadline callback in [`SandboxRuntime::run_tool`] calls this on
/// each epoch tick to decide whether to interrupt *this* store. Because
/// `Engine::increment_epoch` is process-global and shared by every store on the
/// engine, one invocation's watchdog can tick a co-scheduled invocation's
/// deadline; gating the trap on the store's own `start`/`wall_clock` makes the
/// wall-clock kill per-store rather than engine-wide. (AAASM-3990.)
fn wall_clock_expired(start: Instant, wall_clock: Duration) -> bool {
    start.elapsed() >= wall_clock
}

/// Per-store state combining the WASI context with the resource limiter.
///
/// Wraps the [`WasiP1Ctx`] previously held directly by the store; the
/// linker's WASI projection closure now returns `&mut state.wasi`, and
/// `Store::limiter` projects to `&mut state.limiter`.
struct StoreState {
    wasi: WasiP1Ctx,
    limiter: StoreLimits,
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
/// leaks between tools. The wall-clock deadline is enforced per-store
/// (AAASM-3990), so concurrent `run_tool` calls on a shared runtime cannot
/// cross-trigger each other's timeouts.
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
            // Least-privilege grant: read-only unless the policy explicitly
            // opted this mount into read-write. Avoids the DirPerms::all() /
            // FilePerms::all() over-grant. (AAASM-3618.)
            let (dir_perms, file_perms) = match preopen.access {
                PreopenAccess::ReadOnly => (DirPerms::READ, FilePerms::READ),
                PreopenAccess::ReadWrite => (DirPerms::all(), FilePerms::all()),
            };
            builder
                .preopened_dir(&preopen.host_path, &preopen.guest_path, dir_perms, file_perms)
                .map_err(|e| SandboxError::Wasmtime(e.to_string()))?;
        }
        let wasi = builder.build_p1();
        let limiter = StoreLimits {
            max_bytes: (self.config.limits.memory_pages as usize) * 65_536,
            max_table_elements: MAX_TABLE_ELEMENTS,
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
        // Per-store wall-clock enforcement (AAASM-3990). `Engine::increment_epoch`
        // is a process-global tick shared by every store on this engine, so an
        // unconditional `epoch_deadline_trap()` would let one invocation's
        // watchdog kill a *co-scheduled* invocation on a shared `SandboxRuntime`.
        // Instead, gate the trap on this store's own elapsed wall clock: a
        // spurious tick from a sibling's watchdog re-arms the deadline
        // (`Continue`) rather than trapping, and only this store's own watchdog
        // tick — fired once `wall_clock` has elapsed — actually interrupts it.
        let deadline_start = Instant::now();
        let wall_clock = Duration::from_millis(self.config.limits.wall_clock_ms);
        store.epoch_deadline_callback(move |_store| {
            if wall_clock_expired(deadline_start, wall_clock) {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });

        // Wall-clock watchdog — spawn a thread that fires
        // `Engine::increment_epoch` after `wall_clock` unless the call completes
        // first. The tick advances the engine's global epoch to this store's
        // armed deadline; the callback above then confirms this store's own
        // budget is spent and returns `UpdateDeadline::Interrupt`, trapping the
        // guest with `Trap::Interrupt` (mapped to `WallClockTimeout`).
        //
        // The watchdog blocks on an mpsc channel with `recv_timeout` so the main
        // thread can wake it early — keeps fast-completing calls from paying the
        // full `wall_clock` latency.
        let (cancel_tx, cancel_rx) = mpsc::channel::<()>();
        let watchdog = {
            let engine = self.engine.clone();
            std::thread::spawn(move || {
                if matches!(cancel_rx.recv_timeout(wall_clock), Err(mpsc::RecvTimeoutError::Timeout)) {
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
    use crate::policy::{PreopenAccess, PreopenedDir};

    /// Guest that opens `f.txt` in preopen fd 3 requesting write rights,
    /// `fd_write`s one byte, and `proc_exit`s with the errno of whichever
    /// step fails first (0 if the write succeeds).
    ///
    /// Memory layout: bytes 0..5 = "f.txt"; word at 16 = opened-fd output;
    /// the iovec (ptr=64, len=1) at 32..40; byte to write at 64; nwritten
    /// output at 48.
    const PREOPEN_WRITE_PROBE_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "path_open"
            (func $path_open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "fd_write"
            (func $fd_write (param i32 i32 i32 i32) (result i32)))
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $proc_exit (param i32)))
          (memory (export "memory") 1)
          (data (i32.const 0) "f.txt")
          (data (i32.const 64) "X")
          (func (export "_start")
            (local $err i32)
            ;; path_open(dirfd=3, dirflags=0, path=0, path_len=5, oflags=0,
            ;;   fs_rights_base=FD_READ|FD_WRITE=66, fs_rights_inheriting=66,
            ;;   fdflags=0, opened_fd_out=16)
            (local.set $err
              (call $path_open
                (i32.const 3) (i32.const 0) (i32.const 0) (i32.const 5)
                (i32.const 0) (i64.const 66) (i64.const 66) (i32.const 0)
                (i32.const 16)))
            (if (i32.ne (local.get $err) (i32.const 0))
              (then (call $proc_exit (local.get $err))))
            ;; build iovec at 32: base=64, len=1
            (i32.store (i32.const 32) (i32.const 64))
            (i32.store (i32.const 36) (i32.const 1))
            ;; fd_write(opened_fd, iovs=32, iovs_len=1, nwritten=48)
            (local.set $err
              (call $fd_write
                (i32.load (i32.const 16)) (i32.const 32) (i32.const 1) (i32.const 48)))
            (call $proc_exit (local.get $err))
          )
        )
    "#;

    fn write_probe_runtime(access: PreopenAccess) -> (SandboxRuntime, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("temp dir");
        std::fs::write(dir.path().join("f.txt"), b"seed").expect("seed file");
        let config = SandboxConfig {
            preopened_dirs: vec![PreopenedDir {
                host_path: dir.path().to_path_buf(),
                guest_path: ".".to_string(),
                access,
            }],
            ..Default::default()
        };
        (SandboxRuntime::new(config).expect("runtime must construct"), dir)
    }

    #[test]
    fn read_only_preopen_denies_write() {
        let (runtime, _dir) = write_probe_runtime(PreopenAccess::ReadOnly);
        let wasm = wat::parse_str(PREOPEN_WRITE_PROBE_WAT).expect("write-probe WAT must parse");
        let result = runtime.run_tool(&wasm, &[]);
        // A read-only mount must reject the write — either at path_open (rights
        // masked) or fd_write — surfacing a non-zero WASI errno.
        assert!(
            matches!(result, Err(SandboxError::FilesystemBlocked { errno }) if errno != 0),
            "read-only preopen must deny write, got {:?}",
            result,
        );
    }

    #[test]
    fn read_write_preopen_allows_write() {
        let (runtime, _dir) = write_probe_runtime(PreopenAccess::ReadWrite);
        let wasm = wat::parse_str(PREOPEN_WRITE_PROBE_WAT).expect("write-probe WAT must parse");
        let result = runtime.run_tool(&wasm, &[]);
        assert!(
            matches!(result, Ok(SandboxOutput { exit_code: 0 })),
            "read-write preopen must allow write, got {:?}",
            result,
        );
    }

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
    /// `StoreLimits` `ResourceLimiter` returns `Err(MemoryExhaustedMarker)`
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

    /// Table-bomb fixture (AAASM-3990): declares a 1-element funcref table and
    /// asks `table.grow` to add 20 000 elements — well past the
    /// `MAX_TABLE_ELEMENTS` (10 000) cap. A rejected grow returns `-1` (the
    /// standard WASM sentinel), which the guest surfaces via `proc_exit(42)`.
    const TABLE_BOMB_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $proc_exit (param i32)))
          (memory (export "memory") 1)
          (table 1 funcref)
          (func (export "_start")
            (if (i32.eq (table.grow (ref.null func) (i32.const 20000)) (i32.const -1))
              (then (call $proc_exit (i32.const 42)))
              (else (call $proc_exit (i32.const 0)))))
        )
    "#;

    /// Same table, grown by only 100 elements — comfortably under the cap — so
    /// `table.grow` succeeds (returns the prior size, not `-1`) and the guest
    /// exits cleanly. Guards against the cap over-rejecting legitimate growth.
    const TABLE_GROW_OK_WAT: &str = r#"
        (module
          (import "wasi_snapshot_preview1" "proc_exit"
            (func $proc_exit (param i32)))
          (memory (export "memory") 1)
          (table 1 funcref)
          (func (export "_start")
            (if (i32.eq (table.grow (ref.null func) (i32.const 100)) (i32.const -1))
              (then (call $proc_exit (i32.const 42)))
              (else (call $proc_exit (i32.const 0)))))
        )
    "#;

    #[test]
    fn run_tool_rejects_table_grow_beyond_cap() {
        let runtime =
            SandboxRuntime::new(SandboxConfig::default()).expect("SandboxRuntime with default caps must construct");
        let wasm = wat::parse_str(TABLE_BOMB_WAT).expect("table-bomb WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        // The limiter rejects the grow, the guest observes -1 and proc_exits 42,
        // which the runtime maps to FilesystemBlocked { errno: 42 }.
        assert!(
            matches!(result, Err(SandboxError::FilesystemBlocked { errno: 42 })),
            "expected rejected table.grow (guest proc_exit 42), got {:?}",
            result,
        );
    }

    #[test]
    fn run_tool_allows_table_grow_within_cap() {
        let runtime =
            SandboxRuntime::new(SandboxConfig::default()).expect("SandboxRuntime with default caps must construct");
        let wasm = wat::parse_str(TABLE_GROW_OK_WAT).expect("table-grow WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        assert!(
            matches!(result, Ok(SandboxOutput { exit_code: 0 })),
            "expected within-cap table.grow to succeed, got {:?}",
            result,
        );
    }

    /// WAT fixture that imports the counted `aa_sandbox/aa_host_noop` host
    /// function and calls it `$n` times. With a host-fn budget of `N`, calling
    /// it `N + 1` times trips the rate limit on the last call.
    const HOST_FN_CALL_LOOP_WAT: &str = r#"
        (module
          (import "aa_sandbox" "aa_host_noop" (func $noop))
          (func (export "_start")
            (local $i i32)
            (local.set $i (i32.const 0))
            (block $done
              (loop $again
                (br_if $done (i32.ge_u (local.get $i) (i32.const 5)))
                (call $noop)
                (local.set $i (i32.add (local.get $i) (i32.const 1)))
                (br $again)
              )
            )
          )
        )
    "#;

    fn host_fn_loop_config(max_calls_per_call: u32) -> SandboxConfig {
        SandboxConfig {
            host_fn_rate_limit: crate::policy::HostFnRateLimit {
                max_calls_per_call,
                window_calls: None,
            },
            ..Default::default()
        }
    }

    #[test]
    fn run_tool_denies_host_fn_calls_over_rate_limit() {
        // Budget of 3, guest calls the host fn 5 times → the 4th call is
        // denied with HostFnRateLimited.
        let runtime = SandboxRuntime::new(host_fn_loop_config(3)).expect("runtime must construct");
        let wasm = wat::parse_str(HOST_FN_CALL_LOOP_WAT).expect("host-fn loop WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        assert!(
            matches!(result, Err(SandboxError::HostFnRateLimited)),
            "expected SandboxError::HostFnRateLimited, got {:?}",
            result,
        );
    }

    #[test]
    fn run_tool_allows_host_fn_calls_within_rate_limit() {
        // Budget of 5, guest calls the host fn exactly 5 times → all allowed,
        // clean exit.
        let runtime = SandboxRuntime::new(host_fn_loop_config(5)).expect("runtime must construct");
        let wasm = wat::parse_str(HOST_FN_CALL_LOOP_WAT).expect("host-fn loop WAT fixture must parse");

        let result = runtime.run_tool(&wasm, &[]);

        assert!(
            matches!(result, Ok(SandboxOutput { exit_code: 0 })),
            "expected clean exit within budget, got {:?}",
            result,
        );
    }
}
