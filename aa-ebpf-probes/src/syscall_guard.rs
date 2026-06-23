//! Seccomp-style syscall-allowlist enforcement probe (AAASM-3631).
//!
//! Unlike every other probe in this crate — which are observe-only and
//! `return 0` after submitting telemetry — this program ENFORCES: attached at
//! the `raw_syscalls/sys_enter` tracepoint, for any PID present in
//! `PID_FILTER` (the monitored/sandboxed processes) it default-denies any
//! syscall whose number is NOT a key in `SYSCALL_ALLOWLIST`, killing the
//! offending process with `SIGKILL` via `bpf_send_signal`.
//!
//! This is the post-escape kernel-layer second line from the Story's core
//! assumption: even if a sandboxed process escapes the WASM VM, the syscalls
//! it can issue are still confined to the policy-derived allowlist.
//!
//! ## Loading
//!
//! Loaded + attached ONLY through the privileged loader daemon
//! (AAASM-3603/3604); `aa-runtime` holds no `CAP_BPF` (AAASM-3605). The map is
//! populated by the daemon from the policy AST lowering (AAASM-3635).
//!
//! ## Kernel support
//!
//! `bpf_send_signal` requires Linux 5.3+. Unmonitored PIDs (not in
//! `PID_FILTER`) are never inspected, so the probe is a no-op for the rest of
//! the system.

#![no_std]
#![no_main]

use aa_ebpf_common::syscall::MAX_SYSCALL_ALLOWLIST;
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_send_signal},
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};

/// PID filter: only enforce for processes whose tgid is a key here. Mirrors
/// the file-I/O probe's `PID_FILTER`; populated by the daemon for monitored
/// (sandboxed) PIDs.
#[map]
static PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

/// Syscall allowlist keyed by syscall number; a present key = permitted.
#[map]
static SYSCALL_ALLOWLIST: HashMap<u32, u8> = HashMap::with_max_entries(MAX_SYSCALL_ALLOWLIST, 0);

/// `SIGKILL` — sent to a monitored process that issues a non-allowlisted
/// syscall.
const SIGKILL: u32 = 9;

/// `raw_syscalls:sys_enter` layout: the syscall number is the second field
/// (`long id`) after the 8-byte common tracepoint header.
const SYS_ENTER_ID_OFFSET: usize = 8;

/// Enforcement tracepoint: deny-unexpected for monitored PIDs.
///
/// Returning `0` always (the tracepoint return value is not an allow/deny
/// verdict — enforcement is via the kill signal); the function returns early
/// for unmonitored PIDs and allowlisted syscalls.
#[tracepoint]
pub fn aa_syscall_guard(ctx: TracePointContext) -> u32 {
    let _ = try_syscall_guard(&ctx);
    0
}

fn try_syscall_guard(ctx: &TracePointContext) -> Result<(), i64> {
    // Only enforce for monitored (sandboxed) PIDs.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { PID_FILTER.get(&tgid) }.is_none() {
        return Ok(());
    }

    // Read the syscall number from the tracepoint context.
    let syscall_nr = unsafe { ctx.read_at::<i64>(SYS_ENTER_ID_OFFSET) }? as u32;

    // Allowlisted syscalls proceed untouched.
    if unsafe { SYSCALL_ALLOWLIST.get(&syscall_nr) }.is_some() {
        return Ok(());
    }

    // Default-deny: a monitored PID issued a syscall outside the allowlist —
    // kill it. This is the post-escape containment guarantee.
    unsafe {
        bpf_send_signal(SIGKILL);
    }
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
