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
//!
//! ## Descendant confinement (AAASM-3916)
//!
//! Confinement must follow the process family, not just the single launched
//! PID. Without propagation a monitored process could `fork()`/`exec()` a
//! child whose new tgid is absent from `PID_FILTER`, and the guard would
//! early-return for that child — letting it run **unconfined**, defeating the
//! post-escape guarantee. The [`aa_syscall_guard_fork`] tracepoint closes this
//! by copying `PID_FILTER` membership from a monitored parent to each newly
//! forked child at `sched/sched_process_fork`, so the child is confined from
//! its first syscall. The paired [`aa_syscall_guard_exit`] tracepoint releases
//! a tgid's `PID_FILTER` entry at `sched/sched_process_exit` — but only on
//! whole-process (thread-group-leader) exit, since that tracepoint fires
//! per-thread and tearing the entry down on a non-leader thread exit would
//! unconfine a still-live multithreaded process. Leader-gated cleanup keeps the
//! map (cap 1024) from exhausting — which would make later descendants fail
//! open — and stops a reused pid inheriting stale confinement (AAASM-3921c).
//!
//! Note the `SYSCALL_ALLOWLIST` is a single global map keyed by syscall number
//! (not per-PID), so it already applies to every monitored tgid — there is no
//! per-PID allowlist entry to copy, only the `PID_FILTER` membership.
//!
//! ## Best-effort limitations (AAASM-3872)
//!
//! This probe is a *best-effort* second line, not a synchronous syscall
//! firewall:
//!
//! - **Kill-after-syscall race.** Enforcement is `bpf_send_signal(SIGKILL)` at
//!   `sys_enter`. The signal is delivered at the next signal-check point, so
//!   the *offending* syscall still executes once before the task dies — a
//!   single `connect`/`sendto`/`write`/`unlink` can land. A truly synchronous
//!   deny (return `-EPERM` before the handler runs) needs seccomp-BPF or an
//!   LSM `bpf_lsm` hook, which is out of scope here; see AAASM-3872.
//! - **ABI guard (fixed here).** The allowlist is keyed on **native x86_64**
//!   syscall numbers. The x32 compat ABI is now rejected via
//!   [`aa_ebpf_common::abi::native_syscall_nr`] so a compat number cannot
//!   alias an allow-listed native one; i386 `int 0x80` compat remains
//!   undetectable from the tracepoint `id` alone (documented in `abi`).
//! - **Fork-vs-thread (AAASM-3916).** Propagation keys on the fork
//!   tracepoint's `child_pid`. For a real `fork()`/`clone()` of a new process
//!   `child_pid == child_tgid`, so the child tgid is confined. For a new
//!   *thread* (`CLONE_THREAD`) `child_pid` is a new tid while the thread's tgid
//!   equals the already-confined parent tgid — so threads are covered by the
//!   parent's existing membership; the extra tid key is inert (lookups are by
//!   tgid). A child that forks *before* the guard observes the parent (TOCTOU
//!   at attach time) is not covered — attach the guard before launching the
//!   confined process.

#![no_std]
#![no_main]

use aa_ebpf_common::abi::native_syscall_nr;
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

/// `sched:sched_process_fork` layout — byte offset of the `child_pid` field:
///
/// ```text
/// field:char  parent_comm[16]; offset:8;  size:16;
/// field:pid_t parent_pid;      offset:24; size:4;
/// field:char  child_comm[16];  offset:28; size:16;
/// field:pid_t child_pid;       offset:44; size:4;
/// ```
const SCHED_FORK_CHILD_PID_OFFSET: usize = 44;

/// `PID_FILTER` map value marking a tgid as monitored/confined. Only the
/// presence of the key matters to the enforcement tracepoint.
const PID_MONITORED: u8 = 1;

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

    // Read the raw syscall id from the tracepoint context.
    let raw_id = unsafe { ctx.read_at::<i64>(SYS_ENTER_ID_OFFSET) }?;

    // ABI guard (AAASM-3872): the allowlist is keyed on x86_64 *native*
    // syscall numbers. Resolve the native number, rejecting any call we cannot
    // prove is native — a detectable x32 compat call (carrying
    // `__X32_SYSCALL_BIT`) or a negative sentinel — so a compat-ABI number can
    // never alias an allow-listed native one (e.g. i386 execve=11 vs x86_64
    // munmap=11). Non-native resolves to `None` and is default-denied below.
    let syscall_nr = match native_syscall_nr(raw_id) {
        Some(nr) => nr,
        None => {
            // Compat-ABI / sentinel: not describable by the native allowlist.
            // NOTE: SIGKILL is asynchronous — see the kill-after-syscall race
            // in the module docs; this offending entry may still execute once.
            unsafe {
                bpf_send_signal(SIGKILL);
            }
            return Ok(());
        }
    };

    // Allowlisted syscalls proceed untouched.
    if unsafe { SYSCALL_ALLOWLIST.get(&syscall_nr) }.is_some() {
        return Ok(());
    }

    // Default-deny: a monitored PID issued a syscall outside the allowlist —
    // kill it. This is the post-escape containment guarantee.
    //
    // NOTE (AAASM-3872, kill-after-syscall): `bpf_send_signal` is asynchronous;
    // the SIGKILL lands at the next signal-check point, so *this* syscall still
    // runs once before the task dies. A synchronous deny needs seccomp-BPF/LSM
    // (out of scope — see module docs).
    unsafe {
        bpf_send_signal(SIGKILL);
    }
    Ok(())
}

/// Descendant-confinement tracepoint (AAASM-3916): at `sched_process_fork`,
/// copy `PID_FILTER` membership from a monitored parent to the new child so the
/// child is confined from its first syscall.
///
/// Returns `0` always; the propagation is a best-effort map write and any
/// failure (map full) leaves the child unconfined — fail-open is unavoidable
/// here because the tracepoint cannot block the fork.
#[tracepoint]
pub fn aa_syscall_guard_fork(ctx: TracePointContext) -> u32 {
    let _ = try_fork_propagate(&ctx);
    0
}

fn try_fork_propagate(ctx: &TracePointContext) -> Result<(), i64> {
    // The fork tracepoint fires in the *parent's* context, so the current
    // tgid is the parent's. Only propagate when the parent is confined.
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if unsafe { PID_FILTER.get(&parent_tgid) }.is_none() {
        return Ok(());
    }

    // Read the child's pid. For a real new process `child_pid == child_tgid`,
    // which is the key the enforcement tracepoint looks up; for a thread the
    // tgid is already the (confined) parent's, so the extra key is inert.
    let child_pid = unsafe { ctx.read_at::<u32>(SCHED_FORK_CHILD_PID_OFFSET) }?;

    // Confine the child by mirroring the parent's PID_FILTER membership.
    let _ = PID_FILTER.insert(&child_pid, &PID_MONITORED, 0);
    Ok(())
}

/// Descendant-confinement cleanup tracepoint (AAASM-3921c): at
/// `sched_process_exit`, remove the exiting tgid from `PID_FILTER` — but ONLY on
/// whole-process exit (the thread-group leader, `pid == tgid`).
///
/// `sched_process_exit` fires per-thread. A monitored process is confined by
/// tgid, so removing `PID_FILTER[tgid]` when a non-leader thread of a
/// multithreaded confined process (Go/Node/Python agents are all multithreaded)
/// exits would unconfine the still-live process — it would run its remaining
/// syscalls **unconfined** and its forks would no longer be propagated (the
/// fork handler's parent check would see the tgid absent). The `pid == tgid`
/// guard keeps confinement live for the whole process lifetime and cleans up
/// only when the process itself exits.
///
/// Without any cleanup the fork-propagated `PID_FILTER` entries (cap 1024) are
/// never released, so the map exhausts under a forking workload — after which
/// [`try_fork_propagate`]'s `insert` fails and further descendants run
/// **unconfined** (fail-open), defeating the post-escape guarantee. Worse, a
/// stale entry whose tgid is later reused by an unrelated process would cause
/// the enforcement tracepoint to `SIGKILL` that innocent process. Releasing the
/// entry on leader exit bounds the map and closes the pid-reuse hole; this
/// mirrors the exec probe's own leader-gated exit-side cleanup.
///
/// Returns `0` always; the removal is best-effort and a miss (the tgid was
/// never confined) is a harmless no-op.
#[tracepoint]
pub fn aa_syscall_guard_exit(ctx: TracePointContext) -> u32 {
    let _ = try_exit_cleanup(&ctx);
    0
}

fn try_exit_cleanup(_ctx: &TracePointContext) -> Result<(), i64> {
    // sched_process_exit is per-thread; only clean up on whole-process exit so a
    // non-leader thread exit does not unconfine a live multithreaded process.
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = pid_tgid as u32;
    if pid != tgid {
        return Ok(());
    }
    let _ = PID_FILTER.remove(&tgid);
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
