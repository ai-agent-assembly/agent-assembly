//! BPF tracepoint programs for process exec monitoring (AAASM-39).
//!
//! Three tracepoints share a single ring buffer (`EVENTS`) and a PID
//! filter map (`EXEC_PID_FILTER`):
//!
//! - `handle_sched_process_fork` — fires on every `fork`/`clone`. When the
//!   parent is monitored it records the child→parent tgid mapping in
//!   `PARENT_TGID` and propagates `EXEC_PID_FILTER` membership to the child
//!   (AAASM-3916/3921). This is what supplies the **real** parent pid to the
//!   exec event below.
//! - `handle_sched_process_exec` — fires on every `execve`/`execveat` and
//!   emits an [`ExecEvent`] with pid, ppid, uid, filename, and a best-effort
//!   `args` field. NOTE (AAASM-3872): this tracepoint does not expose argv, so
//!   `args` currently holds the truncated 16-byte `comm`, not the real argv —
//!   see the in-body comment for the `sys_enter_execve` follow-up.
//! - `handle_sched_process_exit` — fires on process exit and emits a
//!   [`ProcessExitEvent`] so userspace can clean up the lineage map.
//!
//! ## Parent pid resolution (AAASM-3921c)
//!
//! The `sched_process_exec` tracepoint's `pid` field is the *new* process's own
//! pid, not its parent. Reading it into `ppid` produced `ppid == pid`, which
//! made the userspace `ProcessLineageTracker::is_descendant_of` walk terminate
//! immediately (it treats `ppid == pid` as a self-cycle) and always return
//! false. The real parent is captured at `sched_process_fork` time (the
//! tracepoint carries `parent_pid`/`child_pid`) and stashed in `PARENT_TGID`;
//! the exec handler now reads `ppid` from there, falling back to `0` (unknown
//! root) when the fork was not observed — never the bogus self-parent.
//!
//! ## Stack-limit workaround
//!
//! [`ExecEvent`] is 792 bytes — above the BPF 512-byte stack limit.
//! We use [`RingBuf::reserve`] to allocate the event directly in ring
//! buffer memory and fill it in place before submitting.

#![no_std]
#![no_main]

use aa_ebpf_common::exec::{ExecEvent, ProcessExitEvent, MAX_ARGS_LEN, MAX_FILENAME_LEN};
use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns, bpf_probe_read_kernel_str_bytes},
    macros::{map, tracepoint},
    maps::{HashMap, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};

// ---------------------------------------------------------------------------
// BPF maps
// ---------------------------------------------------------------------------

/// Ring buffer for exec/exit events (256 KiB).
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

/// PID filter for exec events. Keys are tgids that should be traced;
/// the value is unused (only presence matters).
///
/// Key `0u32` is reserved as a wildcard — when present the probe emits
/// every exec event regardless of tgid. Any other key matches that
/// specific tgid. An empty map filters everything out and the probe
/// emits nothing, so userspace must insert either a specific tgid or
/// the wildcard before relying on events.
#[map]
static EXEC_PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

/// Child tgid → parent tgid, populated by the `sched_process_fork` tracepoint
/// (AAASM-3921c). The exec handler reads the real parent pid from here because
/// the `sched_process_exec` tracepoint only exposes the new process's own pid.
#[map]
static PARENT_TGID: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

/// `sched:sched_process_fork` layout — byte offset of the `child_pid` field:
///
/// ```text
/// field:char  parent_comm[16]; offset:8;  size:16;
/// field:pid_t parent_pid;      offset:24; size:4;
/// field:char  child_comm[16];  offset:28; size:16;
/// field:pid_t child_pid;       offset:44; size:4;
/// ```
const SCHED_FORK_CHILD_PID_OFFSET: usize = 44;

// ---------------------------------------------------------------------------
// PID filter helper
// ---------------------------------------------------------------------------

/// Returns `true` when `tgid` should be traced.
///
/// Key `0u32` is reserved as a wildcard: if it is present in the filter
/// map every tgid is allowed. Otherwise the lookup is a direct match on
/// `tgid`. Both branches are constant-time and avoid map iteration so
/// the BPF verifier accepts the program with no unbounded loop.
///
/// The wildcard lets userspace race-proof a test by inserting key `0`
/// before forking, without needing to know the child's pid ahead of
/// `spawn()` (AAASM-1567).
#[inline(always)]
fn pid_allowed(tgid: u32) -> bool {
    unsafe {
        if EXEC_PID_FILTER.get(&0).is_some() {
            return true;
        }
        EXEC_PID_FILTER.get(&tgid).is_some()
    }
}

// ---------------------------------------------------------------------------
// sched_process_exec tracepoint
// ---------------------------------------------------------------------------

/// Tracepoint on `sched/sched_process_exec`: fires on every execve call.
///
/// Extracts pid, ppid, uid, filename, and the first portion of the
/// command-line arguments, then emits an [`ExecEvent`] to the ring buffer.
#[tracepoint]
pub fn handle_sched_process_exec(ctx: TracePointContext) -> u32 {
    try_sched_process_exec(&ctx).unwrap_or_default()
}

fn try_sched_process_exec(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = uid_gid as u32;

    // Check PID filter — skip if not monitoring this process.
    if !pid_allowed(tgid) {
        return Ok(0);
    }

    // Perform all fallible context reads BEFORE reserving the ring-buffer
    // entry (AAASM-1548). The Linux 6.x BPF verifier rejects programs that
    // hold a ring-buffer reservation across an early-return path
    // ("Unreleased reference id=N alloc_insn=M"), so we resolve the inputs
    // first and only reserve once we know the event can be filled in.
    //
    // sched_process_exec tracepoint format:
    //   field:int __data_loc char[] filename;  offset:8;  size:4;
    //   field:pid_t pid;                       offset:12; size:4;
    //   field:pid_t old_pid;                   offset:16; size:4;
    //
    // NOTE (AAASM-3921c): the `pid` field at offset 12 is the *new* process's
    // own pid, NOT its parent — reading it into `ppid` produced `ppid == pid`
    // and broke lineage walks. The real parent tgid is recorded at fork time in
    // `PARENT_TGID`; resolve it here, falling back to 0 (unknown root) rather
    // than the bogus self-parent when the fork was not observed.
    //   __data_loc is a u32 (low 16 bits = offset, high 16 bits = length).
    let ppid = unsafe { PARENT_TGID.get(&tgid) }.copied().unwrap_or(0);
    let data_loc: u32 = unsafe { ctx.read_at(8) }.map_err(|_| -1i64)?;
    // ctx.command() returns [u8; 16] — already raw bytes, not a string.
    let comm = ctx.command().map_err(|_| -1i64)?;

    // Reserve space in the ring buffer for the event (avoids stack overflow).
    let mut entry = EVENTS.reserve::<ExecEvent>(0).ok_or(-1i64)?;
    let event_ptr = entry.as_mut_ptr();

    unsafe {
        (*event_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*event_ptr).pid = tgid;
        (*event_ptr).uid = uid;
        (*event_ptr)._pad = 0;
        (*event_ptr).ppid = ppid;

        let filename_offset = (data_loc & 0xFFFF) as usize;

        // Zero the filename buffer first.
        (*event_ptr).filename = [0u8; MAX_FILENAME_LEN];

        // Read the filename string from the tracepoint data area.
        let _ = bpf_probe_read_kernel_str_bytes(
            (ctx.as_ptr() as *const u8).add(filename_offset),
            &mut (*event_ptr).filename,
        );

        // Zero the args buffer.
        //
        // KNOWN LIMITATION (AAASM-3872, exec comm-not-argv): the
        // `sched_process_exec` tracepoint carries only the executable path +
        // pids — it does NOT expose argv — so we fall back to the 16-byte
        // `comm`. This means `/bin/sh -c 'curl … | sh'` logs only `sh`; the
        // arguments that carry the actual command are invisible here. Genuine
        // argv capture requires a `syscalls:sys_enter_execve` tracepoint that
        // reads the `const char *const *argv` pointer array (bounded), then
        // flattens it via `aa_ebpf_common::exec::flatten_argv_bounded`. Tracked
        // as a follow-up under AAASM-3872.
        (*event_ptr).args = [0u8; MAX_ARGS_LEN];

        // Copy comm bytes (up to 16) into the args buffer byte by byte.
        // Using a fixed-bound loop to satisfy the BPF verifier.
        let max_copy = if 16 > MAX_ARGS_LEN { MAX_ARGS_LEN } else { 16 };
        let mut i: usize = 0;
        while i < max_copy {
            if comm[i] == 0 {
                break;
            }
            (*event_ptr).args[i] = comm[i];
            i += 1;
        }
    }

    entry.submit(0);
    Ok(0)
}

// ---------------------------------------------------------------------------
// sched_process_exit tracepoint
// ---------------------------------------------------------------------------

/// Tracepoint on `sched/sched_process_exit`: fires when a process exits.
///
/// Emits a [`ProcessExitEvent`] so the userspace `ProcessLineageTracker`
/// can remove the PID from the lineage map.
#[tracepoint]
pub fn handle_sched_process_exit(ctx: TracePointContext) -> u32 {
    try_sched_process_exit(&ctx).unwrap_or_default()
}

fn try_sched_process_exit(_ctx: &TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;

    // Capture monitoring status BEFORE cleanup (cleanup may remove this tgid's
    // own filter entry, which `pid_allowed` would otherwise consult).
    let allowed = pid_allowed(tgid);

    // Unconditionally release this tgid's parent-cache and propagated-filter
    // entries (AAASM-3921c). The fork handler records `PARENT_TGID` for *every*
    // fork (so the exec handler can always resolve the real ppid), so the
    // exit-side cleanup must also be unconditional — otherwise the map would
    // grow without bound and reused pids could inherit a stale parent / filter
    // membership. The wildcard key (0) is never an exiting tgid.
    let _ = PARENT_TGID.remove(&tgid);
    let _ = EXEC_PID_FILTER.remove(&tgid);

    // Only emit the exit event for monitored processes (lineage cleanup).
    if !allowed {
        return Ok(0);
    }

    let mut entry = EVENTS.reserve::<ProcessExitEvent>(0).ok_or(-1i64)?;
    let event_ptr = entry.as_mut_ptr();

    unsafe {
        (*event_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*event_ptr).pid = tgid;
        (*event_ptr).exit_code = 0;
    }

    entry.submit(0);
    Ok(0)
}

// ---------------------------------------------------------------------------
// sched_process_fork tracepoint (AAASM-3921c / AAASM-3916)
// ---------------------------------------------------------------------------

/// Tracepoint on `sched/sched_process_fork`: records the child→parent tgid
/// mapping so the exec handler can report the real parent pid, and propagates
/// `EXEC_PID_FILTER` membership to children of monitored processes so the
/// lineage tree covers the whole family.
#[tracepoint]
pub fn handle_sched_process_fork(ctx: TracePointContext) -> u32 {
    try_sched_process_fork(&ctx).unwrap_or_default()
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // The fork tracepoint fires in the parent's context, so the current tgid is
    // the parent's. Only track children of monitored processes.
    let parent_tgid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if !pid_allowed(parent_tgid) {
        return Ok(0);
    }

    // For a real new process `child_pid == child_tgid` (the key used by the
    // exec handler and the filter); for a thread the tgid is already the
    // monitored parent's, so the extra key is inert.
    let child_pid: u32 = unsafe { ctx.read_at(SCHED_FORK_CHILD_PID_OFFSET) }.map_err(|_| -1i64)?;

    // Record the real parent for the exec handler, and confine the child to the
    // exec filter so its own exec is observed (descendant coverage).
    let _ = PARENT_TGID.insert(&child_pid, &parent_tgid, 0);
    let _ = EXEC_PID_FILTER.insert(&child_pid, &1u8, 0);
    Ok(0)
}

// ---------------------------------------------------------------------------
// Panic handler (required for no_std binaries)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
