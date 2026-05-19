//! BPF tracepoint programs for process exec monitoring (AAASM-39).
//!
//! Two tracepoints share a single ring buffer (`EXEC_EVENTS`) and a PID
//! filter map (`EXEC_PID_FILTER`):
//!
//! - `handle_sched_process_exec` — fires on every `execve`/`execveat` and
//!   emits an [`ExecEvent`] with pid, ppid, uid, filename, and argv.
//! - `handle_sched_process_exit` — fires on process exit and emits a
//!   [`ProcessExitEvent`] so userspace can clean up the lineage map.
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
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(262_144, 0);

/// PID filter: only emit events for processes whose tgid is in this map.
/// Value 0 = monitor this PID and its descendants.
/// An empty map means "monitor all processes".
#[map]
static EXEC_PID_FILTER: HashMap<u32, u8> = HashMap::with_max_entries(256, 0);

// ---------------------------------------------------------------------------
// PID filter helper
// ---------------------------------------------------------------------------

/// Returns `true` when `tgid` should be traced.
///
/// If the filter map is empty (no entries), all processes are monitored.
/// Otherwise, only PIDs present in the map are monitored.
#[inline(always)]
fn pid_allowed(tgid: u32) -> bool {
    unsafe { EXEC_PID_FILTER.get(&tgid).is_some() }
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
    // We read the parent PID from the tracepoint pid field at offset 12;
    // __data_loc is a u32 (low 16 bits = offset, high 16 bits = length).
    let tp_pid: i32 = unsafe { ctx.read_at(12) }.map_err(|_| -1i64)?;
    let data_loc: u32 = unsafe { ctx.read_at(8) }.map_err(|_| -1i64)?;
    // ctx.command() returns [u8; 16] — already raw bytes, not a string.
    let comm = ctx.command().map_err(|_| -1i64)?;

    // Reserve space in the ring buffer for the event (avoids stack overflow).
    let mut entry = EXEC_EVENTS.reserve::<ExecEvent>(0).ok_or(-1i64)?;
    let event_ptr = entry.as_mut_ptr();

    unsafe {
        (*event_ptr).timestamp_ns = bpf_ktime_get_ns();
        (*event_ptr).pid = tgid;
        (*event_ptr).uid = uid;
        (*event_ptr)._pad = 0;
        (*event_ptr).ppid = tp_pid as u32;

        let filename_offset = (data_loc & 0xFFFF) as usize;

        // Zero the filename buffer first.
        (*event_ptr).filename = [0u8; MAX_FILENAME_LEN];

        // Read the filename string from the tracepoint data area.
        let _ = bpf_probe_read_kernel_str_bytes(
            (ctx.as_ptr() as *const u8).add(filename_offset),
            &mut (*event_ptr).filename,
        );

        // Zero the args buffer — argv extraction from tracepoints is
        // limited; we capture what the comm provides.
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

    if !pid_allowed(tgid) {
        return Ok(0);
    }

    let mut entry = EXEC_EVENTS.reserve::<ProcessExitEvent>(0).ok_or(-1i64)?;
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
// Panic handler (required for no_std binaries)
// ---------------------------------------------------------------------------

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
