//! Shared types for process exec tracepoint events (AAASM-39).
//!
//! Emitted by the `sched_process_exec` tracepoint in `aa-ebpf-programs`
//! and consumed by the userspace ring-buffer reader in `aa-ebpf`.
//!
//! Also contains the PID lineage map types (`ProcessNode`) and the
//! shell-injection alert types (`ShellInjectionAlert`) used by the
//! `ProcessLineageTracker` in the userspace loader.

// ---------------------------------------------------------------------------
// ExecEvent — raw ring-buffer event from the BPF tracepoint
// ---------------------------------------------------------------------------

/// Maximum bytes captured for the executable path.
pub const MAX_FILENAME_LEN: usize = 256;

/// Maximum bytes captured for the command-line argument string.
pub const MAX_ARGS_LEN: usize = 512;

/// A single process-exec tracepoint event emitted from kernel-space.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ExecEvent {
    /// Monotonic kernel timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Process ID of the new process.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// User ID that spawned the process.
    pub uid: u32,
    /// Padding for alignment.
    pub _pad: u32,
    /// Null-terminated executable path (up to [`MAX_FILENAME_LEN`] bytes).
    pub filename: [u8; MAX_FILENAME_LEN],
    /// Space-separated argv string (up to [`MAX_ARGS_LEN`] bytes).
    ///
    /// **Known limitation (AAASM-3872):** the `sched_process_exec` tracepoint
    /// that fills this carries only the executable path + pids — it does **not**
    /// expose argv — so the live probe currently records the truncated 16-byte
    /// `comm` here, meaning `/bin/sh -c '…'` logs only `sh`. Genuine argv
    /// capture needs a `syscalls:sys_enter_execve` tracepoint that reads the
    /// `const char *const *argv` pointer array; [`flatten_argv_bounded`] is the
    /// shared bounding primitive for that follow-up.
    pub args: [u8; MAX_ARGS_LEN],
}

/// Flatten an argv vector into the fixed-size, space-separated [`ExecEvent::args`]
/// buffer, bounded so neither the eBPF verifier nor userspace ever reads past
/// [`MAX_ARGS_LEN`].
///
/// Arguments are joined with a single `0x20` space and the result is truncated
/// to at most [`MAX_ARGS_LEN`] bytes (no trailing NUL is appended — callers
/// zero the buffer first and use the returned length). Returns the number of
/// bytes written.
///
/// This is the bounding contract for genuine argv capture (see
/// [`ExecEvent::args`]); it is unit-tested as plain Rust because the kernel
/// probe itself cannot run off-Linux.
#[must_use]
pub fn flatten_argv_bounded(argv: &[&[u8]], out: &mut [u8; MAX_ARGS_LEN]) -> usize {
    let mut written = 0usize;
    for (idx, arg) in argv.iter().enumerate() {
        if written >= MAX_ARGS_LEN {
            break;
        }
        if idx > 0 {
            out[written] = b' ';
            written += 1;
            if written >= MAX_ARGS_LEN {
                break;
            }
        }
        for &byte in arg.iter() {
            if written >= MAX_ARGS_LEN {
                break;
            }
            out[written] = byte;
            written += 1;
        }
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_args_with_single_space() {
        let mut out = [0u8; MAX_ARGS_LEN];
        let n = flatten_argv_bounded(&[b"/bin/sh", b"-c", b"echo hi"], &mut out);
        assert_eq!(&out[..n], b"/bin/sh -c echo hi");
    }

    #[test]
    fn empty_argv_writes_nothing() {
        let mut out = [0u8; MAX_ARGS_LEN];
        assert_eq!(flatten_argv_bounded(&[], &mut out), 0);
    }

    #[test]
    fn truncates_at_max_args_len() {
        let big = [b'a'; MAX_ARGS_LEN + 64];
        let mut out = [0u8; MAX_ARGS_LEN];
        let n = flatten_argv_bounded(&[&big], &mut out);
        assert_eq!(n, MAX_ARGS_LEN);
        assert!(out.iter().all(|&b| b == b'a'));
    }

    #[test]
    fn truncation_can_drop_a_trailing_separator() {
        // Fill the buffer exactly, then a further arg cannot even add its
        // separator — bounding must not panic or overflow.
        let exact = [b'x'; MAX_ARGS_LEN];
        let mut out = [0u8; MAX_ARGS_LEN];
        let n = flatten_argv_bounded(&[&exact, b"dropped"], &mut out);
        assert_eq!(n, MAX_ARGS_LEN);
    }
}

// ---------------------------------------------------------------------------
// ProcessExitEvent — ring-buffer event from the sched_process_exit tracepoint
// ---------------------------------------------------------------------------

/// Event emitted when a monitored process exits.
///
/// Used by the userspace `ProcessLineageTracker` to remove stale PIDs from
/// the lineage map.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitEvent {
    /// Monotonic kernel timestamp (nanoseconds).
    pub timestamp_ns: u64,
    /// Process ID of the exiting process.
    pub pid: u32,
    /// Exit code of the process.
    pub exit_code: i32,
}

// ---------------------------------------------------------------------------
// Lineage-map and alert types (AAASM-39 ProcessLineageTracker)
// ---------------------------------------------------------------------------

/// In-kernel node for the PID lineage map (`BpfHashMap<u32, ProcessNode>`).
///
/// Each entry maps a child PID to its parent and the command that spawned it.
/// Fixed-size layout is required for eBPF map compatibility.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessNode {
    /// Process ID of the child.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Command name (`comm`) of the process, null-padded.
    pub comm: [u8; 16],
    /// Kernel timestamp in nanoseconds when the process was spawned.
    pub spawn_time_ns: u64,
}

/// Maximum number of argv entries captured per execve event.
pub const MAX_ARGV_ENTRIES: usize = 5;

/// Maximum byte length of a single argv entry.
pub const MAX_ARGV_LEN: usize = 128;

/// Event emitted from the eBPF tracepoint to userspace on each `execve` call.
///
/// Sent via ring buffer or perf event array. Fixed-size layout ensures
/// predictable memory use in the eBPF program.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ProcessSpawnEvent {
    /// Process ID of the newly spawned process.
    pub pid: u32,
    /// Parent process ID.
    pub ppid: u32,
    /// Command name (`comm`) of the new process, null-padded.
    pub comm: [u8; 16],
    /// First [`MAX_ARGV_ENTRIES`] argv entries, each null-padded to [`MAX_ARGV_LEN`] bytes.
    pub argv: [[u8; MAX_ARGV_LEN]; MAX_ARGV_ENTRIES],
    /// Number of environment variables passed to execve.
    pub env_count: u32,
    /// Kernel timestamp in nanoseconds.
    pub timestamp_ns: u64,
}

/// Maximum byte length of the executable path in a [`ShellInjectionAlert`].
pub const MAX_EXECUTABLE_LEN: usize = 256;

/// Severity level for a shell injection alert.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AlertLevel {
    /// Informational — known-benign shell spawns (e.g. build scripts).
    Info = 0,
    /// Warning — potentially suspicious spawn (e.g. `python`, `node`).
    Warning = 1,
    /// Critical — high-risk spawn (e.g. `curl`, `wget`, raw `sh`/`bash`).
    Critical = 2,
}

/// Alert emitted when an agent process spawns a suspicious child process.
///
/// Generated in the eBPF program when the spawned executable matches a
/// known shell or download utility pattern (e.g. `bash`, `curl`, `wget`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ShellInjectionAlert {
    /// PID of the monitored agent (or its ancestor in the lineage tree).
    pub parent_pid: u32,
    /// PID of the suspicious child process.
    pub child_pid: u32,
    /// Full executable path of the child, null-padded.
    pub executable: [u8; MAX_EXECUTABLE_LEN],
    /// Severity of the alert.
    pub alert_level: AlertLevel,
    /// Kernel timestamp in nanoseconds.
    pub timestamp_ns: u64,
}
