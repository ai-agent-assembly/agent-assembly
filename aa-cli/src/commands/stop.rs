//! `aasm stop` — graceful shutdown of the locally-managed gateway
//! process (Epic 17 / AAASM-1568 / Story AAASM-1578).
//!
//! Reads the PID file written by `aasm start` (Impl-3, AAASM-1717),
//! sends `SIGTERM`, polls the target until it exits or `--timeout`
//! elapses, and escalates to `SIGKILL` if necessary. Always cleans
//! up the PID file before exiting so the next `aasm start` sees a
//! clean slate.

/// `aasm stop` command-line arguments.
#[derive(Debug, clap::Args)]
pub struct StopArgs {
    /// Seconds to wait for graceful shutdown before SIGKILL.
    #[arg(long, default_value_t = 30)]
    pub timeout: u64,
}

/// Send the given Unix signal to `pid`. Returns `true` on success,
/// `false` on any failure (process gone, permission denied, etc.).
///
/// Callers treat the result as advisory: a `false` typically means
/// the target has already exited, which is the desired terminal
/// state for `aasm stop` anyway.
pub fn send_signal(pid: u32, sig: libc::c_int) -> bool {
    // SAFETY: `kill` is signal-safe and does not dereference any
    // caller-supplied pointers. The kernel validates the PID and
    // returns an error code instead of crashing on invalid input.
    let rc = unsafe { libc::kill(pid as libc::pid_t, sig) };
    rc == 0
}

/// Poll `is_pid_alive` until the process exits or `deadline` elapses.
///
/// Returns `true` when the process is gone, `false` when the deadline
/// expired with the process still alive. Poll cadence is fixed at
/// 100 ms — small enough that a graceful SIGTERM completing in tens
/// of ms is detected promptly, large enough to avoid pegging the CPU.
pub fn wait_for_exit(pid: u32, deadline: std::time::Duration) -> bool {
    let start = std::time::Instant::now();
    let poll = std::time::Duration::from_millis(100);
    loop {
        if !super::pidfile::is_pid_alive(pid) {
            return true;
        }
        if start.elapsed() >= deadline {
            return false;
        }
        std::thread::sleep(poll);
    }
}
