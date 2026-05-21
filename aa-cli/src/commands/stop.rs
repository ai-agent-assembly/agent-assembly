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

/// Entry point for `aasm stop`.
///
/// Resolves the PID file, decides between four terminal states —
/// no pid file, stale pid file, graceful SIGTERM, escalated SIGKILL —
/// and always cleans up the PID file before returning so the next
/// `aasm start` sees a clean slate.
pub fn run(args: StopArgs) -> std::process::ExitCode {
    use std::process::ExitCode;
    let pid_file = match super::pidfile::pid_file_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("aasm stop: {e}");
            return ExitCode::FAILURE;
        }
    };
    run_with_pid_file(args, &pid_file)
}

/// Same as [`run`] but with an injectable PID-file path so unit
/// tests can drive the full flow against a temp directory.
pub fn run_with_pid_file(args: StopArgs, pid_file: &std::path::Path) -> std::process::ExitCode {
    use std::process::ExitCode;

    let pid = match super::pidfile::read_pid(pid_file) {
        Ok(Some(p)) => p,
        Ok(None) => {
            println!("No gateway running.");
            return ExitCode::SUCCESS;
        }
        Err(e) => {
            eprintln!("aasm stop: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !super::pidfile::is_pid_alive(pid) {
        // Stale PID — clean up the file and exit silently.
        let _ = super::pidfile::remove_pid(pid_file);
        println!("No gateway running (stale pid file removed).");
        return ExitCode::SUCCESS;
    }

    let timeout = std::time::Duration::from_secs(args.timeout);
    if args.timeout > 0 {
        // Graceful shutdown — SIGTERM, then poll for exit.
        let _ = send_signal(pid, libc::SIGTERM);
        if !wait_for_exit(pid, timeout) {
            eprintln!(
                "aasm stop: gateway PID {pid} did not exit within {}s; escalating to SIGKILL",
                args.timeout,
            );
            let _ = send_signal(pid, libc::SIGKILL);
            // Allow a brief window for the kernel to reap the process.
            let _ = wait_for_exit(pid, std::time::Duration::from_secs(2));
        }
    } else {
        // --timeout 0 → skip graceful shutdown entirely.
        let _ = send_signal(pid, libc::SIGKILL);
        let _ = wait_for_exit(pid, std::time::Duration::from_secs(2));
    }

    let _ = super::pidfile::remove_pid(pid_file);
    println!("Gateway stopped (PID {pid}).");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stringify `ExitCode` (which does not impl `PartialEq`) so tests
    /// can compare against `ExitCode::SUCCESS` / `ExitCode::FAILURE`.
    fn fmt(code: std::process::ExitCode) -> String {
        format!("{code:?}")
    }

    #[test]
    fn run_with_missing_pid_file_returns_success() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        let exit = run_with_pid_file(StopArgs { timeout: 5 }, &pid_file);
        assert_eq!(fmt(exit), fmt(std::process::ExitCode::SUCCESS));
    }

    #[test]
    fn run_with_stale_pid_removes_file_and_returns_success() {
        let tmp = tempfile::TempDir::new().unwrap();
        let pid_file = tmp.path().join("gateway.pid");
        // A near-`pid_t::MAX` value is in nobody's PID space on modern Unix,
        // mirroring the convention from pidfile's is_pid_alive test.
        let dead_pid = (libc::pid_t::MAX as u32).saturating_sub(1);
        super::super::pidfile::write_pid(&pid_file, dead_pid).unwrap();
        assert!(pid_file.exists());

        let exit = run_with_pid_file(StopArgs { timeout: 5 }, &pid_file);
        assert_eq!(fmt(exit), fmt(std::process::ExitCode::SUCCESS));
        assert!(!pid_file.exists(), "stale pid file should be cleaned up");
    }
}
