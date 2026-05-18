//! `aasm gateway stop` — terminate a running aa-gateway via PID file.
//!
//! Sends SIGTERM and waits up to 10s for graceful shutdown (the gateway flushes
//! audit log and closes gRPC connections cleanly on SIGTERM). Escalates to
//! SIGKILL if the process is still alive after the grace period. Idempotent —
//! exits 0 if no PID file exists.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use super::pid;

const GRACEFUL_TIMEOUT: Duration = Duration::from_secs(10);
const POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Dispatch `aasm gateway stop`.
pub fn dispatch() -> ExitCode {
    let Some((gateway_pid, _, _)) = pid::read_pid() else {
        println!("Gateway is not running.");
        return ExitCode::SUCCESS;
    };

    if !pid::is_process_alive(gateway_pid) {
        println!("Gateway process (pid {gateway_pid}) is no longer alive; cleaning up PID file.");
        let _ = pid::remove_pid();
        return ExitCode::SUCCESS;
    }

    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(gateway_pid as libc::pid_t, libc::SIGTERM) };
        if ret != 0 {
            let err = std::io::Error::last_os_error();
            eprintln!("error: could not send SIGTERM to pid {gateway_pid}: {err}");
            return ExitCode::FAILURE;
        }

        let deadline = Instant::now() + GRACEFUL_TIMEOUT;
        while Instant::now() < deadline {
            if !pid::is_process_alive(gateway_pid) {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }

        if pid::is_process_alive(gateway_pid) {
            eprintln!(
                "warning: gateway (pid {gateway_pid}) did not stop within {}s; \
                 sending SIGKILL. Audit log may be truncated.",
                GRACEFUL_TIMEOUT.as_secs()
            );
            unsafe {
                libc::kill(gateway_pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }

    #[cfg(not(unix))]
    {
        eprintln!("error: stop is only supported on Unix platforms");
        return ExitCode::FAILURE;
    }

    let _ = pid::remove_pid();
    println!("Gateway stopped.");
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    struct EnvGuard<'a> {
        _lock: std::sync::MutexGuard<'a, ()>,
        prior: Option<String>,
    }
    impl<'a> EnvGuard<'a> {
        fn set(value: &str) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior = std::env::var("AA_DATA_DIR").ok();
            std::env::set_var("AA_DATA_DIR", value);
            Self { _lock: lock, prior }
        }
    }
    impl Drop for EnvGuard<'_> {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AA_DATA_DIR", v),
                None => std::env::remove_var("AA_DATA_DIR"),
            }
        }
    }

    #[test]
    fn dispatch_returns_success_when_no_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        assert_eq!(dispatch(), ExitCode::SUCCESS);
    }

    #[test]
    fn dispatch_cleans_up_stale_pid_file_for_dead_process() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        // Spawn a process, wait for it to exit, then use its (now-dead) PID.
        // Avoids u32::MAX which wraps to pid_t -1, causing kill(-1, …) to
        // broadcast to all user processes and kill the test runner.
        let mut child = std::process::Command::new("true")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn 'true'");
        let dead_pid = child.id();
        child.wait().expect("wait failed");

        pid::write_pid(dead_pid, "127.0.0.1:50051", "2026-05-18T00:00:00Z").unwrap();
        assert_eq!(dispatch(), ExitCode::SUCCESS);
        // PID file should have been removed.
        assert!(pid::read_pid().is_none());
    }
}
