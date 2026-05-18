//! PID file helpers for `aasm gateway start` / `stop` / `status`.
//!
//! File location: `$AA_DATA_DIR/gateway.pid` when set (used by integration-test
//! harness to isolate per-test state), otherwise `~/.local/share/aasm/gateway.pid`.
//! File format: `<pid>\n<listen_addr>\n<started_at_rfc3339>\n`

use std::io;
use std::path::PathBuf;

/// Returns the path to the gateway PID file.
///
/// Honors `AA_DATA_DIR` so the integration-test harness can give each test its
/// own PID-file location, avoiding races when nextest runs lifecycle tests in
/// parallel. Falls back to `dirs::data_local_dir()` for production.
pub fn pid_path() -> PathBuf {
    if let Ok(dir) = std::env::var("AA_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("gateway.pid");
        }
    }
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("gateway.pid")
}

/// Write `<pid>\n<listen_addr>\n<started_at>\n` to the PID file.
pub fn write_pid(pid: u32, listen: &str, started_at: &str) -> io::Result<()> {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!("{pid}\n{listen}\n{started_at}\n");
    std::fs::write(&path, content)
}

/// Read `(pid, listen_addr, started_at)` from the PID file.
/// Returns `None` if the file is absent or malformed.
pub fn read_pid() -> Option<(u32, String, String)> {
    let content = std::fs::read_to_string(pid_path()).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let listen = lines.next()?.to_string();
    let started_at = lines.next().unwrap_or("").to_string();
    Some((pid, listen, started_at))
}

/// Remove the PID file. Succeeds silently if the file does not exist.
pub fn remove_pid() -> io::Result<()> {
    let path = pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Returns `true` if the process with `pid` is alive (Unix: `kill(pid, 0)`).
/// Always returns `false` on non-Unix platforms.
pub fn is_process_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        let ret = unsafe { libc::kill(pid as libc::pid_t, 0) };
        ret == 0
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
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
        fn unset() -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prior = std::env::var("AA_DATA_DIR").ok();
            std::env::remove_var("AA_DATA_DIR");
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
    fn pid_path_honors_aa_data_dir_when_set() {
        let _guard = EnvGuard::set("/tmp/aasm-gateway-pid-test");
        assert_eq!(pid_path(), PathBuf::from("/tmp/aasm-gateway-pid-test/gateway.pid"));
    }

    #[test]
    fn pid_path_falls_back_to_data_local_dir_when_unset() {
        let _guard = EnvGuard::unset();
        let path = pid_path();
        assert!(
            path.ends_with("aasm/gateway.pid"),
            "default path should end with aasm/gateway.pid; got {path:?}"
        );
    }

    #[test]
    fn pid_path_falls_back_when_aa_data_dir_is_empty() {
        let _guard = EnvGuard::set("");
        let path = pid_path();
        assert!(
            path.ends_with("aasm/gateway.pid"),
            "empty AA_DATA_DIR should fall through to data_local_dir; got {path:?}"
        );
    }

    #[test]
    fn write_and_read_pid_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        write_pid(99999, "127.0.0.1:50051", "2026-05-18T00:00:00Z").unwrap();
        let result = read_pid();
        assert!(result.is_some());
        let (pid, listen, started_at) = result.unwrap();
        assert_eq!(pid, 99999);
        assert_eq!(listen, "127.0.0.1:50051");
        assert_eq!(started_at, "2026-05-18T00:00:00Z");
    }

    #[test]
    fn read_pid_returns_none_when_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        assert!(read_pid().is_none());
    }

    #[test]
    fn remove_pid_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        // No file yet — should succeed silently.
        assert!(remove_pid().is_ok());
        // Write then remove.
        write_pid(1, "127.0.0.1:50051", "2026-05-18T00:00:00Z").unwrap();
        assert!(remove_pid().is_ok());
        assert!(read_pid().is_none());
    }

    #[test]
    fn is_process_alive_returns_true_for_current_process() {
        let pid = std::process::id();
        assert!(is_process_alive(pid));
    }

    #[test]
    fn is_process_alive_returns_false_for_unlikely_pid() {
        // PID 0 is the idle/swapper process; kill(0, 0) succeeds on some OS
        // but PID u32::MAX is reliably non-existent everywhere.
        assert!(!is_process_alive(u32::MAX));
    }
}
