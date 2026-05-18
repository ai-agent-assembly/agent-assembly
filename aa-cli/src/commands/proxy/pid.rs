//! PID file helpers for `aasm proxy start` / `stop`.
//!
//! File location: `$AA_DATA_DIR/proxy.pid` if `AA_DATA_DIR` is set
//! (used by the integration-test harness to isolate per-test state), otherwise
//! `~/.local/share/aasm/proxy.pid`.
//! File format: `<pid>\n<listen_addr>\n`

use std::io;
use std::path::PathBuf;

/// Returns the path to the proxy PID file.
///
/// Honors `AA_DATA_DIR` so the `aa-integration-tests` harness can give each
/// test its own PID-file location, avoiding races on the shared user-home
/// path when `cargo nextest` runs lifecycle tests in parallel. Falls back to
/// `dirs::data_local_dir()` for the default production install.
pub fn pid_path() -> PathBuf {
    if let Ok(dir) = std::env::var("AA_DATA_DIR") {
        if !dir.is_empty() {
            return PathBuf::from(dir).join("proxy.pid");
        }
    }
    dirs::data_local_dir()
        .expect("cannot determine local data directory")
        .join("aasm")
        .join("proxy.pid")
}

/// Write `<pid>\n<listen_addr>\n` to the PID file, creating parent directories as needed.
pub fn write_pid(listen_addr: &str) -> io::Result<()> {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!("{}\n{}\n", std::process::id(), listen_addr);
    std::fs::write(&path, content)
}

/// Read `(pid, listen_addr)` from the PID file. Returns `None` if the file is absent or malformed.
pub fn read_pid() -> Option<(u32, String)> {
    let content = std::fs::read_to_string(pid_path()).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let addr = lines.next()?.to_string();
    Some((pid, addr))
}

/// Remove the PID file. Succeeds silently if the file does not exist.
pub fn remove_pid() -> io::Result<()> {
    let path = pid_path();
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialise tests that mutate the process-global `AA_DATA_DIR` env var
    /// so parallel nextest threads can't race on it.
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
    impl<'a> Drop for EnvGuard<'a> {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AA_DATA_DIR", v),
                None => std::env::remove_var("AA_DATA_DIR"),
            }
        }
    }

    #[test]
    fn pid_path_honors_aa_data_dir_when_set() {
        let _guard = EnvGuard::set("/tmp/aasm-proxy-pid-test-fixture");
        assert_eq!(pid_path(), PathBuf::from("/tmp/aasm-proxy-pid-test-fixture/proxy.pid"));
    }

    #[test]
    fn pid_path_falls_back_to_data_local_dir_when_unset() {
        let _guard = EnvGuard::unset();
        let path = pid_path();
        assert!(
            path.ends_with("aasm/proxy.pid"),
            "default path should end with aasm/proxy.pid; got {path:?}"
        );
    }

    #[test]
    fn pid_path_falls_back_when_aa_data_dir_is_empty() {
        let _guard = EnvGuard::set("");
        let path = pid_path();
        assert!(
            path.ends_with("aasm/proxy.pid"),
            "empty AA_DATA_DIR should fall through to data_local_dir; got {path:?}"
        );
    }

    #[test]
    fn write_and_read_pid_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        write_pid("127.0.0.1:8899").unwrap();
        let (pid, addr) = read_pid().expect("pid file should be readable after write");
        assert_eq!(pid, std::process::id());
        assert_eq!(addr, "127.0.0.1:8899");
    }

    #[test]
    fn read_pid_returns_none_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        assert!(read_pid().is_none());
    }

    #[test]
    fn remove_pid_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        // remove when no file exists — must not error
        remove_pid().unwrap();
        write_pid("127.0.0.1:8899").unwrap();
        remove_pid().unwrap();
        assert!(read_pid().is_none());
    }
}
