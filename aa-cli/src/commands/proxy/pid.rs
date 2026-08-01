//! Proxy state file for `aasm proxy start` / `stop` / `status`, and the record
//! `aasm run` resolves a trusted proxy endpoint from.
//!
//! File location: `$AA_DATA_DIR/proxy.pid` if `AA_DATA_DIR` is set
//! (used by the integration-test harness to isolate per-test state), otherwise
//! `~/.local/share/aasm/proxy.pid`.
//!
//! # Format, and why it grew
//!
//! ```text
//! <pid>
//! <listen_addr>
//! <start_token>
//! <exe_path>
//! ```
//!
//! The first two lines are the lifecycle record `stop` and `status` have always
//! used. The last two are process-identity evidence (see [`super::identity`]):
//! without them a reader can establish that *a* process holds the recorded PID,
//! but not that it is the proxy that was recorded — and `aasm run` routes a
//! governed tool's traffic on the strength of that answer (AAASM-5323).
//!
//! # Why there are two readers
//!
//! [`read_state`] is strict: every field must be present and non-empty, because
//! a partial record cannot support a trust decision and the only safe response
//! to one is to refuse. [`read_pid`] is deliberately lenient about the trailing
//! evidence lines, because `aasm proxy stop` must still be able to reap a proxy
//! whose record it cannot fully vouch for — refusing to signal a live process
//! would orphan it, which is strictly worse than stopping it.

use std::io;
use std::path::{Path, PathBuf};

/// The full proxy state record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyState {
    pub pid: u32,
    /// `host:port` the proxy was told to bind. Not validated here — see
    /// [`super::trust`], which is the only thing entitled to conclude anything
    /// from it.
    pub listen_addr: String,
    /// Opaque process-start token captured at spawn; see [`super::identity`].
    pub start_token: String,
    /// Canonical path of the executable that was spawned.
    pub exe_path: PathBuf,
}

/// Returns the path to the proxy state file.
///
/// Honors `AA_DATA_DIR` so the `aa-integration-tests` harness can give each
/// test its own state-file location, avoiding races on the shared user-home
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

/// Write the state record, creating parent directories as needed.
///
/// The file is left mode `0600` on Unix. This is not hygiene: the reader in
/// [`super::trust`] refuses a record that any other principal could have
/// written, so a group- or world-writable file would make every `aasm run`
/// fail closed. Permissions are set explicitly rather than left to the process
/// umask, and applied after the write so an existing looser file is tightened
/// rather than inherited.
pub fn write_state(state: &ProxyState) -> io::Result<()> {
    let path = pid_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = format!(
        "{}\n{}\n{}\n{}\n",
        state.pid,
        state.listen_addr,
        state.start_token,
        state.exe_path.display(),
    );
    std::fs::write(&path, content)?;
    restrict_permissions(&path)
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Read the complete state record. Returns `None` unless every field is present
/// and non-empty — a half-written or truncated record supports no conclusion,
/// and the caller's only safe response to `None` is to refuse.
pub fn read_state() -> Option<ProxyState> {
    let content = std::fs::read_to_string(pid_path()).ok()?;
    parse_state(&content)
}

/// Parse a state record. Split out from [`read_state`] so the field rules are
/// testable without a filesystem.
pub fn parse_state(content: &str) -> Option<ProxyState> {
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let listen_addr = lines.next()?.trim().to_string();
    let start_token = lines.next()?.trim().to_string();
    let exe_path = lines.next()?.trim().to_string();
    if listen_addr.is_empty() || start_token.is_empty() || exe_path.is_empty() {
        return None;
    }
    Some(ProxyState {
        pid,
        listen_addr,
        start_token,
        exe_path: PathBuf::from(exe_path),
    })
}

/// Read `(pid, listen_addr)` for the lifecycle commands. Tolerates a record
/// carrying no identity evidence on purpose — see the module docs.
pub fn read_pid() -> Option<(u32, String)> {
    let content = std::fs::read_to_string(pid_path()).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.trim().parse().ok()?;
    let addr = lines.next()?.trim().to_string();
    Some((pid, addr))
}

/// Remove the state file. Succeeds silently if the file does not exist.
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
    use std::sync::MutexGuard;

    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        prior: Option<String>,
    }
    impl EnvGuard {
        fn set(value: &str) -> Self {
            let lock = crate::test_support::env_guard();
            let prior = std::env::var("AA_DATA_DIR").ok();
            std::env::set_var("AA_DATA_DIR", value);
            Self { _lock: lock, prior }
        }
        fn unset() -> Self {
            let lock = crate::test_support::env_guard();
            let prior = std::env::var("AA_DATA_DIR").ok();
            std::env::remove_var("AA_DATA_DIR");
            Self { _lock: lock, prior }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.prior.take() {
                Some(v) => std::env::set_var("AA_DATA_DIR", v),
                None => std::env::remove_var("AA_DATA_DIR"),
            }
        }
    }

    fn sample_state() -> ProxyState {
        ProxyState {
            pid: std::process::id(),
            listen_addr: "127.0.0.1:8899".into(),
            start_token: "linux-pidfs:123456.789".into(),
            exe_path: PathBuf::from("/usr/local/bin/aa-proxy"),
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
    fn write_and_read_state_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        let state = sample_state();
        write_state(&state).unwrap();
        assert_eq!(read_state().expect("state should be readable after write"), state);
    }

    /// The trust check refuses a record any other principal could have written,
    /// so the writer must not leave one behind. A `0644` file (the umask
    /// default) would make every `aasm run` fail closed.
    #[cfg(unix)]
    #[test]
    fn write_state_leaves_the_file_unreadable_to_group_and_other() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());

        // Pre-create the file world-writable: the writer must tighten it, not
        // inherit whatever was already there.
        std::fs::write(pid_path(), "stale").unwrap();
        std::fs::set_permissions(pid_path(), std::fs::Permissions::from_mode(0o666)).unwrap();

        write_state(&sample_state()).unwrap();

        let mode = std::fs::metadata(pid_path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state file must be 0600, saw {mode:o}");
    }

    #[test]
    fn read_state_returns_none_when_file_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        assert!(read_state().is_none());
        assert!(read_pid().is_none());
    }

    /// A record with only the lifecycle fields carries no identity evidence, so
    /// it must not parse as state a trust decision could rest on.
    #[test]
    fn parse_state_rejects_a_record_without_identity_evidence() {
        assert!(parse_state("4242\n127.0.0.1:8899\n").is_none());
    }

    #[test]
    fn parse_state_rejects_empty_fields() {
        for content in [
            "4242\n\nlinux-pidfs:1.2\n/usr/local/bin/aa-proxy\n",
            "4242\n127.0.0.1:8899\n\n/usr/local/bin/aa-proxy\n",
            "4242\n127.0.0.1:8899\nlinux-pidfs:1.2\n\n",
        ] {
            assert!(
                parse_state(content).is_none(),
                "a record with an empty field must not parse: {content:?}"
            );
        }
    }

    /// `stop` and `status` must stay able to reap a proxy recorded by a build
    /// that wrote no evidence lines; orphaning a live proxy is worse than
    /// stopping one whose identity cannot be vouched for.
    #[test]
    fn read_pid_still_reads_a_record_without_identity_evidence() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        std::fs::write(pid_path(), "4242\n127.0.0.1:8899\n").unwrap();
        assert_eq!(read_pid(), Some((4242, "127.0.0.1:8899".to_string())));
        assert!(
            read_state().is_none(),
            "the same record must not satisfy the trust reader"
        );
    }

    #[test]
    fn remove_pid_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let _guard = EnvGuard::set(tmp.path().to_str().unwrap());
        // remove when no file exists — must not error
        remove_pid().unwrap();
        write_state(&sample_state()).unwrap();
        remove_pid().unwrap();
        assert!(read_state().is_none());
    }
}
