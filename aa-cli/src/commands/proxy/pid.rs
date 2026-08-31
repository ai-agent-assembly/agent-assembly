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

/// Result of [`kill_process`], distinguishing how the process ended (or
/// didn't) so a caller can report it honestly rather than a bare bool.
#[derive(Debug)]
pub enum KillOutcome {
    /// No process with this PID existed when we tried to signal it.
    AlreadyGone,
    /// Exited on its own after SIGTERM, within the poll window.
    Terminated,
    /// Did not exit after SIGTERM within the poll window; SIGKILL was sent
    /// and accepted by the kernel.
    Killed,
    /// A signal send failed for a reason other than "no such process" —
    /// e.g. `EPERM`. The process may still be running.
    Failed(io::Error),
}

/// Terminate `pid` by PID alone (not a process this call owns as a child —
/// see [`terminate_child`] for that case): SIGTERM, poll for up to 5s for a
/// clean exit, escalate to SIGKILL if still alive.
///
/// Used by `proxy stop`, which only ever has a PID read back from the state
/// file, not a live [`std::process::Child`] handle.
#[cfg(unix)]
pub fn kill_process(pid: u32) -> KillOutcome {
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        // ESRCH means the process no longer exists — already gone.
        return if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH) {
            KillOutcome::AlreadyGone
        } else {
            KillOutcome::Failed(err)
        };
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(100));
        let still_alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0;
        if !still_alive {
            return KillOutcome::Terminated;
        }
    }

    // Still alive after 5s — escalate to SIGKILL, and check whether the
    // kernel actually accepted it rather than assuming success.
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        return if err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH) {
            // Exited between our last poll and this signal — a race, not a
            // failure.
            KillOutcome::Terminated
        } else {
            KillOutcome::Failed(err)
        };
    }
    KillOutcome::Killed
}

#[cfg(not(unix))]
pub fn kill_process(_pid: u32) -> KillOutcome {
    KillOutcome::Failed(io::Error::other("process termination is only supported on Unix"))
}

/// Terminate a process this call owns a [`std::process::Child`] handle for:
/// SIGTERM, poll for up to 5s, escalate to `Child::kill` (SIGKILL) if still
/// alive, and reap it either way. Returns `true` if the child is confirmed
/// exited (and reaped) by the time this returns.
///
/// Deliberately **not** [`kill_process`] plus a reap: liveness here is
/// checked via `Child::try_wait`, which correctly observes death the
/// instant it happens. [`kill_process`]'s signal-0 poll cannot — a signalled
/// child that only this process could reap stays a zombie (still answers
/// signal 0) until reaped, so a signal-0-based poll against our own child
/// would spuriously wait out the entire window and escalate to SIGKILL on
/// every call, even when SIGTERM alone succeeded (AAASM-5372 review).
#[cfg(unix)]
pub fn terminate_child(child: &mut std::process::Child) -> bool {
    let pid = child.id();
    let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if ret != 0 {
        let err = io::Error::last_os_error();
        if !(err.kind() == io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ESRCH)) {
            return false;
        }
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_status)) => return true,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(_) => break,
        }
    }

    // Still alive after 5s — escalate to SIGKILL and reap.
    match child.kill() {
        Ok(()) => {
            let _ = child.wait();
            true
        }
        Err(_) => false,
    }
}

#[cfg(not(unix))]
pub fn terminate_child(_child: &mut std::process::Child) -> bool {
    false
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

    /// AAASM-5372 falsification: a process that is spawned but never reaches
    /// a state the caller waits for must still be reapable, not left orphaned.
    ///
    /// `kill_process` polls liveness via signal 0, which cannot distinguish
    /// "exited" from "exited but not yet reaped" (a zombie still answers
    /// signal 0) — accurate for its real caller, `proxy stop`, because the
    /// target there is never *this* process's own child. To test it
    /// honestly a *test-owned* child needs a concurrent reaper standing in
    /// for that real-world "someone else reaps it promptly" fact, or every
    /// case here would spuriously read as Killed regardless of whether
    /// SIGTERM was honoured (AAASM-5372 review).
    #[cfg(unix)]
    #[test]
    fn kill_process_terminates_a_live_process_via_sigterm() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep 30");
        let pid = child.id();
        let reaper = std::thread::spawn(move || child.wait());

        assert!(
            matches!(kill_process(pid), KillOutcome::Terminated),
            "a process that honours SIGTERM should be reported as Terminated, not escalated to SIGKILL"
        );

        let status = reaper.join().unwrap().expect("killed child should be waitable");
        assert!(!status.success(), "process should have exited via signal, not cleanly");
    }

    /// AAASM-5372 review: the SIGKILL escalation path was previously
    /// untested — `sleep` dies on SIGTERM, so it never exercised it. See
    /// the concurrent-reaper note on the Terminated-path test above for why
    /// this needs one too: without it, this case reads as Killed for the
    /// wrong reason (no one ever reaps it) rather than because SIGTERM was
    /// actually ignored.
    #[cfg(unix)]
    #[test]
    fn kill_process_escalates_to_sigkill_when_sigterm_is_ignored() {
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
            ])
            .spawn()
            .expect("spawn a SIGTERM-ignoring fixture");
        let pid = child.id();
        // Give the interpreter time to actually install the SIG_IGN handler
        // before signalling — SIGTERM's default disposition (terminate)
        // still applies during Python's own startup, so a signal sent too
        // early kills it before signal.signal() ever runs.
        std::thread::sleep(std::time::Duration::from_millis(300));
        let reaper = std::thread::spawn(move || child.wait());

        assert!(
            matches!(kill_process(pid), KillOutcome::Killed),
            "a process that ignores SIGTERM must be reported as Killed (SIGKILL escalation)"
        );
        let status = reaper.join().unwrap().expect("killed child should be waitable");
        assert!(!status.success());
    }

    #[cfg(unix)]
    #[test]
    fn kill_process_on_an_already_dead_pid_reports_already_gone() {
        let mut child = std::process::Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        let _ = child.wait(); // reap it — pid is now free/dead

        assert!(
            matches!(kill_process(pid), KillOutcome::AlreadyGone),
            "an already-gone process must be reported as AlreadyGone, not a kill failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_child_reaps_a_process_that_honours_sigterm() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep 30");
        assert!(terminate_child(&mut child), "terminate_child should report success");
        // Already reaped internally; a second wait must not hang.
        assert!(child.try_wait().unwrap().is_some(), "child must already be reaped");
    }

    /// The scenario `terminate_child` exists for: an own-child whose death
    /// via signal-0 polling (`kill_process`) would be invisible until
    /// reaped, spuriously waiting out the whole window and escalating every
    /// time even though SIGTERM alone succeeded.
    #[cfg(unix)]
    #[test]
    fn terminate_child_observes_sigterm_death_without_waiting_out_the_full_window() {
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn sleep 30");
        let start = std::time::Instant::now();
        assert!(terminate_child(&mut child));
        assert!(
            start.elapsed() < std::time::Duration::from_secs(3),
            "try_wait should observe death well before the 5s SIGKILL escalation deadline, took {:?}",
            start.elapsed()
        );
    }

    #[cfg(unix)]
    #[test]
    fn terminate_child_escalates_to_sigkill_when_sigterm_is_ignored() {
        let mut child = std::process::Command::new("python3")
            .args([
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
            ])
            .spawn()
            .expect("spawn a SIGTERM-ignoring fixture");
        // See the matching note on `kill_process_escalates_to_sigkill_when_sigterm_is_ignored`.
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(
            terminate_child(&mut child),
            "terminate_child should still succeed via SIGKILL"
        );
        assert!(child.try_wait().unwrap().is_some(), "child must be reaped");
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
