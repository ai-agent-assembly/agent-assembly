//! Waiting for a spawned `aa-proxy` child to become ready to serve traffic.
//!
//! Two waits live here because they answer different questions about the same
//! spawn: [`wait_for_port`] asks the network ("is anything answering at this
//! *known* address yet") and is what standalone `aasm proxy start` has always
//! used, since its address is fixed by `--listen`/`AA_PROXY_ADDR` before the
//! child is even spawned. [`wait_for_ready_file`] asks the filesystem ("what
//! address did the child actually bind, and is it done binding") and is for
//! AAASM-5857's per-launch dedicated proxy, whose address is not known in
//! advance — it asks for port `0` and the child reports back what it got
//! (`AA_PROXY_READY_FILE`, AAASM-5859).
//!
//! `wait_for_ready_file` additionally distinguishes "not ready yet" from
//! "the child already exited": a per-launch proxy that fails to start (bad
//! config, CA install refused, gateway unreachable) should surface that
//! failure immediately rather than spend its whole timeout polling a file a
//! dead process will never write.

use std::net::SocketAddr;
use std::path::Path;
use std::process::{Child, ExitStatus};
use std::time::{Duration, Instant};

/// Poll TCP connect on `addr` until the socket accepts or `timeout` elapses.
///
/// Used by standalone `aasm proxy start`, whose listen address is fixed
/// before the child is spawned — there is nothing to read back, only to
/// confirm.
pub fn wait_for_port(addr: &str, timeout: Duration) -> bool {
    let Ok(sock_addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if std::net::TcpStream::connect_timeout(&sock_addr, Duration::from_millis(100)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// What became true first while waiting on a ready file.
#[derive(Debug)]
pub enum ReadyFileOutcome {
    /// The file appeared, and its first line parsed as a socket address.
    Ready(SocketAddr),
    /// The child process exited before the file appeared — waiting out the
    /// rest of the timeout would only delay reporting a failure that has
    /// already happened.
    ChildExited(ExitStatus),
    /// Neither of the above happened before `timeout` elapsed.
    Timeout,
}

/// Poll for `ready_file` to appear and parse, checking `child`'s liveness on
/// every iteration so a dead child is reported immediately rather than only
/// after the full timeout (AAASM-5857 requirement 2: a managed launch must
/// fail closed promptly when its dedicated proxy cannot start).
///
/// `child.try_wait()` is checked *before* the file read each iteration: a
/// child that wrote the file and then immediately crashed should still be
/// reported [`ReadyFileOutcome::Ready`] (the file's contents are what a
/// caller acts on, and are valid even if the process that wrote them is now
/// gone — same reasoning as `write_ready_file`'s atomic-write guarantee).
/// Checking child liveness first, file second, means a child that exits
/// without ever writing the file is reported as `ChildExited`, not `Timeout`.
pub fn wait_for_ready_file(ready_file: &Path, timeout: Duration, child: &mut Child) -> ReadyFileOutcome {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            // One last check: the child may have written the file and exited
            // in the same instant the poll observes it (e.g. a proxy that
            // reports readiness then is killed by something external before
            // this loop's next iteration). Reading the file's own success is
            // definitive either way.
            if let Some(addr) = read_ready_file(ready_file) {
                return ReadyFileOutcome::Ready(addr);
            }
            return ReadyFileOutcome::ChildExited(status);
        }
        if let Some(addr) = read_ready_file(ready_file) {
            return ReadyFileOutcome::Ready(addr);
        }
        if Instant::now() >= deadline {
            return ReadyFileOutcome::Timeout;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Read and parse the address line `write_ready_file` (`aa-proxy`) writes.
/// `None` for any failure to read or parse — a partially-written file cannot
/// be observed (the writer renames into place atomically), so a read failure
/// here means "not written yet", not "written badly".
fn read_ready_file(path: &Path) -> Option<SocketAddr> {
    let body = std::fs::read_to_string(path).ok()?;
    body.lines().next()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_for_port_returns_false_on_unbound_addr() {
        // Port 1 is privileged and never listening in test environments.
        assert!(!wait_for_port("127.0.0.1:1", Duration::from_millis(200)));
    }

    #[test]
    fn wait_for_port_returns_false_on_invalid_addr() {
        assert!(!wait_for_port("not-an-address", Duration::from_millis(100)));
    }

    fn sleep_child(secs: f64) -> Child {
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("sleep {secs}"))
            .spawn()
            .expect("spawn sh")
    }

    /// The positive path: the file appears while the child is still alive.
    #[test]
    fn wait_for_ready_file_returns_ready_when_the_file_appears() {
        let dir = tempfile::tempdir().unwrap();
        let ready_file = dir.path().join("ready");
        std::fs::write(&ready_file, "127.0.0.1:9999\n12345\n").unwrap();

        let mut child = sleep_child(2.0);
        let outcome = wait_for_ready_file(&ready_file, Duration::from_secs(5), &mut child);
        let _ = child.kill();
        let _ = child.wait();

        match outcome {
            ReadyFileOutcome::Ready(addr) => assert_eq!(addr, "127.0.0.1:9999".parse().unwrap()),
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// The failure-detection path this type exists for: a child that exits
    /// without ever writing the file must be reported as ChildExited well
    /// before the timeout, not as an eventual Timeout.
    #[test]
    fn wait_for_ready_file_returns_child_exited_promptly_when_the_child_dies_first() {
        let dir = tempfile::tempdir().unwrap();
        // Never written to — this child exits immediately without touching it.
        let ready_file = dir.path().join("never-written");

        let mut child = std::process::Command::new("sh")
            .arg("-c")
            .arg("exit 7")
            .spawn()
            .expect("spawn sh");

        let start = Instant::now();
        let outcome = wait_for_ready_file(&ready_file, Duration::from_secs(30), &mut child);
        let elapsed = start.elapsed();

        assert!(
            elapsed < Duration::from_secs(5),
            "a dead child must be reported promptly, not after most of a 30s timeout: took {elapsed:?}"
        );
        match outcome {
            ReadyFileOutcome::ChildExited(status) => {
                assert_eq!(status.code(), Some(7));
            }
            other => panic!("expected ChildExited, got {other:?}"),
        }
    }

    /// Neither the file nor a dead child — the honest "nothing happened" case.
    #[test]
    fn wait_for_ready_file_times_out_when_nothing_happens() {
        let dir = tempfile::tempdir().unwrap();
        let ready_file = dir.path().join("never-appears");
        let mut child = sleep_child(2.0);

        let outcome = wait_for_ready_file(&ready_file, Duration::from_millis(200), &mut child);
        let _ = child.kill();
        let _ = child.wait();

        assert!(
            matches!(outcome, ReadyFileOutcome::Timeout),
            "expected Timeout, got {outcome:?}"
        );
    }
}
