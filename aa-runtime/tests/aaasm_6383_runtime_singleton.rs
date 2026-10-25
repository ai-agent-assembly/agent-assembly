//! AAASM-6383 - a second `aa-runtime` must refuse to start rather than run
//! alongside (and over) the first.
//!
//! Every test launches the real `aa-runtime` executable: the refusal is an
//! exit status, and the harm being prevented (a second process taking over the
//! first's IPC socket path) only exists between two live processes. In-process
//! `run()` cannot be used - it installs a process-global metrics recorder.
//!
//! "The first runtime is undisturbed" is asserted three independent ways, so a
//! refusal that merely happened to exit cannot pass: the first process is
//! still alive, its socket file is the same inode, and a fresh IPC connection
//! still receives the handshake challenge from it.
//!
//! Readiness is a real `GET /health` 200, not a TCP connect: the health listener
//! is bound early but only served at the end of startup, so a bare connect can
//! succeed (and then hang) before the runtime is up.
#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const REFUSED: i32 = 78;
/// IPC frame tag of the server's handshake challenge (`ipc/handshake.rs`).
const HANDSHAKE_CHALLENGE_TAG: u8 = 5;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn unique_agent() -> String {
    format!(
        "s6383-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::SeqCst)
    )
}

fn socket_for(agent: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/aa-runtime-{agent}.sock"))
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Runtime {
    child: Child,
    agent: String,
    port: u16,
    log: PathBuf,
    _dir: tempfile::TempDir,
}

impl Runtime {
    fn spawn(agent: &str, port: u16) -> Self {
        // A freshly built binary can take minutes to validate on first launch
        // on macOS; pay that once so it cannot land inside a timed window.
        static WARM: std::sync::Once = std::sync::Once::new();
        WARM.call_once(|| {
            let _ = Command::new(env!("CARGO_BIN_EXE_aa-runtime")).arg("--version").output();
        });
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("runtime.log");
        let out = std::fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_aa-runtime"))
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("AA_AGENT_ID", agent)
            .env("AA_POLICY_PATH", "")
            .env("AA_METRICS_ADDR", format!("127.0.0.1:{port}"))
            .env("AA_AUDIT_BUFFER_PATH", dir.path().join("audit.db"))
            .env("RUST_LOG", "info")
            .env("AA_RUNTIME_SHUTDOWN_TIMEOUT_SECS", "3")
            .stdout(Stdio::from(out.try_clone().unwrap()))
            .stderr(Stdio::from(out))
            .spawn()
            .expect("spawn aa-runtime");
        Self {
            child,
            agent: agent.to_string(),
            port,
            log,
            _dir: dir,
        }
    }

    fn socket(&self) -> PathBuf {
        socket_for(&self.agent)
    }

    fn signal(&self, sig: i32) {
        unsafe { libc::kill(self.child.id() as i32, sig) };
    }

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Ready = IPC accepts and `/health` answers 200.
    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("runtime exited early with {status}:\n{}", self.log_text());
            }
            if UnixStream::connect(self.socket()).is_ok() && self.health_ok() {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "runtime never became ready (ipc connect: {:?}, health 200: {}, port {}, socket {}):\n{}",
                UnixStream::connect(self.socket()).map(drop),
                self.health_ok(),
                self.port,
                self.socket().display(),
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn health_ok(&self) -> bool {
        let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", self.port)) else {
            return false;
        };
        s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let _ = s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n");
        let mut head = String::new();
        let _ = s.read_to_string(&mut head);
        head.starts_with("HTTP/1.0 200") || head.starts_with("HTTP/1.1 200")
    }

    /// Start `agent` on a free port and wait until ready. `free_port` can lose a
    /// race for the port between probing and binding; that one refusal is
    /// retried with a fresh port, any other early exit is a real failure.
    fn start_ready(agent: &str) -> Self {
        for _ in 0..4 {
            let mut rt = Self::spawn(agent, free_port());
            let deadline = Instant::now() + Duration::from_secs(120);
            loop {
                if let Some(status) = rt.child.try_wait().unwrap() {
                    assert!(
                        rt.log_text().contains("failed to bind health server"),
                        "runtime exited early with {status}:\n{}",
                        rt.log_text()
                    );
                    break;
                }
                if UnixStream::connect(rt.socket()).is_ok() && rt.health_ok() {
                    return rt;
                }
                assert!(Instant::now() < deadline, "runtime never became ready");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        panic!("could not find a free health port");
    }

    fn wait_exit(&mut self) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "runtime should have refused and exited:\n{}",
                self.log_text()
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn still_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// `/health` answers 200 with a JSON body.
    fn health(&self) -> serde_json::Value {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", self.port)).expect("health connect");
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.write_all(b"GET /health HTTP/1.0\r\nHost: x\r\n\r\n").unwrap();
        let mut body = String::new();
        s.read_to_string(&mut body).unwrap();
        serde_json::from_str(body.split("\r\n\r\n").nth(1).expect("http body")).expect("health json")
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        // A runtime that was refused has already exited and never owned the
        // path; deleting it here would remove a live peer's socket.
        let was_running = matches!(self.child.try_wait(), Ok(None));
        let _ = self.child.kill();
        let _ = self.child.wait();
        if was_running {
            let _ = std::fs::remove_file(socket_for(&self.agent));
        }
        // The lock file belongs to the agent id, not to a process: remove it for
        // refused runtimes too (all spawning is over by the time they drop).
        let _ = std::fs::remove_file(format!("/tmp/aa-runtime-{}.lock", self.agent));
    }
}

/// A fresh IPC connection gets the handshake challenge, i.e. a live server owns
/// the path and is accepting.
fn ipc_serves(socket: &Path) -> bool {
    let Ok(mut s) = UnixStream::connect(socket) else {
        return false;
    };
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tag = [0u8; 1];
    s.read_exact(&mut tag).is_ok() && tag[0] == HANDSHAKE_CHALLENGE_TAG
}

fn assert_first_undisturbed(first: &mut Runtime, socket_inode: u64) {
    assert!(first.still_running(), "the first runtime must keep running");
    assert_eq!(
        std::fs::metadata(first.socket())
            .expect("first socket still present")
            .ino(),
        socket_inode,
        "the first runtime's socket file must not be replaced"
    );
    assert!(ipc_serves(&first.socket()), "the first runtime must still serve IPC");
    assert!(
        first.health().get("status").is_some(),
        "the first runtime must still serve /health"
    );
}

#[test]
fn second_runtime_on_the_same_health_port_refuses_and_leaves_the_first_serving() {
    let mut first = Runtime::start_ready(&unique_agent());
    let port = first.port;
    let inode = std::fs::metadata(first.socket()).unwrap().ino();

    let mut second = Runtime::spawn(&unique_agent(), port);
    let status = second.wait_exit();
    let log = second.log_text();

    assert_eq!(status.code(), Some(REFUSED), "refusal must be exit 78:\n{log}");
    assert!(
        log.contains("failed to bind health server"),
        "refusal must name the cause:\n{log}"
    );
    // Refused before anything was bound or served.
    assert!(
        !log.contains("aa-runtime starting"),
        "refusal must precede startup:\n{log}"
    );
    assert!(
        !log.contains("IPC server task spawned"),
        "refusal must precede IPC:\n{log}"
    );
    assert!(
        !second.socket().exists(),
        "the refused runtime must not create its socket"
    );

    assert_first_undisturbed(&mut first, inode);
}

#[test]
fn second_runtime_with_the_same_agent_id_refuses_and_does_not_take_over_the_socket() {
    let agent = unique_agent();
    let mut first = Runtime::start_ready(&agent);
    let inode = std::fs::metadata(first.socket()).unwrap().ino();

    let mut second = Runtime::spawn(&agent, free_port());
    let status = second.wait_exit();
    let log = second.log_text();

    assert_eq!(status.code(), Some(REFUSED), "refusal must be exit 78:\n{log}");
    assert!(
        log.contains("already holds the lock"),
        "refusal must name the cause:\n{log}"
    );
    assert!(
        !log.contains("aa-runtime starting"),
        "refusal must precede startup:\n{log}"
    );
    assert!(
        !log.contains("removed stale socket file"),
        "must not touch the live socket:\n{log}"
    );
    assert_first_undisturbed(&mut first, inode);
}

#[test]
fn a_stale_socket_left_by_a_killed_runtime_is_still_replaced() {
    let agent = unique_agent();
    let mut first = Runtime::start_ready(&agent);
    // SIGKILL runs no cleanup, so the socket file stays behind with no listener.
    first.child.kill().unwrap();
    first.child.wait().unwrap();
    assert!(
        first.socket().exists(),
        "control: kill -9 must leave the socket file behind"
    );
    assert!(
        UnixStream::connect(first.socket()).is_err(),
        "control: nothing listens on it"
    );
    let stale_inode = std::fs::metadata(first.socket()).unwrap().ino();

    let restarted = Runtime::start_ready(&agent);
    assert!(ipc_serves(&restarted.socket()), "the restarted runtime must serve IPC");
    assert_ne!(
        std::fs::metadata(restarted.socket()).unwrap().ino(),
        stale_inode,
        "the stale socket file must have been replaced"
    );
    assert!(restarted.log_text().contains("removed stale socket file"));
}

#[test]
fn a_stopped_first_runtime_does_not_hang_or_lose_its_socket_to_a_second() {
    let agent = unique_agent();
    let mut first = Runtime::start_ready(&agent);
    let inode = std::fs::metadata(first.socket()).unwrap().ino();
    // A SIGSTOPped first runtime still holds the agent lock, so the second is
    // refused at the lock stage (the probe is not reached) and must not hang.
    first.signal(libc::SIGSTOP);

    let mut second = Runtime::spawn(&agent, free_port());
    let status = second.wait_exit();
    first.signal(libc::SIGCONT);

    assert_eq!(status.code(), Some(REFUSED), "{}", second.log_text());
    assert_eq!(std::fs::metadata(first.socket()).unwrap().ino(), inode);
    assert_first_undisturbed(&mut first, inode);
}

#[test]
fn a_foreign_listener_that_never_accepts_holds_the_path_against_a_runtime() {
    // No lock holder exists, so only the connect probe stands between this
    // runtime and `IpcServer::bind` deleting the path: the pre-lock-peer case.
    // The connect completes through the listener's backlog (Ok), so the 2 s
    // deadline is not what refuses here.
    let agent = unique_agent();
    let path = socket_for(&agent);
    let _ = std::fs::remove_file(&path);
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();

    let mut rt = Runtime::spawn(&agent, free_port());
    let status = rt.wait_exit();
    let log = rt.log_text();
    assert_eq!(status.code(), Some(REFUSED), "{log}");
    assert!(log.contains("held by a live listener"), "{log}");
    assert_eq!(
        std::fs::metadata(&path).unwrap().ino(),
        inode,
        "the foreign socket must be left alone"
    );
    drop(listener);
    let _ = std::fs::remove_file(&path);
}

/// AAASM-6383 H2: runtimes of one agent id started together must not both pass
/// a check-then-bind. Exactly one survives, the rest are refused, and the
/// survivor's socket is the one it bound.
#[test]
fn runtimes_started_together_with_one_agent_id_leave_exactly_one_serving() {
    const N: usize = 4;
    let agent = unique_agent();
    let mut all: Vec<Runtime> = (0..N).map(|_| Runtime::spawn(&agent, free_port())).collect();

    let deadline = Instant::now() + Duration::from_secs(120);
    // Wait until N-1 have exited (the losers), or fail.
    loop {
        let exited = all.iter_mut().filter_map(|r| r.child.try_wait().unwrap()).count();
        if exited == N - 1 {
            break;
        }
        assert!(exited < N, "every runtime exited; none survived");
        assert!(Instant::now() < deadline, "expected {} refusals, saw {exited}", N - 1);
        std::thread::sleep(Duration::from_millis(50));
    }
    let (mut alive, dead): (Vec<_>, Vec<_>) = all.into_iter().partition_map_alive();
    assert_eq!(alive.len(), 1);
    for mut d in dead {
        let st = d.child.try_wait().unwrap().unwrap();
        let log = d.log_text();
        // A health-port race between `free_port` calls would also exit 78; the
        // cause must be the agent lock.
        assert_eq!(st.code(), Some(REFUSED), "{log}");
        assert!(log.contains("already holds the lock"), "{log}");
    }
    let mut survivor = alive.pop().unwrap();
    survivor.wait_ready();
    let inode = std::fs::metadata(survivor.socket()).unwrap().ino();
    std::thread::sleep(Duration::from_millis(500));
    assert_first_undisturbed(&mut survivor, inode);
}

trait PartitionAlive {
    fn partition_map_alive(self) -> (Vec<Runtime>, Vec<Runtime>);
}
impl<I: Iterator<Item = Runtime>> PartitionAlive for I {
    fn partition_map_alive(self) -> (Vec<Runtime>, Vec<Runtime>) {
        let mut alive = Vec::new();
        let mut dead = Vec::new();
        for mut r in self {
            if r.child.try_wait().unwrap().is_none() {
                alive.push(r);
            } else {
                dead.push(r);
            }
        }
        (alive, dead)
    }
}

#[test]
fn an_unparseable_health_address_is_a_refusal_not_a_panic() {
    let agent = unique_agent();
    let dir = tempfile::tempdir().unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_aa-runtime"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap_or_default())
        .env("AA_AGENT_ID", &agent)
        .env("AA_METRICS_ADDR", "not-an-address")
        .env("AA_AUDIT_BUFFER_PATH", dir.path().join("audit.db"))
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(REFUSED), "{text}");
    let _ = std::fs::remove_file(format!("/tmp/aa-runtime-{agent}.lock"));
    assert!(text.contains("invalid AA_METRICS_ADDR"), "{text}");
    assert!(!socket_for(&agent).exists());
}

#[test]
fn a_symlinked_lock_path_is_refused_with_its_own_reason() {
    let agent = unique_agent();
    let lock = format!("/tmp/aa-runtime-{agent}.lock");
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("elsewhere");
    std::fs::write(&target, b"").unwrap();
    std::os::unix::fs::symlink(&target, &lock).unwrap();

    let mut rt = Runtime::spawn(&agent, free_port());
    let status = rt.wait_exit();
    let log = rt.log_text();
    let _ = std::fs::remove_file(&lock);

    assert_eq!(status.code(), Some(REFUSED), "{log}");
    assert!(log.contains("symbolic link"), "{log}");
    assert!(!log.contains("already holds the lock"), "not a peer: {log}");
    assert!(!socket_for(&agent).exists());
}

#[test]
fn a_group_writable_lock_file_is_refused_with_its_own_reason() {
    use std::os::unix::fs::PermissionsExt;
    let agent = unique_agent();
    let lock = format!("/tmp/aa-runtime-{agent}.lock");
    std::fs::write(&lock, b"").unwrap();
    std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o666)).unwrap();

    let mut rt = Runtime::spawn(&agent, free_port());
    let status = rt.wait_exit();
    let log = rt.log_text();
    let _ = std::fs::remove_file(&lock);

    assert_eq!(status.code(), Some(REFUSED), "{log}");
    assert!(log.contains("is unsafe") && log.contains("writable"), "{log}");
    assert!(!log.contains("already holds the lock"), "not a peer: {log}");
}
