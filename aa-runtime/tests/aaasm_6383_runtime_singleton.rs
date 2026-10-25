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

    fn log_text(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn wait_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("runtime exited early with {status}:\n{}", self.log_text());
            }
            if UnixStream::connect(self.socket()).is_ok()
                && std::net::TcpStream::connect(("127.0.0.1", self.port)).is_ok()
            {
                return;
            }
            assert!(Instant::now() < deadline, "runtime never became ready");
            std::thread::sleep(Duration::from_millis(50));
        }
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
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(socket_for(&self.agent));
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
    let port = free_port();
    let mut first = Runtime::spawn(&unique_agent(), port);
    first.wait_ready();
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
    let mut first = Runtime::spawn(&agent, free_port());
    first.wait_ready();
    let inode = std::fs::metadata(first.socket()).unwrap().ino();

    let second_port = free_port();
    let mut second = Runtime::spawn(&agent, second_port);
    let status = second.wait_exit();
    let log = second.log_text();

    assert_eq!(status.code(), Some(REFUSED), "refusal must be exit 78:\n{log}");
    assert!(
        log.contains("held by a live listener"),
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
    // The refused runtime must not be left holding its own health port either.
    assert!(
        std::net::TcpListener::bind(("127.0.0.1", second_port)).is_ok(),
        "a refused runtime must release/never take its health port"
    );

    assert_first_undisturbed(&mut first, inode);
}

#[test]
fn a_stale_socket_left_by_a_killed_runtime_is_still_replaced() {
    let agent = unique_agent();
    let mut first = Runtime::spawn(&agent, free_port());
    first.wait_ready();
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

    let mut restarted = Runtime::spawn(&agent, free_port());
    restarted.wait_ready();
    assert!(ipc_serves(&restarted.socket()), "the restarted runtime must serve IPC");
    assert_ne!(
        std::fs::metadata(restarted.socket()).unwrap().ino(),
        stale_inode,
        "the stale socket file must have been replaced"
    );
    assert!(restarted.log_text().contains("removed stale socket file"));
}
