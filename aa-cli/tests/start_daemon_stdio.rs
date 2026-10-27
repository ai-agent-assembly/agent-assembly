//! `aasm start` detaches the daemon's stdio, names a missing binary usefully and
//! surfaces a startup failure's reason (AAASM-6389).
//!
//! Everything runs against a *fake* `aa-api-server` next to a copy of the `aasm`
//! binary (the resolver looks next to the running executable first), under a
//! throwaway `HOME`: no real gateway, no real `~/.aasm`.
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use assert_cmd::cargo::cargo_bin;

struct Rig {
    _dir: tempfile::TempDir,
    home: PathBuf,
    aasm: PathBuf,
}

/// A copy of `aasm` alone in `bin/`, plus `fake` (a shell script) installed as
/// `aa-api-server` beside it when given.
fn rig(fake: Option<&str>) -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let aasm = bin.join("aasm");
    std::fs::copy(cargo_bin("aasm"), &aasm).unwrap();
    if let Some(script) = fake {
        let p = bin.join("aa-api-server");
        std::fs::write(&p, script).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    Rig { _dir: dir, home, aasm }
}

impl Rig {
    fn cmd(&self, path_env: &str) -> Command {
        let mut c = Command::new(&self.aasm);
        c.env_clear()
            .env("HOME", &self.home)
            .env("PATH", path_env)
            .stdin(Stdio::null());
        c
    }
    fn log(&self) -> PathBuf {
        self.home.join(".aasm").join("aa-api-server.log")
    }
    fn stop(&self) {
        let _ = self.cmd("/usr/bin:/bin").arg("stop").output();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Run `cmd` to completion on a helper thread, failing if it does not return
/// within `limit` (the pipe it holds is what a leaked daemon would keep open).
fn output_within(mut cmd: Command, limit: Duration) -> Output {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).output());
    });
    rx.recv_timeout(limit)
        .expect("`aasm start` did not return: the daemon is holding the caller's pipe")
        .unwrap()
}

const SERVING: &str = r#"#!/bin/sh
echo "fake-aa-api-server out on $AA_API_ADDR"
echo "fake-aa-api-server err line" >&2
exec python3 -u -c '
import os, socket, time
host, port = os.environ["AA_API_ADDR"].rsplit(":", 1)
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, int(port)))
s.listen(5)
print("fake listening", flush=True)
time.sleep(60)
'
"#;

const FAILING: &str = r#"#!/bin/sh
echo 'Error: "invalid AASM_API_KEY: key must start with aa_"' >&2
exit 1
"#;

#[test]
fn start_returns_while_the_daemon_keeps_running_and_logs_to_an_owner_only_file() {
    let r = rig(Some(SERVING));
    let port = free_port();
    let mut c = r.cmd(&std::env::var("PATH").unwrap_or_default());
    c.args(["start", "--port", &port.to_string()]);
    // A pipe on stdout/stderr, like `aasm start | head`: it must reach EOF
    // without the daemon exiting.
    let out = output_within(c, Duration::from_secs(20));
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let ok = out.status.success();

    let log = r.log();
    let log_text = std::fs::read_to_string(&log).unwrap_or_default();
    let mode = std::fs::metadata(&log).map(|m| m.permissions().mode() & 0o777).ok();
    let dir_mode = std::fs::metadata(log.parent().unwrap())
        .map(|m| m.permissions().mode() & 0o777)
        .ok();
    r.stop();

    assert!(ok, "stdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(
        stdout.contains(&log.display().to_string()),
        "the banner names the log: {stdout}"
    );
    assert!(
        !stdout.contains("fake-aa-api-server") && !stderr.contains("fake-aa-api-server"),
        "the daemon's output must go to the log, not the caller: {stdout}{stderr}"
    );
    assert!(
        log_text.contains("fake-aa-api-server out") && log_text.contains("err line"),
        "{log_text}"
    );
    assert_eq!(mode, Some(0o600), "log mode");
    assert_eq!(dir_mode, Some(0o700), "~/.aasm mode");
}

#[test]
fn a_daemon_that_dies_at_startup_is_reported_with_its_reason() {
    let r = rig(Some(FAILING));
    let mut c = r.cmd("/usr/bin:/bin");
    c.args(["start", "--port", &free_port().to_string()]);
    let started = std::time::Instant::now();
    let out = output_within(c, Duration::from_secs(20));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    let pid_file = r.home.join(".aasm").join("gateway.pid");
    let leftover = pid_file.exists();

    assert!(!out.status.success(), "{stderr}");
    assert!(
        started.elapsed() < Duration::from_secs(4),
        "should fail fast, not after the 5s timeout"
    );
    assert!(stderr.contains("exited before it was ready"), "{stderr}");
    assert!(
        stderr.contains("invalid AASM_API_KEY"),
        "the child's reason is surfaced: {stderr}"
    );
    assert!(stderr.contains(&r.log().display().to_string()), "{stderr}");
    assert!(!leftover, "no pid record may point at a dead daemon");
}

#[test]
fn a_missing_server_binary_gets_actionable_guidance() {
    let r = rig(None);
    let mut c = r.cmd("/usr/bin:/bin");
    c.args(["start", "--port", &free_port().to_string()]);
    let out = output_within(c, Duration::from_secs(20));
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(!out.status.success());
    assert!(stderr.contains("`aa-api-server` was not found"), "{stderr}");
    assert!(stderr.contains("$PATH") && stderr.contains("~/.cargo/bin"), "{stderr}");
    assert!(stderr.contains("cargo build -p aa-api --bin aa-api-server"), "{stderr}");
}
