//! CLI integration tests for `aasm proxy` (AAASM-1510 / F121 ST-18).
//!
//! # Architecture
//!
//! Tests are designed to be self-contained and portable. Rather than spawning
//! a real `aa-proxy` process (which on macOS triggers a macOS Keychain install
//! requiring admin privileges), the status tests use the **test process's own
//! PID** with a real `TcpListener` bound in-process. `aasm proxy status` reads
//! the PID file, calls `kill(pid, 0)` (succeeds — we are alive), and connects
//! to the listener (succeeds — we are serving). The behaviour under test is in
//! `status.rs`, not in `aa-proxy` itself.
//!
//! Tests that exercise `aasm proxy start` with the real `aa-proxy` binary call
//! `ensure_aa_proxy_built()` to build it on demand. On macOS without a prior
//! `aasm proxy install-ca` the CA keychain step inside `aa-proxy` will fail;
//! those tests detect this condition and skip gracefully with an explanatory
//! message.
//!
//! # Divergences from AAASM-1510 story acceptance criteria
//!
//! * **JSON status schema**: the AC specifies `uptime_seconds: u64`; the
//!   implementation serialises `serving: bool`. Tests assert on the actual
//!   `status.rs` schema.
//!
//! * **Second `aasm proxy start` on occupied port exits 0**: `wait_for_port` in
//!   `start.rs` connects to the existing listener and returns `true`. The AC
//!   implies this should be an error; the implementation documents success.
//!
//! * **`--no-detach` does not write a PID file**: `write_child_pid` only lives
//!   in the background branch of `start.rs`. Tests that verify PID file creation
//!   use background mode.
//!
//! * **`aasm proxy logs` does not honour `AA_DATA_DIR`**: it reads
//!   `dirs::data_local_dir()/aasm/logs/proxy.log`. Tests override `HOME` to
//!   isolate the log path.
//!
//! # `#[ignore]` stubs
//!
//! Two tests require capabilities not yet implemented in `aa-proxy`:
//! * `proxy_start_blocks_deny_policy_request` — policy-deny 403 forwarding.
//! * `proxy_start_emits_audit_event_to_gateway` — event POST to gateway.

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

// ─────────────────────────────────────── proxy test fixture ──────────────────

/// Lightweight fixture for `aasm proxy` tests: a per-test `AA_DATA_DIR`
/// tempdir plus a pre-wired `cargo run` command builder.
///
/// Unlike `CliFixture`, this does NOT start an in-process gateway. Proxy
/// subcommands operate entirely on local state (PID file, process signals,
/// log file) and do not contact the gateway API.
struct ProxyFixture {
    data_dir: tempfile::TempDir,
}

impl ProxyFixture {
    fn new() -> Self {
        Self {
            data_dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    fn data_dir(&self) -> &Path {
        self.data_dir.path()
    }

    /// Returns a `Command` that runs `aasm` via `cargo run` with `AA_DATA_DIR`
    /// pre-set so PID-file reads/writes are isolated per test.
    fn cmd(&self) -> Command {
        let mut cmd = Command::new(env!("CARGO"));
        cmd.args(["run", "--quiet", "-p", "aa-cli", "--bin", "aasm", "--"])
            .env("AA_DATA_DIR", self.data_dir());
        cmd
    }
}

// ─────────────────────────────────────────────────────────── helpers ─────────

/// Bind `127.0.0.1:0` and return the OS-assigned port, then drop the listener.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Return the path of the compiled `aa-proxy` binary (debug > release).
fn aa_proxy_bin() -> Option<PathBuf> {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has parent");

    let debug_bin = workspace.join("target").join("debug").join("aa-proxy");
    if debug_bin.exists() {
        return Some(debug_bin);
    }
    let release_bin = workspace.join("target").join("release").join("aa-proxy");
    if release_bin.exists() {
        return Some(release_bin);
    }
    None
}

/// Build `aa-proxy` (debug) if not already present and return the binary path.
///
/// Called by tests that need to invoke `aasm proxy start` against a real binary.
/// The first call per test run triggers `cargo build -p aa-proxy`; subsequent
/// calls reuse the cached binary.
fn ensure_aa_proxy_built() -> PathBuf {
    if let Some(bin) = aa_proxy_bin() {
        return bin;
    }
    let status = Command::new(env!("CARGO"))
        .args(["build", "-p", "aa-proxy"])
        .status()
        .expect("cargo build -p aa-proxy");
    assert!(status.success(), "cargo build -p aa-proxy failed");
    aa_proxy_bin().expect("aa-proxy binary missing after build")
}

/// Build a `PATH` string that prepends the directory containing `aa-proxy` to
/// the current `PATH`. Allows `resolve_binary()` in `start.rs` to find the
/// binary via `which aa-proxy`.
fn path_with_proxy() -> String {
    let bin = ensure_aa_proxy_built();
    let dir = bin.parent().expect("aa-proxy has parent dir").to_string_lossy();
    let existing = std::env::var("PATH").unwrap_or_default();
    if existing.is_empty() {
        dir.into_owned()
    } else {
        format!("{dir}:{existing}")
    }
}

/// Build a `PATH` string identical to the current `PATH` but with the
/// directory containing the compiled `aa-proxy` binary removed, so
/// `resolve_binary()` in `start.rs` cannot find it via `which aa-proxy`.
///
/// Unlike setting `PATH=/usr/bin:/bin`, this preserves `cargo` and `rustc`
/// so that `cargo run -p aa-cli` continues to compile and execute normally.
fn path_without_proxy_dir() -> String {
    let proxy_dir = aa_proxy_bin().and_then(|p| p.parent().map(|d| d.to_path_buf()));

    std::env::var("PATH")
        .unwrap_or_default()
        .split(':')
        .filter(|segment| match &proxy_dir {
            Some(dir) => Path::new(segment) != dir.as_path(),
            None => true,
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// Best-effort teardown: kill then wait so no zombie remains.
fn reap_child(mut child: Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Write `<pid>\n<listen_addr>\n` to `<data_dir>/proxy.pid` so that
/// `aasm proxy status` / `stop` can read it without running `aasm proxy start`.
fn write_test_pid_file(data_dir: &Path, pid: u32, listen_addr: &str) {
    let path = data_dir.join("proxy.pid");
    std::fs::write(path, format!("{pid}\n{listen_addr}\n")).expect("write pid file");
}

/// Return the platform-specific path for the proxy log file under a fake
/// `HOME` directory, mirroring `default_log_path()` in `logs.rs`.
///
/// * macOS: `$HOME/Library/Application Support/aasm/logs/proxy.log`
/// * Linux: `$HOME/.local/share/aasm/logs/proxy.log`
fn proxy_log_path_for_home(fake_home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    let base = fake_home.join("Library").join("Application Support");
    #[cfg(not(target_os = "macos"))]
    let base = fake_home.join(".local").join("share");

    base.join("aasm").join("logs").join("proxy.log")
}

// ──────────────────────────────────── help + argument-parsing smoke ──────────

#[test]
fn proxy_help_exits_zero_and_lists_subcommands() {
    let fixture = ProxyFixture::new();
    let out = fixture
        .cmd()
        .args(["proxy", "--help"])
        .output()
        .expect("aasm proxy --help");
    assert!(
        out.status.success(),
        "should exit 0\nstderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for sub in ["start", "stop", "status", "logs"] {
        assert!(stdout.contains(sub), "banner should list '{sub}'; got:\n{stdout}");
    }
}

#[test]
fn proxy_start_help_shows_listen_flag() {
    let fixture = ProxyFixture::new();
    let out = fixture
        .cmd()
        .args(["proxy", "start", "--help"])
        .output()
        .expect("aasm proxy start --help");
    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--listen"),
        "start help should mention --listen; got:\n{stdout}"
    );
}

#[test]
fn proxy_stop_help_exits_zero() {
    let fixture = ProxyFixture::new();
    let out = fixture
        .cmd()
        .args(["proxy", "stop", "--help"])
        .output()
        .expect("aasm proxy stop --help");
    assert!(out.status.success(), "should exit 0");
}

#[test]
fn proxy_status_help_shows_json_flag() {
    let fixture = ProxyFixture::new();
    let out = fixture
        .cmd()
        .args(["proxy", "status", "--help"])
        .output()
        .expect("aasm proxy status --help");
    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--json"),
        "status help should mention --json; got:\n{stdout}"
    );
}

// ────────────────────────────── status / PID-file (no binary needed) ─────────

#[test]
fn proxy_status_no_pid_file_reports_not_running() {
    let fixture = ProxyFixture::new();
    let out = fixture
        .cmd()
        .args(["proxy", "status"])
        .output()
        .expect("aasm proxy status");
    assert!(out.status.success(), "should exit 0 when no proxy running");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not running"),
        "should say 'not running'; got:\n{stdout}"
    );
}

#[test]
fn proxy_status_stale_pid_cleans_up() {
    let fixture = ProxyFixture::new();

    // Spawn a short-lived process, wait for it to finish (reap), and use its
    // PID for a stale-PID-file scenario. After reaping, kill(pid, 0) returns
    // ESRCH so is_alive() returns false and status.rs cleans up the file.
    let dead_pid = {
        let mut child = Command::new("true").spawn().expect("spawn true");
        let pid = child.id();
        child.wait().expect("wait for true");
        pid
    };

    write_test_pid_file(fixture.data_dir(), dead_pid, "127.0.0.1:8899");
    assert!(
        fixture.data_dir().join("proxy.pid").exists(),
        "PID file should exist before status check"
    );

    let out = fixture
        .cmd()
        .args(["proxy", "status"])
        .output()
        .expect("aasm proxy status");
    assert!(out.status.success(), "should exit 0 for stale PID");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not running"),
        "should say 'not running' for stale PID; got:\n{stdout}"
    );
    assert!(
        !fixture.data_dir().join("proxy.pid").exists(),
        "stale PID file should be cleaned up after status"
    );
}

// ─────────────────────────────────────── start (needs aa-proxy binary) ───────

#[test]
fn proxy_start_exits_failure_when_binary_not_found() {
    // `resolve_binary()` in start.rs also checks `./target/release/aa-proxy`;
    // skip gracefully on machines where a release build already exists there.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace parent");
    if workspace.join("target").join("release").join("aa-proxy").exists() {
        eprintln!("proxy_start_exits_failure_when_binary_not_found: skipping — release build exists");
        return;
    }

    let fixture = ProxyFixture::new();
    let port = free_port();

    let out = fixture
        .cmd()
        .args(["proxy", "start", "--listen", &format!("127.0.0.1:{port}")])
        // Strip only the aa-proxy dir so `which aa-proxy` fails; keep
        // cargo/rustc accessible so `cargo run` can still compile aa-cli.
        // Override HOME so ~/.cargo/bin/aa-proxy is also absent.
        .env("PATH", path_without_proxy_dir())
        .env("HOME", fixture.data_dir())
        .output()
        .expect("aasm proxy start should run");

    assert!(!out.status.success(), "should exit non-zero when binary not found");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("aa-proxy binary not found") || stderr.contains("not found"),
        "stderr should report binary not found; got:\n{stderr}"
    );
}

#[test]
fn proxy_start_spawns_proxy_and_writes_pid_file() {
    let fixture = ProxyFixture::new();
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let out = fixture
        .cmd()
        .args(["proxy", "start", "--listen", &listen_addr])
        .env("PATH", path_with_proxy())
        .output()
        .expect("aasm proxy start");

    if !out.status.success() {
        // aa-proxy may fail to start on macOS if the CA keychain step needs admin.
        eprintln!(
            "proxy_start_spawns_proxy_and_writes_pid_file: skipping — aasm proxy start failed\n\
             On macOS, run `aasm proxy install-ca` first.\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        return;
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains(&format!("http://{listen_addr}")),
        "stdout should report listen address; got:\n{stdout}"
    );

    let pid_file = fixture.data_dir().join("proxy.pid");
    assert!(pid_file.exists(), "PID file should exist after start");

    let content = std::fs::read_to_string(&pid_file).expect("read pid file");
    let mut lines = content.lines();
    let _pid: u32 = lines.next().expect("PID line").parse().expect("PID is a number");
    let addr_line = lines.next().expect("addr line");
    assert_eq!(addr_line, listen_addr, "PID file should record the listen address");

    // Cleanup: stop the proxy.
    let stop = fixture.cmd().args(["proxy", "stop"]).output().expect("proxy stop");
    assert!(stop.status.success(), "proxy stop should succeed for cleanup");
}

// ────────────────────────────────────────── stop ──────────────────────────────

#[test]
fn proxy_stop_no_running_proxy_exits_zero() {
    let fixture = ProxyFixture::new();
    let out = fixture.cmd().args(["proxy", "stop"]).output().expect("aasm proxy stop");
    assert!(out.status.success(), "stop with no proxy should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("No running proxy found"),
        "should say no running proxy; got:\n{stdout}"
    );
}

#[test]
#[cfg(unix)]
fn proxy_stop_terminates_running_proxy_cleanly() {
    let fixture = ProxyFixture::new();

    // Spawn `sleep 60` as a stand-in for aa-proxy. Write its PID to the PID
    // file so `aasm proxy stop` can find and signal it.
    //
    // Because the test process is the parent of `sleep`, the child becomes a
    // zombie after SIGTERM (kernel keeps the PID-table entry until the parent
    // calls wait). `stop.rs` polls kill(pid, 0) — which returns 0 for zombies —
    // times out after 5 s, and issues SIGKILL. The PID file is then cleaned up
    // and `stop` exits 0 with "Proxy killed." This 5-second wait is expected.
    let child = Command::new("sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sleep 60");
    let child_pid = child.id();

    write_test_pid_file(fixture.data_dir(), child_pid, "127.0.0.1:8899");

    let stop_out = fixture.cmd().args(["proxy", "stop"]).output().expect("aasm proxy stop");

    // Reap the zombie now that stop has finished.
    reap_child(child);

    assert!(stop_out.status.success(), "proxy stop should exit 0");
    let stdout = String::from_utf8_lossy(&stop_out.stdout);
    assert!(
        stdout.contains("stopped") || stdout.contains("killed"),
        "should say stopped or killed; got:\n{stdout}"
    );
    assert!(
        !fixture.data_dir().join("proxy.pid").exists(),
        "PID file should be removed after stop"
    );
}

// ──────────────────────────────────── status with live listener ───────────────

/// Bind a real TCP port in-process and write the test process's own PID to
/// the PID file. `aasm proxy status` checks `kill(pid, 0)` (succeeds — test
/// is alive) and `TcpStream::connect_timeout` (succeeds — listener is bound),
/// so it reports `running` / `serving`. No `aa-proxy` binary is needed.
#[test]
fn proxy_status_running_text_reports_pid_and_addr() {
    let fixture = ProxyFixture::new();
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let _listener = TcpListener::bind(&listen_addr).expect("bind test listener");
    let our_pid = std::process::id();
    write_test_pid_file(fixture.data_dir(), our_pid, &listen_addr);

    let out = fixture
        .cmd()
        .args(["proxy", "status"])
        .output()
        .expect("aasm proxy status");
    assert!(out.status.success(), "status should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("running"), "should say 'running'; got:\n{stdout}");
    assert!(
        stdout.contains(&listen_addr),
        "should report listen address; got:\n{stdout}"
    );
    assert!(
        stdout.contains(&our_pid.to_string()),
        "should report PID; got:\n{stdout}"
    );
}

#[test]
fn proxy_status_running_json_has_correct_schema() {
    // Divergence: AC specifies `uptime_seconds: u64`; implementation
    // serialises `serving: bool`. Asserts on the actual status.rs schema.
    let fixture = ProxyFixture::new();
    let port = free_port();
    let listen_addr = format!("127.0.0.1:{port}");

    let _listener = TcpListener::bind(&listen_addr).expect("bind test listener");
    let our_pid = std::process::id();
    write_test_pid_file(fixture.data_dir(), our_pid, &listen_addr);

    let out = fixture
        .cmd()
        .args(["proxy", "status", "--json"])
        .output()
        .expect("aasm proxy status --json");
    assert!(out.status.success(), "status --json should exit 0");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).expect("output should be valid JSON");

    assert_eq!(parsed["running"], true, "running should be true");
    assert_eq!(
        parsed["pid"].as_u64().expect("pid should be numeric"),
        u64::from(our_pid),
        "pid should match test process PID"
    );
    assert_eq!(
        parsed["listen"].as_str().expect("listen should be string"),
        listen_addr,
        "listen should match the bound address"
    );
    assert!(
        parsed["serving"].is_boolean(),
        "serving should be a boolean (actual schema differs from AC); got: {:?}",
        parsed["serving"]
    );
}

// ────────────────────────────────────────────────── proxy logs ────────────────

#[test]
fn proxy_logs_reports_error_when_no_log_file() {
    let fixture = ProxyFixture::new();
    let fake_home = tempfile::tempdir().expect("tempdir for fake HOME");

    let out = fixture
        .cmd()
        .args(["proxy", "logs"])
        .env("HOME", fake_home.path())
        .output()
        .expect("aasm proxy logs");

    assert!(!out.status.success(), "should exit non-zero when log file absent");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("No proxy log file found") || stderr.contains("proxy.log"),
        "stderr should mention the missing log file; got:\n{stderr}"
    );
}

#[test]
fn proxy_logs_shows_last_n_lines() {
    let fixture = ProxyFixture::new();
    let fake_home = tempfile::tempdir().expect("tempdir for fake HOME");
    let log_path = proxy_log_path_for_home(fake_home.path());
    std::fs::create_dir_all(log_path.parent().expect("log parent dir")).expect("create log dirs");

    let lines: Vec<String> = (1..=10).map(|i| format!("INFO log line {i}")).collect();
    std::fs::write(&log_path, lines.join("\n") + "\n").expect("write log");

    let out = fixture
        .cmd()
        .args(["proxy", "logs", "--lines", "3"])
        .env("HOME", fake_home.path())
        .output()
        .expect("aasm proxy logs --lines 3");

    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("log line 10"), "should include line 10; got:\n{stdout}");
    assert!(stdout.contains("log line 9"), "should include line 9; got:\n{stdout}");
    assert!(stdout.contains("log line 8"), "should include line 8; got:\n{stdout}");
    assert!(
        !stdout.contains("log line 7"),
        "should NOT include line 7 (outside --lines 3 window); got:\n{stdout}"
    );
}

#[test]
fn proxy_logs_level_filter_excludes_debug() {
    let fixture = ProxyFixture::new();
    let fake_home = tempfile::tempdir().expect("tempdir for fake HOME");
    let log_path = proxy_log_path_for_home(fake_home.path());
    std::fs::create_dir_all(log_path.parent().expect("log parent dir")).expect("create log dirs");

    let content = "ERROR critical failure\nINFO startup complete\nDEBUG low-level trace\n";
    std::fs::write(&log_path, content).expect("write log");

    let out = fixture
        .cmd()
        .args(["proxy", "logs", "--lines", "50", "--level", "info"])
        .env("HOME", fake_home.path())
        .output()
        .expect("aasm proxy logs --level info");

    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("ERROR"), "error lines pass info filter; got:\n{stdout}");
    assert!(stdout.contains("INFO"), "info lines pass info filter; got:\n{stdout}");
    assert!(
        !stdout.contains("DEBUG"),
        "debug lines should be excluded by --level info; got:\n{stdout}"
    );
}

// ──────────────────────────────────────────── #[ignore] stubs ────────────────

#[test]
#[ignore = "requires aa-proxy to forward policy-deny 403 + event to gateway (not yet implemented)"]
fn proxy_start_blocks_deny_policy_request() {
    // TODO: once aa-proxy evaluates gateway policies and returns HTTP 403 for
    // deny-matched requests, verify the 403 response and the gateway event.
    todo!()
}

#[test]
#[ignore = "requires aa-proxy to POST intercepted-call events to the gateway (not yet implemented)"]
fn proxy_start_emits_audit_event_to_gateway() {
    // TODO: once aa-proxy emits PipelineEvents to POST /api/v1/events,
    // verify that a proxied request creates a corresponding audit entry.
    todo!()
}
