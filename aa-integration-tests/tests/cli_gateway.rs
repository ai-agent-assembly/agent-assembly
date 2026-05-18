//! Integration tests for `aasm gateway` subcommand lifecycle.
//!
//! AAASM-1511 / F121 ST-19.
//! Pattern mirrors cli_dashboard.rs (AAASM-1481 ST-15b).
//!
//! Each test uses CliFixture which sets a per-test AA_DATA_DIR for
//! gateway.pid isolation, preventing races under parallel nextest runs.
//!
//! ## Notes on timing
//!
//! * `gateway_start_with_invalid_policy_returns_clear_error` and
//!   `gateway_start_port_collision_returns_error` each take ~10s because
//!   `aasm gateway start` polls TCP for up to 10s before declaring failure.
//! * `gateway_stop_force_kills_after_timeout` is `#[ignore]`'d (see test).
//!
//! ## Tracing log format
//!
//! aa-gateway uses `tracing_subscriber::fmt()` (plain-text, not JSON).
//! Tests that seed or inspect the log file work with plain-text lines.
//! The `aasm gateway logs` command passes non-JSON lines through unchanged.

mod common;

use std::io::Write;
use std::net::TcpListener;
use std::process::Stdio;
use std::time::Duration;

use common::cli::CliFixture;
use tempfile::TempDir;

// ── shared helpers ─────────────────────────────────────────────────────────

const MINIMAL_POLICY: &str = "\
apiVersion: agent-assembly.dev/v1alpha1\n\
kind: GovernancePolicy\n\
spec:\n\
  rules: []\n";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .expect("local_addr")
        .port()
}

fn write_policy_file(dir: &TempDir) -> std::path::PathBuf {
    let path = dir.path().join("policy.yaml");
    std::fs::write(&path, MINIMAL_POLICY).expect("write policy.yaml");
    path
}

fn read_pid_file(data_dir: &std::path::Path) -> Option<(u32, String)> {
    let content = std::fs::read_to_string(data_dir.join("gateway.pid")).ok()?;
    let mut lines = content.lines();
    let pid: u32 = lines.next()?.parse().ok()?;
    let listen = lines.next()?.to_string();
    Some((pid, listen))
}

async fn poll_tcp(addr: &str, timeout: Duration) -> bool {
    let Ok(sock) = addr.parse::<std::net::SocketAddr>() else {
        return false;
    };
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        if tokio::net::TcpStream::connect(sock).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[cfg(unix)]
fn kill_process(pid: u32, signal: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
}

// ── help banner (3 tests) ─────────────────────────────────────────────────

#[tokio::test]
async fn gateway_help_lists_all_four_subcommands() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let out = ctx.cmd().args(["gateway", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    for sub in ["start", "stop", "status", "logs"] {
        assert!(
            stdout.contains(sub),
            "'{sub}' missing from `aasm gateway --help`:\n{stdout}"
        );
    }
}

#[tokio::test]
async fn gateway_help_describes_brain_role() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let out = ctx.cmd().args(["gateway", "--help"]).output().expect("run");
    let text = String::from_utf8_lossy(&out.stdout).to_ascii_lowercase();
    assert!(
        text.contains("governance") || text.contains("policy") || text.contains("registry"),
        "gateway --help should describe its governance role:\n{text}"
    );
}

#[tokio::test]
async fn gateway_start_help_lists_flags() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let out = ctx.cmd().args(["gateway", "start", "--help"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    for flag in ["--policy", "--listen", "--socket", "--no-detach", "--log-file"] {
        assert!(
            stdout.contains(flag),
            "'{flag}' missing from `aasm gateway start --help`:\n{stdout}"
        );
    }
}

// ── start (5 tests) ───────────────────────────────────────────────────────

#[tokio::test]
async fn gateway_start_spawns_grpc_listener_and_writes_pidfile() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_policy_file(&tmp);
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let log_file = tmp.path().join("gateway.log");

    let out = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            policy.to_str().unwrap(),
            "--listen",
            &listen,
            "--log-file",
            log_file.to_str().unwrap(),
            "--no-detach",
        ])
        .output()
        .expect("run aasm gateway start");

    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "start should exit 0; stderr:\n{stderr}");
    assert!(
        stdout.contains(&format!("grpc://{listen}")),
        "stdout should contain 'grpc://{listen}':\n{stdout}"
    );

    // PID file must exist with matching listen address.
    let (gateway_pid, pid_listen) = read_pid_file(ctx.data_dir()).expect("gateway.pid must exist after start");
    assert_eq!(pid_listen, listen, "PID file listen addr mismatch");
    assert!(gateway_pid > 0, "gateway PID must be positive");

    // gRPC transport layer: gateway must accept TCP connections.
    // (aasm gateway start already probed this; we verify independently.)
    assert!(
        poll_tcp(&listen, Duration::from_secs(5)).await,
        "gRPC listener must accept TCP connections on {listen}"
    );

    // Graceful stop removes PID file.
    let stop = ctx
        .cmd()
        .args(["gateway", "stop"])
        .output()
        .expect("run aasm gateway stop");
    assert!(stop.status.success(), "stop should exit 0");
    assert!(
        !ctx.data_dir().join("gateway.pid").exists(),
        "gateway.pid should be removed after stop"
    );

    // Verify the gateway process is gone.
    #[cfg(unix)]
    {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let ret = unsafe { libc::kill(gateway_pid as libc::pid_t, 0) };
        assert_ne!(ret, 0, "gateway process (pid {gateway_pid}) should be dead after stop");
    }
}

#[tokio::test]
async fn gateway_start_default_policy_resolution_falls_through() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let port = free_port();

    // Point HOME at a fresh temp dir so ~/.aasm/policy.yaml does not exist.
    // AA_POLICY is explicitly removed so all 4 resolution paths are tried and
    // fail, triggering the "no policy file found" error immediately.
    let out = ctx
        .cmd()
        .env("HOME", tmp.path())
        .env_remove("AA_POLICY")
        .args(["gateway", "start", "--listen", &format!("127.0.0.1:{port}")])
        .output()
        .expect("run");

    assert!(!out.status.success(), "start must fail when no policy file is found");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("policy") || stderr.contains("AA_POLICY"),
        "error must mention policy resolution; got:\n{stderr}"
    );
}

// Note: this test takes ~10s because aasm gateway start polls TCP for 10s
// before declaring the gateway unreachable when aa-gateway exits immediately
// due to policy parse failure.
#[tokio::test]
async fn gateway_start_with_invalid_policy_returns_clear_error() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let bad_policy = tmp.path().join("bad.yaml");
    // Syntactically valid YAML but invalid GovernancePolicy content forces
    // aa-gateway to exit immediately, so CLI's TCP readiness probe times out.
    std::fs::write(&bad_policy, b"not_a_policy: true\ninvalid_field: [1, 2\n").unwrap();
    let port = free_port();
    let log_file = tmp.path().join("gateway.log");

    let out = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            bad_policy.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--log-file",
            log_file.to_str().unwrap(),
        ])
        .output()
        .expect("run");

    assert!(!out.status.success(), "start must fail with invalid policy");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // CLI reports readiness timeout; actual parse error is in the log file.
    assert!(
        stderr.contains("ready") || stderr.contains("10s") || stderr.contains("log"),
        "stderr should explain the failure or point to log file:\n{stderr}"
    );
}

// Note: this test takes ~10s because aasm gateway start polls TCP for 10s
// before declaring the gateway unreachable when aa-gateway fails to bind.
#[tokio::test]
async fn gateway_start_port_collision_returns_error() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_policy_file(&tmp);
    let log_file = tmp.path().join("gateway.log");

    // Hold the port so aa-gateway can't bind it.
    let holder = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = holder.local_addr().unwrap().port();

    let out = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            policy.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--log-file",
            log_file.to_str().unwrap(),
        ])
        .output()
        .expect("run");

    drop(holder);
    assert!(!out.status.success(), "start must fail when port is already in use");
}

#[cfg(unix)]
#[tokio::test]
async fn gateway_start_unix_socket_mode_binds_socket() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_policy_file(&tmp);
    let socket_path = tmp.path().join("aasm-gw.sock");
    let log_file = tmp.path().join("gateway.log");

    // Socket mode: CLI exits immediately after spawning (no TCP readiness probe).
    let out = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            policy.to_str().unwrap(),
            "--socket",
            socket_path.to_str().unwrap(),
            "--log-file",
            log_file.to_str().unwrap(),
            "--no-detach",
        ])
        .output()
        .expect("run");

    assert!(
        out.status.success(),
        "start (socket mode) should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Poll until socket file appears — gateway may still be initializing.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !socket_path.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        socket_path.exists(),
        "socket file must exist at {}",
        socket_path.display()
    );

    // Verify the Unix socket accepts connections.
    assert!(
        tokio::net::UnixStream::connect(&socket_path).await.is_ok(),
        "should be able to connect to gateway Unix socket"
    );

    // Cleanup: SIGTERM the gateway via PID file.
    if let Some((pid, _)) = read_pid_file(ctx.data_dir()) {
        kill_process(pid, libc::SIGTERM);
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

// ── status (3 tests) ─────────────────────────────────────────────────────

#[tokio::test]
async fn gateway_status_when_not_running_returns_not_running() {
    let ctx = CliFixture::start().await.expect("start fixture");
    // No gateway started → no PID file → status reports not running.
    let out = ctx.cmd().args(["gateway", "status"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Exit 1 (not 0) when not running: lets scripts do `status || start`.
    assert_eq!(out.status.code(), Some(1), "exit code must be 1 when not running");
    assert!(
        stdout.to_ascii_lowercase().contains("not running"),
        "stdout must say 'not running':\n{stdout}"
    );
}

#[tokio::test]
async fn gateway_status_when_running_includes_grpc_metadata() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_policy_file(&tmp);
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let log_file = tmp.path().join("gateway.log");

    let start = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            policy.to_str().unwrap(),
            "--listen",
            &listen,
            "--log-file",
            log_file.to_str().unwrap(),
            "--no-detach",
        ])
        .output()
        .expect("run start");
    assert!(start.status.success(), "gateway start must succeed");

    let status_out = ctx
        .cmd()
        .args(["gateway", "status", "--json"])
        .output()
        .expect("run status --json");

    assert!(
        status_out.status.success(),
        "status --json must exit 0 when gateway is running"
    );

    let json: serde_json::Value =
        serde_json::from_slice(&status_out.stdout).expect("status --json must emit valid JSON");

    assert_eq!(json["running"], true, "running field must be true");
    assert!(json.get("pid").is_some(), "pid must be present in JSON output");
    assert!(json.get("listen").is_some(), "listen must be present in JSON output");
    assert!(
        json.get("uptime_seconds").is_some(),
        "uptime_seconds must be present (started_at is a valid RFC3339 timestamp)"
    );
    // Note: agents_registered / policy_version / audit_log_path are pending a
    // follow-up gRPC status RPC in aa-gateway (see status.rs comment).

    // Cleanup.
    let _ = ctx.cmd().args(["gateway", "stop"]).output();
}

#[tokio::test]
async fn gateway_status_when_pidfile_exists_but_process_dead_reports_stale() {
    let ctx = CliFixture::start().await.expect("start fixture");

    // Spawn a process, wait for it to exit, then use its (now-reaped) PID.
    // Avoids u32::MAX which wraps to pid_t -1 and broadcasts SIGTERM to all
    // user processes (matching pattern from stop.rs unit tests).
    let mut child = std::process::Command::new("true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn 'true'");
    let dead_pid = child.id();
    child.wait().expect("wait for 'true' to exit");

    // Write a PID file pointing to the dead process.
    std::fs::create_dir_all(ctx.data_dir()).unwrap();
    std::fs::write(
        ctx.data_dir().join("gateway.pid"),
        format!("{dead_pid}\n127.0.0.1:50099\n2026-05-18T00:00:00Z\n"),
    )
    .unwrap();

    let out = ctx.cmd().args(["gateway", "status"]).output().expect("run");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Non-zero exit: dead process means gateway is not running.
    assert_ne!(
        out.status.code(),
        Some(0),
        "status must exit non-zero for a stale PID file"
    );
    assert!(
        stdout.contains(&dead_pid.to_string()) || stdout.to_ascii_lowercase().contains("not respond"),
        "stdout should mention stale pid ({dead_pid}) or 'not respond':\n{stdout}"
    );
}

// ── stop (3 tests, 1 #[ignore]) ───────────────────────────────────────────

#[tokio::test]
async fn gateway_stop_graceful_shutdown_flushes_audit() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_policy_file(&tmp);
    let port = free_port();
    let listen = format!("127.0.0.1:{port}");
    let log_file = tmp.path().join("gateway.log");

    let start = ctx
        .cmd()
        .args([
            "gateway",
            "start",
            "--policy",
            policy.to_str().unwrap(),
            "--listen",
            &listen,
            "--log-file",
            log_file.to_str().unwrap(),
            "--no-detach",
        ])
        .output()
        .expect("run start");
    assert!(start.status.success(), "gateway start must succeed");

    // Let the gateway emit at least its startup log lines.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Graceful stop: SIGTERM → up to 10s grace period → SIGKILL fallback.
    let stop = ctx.cmd().args(["gateway", "stop"]).output().expect("run stop");
    assert!(stop.status.success(), "stop must exit 0");

    // Log file must exist and be non-empty (gateway wrote startup tracing lines).
    assert!(log_file.exists(), "gateway log file must exist after shutdown");
    let content = std::fs::read_to_string(&log_file).expect("read log file");
    assert!(
        !content.is_empty(),
        "log file must not be empty after graceful shutdown"
    );

    // File must end with a newline: confirms tracing flush was not truncated
    // mid-line by an abrupt SIGKILL (all buffered output should be flushed on
    // graceful SIGTERM exit).
    assert!(
        content.ends_with('\n'),
        "log file must end with a newline — truncation would indicate unclean shutdown"
    );
}

#[tokio::test]
async fn gateway_stop_is_idempotent_when_not_running() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let out = ctx.cmd().args(["gateway", "stop"]).output().expect("run");
    assert!(out.status.success(), "stop must exit 0 when no gateway is running");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_ascii_lowercase().contains("not running"),
        "stdout should say 'not running':\n{stdout}"
    );
}

#[ignore = "requires reliably holding aa-gateway busy via concurrent gRPC RPCs — blocked on tonic client fixtures in aa-integration-tests"]
#[tokio::test]
async fn gateway_stop_force_kills_after_timeout() {
    // TODO: start gateway; fire many concurrent gRPC RPCs to simulate a hung
    // shutdown; call `aasm gateway stop`; verify SIGKILL warning is printed
    // and the process terminates within ~11s (10s SIGTERM grace + 1s).
    //
    // Blocked on: tonic client deps in aa-integration-tests/Cargo.toml so
    // the test harness can call gateway gRPC endpoints directly.
}

// ── logs (2 tests) ────────────────────────────────────────────────────────

#[tokio::test]
async fn gateway_logs_last_n_returns_recent_entries() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let log_file = tmp.path().join("gateway.log");

    // Seed 10 structured log lines (plain-text format, matching aa-gateway's
    // tracing_subscriber::fmt() output; matches_level passes non-JSON through).
    {
        let mut f = std::fs::File::create(&log_file).unwrap();
        for i in 0..10u32 {
            writeln!(f, "2026-05-18T10:{i:02}:00Z  INFO aa_gateway: entry {i}").unwrap();
        }
    }

    let out = ctx
        .cmd()
        .args([
            "gateway",
            "logs",
            "--lines",
            "3",
            "--log-file",
            log_file.to_str().unwrap(),
        ])
        .output()
        .expect("run");

    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "must print exactly 3 lines (last 3 of 10); got:\n{stdout}"
    );
    // Last 3 entries are i = 7, 8, 9.
    assert!(
        lines[0].contains("entry 7"),
        "line[0] should be entry 7; got: {}",
        lines[0]
    );
    assert!(
        lines[2].contains("entry 9"),
        "line[2] should be entry 9; got: {}",
        lines[2]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn gateway_logs_follow_streams_new_entries() {
    let ctx = CliFixture::start().await.expect("start fixture");
    let tmp = tempfile::tempdir().unwrap();
    let log_file = tmp.path().join("gateway.log");

    // Create an empty log file so `logs -f` can open it.
    std::fs::File::create(&log_file).unwrap();

    // Spawn `aasm gateway logs -f` and capture its stdout.
    // stdout uses LineWriter so each println! call flushes immediately,
    // making the output available to wait_with_output() even after SIGTERM.
    let child = ctx
        .cmd()
        .args(["gateway", "logs", "-f", "--log-file", log_file.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn gateway logs -f");

    // Give the follow process time to open the file and seek to EOF.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // Append one new tracing-style log line.
    let new_line = "2026-05-18T11:00:00Z  INFO aa_gateway: streamed";
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(&log_file).unwrap();
        writeln!(f, "{new_line}").unwrap();
    }

    // Follow polls every 100ms; allow 2s for the line to appear in stdout.
    tokio::time::sleep(Duration::from_secs(2)).await;

    let child_pid = child.id();
    kill_process(child_pid, libc::SIGTERM);
    let result = child.wait_with_output().expect("wait_with_output");
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("streamed"),
        "follow output must contain the appended line 'streamed';\ngot:\n{stdout}"
    );
}
