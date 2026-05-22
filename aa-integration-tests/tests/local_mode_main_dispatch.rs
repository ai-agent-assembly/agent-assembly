//! AAASM-1731 — cross-binary end-to-end test for `AA_MODE=local`.
//!
//! Spawns the real `aa-gateway` binary with `AA_MODE=local`, an
//! ephemeral `AAASM_GATEWAY_PORT`, and `HOME` redirected to a tempdir
//! (so the PID file and SQLite DB land there instead of polluting the
//! developer's real `~/.aasm/`). Then:
//!
//! 1. Polls `GET /healthz` until 200; asserts `mode == "local"` and
//!    `storage == "sqlite"`.
//! 2. Sends SIGTERM to the gateway process.
//! 3. Asserts the process exits 0 within 5 s.
//! 4. Asserts `<tempdir>/.aasm/gateway.pid` was removed by the
//!    graceful shutdown path (AAASM-1728).
//!
//! Unix-only — relies on `libc::kill(SIGTERM)` and `$HOME` redirection.

#![cfg(unix)]

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use tempfile::TempDir;

/// Grab a free port by binding to `127.0.0.1:0` and immediately dropping.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind 127.0.0.1:0")
        .local_addr()
        .expect("local_addr")
        .port()
}

/// Locate the `aa-gateway` binary on disk, or return `None` to signal
/// the test should skip.
///
/// Mirrors `cli_gateway.rs` skip-gracefully pattern so the Integration
/// tests CI job (which runs `cargo nextest run --workspace` without
/// first invoking `cargo build -p aa-gateway`) doesn't fail when the
/// binary isn't yet built. Uses absolute paths via `CARGO_MANIFEST_DIR`
/// because nextest sets the test's CWD to the test-crate's manifest
/// directory, not the workspace root.
fn locate_aa_gateway() -> Option<PathBuf> {
    fn binary_runnable(path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        path.metadata().is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
    }

    // Workspace target/ — CARGO_MANIFEST_DIR is `<workspace>/aa-integration-tests`,
    // so the workspace root is one level up.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(workspace_root) = manifest_dir.parent() {
        for profile in &["release", "debug"] {
            let p = workspace_root.join("target").join(profile).join("aa-gateway");
            if binary_runnable(&p) {
                return Some(p);
            }
        }
    }

    // `$HOME/.cargo/bin/aa-gateway` (cargo install).
    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(home).join(".cargo").join("bin").join("aa-gateway");
        if binary_runnable(&p) {
            return Some(p);
        }
    }

    // PATH lookup.
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let p = std::path::Path::new(dir).join("aa-gateway");
            if binary_runnable(&p) {
                return Some(p);
            }
        }
    }

    None
}

/// Send `signal` to `pid`. No-op on failure (process may have already exited).
fn kill_process(pid: u32, signal: libc::c_int) {
    unsafe {
        libc::kill(pid as libc::pid_t, signal);
    }
}

/// Poll `GET /healthz` until 200 or `deadline` elapses.
async fn wait_for_healthz(port: u16, deadline: Duration) -> Option<serde_json::Value> {
    let url = format!("http://127.0.0.1:{port}/healthz");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(250))
        .build()
        .expect("reqwest client");
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.json::<serde_json::Value>().await {
                    return Some(body);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

#[tokio::test]
async fn aa_mode_local_serves_healthz_and_exits_cleanly_on_sigterm() {
    let Some(binary) = locate_aa_gateway() else {
        eprintln!("skip: aa-gateway binary not found — run `cargo build -p aa-gateway` first");
        return;
    };

    // Hermetic tempdir for $HOME so PID + SQLite DB land here.
    let tmp = TempDir::new().expect("tempdir");
    let port = free_port();

    let mut child = Command::new(&binary)
        .env("AA_MODE", "local")
        .env("AAASM_GATEWAY_PORT", port.to_string())
        .env("HOME", tmp.path())
        // Silence the startup banner / tracing output so test logs stay clean.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn aa-gateway");
    let pid = child.id();

    // 1. /healthz round-trip.
    let body = wait_for_healthz(port, Duration::from_secs(10)).await;
    let body = match body {
        Some(b) => b,
        None => {
            kill_process(pid, libc::SIGKILL);
            let _ = child.wait();
            panic!("AA_MODE=local: /healthz never came up on port {port}");
        }
    };
    assert_eq!(body["mode"], "local", "AAASM-1576 AC #4 — mode label");
    assert_eq!(body["storage"], "sqlite", "AAASM-1576 AC #4 — storage label");

    // PID file must exist while the process is running.
    let pid_path: PathBuf = tmp.path().join(".aasm/gateway.pid");
    assert!(
        pid_path.is_file(),
        "AAASM-1576 AC #7 — PID file must be written while gateway runs"
    );

    // 2. Send SIGTERM.
    kill_process(pid, libc::SIGTERM);

    // 3. Wait for clean exit (within 5s). Use spawn_blocking — std::process::Child::wait blocks.
    let exit_status = tokio::task::spawn_blocking(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if std::time::Instant::now() >= deadline => {
                    let _ = child.kill();
                    return Err("process did not exit within 5 s of SIGTERM");
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(e) => return Err(Box::leak(format!("wait error: {e}").into_boxed_str())),
            }
        }
    })
    .await
    .expect("spawn_blocking")
    .expect("clean exit within 5 s of SIGTERM");

    assert!(
        exit_status.success(),
        "AA_MODE=local must exit 0 on SIGTERM; got {exit_status:?}"
    );

    // 4. PID file removed by the AAASM-1728 cleanup path.
    assert!(
        !pid_path.exists(),
        "AAASM-1576 AC #8 — PID file must be removed by clean shutdown"
    );
}
