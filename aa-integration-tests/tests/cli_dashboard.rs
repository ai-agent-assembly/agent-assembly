//! CLI integration tests for `aasm dashboard` (AAASM-1471 ST-15 + AAASM-1481 ST-15b).
//!
//! Two waves of coverage live in this file:
//!
//! * **`--help` banner smoke** (AAASM-1471, ST-15) — the original 4 tests for
//!   the parent `dashboard` command and global-flag clap acceptance.
//! * **HTTP server lifecycle** (AAASM-1481, ST-15b) — spawn `aasm dashboard
//!   start`, exercise the embedded SPA route + `/api/*` reverse-proxy +
//!   `aasm dashboard stop` (PID file) + signal-driven graceful shutdown +
//!   edge cases (port collision, unreachable gateway). The legacy crate
//!   `aa-cli/tests/dashboard_start.rs` is superseded by these tests.
//!
//! ## Stub-tolerance for the embedded SPA
//!
//! `aa-cli/build.rs` produces a build-time stub `dashboard/dist/index.html`
//! (`Dashboard not built. Run pnpm build…`) when the real React build isn't
//! present — this is the production fallback and the harness exercises it
//! verbatim. The lifecycle tests therefore assert on properties that hold
//! for **both** the stub and the real SPA (HTTP 200, non-empty body, HTML
//! content-type, identifiable HTML markup). Asset-discovery and React-root
//! assertions only fire when a real `/assets/*.js` reference is present;
//! when the stub is being served, the asset case is skipped with a logged
//! note so the test still reports green without false-positive coverage.
//!
//! ## Divergence from subtask description (AAASM-1481)
//!
//! * `--bind ADDR` / `--gateway URL` / `--no-open` flags don't exist on
//!   `aasm dashboard start`. The actual surface is `--port N [--open]`.
//!   The proxy test routes via the top-level global `--api-url` (already
//!   wired by `CliFixture::cmd()`).
//! * `--port 0` for stdout port discovery would print `…:0` (the print
//!   uses the requested port, not the bound port), so tests pre-pick a
//!   free port via `TcpListener::bind("127.0.0.1:0")` instead.
//!
//! ## Divergence from subtask description (AAASM-1471)
//!
//! AAASM-1471's description calls the global override flag `--gateway-url`;
//! master ships it as `--api-url` (declared on the top-level `Cli` struct
//! at `aa-cli/src/lib.rs` with `global = true`). The clap-parser-smoke
//! test uses `--api-url` accordingly.
//!
//! ## Future follow-up (not in scope)
//!
//! Full TUI interaction testing (key navigation, dialog rendering, feed
//! updates) requires a `vte`-style virtual-terminal harness. The parent
//! Story's "Out of scope" section explicitly defers this.

mod common;

use std::net::TcpListener;
use std::process::{Child, Stdio};
use std::time::{Duration, Instant};

use common::cli::CliFixture;

/// Pre-pick a free TCP port for `aasm dashboard start --port <N>`. We pick
/// here and immediately drop the listener; there's a small TOCTOU window
/// before the dashboard binds, but in practice it's reliable for tests and
/// matches the legacy `aa-cli/tests/dashboard_start.rs` pattern.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("could not bind 127.0.0.1:0")
        .local_addr()
        .expect("could not read local_addr")
        .port()
}

/// Poll `url` until it responds with status < 500 or `timeout` elapses.
/// Returns the final HTTP status code if the server became ready in time,
/// else `None`.
async fn wait_for_http(url: &str, timeout: Duration) -> Option<u16> {
    let deadline = Instant::now() + timeout;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .expect("reqwest client");
    while Instant::now() < deadline {
        if let Ok(resp) = client.get(url).send().await {
            let status = resp.status().as_u16();
            if status < 500 {
                return Some(status);
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// Best-effort teardown — `kill()` then `wait_with_output()` so the child
/// is reaped and no zombie remains. Safe to call even if the child already
/// exited. Returns the captured output for callers that want to inspect
/// stderr after teardown.
fn reap_child(mut child: Child) -> std::process::Output {
    let _ = child.kill();
    child.wait_with_output().unwrap_or_else(|_| std::process::Output {
        status: std::process::ExitStatus::default(),
        stdout: vec![],
        stderr: vec![],
    })
}

// ============================================================================
// aasm dashboard --help — banner-content tests (preserved from AAASM-1471)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_help_exits_zero_and_describes_tui() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "--help"])
        .output()
        .expect("aasm dashboard --help should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Open an interactive TUI dashboard"),
        "banner should describe the TUI; got:\n{stdout}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_subcommand_name_appears_in_banner() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "--help"])
        .output()
        .expect("aasm dashboard --help should execute");
    assert!(out.status.success(), "should exit 0");
    let stdout = String::from_utf8_lossy(&out.stdout);
    // Catches an accidental rename of the subcommand (e.g. dashboard→ui).
    // The Usage line is `Usage: aasm dashboard [OPTIONS] [COMMAND]`, so
    // asserting on the qualified `aasm dashboard` token is precise enough
    // to fail loudly if the leaf is renamed without also being unique
    // enough to false-positive against an unrelated mention.
    assert!(
        stdout.contains("aasm dashboard"),
        "banner should contain the qualified subcommand name 'aasm dashboard'; got:\n{stdout}",
    );
}

// ============================================================================
// aasm dashboard --help — clap parser smoke for global flags (AAASM-1471)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_help_accepts_global_api_url_flag() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    // Global `--api-url` is declared on the top-level `Cli` struct with
    // `global = true`, so clap must accept it next to any subcommand
    // including `dashboard --help`. The flag value is irrelevant to
    // `--help`; this just verifies clap doesn't choke.
    let out = fixture
        .cmd()
        .args(["dashboard", "--help", "--api-url", "http://x"])
        .output()
        .expect("aasm dashboard --help --api-url … should execute");
    assert!(
        out.status.success(),
        "clap should accept global --api-url next to dashboard --help\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_help_accepts_global_output_format_flag() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "--help", "--output", "json"])
        .output()
        .expect("aasm dashboard --help --output json should execute");
    assert!(
        out.status.success(),
        "clap should accept global --output next to dashboard --help\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

// ============================================================================
// aasm dashboard start — HTTP serving happy path (AAASM-1481)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_serves_index_html() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    let status = wait_for_http(&url, Duration::from_secs(30)).await;
    assert_eq!(
        status,
        Some(200),
        "dashboard should respond 200 at / within 30s; got {status:?}"
    );

    let body = reqwest::get(&url)
        .await
        .expect("GET /")
        .text()
        .await
        .expect("body text");
    assert!(
        body.contains("<html") || body.contains("<!doctype"),
        "/ should serve HTML markup (stub or real); got:\n{body}",
    );

    let _ = reap_child(child);
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_returns_200_for_root_repeatedly() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    assert_eq!(
        wait_for_http(&url, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should become reachable",
    );

    let client = reqwest::Client::new();
    for i in 0..3 {
        let status = client
            .get(&url)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET / attempt {i} failed: {e}"))
            .status()
            .as_u16();
        assert_eq!(status, 200, "GET / attempt {i} should return 200");
    }

    let _ = reap_child(child);
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_serves_static_assets() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    assert_eq!(
        wait_for_http(&url, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should become reachable",
    );

    let index_body = reqwest::get(&url)
        .await
        .expect("GET /")
        .text()
        .await
        .expect("index body");

    // Find the first `/assets/...js` reference if present. When the build.rs
    // stub is embedded, no such reference exists and we skip the asset
    // fetch — the stub case is exercised by the other two happy-path tests.
    let asset_rel = index_body
        .split('"')
        .chain(index_body.split('\''))
        .find(|s| s.starts_with("/assets/") && (s.ends_with(".js") || s.contains(".js?")));

    if let Some(rel) = asset_rel {
        let asset_url = format!("http://127.0.0.1:{port}{rel}");
        let resp = reqwest::get(&asset_url).await.expect("GET asset");
        let status = resp.status();
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body_bytes = resp.bytes().await.expect("asset body bytes");
        assert!(status.is_success(), "asset GET should succeed; got {status}");
        assert!(
            content_type.contains("javascript"),
            "asset content-type should be javascript-flavoured; got {content_type:?}",
        );
        assert!(!body_bytes.is_empty(), "asset body should be non-empty");
    } else {
        eprintln!(
            "dashboard_start_serves_static_assets: no /assets/*.js reference in served index — \
             likely the build.rs stub; skipping the asset-fetch assertion. \
             Re-run `pnpm build` in dashboard/ to exercise the real SPA path.",
        );
    }

    let _ = reap_child(child);
}

// ============================================================================
// aasm dashboard start / stop — lifecycle + signal handling (AAASM-1481)
// ============================================================================

/// Send `signum` to `pid` on Unix. Returns 0 on success (matches the libc
/// convention). Tests SHOULD use this rather than `Child::kill()` when the
/// goal is to trigger the dashboard's graceful-shutdown path, which only
/// listens for SIGINT (`tokio::signal::ctrl_c()` in `start.rs`). Posting
/// SIGKILL via `Child::kill()` would skip cleanup entirely.
#[cfg(unix)]
fn send_signal(pid: u32, signum: libc::c_int) -> i32 {
    unsafe { libc::kill(pid as libc::pid_t, signum) }
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_then_stop_cleans_pidfile() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");
    let pid_file = fixture.data_dir().join("dashboard.pid");

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    assert_eq!(
        wait_for_http(&url, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should become reachable",
    );
    // Give start.rs a tick to flush the pid file (write_pid runs immediately
    // after bind but before the println; we already waited on HTTP readiness
    // so this is just paranoia for slow filesystems).
    for _ in 0..10 {
        if pid_file.exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        pid_file.exists(),
        "PID file should exist after start at {}",
        pid_file.display(),
    );

    let stop_out = fixture
        .cmd()
        .args(["dashboard", "stop"])
        .output()
        .expect("aasm dashboard stop should execute");
    assert!(
        stop_out.status.success(),
        "stop should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&stop_out.stderr),
    );

    assert!(
        !pid_file.exists(),
        "PID file should be removed after stop; still present at {}",
        pid_file.display(),
    );

    // The child has been SIGTERM'd by `stop`; reap it and verify the port
    // is released (a fresh bind should succeed within ~2 s).
    let _ = reap_child(child);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bound_again = false;
    while Instant::now() < deadline {
        if TcpListener::bind(format!("127.0.0.1:{port}")).is_ok() {
            bound_again = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(bound_again, "port {port} should be released after stop within 2 s");
}

#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_sigint_clean_shutdown() {
    // start.rs uses `tokio::signal::ctrl_c()` (SIGINT only) as the graceful-
    // shutdown trigger. SIGTERM (what `aasm dashboard stop` sends) has no
    // handler and terminates the process via the default action; this test
    // therefore targets SIGINT to exercise the actual graceful path.
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    assert_eq!(
        wait_for_http(&url, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should become reachable",
    );

    let pid = child.id();
    assert_eq!(send_signal(pid, libc::SIGINT), 0, "kill(SIGINT) should succeed");

    // Wait up to 3 s for the graceful shutdown.
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut child = child;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if Instant::now() >= deadline => break None,
            Ok(None) => tokio::time::sleep(Duration::from_millis(50)).await,
            Err(_) => break None,
        }
    };
    if let Some(status) = exit_status {
        assert!(
            status.success(),
            "dashboard should exit cleanly under SIGINT; got status {status}",
        );
    } else {
        let _ = child.kill();
        panic!("dashboard did not exit within 3 s of SIGINT");
    }
    let _ = child.wait_with_output();
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_stop_with_no_server_running() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let pid_file = fixture.data_dir().join("dashboard.pid");
    assert!(
        !pid_file.exists(),
        "precondition: pid file should not exist in a fresh fixture",
    );

    let out = fixture
        .cmd()
        .args(["dashboard", "stop"])
        .output()
        .expect("aasm dashboard stop should execute");
    // `stop.rs` returns ExitCode::SUCCESS with stdout "No running dashboard
    // found." when no pid file is present — verified against the implementation.
    // (The ticket's wishful "non-zero exit" doesn't match real behaviour; we
    // pin what's there so accidental regressions show up.)
    assert!(
        out.status.success(),
        "stop with no server should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.to_lowercase().contains("no running dashboard"),
        "stop with no server should print a 'no running dashboard' message; got:\n{stdout}",
    );
}

// ============================================================================
// aasm dashboard start — gateway reverse-proxy (AAASM-1481)
// ============================================================================

// `dashboard start` reverse-proxies `/api/*` to `ctx.api_url` (the value of
// the top-level `--api-url` global flag, already wired by `CliFixture::cmd()`
// to the harness's in-process gateway). This test seeds two agents into the
// gateway, GETs `/api/v1/agents` through the dashboard, and asserts the
// response is structurally identical to a direct GET against the gateway.
#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_proxies_gateway_api() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_agents(2);

    let port = free_port();
    let dashboard_root = format!("http://127.0.0.1:{port}/");
    let proxied = format!("http://127.0.0.1:{port}/api/v1/agents");
    let direct = format!("{}/api/v1/agents", fixture.base_url());

    let child = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    assert_eq!(
        wait_for_http(&dashboard_root, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should become reachable",
    );

    let through_proxy: serde_json::Value = reqwest::get(&proxied)
        .await
        .expect("GET via dashboard proxy")
        .json()
        .await
        .expect("proxy response is JSON");
    let direct_resp: serde_json::Value = reqwest::get(&direct)
        .await
        .expect("GET direct against gateway")
        .json()
        .await
        .expect("direct response is JSON");

    assert_eq!(
        through_proxy, direct_resp,
        "proxied response should match direct gateway response",
    );

    let _ = reap_child(child);
}

// ============================================================================
// aasm dashboard start — edge cases (AAASM-1481)
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_port_collision() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    // Hold a listener on the port for the duration of the test so the
    // dashboard hits a guaranteed collision.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind should succeed");
    let port = listener.local_addr().expect("local_addr").port();

    let out = fixture
        .cmd()
        .args(["dashboard", "start", "--port", &port.to_string()])
        .output()
        .expect("aasm dashboard start should execute");

    assert!(
        !out.status.success(),
        "dashboard start should fail on port collision; got status {:?}",
        out.status,
    );
    let stderr = String::from_utf8_lossy(&out.stderr).to_lowercase();
    assert!(
        stderr.contains("address already in use") || stderr.contains("eaddrinuse"),
        "stderr should explain the collision (looking for 'address already in use' or 'eaddrinuse'); got:\n{stderr}",
    );
    drop(listener);
}

#[tokio::test(flavor = "multi_thread")]
async fn dashboard_start_invalid_gateway_url() {
    // `--api-url` is rejected by clap when supplied twice, so we cannot
    // simply append a second copy onto `CliFixture::cmd()` (which already
    // pins it to the fixture's reachable gateway). Build a fresh Command
    // manually that points at a deliberately bogus gateway, while still
    // setting `AA_DATA_DIR` for PID-file isolation.
    let fixture = CliFixture::start().await.expect("fixture should start");
    let port = free_port();
    let url = format!("http://127.0.0.1:{port}/");

    let child = std::process::Command::new(env!("CARGO"))
        .args([
            "run",
            "--quiet",
            "-p",
            "aa-cli",
            "--bin",
            "aasm",
            "--",
            "--api-url",
            "http://nope.invalid:1",
            "dashboard",
            "start",
            "--port",
            &port.to_string(),
        ])
        .env("AA_DATA_DIR", fixture.data_dir())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm dashboard start should spawn");

    // Confirms the documented contract: the gateway URL is only contacted
    // lazily on `/api/*` calls, so an unreachable gateway does NOT prevent
    // boot or block static-file serving at `/`.
    assert_eq!(
        wait_for_http(&url, Duration::from_secs(30)).await,
        Some(200),
        "dashboard should still serve `/` even with an unreachable gateway",
    );

    let _ = reap_child(child);
}

// ============================================================================
// aasm dashboard open — CLI smoke only (AAASM-1481)
// ============================================================================

// We intentionally do NOT invoke `aasm dashboard open` for real: it tries
// to launch the system browser via `open::that(...)`, which is unreliable
// (and disruptive) in CI runners and on local-developer machines alike.
// The `--help` banner is enough to pin the clap parser surface and catch
// accidental flag renames; the `open.rs` reachability+launch path is
// covered indirectly by its own unit tests in `aa-cli`.
#[tokio::test(flavor = "multi_thread")]
async fn dashboard_open_help_lists_flags() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["dashboard", "open", "--help"])
        .output()
        .expect("aasm dashboard open --help should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("--port"),
        "open --help banner should list the --port flag; got:\n{stdout}",
    );
}
