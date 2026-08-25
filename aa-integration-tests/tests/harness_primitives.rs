//! Self-tests for the AAASM-5902 harness primitives.
//!
//! These are not journey tests — they prove the primitives themselves are
//! trustworthy before any Subtask B journey builds on them. Two properties
//! matter most, both because a silent failure here would make every
//! downstream journey pass for the wrong reason:
//!
//! 1. [`canary_is_detected_by_the_real_scanner_with_expected_kind`] — a
//!    canary is only evidence if the real `aa_security` scanner actually
//!    recognises it as the kind it claims to be. If the scanner's detector
//!    regex ever drifts from what [`common::canary::Canary`] generates, every
//!    downstream "the raw canary is absent" assertion would still pass, not
//!    because redaction worked, but because the "secret" was never
//!    recognisable as one.
//! 2. [`api_server_spawn_fails_when_the_telemetry_port_is_already_held`] — the
//!    load-bearing truthfulness case. `aa-api-server`'s telemetry ingest
//!    degrades a port collision to a warning and keeps serving REST, so a
//!    harness that only polled `/api/v1/health` could not tell a fully healthy
//!    server apart from one silently missing its telemetry ingest. This test
//!    proves `ApiServerProcess::spawn` genuinely reports that degraded state
//!    as a spawn failure rather than a healthy-looking handle.

mod common;

use std::time::Duration;

use aa_security::CredentialKind;
use common::api_server::ApiServerProcess;
use common::canary::{self, Canary};
use common::capturing_upstream::{CapturingUpstream, UpstreamOptions};
use common::managed_process::{pick_free_port, ManagedProcess, ProcessSpec, Readiness};

// ── Canary ───────────────────────────────────────────────────────────────

#[test]
fn canary_is_detected_by_the_real_scanner_with_expected_kind() {
    for kind in [
        CredentialKind::AwsAccessKey,
        CredentialKind::AnthropicKey,
        CredentialKind::OpenAiKey,
        CredentialKind::GitHubPat,
    ] {
        let c = Canary::new(kind.clone());
        let text = format!("some log line containing {} inline", c.value());
        let result = canary::scan(&text);
        let matched = result.findings.iter().find(|f| f.kind == kind).unwrap_or_else(|| {
            panic!(
                "canary {:?} (value {:?}) was NOT detected as {kind:?} by the real scanner — \
                     findings: {:?}. Either the generator's shape or the scanner's detector has \
                     drifted; this must be fixed before any journey trusts this canary kind.",
                c.kind(),
                c.value(),
                result.findings,
            )
        });
        assert_eq!(
            matched.matched,
            c.expected_redaction_marker(),
            "redaction label mismatch for {kind:?}",
        );
    }
}

#[test]
fn two_canaries_in_one_process_differ() {
    let a = Canary::new(CredentialKind::AwsAccessKey);
    let b = Canary::new(CredentialKind::AwsAccessKey);
    assert_ne!(a.value(), b.value(), "two canaries of the same kind must not collide");
    assert_ne!(a.run_id(), b.run_id());
}

#[test]
fn assert_absent_panics_naming_the_destination_on_leak() {
    let c = Canary::new(CredentialKind::AwsAccessKey);
    let leaked = format!("payload containing {}", c.value());
    let result = std::panic::catch_unwind(|| c.assert_absent("mock-upstream", &leaked));
    let err = result.expect_err("assert_absent must panic when the raw canary is present");
    let msg = err.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("mock-upstream"),
        "panic message must name the destination, got: {msg}"
    );
}

// ── CapturingUpstream ────────────────────────────────────────────────────

#[tokio::test]
async fn capturing_upstream_records_exact_forwarded_bytes() {
    let opts = UpstreamOptions {
        response_body: b"{\"ok\":true}".to_vec(),
        ..Default::default()
    };
    let upstream = CapturingUpstream::start_plain(opts)
        .await
        .expect("start plain upstream");

    let body = b"exact bytes 12345 \x00\x01 canary-value".to_vec();
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/v1/messages", upstream.addr))
        .body(body.clone())
        .send()
        .await
        .expect("POST to capturing upstream");
    assert!(resp.status().is_success());

    let observed = upstream.wait_for_requests(1, Duration::from_secs(5)).await;
    assert_eq!(observed, 1);
    let requests = upstream.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].body, body,
        "captured body must be byte-identical to what was sent"
    );
    assert_eq!(requests[0].path, "/v1/messages");
}

// ── ManagedProcess ───────────────────────────────────────────────────────

/// A `python3` one-liner that binds `port`, prints `READY_MARKER` (flushed),
/// then sleeps until it receives SIGTERM (Python's default SIGTERM handler
/// exits the process). Used instead of a hand-rolled test-only binary so this
/// self-test carries no new build target — `sdk_driver.rs` already resolves
/// `python3` from `$PATH` for the same reason.
fn python_bind_and_wait_script(port: u16) -> String {
    format!(
        "import socket,sys,time\n\
         s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind(('127.0.0.1', {port}))\n\
         s.listen(1)\n\
         print('READY_MARKER', flush=True)\n\
         time.sleep(120)\n"
    )
}

#[test]
fn managed_process_stop_reaps_pid_and_frees_port() {
    let port = pick_free_port().expect("pick free port");
    let log_dir = tempfile::tempdir().expect("temp log dir");

    let spec = ProcessSpec {
        name: "managed-process-selftest".to_owned(),
        program: "python3".into(),
        args: vec!["-c".to_owned(), python_bind_and_wait_script(port)],
        env: Vec::new(),
        cwd: None,
        ready: vec![Readiness::LogLine("READY_MARKER")],
        ready_timeout: Duration::from_secs(10),
        log_dir: log_dir.path().to_path_buf(),
        owned_ports: vec![port],
    };

    let mut proc = ManagedProcess::spawn(spec).expect("spawn must succeed once READY_MARKER is observed");
    let pid = proc.pid();
    #[cfg(unix)]
    assert_eq!(
        unsafe { libc::kill(pid as libc::pid_t, 0) },
        0,
        "child should be alive right after spawn"
    );

    // The port really is held while the child is alive: binding it ourselves
    // must fail. This is what makes the post-stop re-bindability check below
    // meaningful rather than trivially true.
    assert!(
        std::net::TcpListener::bind(("127.0.0.1", port)).is_err(),
        "port {port} should still be held by the child before stop()",
    );

    proc.stop(Duration::from_secs(5))
        .expect("stop must succeed without needing the SIGKILL safety net");
    proc.assert_no_leaks();
}

#[test]
fn managed_process_readiness_times_out_cleanly() {
    let log_dir = tempfile::tempdir().expect("temp log dir");
    let spec = ProcessSpec {
        name: "managed-process-timeout-selftest".to_owned(),
        program: "python3".into(),
        args: vec!["-c".to_owned(), "import time; time.sleep(60)".to_owned()],
        env: Vec::new(),
        cwd: None,
        // This line is never printed by the script above, so readiness can
        // only be satisfied by the timeout firing.
        ready: vec![Readiness::LogLine("THIS_LINE_NEVER_APPEARS")],
        ready_timeout: Duration::from_millis(500),
        log_dir: log_dir.path().to_path_buf(),
        owned_ports: Vec::new(),
    };

    let start = std::time::Instant::now();
    let result = ManagedProcess::spawn(spec);
    let elapsed = start.elapsed();

    assert!(
        result.is_err(),
        "spawn must return Err on a readiness timeout, not a not-ready handle"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("did not become ready"),
        "error must explain the timeout, got: {msg}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "a 500ms readiness timeout must not turn into a long hang; took {elapsed:?}",
    );
}

// ── ApiServerProcess ─────────────────────────────────────────────────────

/// AAASM-5875's core truthfulness property, exercised directly: a degraded
/// telemetry bind must be reported as a spawn failure, never as a
/// healthy-looking handle.
///
/// # Why this proves the `LogLine` condition is load-bearing
///
/// `aa-api-server`'s REST/health surface comes up regardless of whether the
/// telemetry port bind succeeds (`aa-api/src/server.rs::serve_local_telemetry_grpc`
/// degrades a port collision to a warning and continues). So `/api/v1/health`
/// alone cannot distinguish this scenario from a fully healthy server — only
/// the absence of the telemetry-bind log line can. Pre-binding the telemetry
/// port here, before `ApiServerProcess::spawn_with` ever tries it, forces
/// exactly that degraded path and asserts the spawn call surfaces it as an
/// error rather than silently returning a REST-only server that looks fine.
#[test]
fn api_server_spawn_fails_when_the_telemetry_port_is_already_held() {
    let telemetry_port = pick_free_port().expect("pick a port to pre-hold");
    // Held for the whole test: this is what forces aa-api-server's telemetry
    // bind into the AddrInUse/degrade path.
    let _holder = std::net::TcpListener::bind(("127.0.0.1", telemetry_port)).expect("pre-bind the telemetry port");

    let result = ApiServerProcess::spawn_with(Some(telemetry_port), Duration::from_secs(15));

    assert!(
        result.is_err(),
        "ApiServerProcess::spawn_with must fail when the telemetry port is already held — a \
         degraded server (REST healthy, telemetry silently missing) must never look like a \
         healthy spawn",
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("did not become ready"),
        "expected a readiness-timeout error (the HttpOk condition succeeds but the LogLine \
         condition never does), got: {msg}",
    );
}

/// Positive control for the test above: with a free telemetry port,
/// `ApiServerProcess::spawn` must succeed and both readiness conditions must
/// actually have been observed (not just "no error").
#[test]
fn api_server_spawn_succeeds_and_reports_alerts_when_telemetry_port_is_free() {
    let mut server = ApiServerProcess::spawn().expect("spawn must succeed with a free telemetry port");
    let logs = server.logs();
    assert!(
        logs.contains(common::api_server::TELEMETRY_READY_LOG_LINE),
        "captured logs must contain the telemetry-ready line once spawn() has returned Ok; got:\n{logs}",
    );

    let alerts = server.alerts().expect("GET /api/v1/alerts");
    assert_eq!(alerts.total, 0, "a freshly spawned server has no alerts yet");

    server.stop().expect("stop must succeed cleanly");
    server.assert_no_leaks();
}
