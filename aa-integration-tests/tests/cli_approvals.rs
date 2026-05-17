//! CLI integration tests for `aasm approvals` (AAASM-1469 / F121 ST-13).
//!
//! Exercises the testable subset of `aasm approvals` against a live
//! in-process gateway booted via `CliFixture`. Per the scope-adjustment
//! note on AAASM-1469, 11 of the originally-planned 21 tests are blocked
//! on the prereq Subtask AAASM-1477 (missing `GET /approvals/:id`,
//! list filter flags, stdin reason support) and ride a follow-up
//! "ST-13b" Subtask once that lands.
//!
//! ## Leaf surface
//!
//! | Leaf | Args | Flags | Notes |
//! | --- | --- | --- | --- |
//! | list | — | `--output` | Maps `/api/v1/approvals` paginated response → items array |
//! | approve | `<id>` | `--reason` (optional) | POST `/approve`; entry leaves pending queue |
//! | reject | `<id>` | `--reason` (required at runtime) | POST `/reject`; entry leaves pending queue |
//! | watch | — | `--interactive` | Subcommand (not a flag); WS-streaming |
//!
//! `get` is *not* covered — the route does not exist in `aa-api` yet.
//! See AAASM-1477.

mod common;

use std::process::Stdio;
use std::time::Duration;

use common::cli::CliFixture;
use rstest::rstest;

// =============================================================================
// aasm approvals list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_list_happy_path_returns_all_seeded() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_approval("agent-a", "tool.invoke");
    fixture.seed_approval("agent-b", "tool.invoke");
    fixture.seed_approval("agent-c", "tool.invoke");

    let out = fixture
        .cmd()
        .args(["approvals", "list", "--output", "json"])
        .output()
        .expect("aasm approvals list should execute");

    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );

    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("stdout should be valid JSON array");
    let items = v.as_array().expect("stdout JSON should be an array");
    assert_eq!(items.len(), 3, "list should return all 3 seeded approvals");
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn approvals_list_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    fixture.seed_approval("agent-a", "tool.invoke");

    let out = fixture
        .cmd()
        .args(["approvals", "list", "--output", fmt])
        .output()
        .expect("aasm approvals list should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "{fmt} should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

// =============================================================================
// aasm approvals approve
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_approve_happy_path_consumes_pending_entry() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_approval("agent-a", "tool.invoke");
    let id_str = id.to_string();

    let out = fixture
        .cmd()
        .args(["approvals", "approve", &id_str, "--reason", "ok"])
        .output()
        .expect("aasm approvals approve should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "approve should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stdout.contains("Approved"),
        "stdout should report Approved\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&id_str),
        "stdout should echo the approval id\nstdout:\n{stdout}"
    );

    // The pending queue should have lost the entry after the transition.
    let list_out = fixture
        .cmd()
        .args(["approvals", "list", "--output", "json"])
        .output()
        .expect("aasm approvals list should execute");
    let list_stdout = String::from_utf8_lossy(&list_out.stdout);
    let v: serde_json::Value =
        serde_json::from_slice(&list_out.stdout).expect("list stdout should be valid JSON array");
    let items = v.as_array().expect("list stdout should be a JSON array");
    assert!(
        items.is_empty(),
        "approved entry should leave the pending queue (got {} item(s))\nstdout:\n{list_stdout}",
        items.len(),
    );
}

// =============================================================================
// aasm approvals reject
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_happy_path_consumes_pending_entry() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_approval("agent-a", "tool.invoke");
    let id_str = id.to_string();

    let out = fixture
        .cmd()
        .args(["approvals", "reject", &id_str, "--reason", "no"])
        .output()
        .expect("aasm approvals reject should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        out.status.success(),
        "reject should exit 0\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stdout.contains("Rejected"),
        "stdout should report Rejected\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&id_str),
        "stdout should echo the approval id\nstdout:\n{stdout}"
    );

    let list_out = fixture
        .cmd()
        .args(["approvals", "list", "--output", "json"])
        .output()
        .expect("aasm approvals list should execute");
    let v: serde_json::Value =
        serde_json::from_slice(&list_out.stdout).expect("list stdout should be valid JSON array");
    let items = v.as_array().expect("list stdout should be a JSON array");
    assert!(
        items.is_empty(),
        "rejected entry should leave the pending queue (got {} item(s))",
        items.len(),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_without_reason_errors() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let id = fixture.seed_approval("agent-a", "tool.invoke");

    let out = fixture
        .cmd()
        .args(["approvals", "reject", &id.to_string()])
        .output()
        .expect("aasm approvals reject (no --reason) should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "reject without --reason should exit non-zero\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        stderr.contains("--reason"),
        "stderr should mention the missing --reason flag\nstderr:\n{stderr}",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_approve_unknown_id_errors() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    // Well-formed UUID that was never submitted to the queue → expect 404 from
    // aa-api → CLI surfaces as non-zero exit with an error on stderr.
    let unknown_id = "00000000-0000-0000-0000-000000000000";

    let out = fixture
        .cmd()
        .args(["approvals", "approve", unknown_id, "--reason", "ok"])
        .output()
        .expect("aasm approvals approve should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "approve <unknown> should exit non-zero\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        !stderr.is_empty(),
        "stderr should describe the not-found error\nstderr:\n{stderr}",
    );
}

// =============================================================================
// aasm approvals watch — streaming
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn approvals_watch_runs_until_killed() {
    // Establishes that the `watch` subcommand wires the WebSocket connection
    // and enters its event loop without crashing. The "≥N events" assertion
    // from the AC is intentionally not made here — Rust's stdout is
    // block-buffered to pipes and in-flight bytes are lost on kill (see the
    // matching note on `cli_agent::agent_list_watch_runs_until_killed`).
    let fixture = CliFixture::start().await.expect("fixture should start");

    let mut child = fixture
        .cmd()
        .args(["approvals", "watch"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("aasm approvals watch should spawn");

    // Give the CLI enough time to open the WS connection and enter its loop.
    std::thread::sleep(Duration::from_millis(1500));
    assert!(
        child.try_wait().expect("try_wait should work").is_none(),
        "approvals watch should keep the process alive (not exit on its own)",
    );

    child.kill().expect("kill should succeed");
    let _ = child.wait_with_output();
}

#[tokio::test(flavor = "multi_thread")]
async fn approvals_reject_unknown_id_errors() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let unknown_id = "00000000-0000-0000-0000-000000000000";

    let out = fixture
        .cmd()
        .args(["approvals", "reject", unknown_id, "--reason", "no"])
        .output()
        .expect("aasm approvals reject should execute");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "reject <unknown> should exit non-zero\nstdout:\n{stdout}\nstderr:\n{stderr}",
    );
    assert!(
        !stderr.is_empty(),
        "stderr should describe the not-found error\nstderr:\n{stderr}",
    );
}
