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
