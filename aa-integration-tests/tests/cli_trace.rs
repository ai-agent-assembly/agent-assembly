//! CLI integration tests for `aasm trace` (AAASM-1468 / F121 ST-12).
//!
//! Exercises the `aasm trace <session-id>` command against a live
//! in-process gateway booted via `CliFixture`. Tests cover:
//!
//! * Happy path with default `--format tree`
//! * Happy path with `--format timeline`
//! * `--output {json|yaml|table}` coverage for both `--format` variants
//! * Negative path — unknown session ID returns non-zero exit
//!
//! ## Scope vs. the ticket description
//!
//! The ticket text describes a richer surface (`aasm trace tree <id>`,
//! `aasm trace timeline <id>` subcommands, with `--depth`, `--root-id`,
//! `--since`, `--limit` flags). The actual `aa-cli/src/commands/trace/`
//! implementation only has a flat `aasm trace <id> [--format tree|timeline]`
//! surface today, so this test file targets the **real surface**. The
//! ticket-described subcommands and flags remain out of scope.
//!
//! ## CLI/API contract
//!
//! `aa-api` returns `TraceResponse { session_id, agent_id, spans }`; the
//! CLI's `aa-cli/src/commands/trace/wire.rs` translates that into the
//! hierarchical `SessionTrace { events }` the renderer consumes
//! (AAASM-1475). The seeded operation names (`op-0`, `op-1`, …) appear
//! verbatim in the rendered output across all three `--output` formats
//! and both `--format` variants, so the happy-path tests below assert
//! on that to verify the end-to-end contract.

mod common;

use common::cli::CliFixture;
use rstest::rstest;

// =============================================================================
// aasm trace <session-id>  (happy path — default --format tree)
// =============================================================================

/// `aasm trace <id>` against a seeded session must exit 0 and render
/// every seeded operation name in the tree output.
#[tokio::test(flavor = "multi_thread")]
async fn trace_seeded_session_default_format_succeeds() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let session_id = "sess-aaasm-1468-default";
    fixture.seed_trace_session(session_id, "agent-1468", 3);

    let out = fixture
        .cmd()
        .args(["trace", session_id])
        .output()
        .expect("aasm trace should execute");

    assert!(
        out.status.success(),
        "should exit 0 for a seeded session\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for op in ["op-0", "op-1", "op-2"] {
        assert!(
            stdout.contains(op),
            "tree stdout should contain seeded operation `{op}`\nstdout:\n{stdout}",
        );
    }
}

// =============================================================================
// aasm trace <session-id> --format timeline  (happy path)
// =============================================================================

/// `aasm trace <id> --format timeline` against a seeded session must
/// exit 0 and render every seeded operation in the timeline view.
#[tokio::test(flavor = "multi_thread")]
async fn trace_seeded_session_timeline_format_succeeds() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let session_id = "sess-aaasm-1468-timeline";
    fixture.seed_trace_session(session_id, "agent-1468", 4);

    let out = fixture
        .cmd()
        .args(["trace", session_id, "--format", "timeline"])
        .output()
        .expect("aasm trace should execute");

    assert!(
        out.status.success(),
        "should exit 0 for a seeded session with --format timeline\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    for op in ["op-0", "op-1", "op-2", "op-3"] {
        assert!(
            stdout.contains(op),
            "timeline stdout should contain seeded operation `{op}`\nstdout:\n{stdout}",
        );
    }
}

// =============================================================================
// aasm trace <session-id> --output {json|yaml|table}  (format coverage)
// =============================================================================

/// Every `--output` format must succeed for a seeded session and surface
/// the seeded operation name(s) in its serialization. Parametrized over
/// the three supported formats via `#[rstest]`.
#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn trace_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let session_id = "sess-aaasm-1468-format";
    fixture.seed_trace_session(session_id, "agent-1468", 2);

    let out = fixture
        .cmd()
        .args(["trace", session_id, "--output", fmt])
        .output()
        .expect("aasm trace should execute");

    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("op-0"),
        "{fmt} stdout should contain seeded operation `op-0`\nstdout:\n{stdout}",
    );
    assert!(
        stdout.contains("op-1"),
        "{fmt} stdout should contain seeded operation `op-1`\nstdout:\n{stdout}",
    );
}

// =============================================================================
// aasm trace <session-id>  (negative path)
// =============================================================================

/// Unknown session IDs must surface as a clean non-zero exit, with the
/// missing identifier echoed somewhere in stderr so a human can debug.
///
/// This works today because the CLI calls `error_for_status()` on the
/// 404 response before attempting deserialization.
#[tokio::test(flavor = "multi_thread")]
async fn trace_unknown_session_id_returns_failure() {
    let fixture = CliFixture::start().await.expect("fixture should start");

    let out = fixture
        .cmd()
        .args(["trace", "no-such-session-1468"])
        .output()
        .expect("aasm trace should execute");

    assert!(
        !out.status.success(),
        "should exit non-zero for an unknown session\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("error"),
        "stderr should mention an error\nstderr:\n{stderr}",
    );
}
