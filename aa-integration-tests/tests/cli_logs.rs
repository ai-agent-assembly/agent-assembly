//! CLI integration tests for `aasm logs` (AAASM-1462 / F121 ST-6).
//!
//! Covers the snapshot path (`aasm logs`) backed by `GET /api/v1/logs`, the
//! per-`--output` format matrix, every supported filter flag, a combined-filter
//! scenario, and a `--follow` streaming-alive smoke test.
//!
//! ## Leaf surface (from `aa-cli/src/commands/logs/`)
//!
//! | Flag         | Notes                                                                  |
//! | ---          | ---                                                                    |
//! | `--follow` / `-f` | Switches dispatch to the WebSocket follow path.                   |
//! | `--agent`    | Hex-encoded agent ID; forwarded as `?agent_id=...` to the REST query.  |
//! | `--type`     | Event-type filter (`violation` / `approval` / `budget`).               |
//! | `--since`    | Duration shorthand (`30m`, `2h`, `1d`) or ISO 8601; client-side cut.   |
//! | `--until`    | ISO 8601 only; client-side cut.                                        |
//! | `--limit`    | `per_page` for the REST query (default 50).                            |
//! | `--no-color` | Disables ANSI color in plain-text output.                              |
//! | `--output`   | `json` branches to `format_log_json`; everything else falls through    |
//! |              | to `format_log_line` — so `yaml` currently renders the same plain-text |
//! |              | output as `table`.                                                     |
//!
//! ## Divergence notes from the ticket text (AAASM-1462)
//!
//! * Ticket mentions a `--level` flag and a `--component` flag — neither
//!   exists in the CLI. The closest surface is `--type`, which is what these
//!   tests exercise; `--component` has no analogue so the test for it is
//!   omitted (the ticket itself disclaimed this with "verify at impl time").
//! * Ticket asks the `--follow` test to assert `≥7 events on stdout within
//!   3s, then SIGTERM`. The established cli_agent.rs `--watch` precedent
//!   documents that stdout-count assertions under SIGKILL are unreliable
//!   because Rust's stdout is block-buffered to pipes. This file adopts the
//!   same "process-stays-alive" assertion (cli_agent.rs:155-179).

mod common;

use aa_core::audit::AuditEventType;
use common::cli::CliFixture;
use rstest::rstest;
use serde_json::Value;

/// Parse newline-delimited JSON from `aasm logs --output json`.
fn parse_jsonl(stdout: &[u8]) -> Vec<Value> {
    std::str::from_utf8(stdout)
        .expect("stdout is utf-8")
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str::<Value>(l).expect("each stdout line is a JSON object"))
        .collect()
}

// =============================================================================
// aasm logs (snapshot mode)
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_happy_path_returns_seeded_events() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent = fixture.seed_agents(1)[0];
    fixture
        .seed_audit_events(5, agent, AuditEventType::PolicyViolation)
        .expect("seed should succeed");

    let out = fixture
        .cmd()
        .args(["logs", "--output", "json"])
        .output()
        .expect("aasm logs should execute");
    assert!(
        out.status.success(),
        "aasm logs should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let entries = parse_jsonl(&out.stdout);
    assert_eq!(entries.len(), 5, "5 seeded events expected in stdout");
}

// NOTE on `--output yaml`: `aa-cli/src/commands/logs/fetch.rs` only branches
// on `Json` vs. text — yaml is parsed by clap but renders the same plain-text
// shape as `table`. The format test below parametrizes all three so the matrix
// matches the ticket AC; it asserts on exit + non-empty stdout rather than on
// format-specific structure because yaml/table share the same renderer today.
#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn logs_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent = fixture.seed_agents(1)[0];
    fixture
        .seed_audit_events(2, agent, AuditEventType::PolicyViolation)
        .expect("seed should succeed");

    let out = fixture
        .cmd()
        .args(["logs", "--output", fmt])
        .output()
        .expect("aasm logs should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_agent_filter_only_returns_matching() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agents = fixture.seed_agents(2);
    let (agent_a, agent_b) = (agents[0], agents[1]);
    fixture
        .seed_audit_events(3, agent_a, AuditEventType::PolicyViolation)
        .expect("seed A should succeed");
    fixture
        .seed_audit_events(2, agent_b, AuditEventType::PolicyViolation)
        .expect("seed B should succeed");

    let agent_a_hex = CliFixture::hex_id(&agent_a);
    let out = fixture
        .cmd()
        .args(["logs", "--agent", &agent_a_hex, "--output", "json"])
        .output()
        .expect("aasm logs --agent should execute");
    assert!(out.status.success());
    let entries = parse_jsonl(&out.stdout);
    assert_eq!(entries.len(), 3, "only agent_a events expected");
    for e in &entries {
        assert_eq!(e["agent_id"], agent_a_hex, "stray non-matching event in stdout");
    }
}
