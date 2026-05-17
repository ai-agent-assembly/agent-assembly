//! CLI integration tests for `aasm audit` (AAASM-1461 / F121 ST-5).
//!
//! Exercises every `aasm audit <leaf>` subcommand against a live in-process
//! gateway booted via `CliFixture`. Two leaves (`list`, `export`) hit the
//! gateway via `GET /api/v1/logs`; the third (`verify-chain`) is
//! filesystem-only and reads a JSONL file via [`aa_gateway::audit::AuditWriter::verify_chain`].
//!
//! ## Leaf surface (from `aa-cli/src/commands/audit/`)
//!
//! | Leaf         | Args                                                   | Backend                                              | Notes |
//! | ------------ | ------------------------------------------------------ | ---------------------------------------------------- | ----- |
//! | list         | `--agent --action --result --since --until --limit`     | `GET /api/v1/logs`                                   | Honors global `--output {table,json,yaml}` |
//! | export       | `--format {csv,json} --output <file> --compliance ...` | `GET /api/v1/logs`                                   | Writes to stdout when `--output` is absent |
//! | verify-chain | positional `<path>`                                    | local JSONL file via `AuditWriter::verify_chain`     | Stdout `OK — N entries verified` on success; stderr `FAIL — hash chain broken at entry N` on tampered |
//!
//! Audit events surface through `/api/v1/logs` by reading JSONL files from
//! the harness's `audit_dir`. The `seed_audit_events` helper (added in this
//! file's companion `common/cli.rs` commit) writes `aa_core::AuditEntry`
//! lines into that dir so the real `AuditReader` picks them up.

mod common;

use aa_core::audit::AuditEventType;
use aa_core::identity::SessionId;
use aa_core::{AgentId, AuditEntry};
use common::cli::CliFixture;
use rstest::rstest;

/// Nanoseconds in one hour — used by the `--since` / `--until` filter
/// tests to position seeded events on either side of an absolute cutoff.
const NANOS_PER_HOUR: u64 = 3_600 * 1_000_000_000;

// =============================================================================
// aasm audit list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_happy_path_renders_table_with_seeded_events() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent: [u8; 16] = [0xa1; 16];
    fixture
        .seed_audit_events(5, agent, AuditEventType::ToolCallIntercepted)
        .expect("seed_audit_events should succeed");

    let out = fixture
        .cmd()
        .args(["audit", "list"])
        .output()
        .expect("aasm audit list should execute");
    assert!(
        out.status.success(),
        "should exit 0\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("TIMESTAMP"),
        "table header missing TIMESTAMP; got:\n{stdout}"
    );
    assert!(stdout.contains("ACTION"), "table header missing ACTION; got:\n{stdout}");
    assert!(
        stdout.contains("ToolCallIntercepted"),
        "event_type row missing; got:\n{stdout}"
    );
    assert!(stdout.contains("bash"), "seeded tool name missing; got:\n{stdout}");
}

#[rstest]
#[case::json("json")]
#[case::yaml("yaml")]
#[case::table("table")]
#[tokio::test(flavor = "multi_thread")]
async fn audit_list_succeeds_for_every_output_format(#[case] fmt: &str) {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent: [u8; 16] = [0xa2; 16];
    fixture
        .seed_audit_events(3, agent, AuditEventType::ToolCallIntercepted)
        .expect("seed_audit_events");

    let out = fixture
        .cmd()
        .args(["--output", fmt, "audit", "list"])
        .output()
        .expect("aasm audit list should execute");
    assert!(
        out.status.success(),
        "{fmt} should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(!out.stdout.is_empty(), "{fmt} stdout should not be empty");
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_json_and_yaml_describe_equivalent_records() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent: [u8; 16] = [0xa3; 16];
    fixture
        .seed_audit_events(4, agent, AuditEventType::ToolCallIntercepted)
        .expect("seed_audit_events");

    let json_out = fixture
        .cmd()
        .args(["--output", "json", "audit", "list"])
        .output()
        .expect("aasm audit list --output json should execute");
    assert!(json_out.status.success(), "json case should exit 0");

    let yaml_out = fixture
        .cmd()
        .args(["--output", "yaml", "audit", "list"])
        .output()
        .expect("aasm audit list --output yaml should execute");
    assert!(yaml_out.status.success(), "yaml case should exit 0");

    common::format::assert_equivalent_records(&json_out.stdout, &yaml_out.stdout, "agent_id");
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_agent_filter_narrows_to_one_agent() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent_keep: [u8; 16] = [0xb1; 16];
    let agent_drop: [u8; 16] = [0xb2; 16];
    fixture
        .seed_audit_events(2, agent_keep, AuditEventType::ToolCallIntercepted)
        .expect("seed agent_keep");
    fixture
        .seed_audit_events(3, agent_drop, AuditEventType::ToolCallIntercepted)
        .expect("seed agent_drop");

    let keep_hex = CliFixture::hex_id(&agent_keep);
    let drop_hex = CliFixture::hex_id(&agent_drop);
    let out = fixture
        .cmd()
        .args(["--output", "json", "audit", "list", "--agent", &keep_hex])
        .output()
        .expect("aasm audit list --agent should execute");
    assert!(
        out.status.success(),
        "should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let entries = common::format::parse_json(&out.stdout);
    let arr = entries.as_array().expect("json stdout should be an array");
    assert_eq!(
        arr.len(),
        2,
        "should return only the 2 events for agent_keep; got:\n{entries:#}"
    );
    for e in arr {
        assert_eq!(e.get("agent_id").and_then(|v| v.as_str()), Some(keep_hex.as_str()));
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains(&drop_hex),
        "agent_drop events should not leak through; got:\n{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_action_filter_narrows_to_one_event_type() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent: [u8; 16] = [0xb3; 16];
    fixture
        .seed_audit_events(2, agent, AuditEventType::ToolCallIntercepted)
        .expect("seed tool-call events");
    fixture
        .seed_audit_events(3, agent, AuditEventType::PolicyViolation)
        .expect("seed policy-violation events");

    let out = fixture
        .cmd()
        .args(["--output", "json", "audit", "list", "--action", "PolicyViolation"])
        .output()
        .expect("aasm audit list --action should execute");
    assert!(
        out.status.success(),
        "should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let entries = common::format::parse_json(&out.stdout);
    let arr = entries.as_array().expect("json stdout should be an array");
    assert_eq!(
        arr.len(),
        3,
        "should return only the 3 PolicyViolation events; got:\n{entries:#}"
    );
    for e in arr {
        assert_eq!(e.get("event_type").and_then(|v| v.as_str()), Some("PolicyViolation"));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn audit_list_since_filter_excludes_events_before_cutoff() {
    use std::io::Write as _;
    let fixture = CliFixture::start().await.expect("fixture should start");
    let agent_id = AgentId::from_bytes([0xb4; 16]);
    let session_id = SessionId::from_bytes([0xee; 16]);

    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock should be after Unix epoch")
        .as_nanos() as u64;

    // Genesis entry is ~24h old (well outside `--since 1h`) so the filter
    // must drop it; the second entry is ~5s old (inside the window).
    let old = AuditEntry::new(
        0,
        now_ns.saturating_sub(24 * NANOS_PER_HOUR),
        AuditEventType::ToolCallIntercepted,
        agent_id,
        session_id,
        r#"{"tool":"old","result":"allow","policy":"default"}"#.into(),
        [0u8; 32],
    );
    let new_entry = AuditEntry::new(
        1,
        now_ns.saturating_sub(5 * 1_000_000_000),
        AuditEventType::ToolCallIntercepted,
        agent_id,
        session_id,
        r#"{"tool":"new","result":"allow","policy":"default"}"#.into(),
        *old.entry_hash(),
    );
    let path = fixture.env.audit_dir.join("since-filter.jsonl");
    let mut f = std::fs::File::create(&path).expect("create since-filter.jsonl");
    writeln!(f, "{}", serde_json::to_string(&old).unwrap()).unwrap();
    writeln!(f, "{}", serde_json::to_string(&new_entry).unwrap()).unwrap();
    drop(f);

    let out = fixture
        .cmd()
        .args(["--output", "json", "audit", "list", "--since", "1h"])
        .output()
        .expect("aasm audit list --since should execute");
    assert!(
        out.status.success(),
        "should exit 0; stderr:\n{}",
        String::from_utf8_lossy(&out.stderr),
    );
    let parsed = common::format::parse_json(&out.stdout);
    let arr = parsed.as_array().expect("json stdout should be an array");
    assert_eq!(
        arr.len(),
        1,
        "--since 1h should exclude the 24h-old entry and keep only the recent one; got:\n{parsed:#}"
    );
    let payload = arr[0].get("payload").and_then(|v| v.as_str()).unwrap_or_default();
    assert!(
        payload.contains("\"tool\":\"new\""),
        "remaining entry should be the recent one; got payload {payload}"
    );
}

// =============================================================================
// aasm audit export
// =============================================================================

// =============================================================================
// aasm audit verify-chain
// =============================================================================
