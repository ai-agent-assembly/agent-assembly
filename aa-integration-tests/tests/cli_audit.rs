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
use common::cli::CliFixture;
use rstest::rstest;

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

// =============================================================================
// aasm audit export
// =============================================================================

// =============================================================================
// aasm audit verify-chain
// =============================================================================
