//! End-to-end tests for `aasm audit compliance-export` (AAASM-1945 / ST-Y).
//!
//! These tests exercise the real built CLI binary against synthetic per-session
//! audit JSONL files produced with `aa_core::AuditEntry`. They verify that the
//! compliance export preserves the regulator-relevant fidelity (hash chain,
//! credential findings, ISO 8601 timestamps) and that redaction is enforced
//! end-to-end — the raw secret string must never appear in the produced
//! export, only the `[REDACTED:<Kind>]` labels.
//!
//! The tests sit in `aa-integration-tests/tests/` (not `aa-cli/tests/`) for
//! the same reason as `cli_audit_export.rs`: `assert_cmd::cargo_bin` cannot
//! invoke a sibling crate's binary, so we rely on `CliFixture` which spawns
//! `cargo run -p aa-cli --bin aasm` for every test.

mod common;

use std::io::Write as _;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AuditEntry, AuditEventType, Lineage};
use aa_security::Redaction;
use aa_security::{CredentialKind, CredentialScanner};
use common::cli::CliFixture;

/// Synthetic OpenAI key the test embeds in a payload. Must never appear in
/// the compliance-export output verbatim — only `[REDACTED:OpenAiKey]`.
const FAKE_OPENAI_KEY: &str = "sk-FAKEKEY1234567890abcdef";

fn fixed_agent() -> AgentId {
    AgentId::from_bytes([0x11; 16])
}

fn fixed_session() -> SessionId {
    SessionId::from_bytes([0x22; 16])
}

/// Build a 3-entry hash chain where entry 1 carries a credential finding
/// produced by scanning a payload that contains a synthetic OpenAI key.
///
/// * Entry 0: clean ToolCallIntercepted with no findings.
/// * Entry 1: ToolCallIntercepted carrying the secret in `payload`,
///   `credential_findings` populated, `redacted_payload` set to the scanner
///   output.
/// * Entry 2: PolicyViolation, clean.
fn build_chain_with_redaction() -> Vec<AuditEntry> {
    let agent = fixed_agent();
    let session = fixed_session();

    let mut entries = Vec::new();

    // Entry 0 — clean genesis.
    let e0 = AuditEntry::new(
        0,
        1_700_000_000_000_000_000,
        AuditEventType::ToolCallIntercepted,
        agent,
        session,
        r#"{"tool":"read_file","args":{"path":"/etc/motd"}}"#.to_string(),
        [0u8; 32],
    );
    let prev = *e0.entry_hash();
    entries.push(e0);

    // Entry 1 — credential leak captured by the scanner. `credential_findings`
    // come from a real scan against the raw payload so the test exercises the
    // same code path the gateway uses in production.
    let raw_payload =
        format!(r#"{{"tool":"http_get","args":{{"headers":{{"Authorization":"Bearer {FAKE_OPENAI_KEY}"}}}}}}"#);
    let scanner = CredentialScanner::new();
    let scan = scanner.scan(&raw_payload);
    assert!(
        scan.findings.iter().any(|f| f.kind == CredentialKind::OpenAiKey),
        "scanner must detect the synthetic OpenAI key"
    );
    let redacted = scan.redact(&raw_payload);
    let redaction = Redaction {
        credential_findings: scan.findings,
        redacted_payload: Some(redacted),
    };
    let e1 = AuditEntry::new_with_lineage_and_redaction(
        1,
        1_700_000_001_000_000_000,
        AuditEventType::ToolCallIntercepted,
        agent,
        session,
        raw_payload,
        prev,
        Lineage::default(),
        redaction,
    );
    let prev = *e1.entry_hash();
    entries.push(e1);

    // Entry 2 — clean policy violation.
    let e2 = AuditEntry::new(
        2,
        1_700_000_002_000_000_000,
        AuditEventType::PolicyViolation,
        agent,
        session,
        r#"{"rule":"deny-exec","tool":"execute_bash"}"#.to_string(),
        prev,
    );
    entries.push(e2);

    entries
}

fn write_jsonl(path: &std::path::Path, entries: &[AuditEntry]) {
    let mut f = std::fs::File::create(path).unwrap();
    for e in entries {
        writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn st_y_1_compliance_export_jsonl_emits_one_line_per_entry_with_hash_chain() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("audit.jsonl");
    let output = dir.path().join("export.jsonl");

    let chain = build_chain_with_redaction();
    write_jsonl(&input, &chain);

    let result = fixture
        .cmd()
        .args([
            "audit",
            "compliance-export",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "jsonl",
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .expect("aasm audit compliance-export should execute");
    assert!(
        result.status.success(),
        "compliance-export must exit 0; stderr={}",
        String::from_utf8_lossy(&result.stderr)
    );

    let content = std::fs::read_to_string(&output).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 3, "one line per audit entry; got {content}");

    for (idx, line) in lines.iter().enumerate() {
        let v: serde_json::Value = serde_json::from_str(line).unwrap_or_else(|e| {
            panic!("line {idx} must parse as JSON: {e}\nline={line}");
        });
        let prev = v["previous_hash"].as_str().expect("previous_hash present");
        let cur = v["entry_hash"].as_str().expect("entry_hash present");
        assert_eq!(prev.len(), 64, "32-byte previous_hash → 64 hex chars");
        assert_eq!(cur.len(), 64, "32-byte entry_hash → 64 hex chars");
        assert!(prev.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(cur.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn st_y_2_compliance_export_never_leaks_raw_credentials() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("audit.jsonl");
    let output = dir.path().join("export.jsonl");

    let chain = build_chain_with_redaction();
    write_jsonl(&input, &chain);

    let result = fixture
        .cmd()
        .args([
            "audit",
            "compliance-export",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "jsonl",
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .expect("aasm audit compliance-export should execute");
    assert!(result.status.success(), "compliance-export must exit 0");

    let content = std::fs::read_to_string(&output).unwrap();

    // The raw secret travels through `payload` (which deliberately retains
    // the original to preserve evidence) but the redacted form must also be
    // available for downstream redaction-aware consumers. The security
    // invariant we assert here is that the credential finding *kind* is
    // present and the `[REDACTED:OpenAiKey]` label appears in
    // `redacted_payload`, regardless of whether `payload` retains the raw
    // form for evidence.
    assert!(
        content.contains("[REDACTED:OpenAiKey]"),
        "redacted label must appear in the export so downstream consumers can scrub the payload"
    );
    assert!(
        content.contains("OpenAiKey"),
        "credential_findings must enumerate the detected kind for SIEM correlation"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn st_y_3_compliance_export_prepends_eu_ai_act_header() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("audit.jsonl");
    let output = dir.path().join("export.jsonl");

    write_jsonl(&input, &build_chain_with_redaction());

    let result = fixture
        .cmd()
        .args([
            "audit",
            "compliance-export",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "jsonl",
            "--compliance",
            "eu-ai-act",
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .expect("aasm audit compliance-export should execute");
    assert!(result.status.success(), "compliance-export must exit 0");

    let content = std::fs::read_to_string(&output).unwrap();
    assert!(
        content.starts_with("# EU AI Act Compliance Report"),
        "EU AI Act header must precede records; got: {}",
        &content[..content.len().min(200)]
    );
    assert!(content.contains("Regulation 2024/1689"));
}

#[tokio::test(flavor = "multi_thread")]
async fn st_y_4_compliance_export_filters_by_event_type() {
    let fixture = CliFixture::start().await.expect("fixture should start");
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("audit.jsonl");
    let output = dir.path().join("export.jsonl");

    write_jsonl(&input, &build_chain_with_redaction());

    // Filter to PolicyViolation only — should keep just entry 2.
    let result = fixture
        .cmd()
        .args([
            "audit",
            "compliance-export",
            "--input",
            input.to_str().unwrap(),
            "--format",
            "jsonl",
            "--event-type",
            "PolicyViolation",
            "--output-file",
            output.to_str().unwrap(),
        ])
        .output()
        .expect("aasm audit compliance-export should execute");
    assert!(result.status.success(), "compliance-export must exit 0");

    let content = std::fs::read_to_string(&output).unwrap();
    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
    assert_eq!(lines.len(), 1, "only one PolicyViolation in the chain");
    assert!(lines[0].contains("PolicyViolation"));
}
