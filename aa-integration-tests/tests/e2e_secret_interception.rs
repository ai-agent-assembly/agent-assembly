//! F116 ST-I — E2E secret-value interception (detection slice).
//!
//! Exercises the live credential scanner inside `aa_gateway::PolicyEngine` by
//! evaluating governance actions whose `args` payload embeds a synthetic API
//! key, GitHub PAT, OpenAI key, or a custom policy-defined pattern. Asserts:
//!
//! 1. The decision stays `Allow` (the scanner redacts in-memory, it does not
//!    deny on its own — see `aa-gateway/src/engine/mod.rs:471` Stage 6).
//! 2. `credential_findings` is non-empty and carries the expected
//!    `CredentialKind`.
//! 3. `redacted_payload` is `Some(_)` and contains the `[REDACTED:<kind>]`
//!    label.
//! 4. The full original secret never appears in `redacted_payload`.
//!
//! ## Scope
//!
//! This file ships the **detection-only** slice of the original 8-test ST.
//! The remaining tests in the ST require runtime features that are not yet
//! implemented (audit-log emission of credential findings, alert emission
//! with severity=critical, policy action modes `block` / `redact_only`,
//! mock LLM upstream). See AAASM-1544 / 1545 / 1546 / 1547 for the follow-up
//! work; the corresponding tests will be added in a second PR once those
//! runtime features land.
//!
//! ## Synthetic secrets only
//!
//! Every secret value below is synthetic — from AWS public-docs examples
//! (`AKIAIOSFODNN7EXAMPLE`), from prefixes documented as test-only
//! (`sk-test-`), or manually-fabricated padding (`ghp_0000…`). No real
//! secrets are stored in this fixture.

use std::collections::BTreeMap;
use std::path::Path;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, CredentialKind, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::{EvaluationResult, PolicyEngine};

// ── Synthetic secret fixtures ────────────────────────────────────────────────

/// AWS access key ID from AWS public documentation. Synthetic.
const FAKE_AWS_ACCESS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// GitHub personal access token prefix + zero-padding. Synthetic.
const FAKE_GITHUB_PAT: &str = "ghp_0000000000000000000000000000000000";

/// OpenAI key with the documented `sk-test-` test prefix. Synthetic.
const FAKE_OPENAI_KEY: &str = "sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890";

/// Custom-pattern token shaped to match `MYCO-SECRET-[A-Za-z0-9]+`.
#[allow(dead_code)] // wired in by the custom-regex detection test commit
const FAKE_CUSTOM_TOKEN: &str = "MYCO-SECRET-DEADBEEFCAFE0001";

/// Below the `GenericHighEntropy` length floor (20 chars) — must not trip the
/// scanner. 12 alphanumeric characters with no built-in prefix match.
#[allow(dead_code)] // wired in by the no-false-positive test commit
const SHORT_HIGH_ENTROPY: &str = "abc123def456";

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve a fixture path relative to this crate's manifest root.
fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

/// Build a minimal `AgentContext` for tests. The 16-byte agent ID seed is
/// passed in so each test can produce a distinct, deterministic identity.
fn make_ctx(agent_bytes: [u8; 16]) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes(agent_bytes),
        session_id: SessionId::from_bytes([0xAAu8; 16]),
        pid: 1,
        started_at: Timestamp::from_nanos(0),
        metadata: BTreeMap::new(),
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

/// Construct a `PolicyEngine` from the F116 ST-I secret-detection fixture.
fn make_engine() -> PolicyEngine {
    let path = fixture_path("policies/secret_detection_patterns.yaml");
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(&path, tx).expect("secret_detection_patterns.yaml must load cleanly")
}

/// Build a `ToolCall` action against the policy-allowed `test_tool` whose
/// `args` payload is the supplied string. Stage 6 of `evaluate()` scans the
/// `args` field; see `aa-gateway/src/engine/mod.rs:478`.
fn tool_call_with_args(args: impl Into<String>) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: "test_tool".to_string(),
        args: args.into(),
    }
}

/// Evaluate `action` with a fresh engine and a deterministic agent identity.
fn evaluate(action: &GovernanceAction, agent_seed: u8) -> EvaluationResult {
    let engine = make_engine();
    let ctx = make_ctx([agent_seed; 16]);
    engine.evaluate(&ctx, action)
}

/// Helper for the no-false-positive expectations: asserts `Allow` and clean
/// scan output. Used by the negative-path test below.
#[allow(dead_code)] // wired in by the no-false-positive test commit
fn assert_clean(result: &EvaluationResult) {
    assert_eq!(result.decision, PolicyResult::Allow, "clean payload must yield Allow");
    assert!(
        result.credential_findings.is_empty(),
        "clean payload must produce no credential findings, got {:?}",
        result.credential_findings,
    );
    assert!(
        result.redacted_payload.is_none(),
        "clean payload must leave redacted_payload as None",
    );
}

/// Helper for the positive-path expectations: asserts a single finding of the
/// expected `CredentialKind` and a non-None `redacted_payload`. Used by every
/// detection test below.
fn assert_detected(result: &EvaluationResult, expected: CredentialKind) {
    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "scanner-only detection must not deny — decision should remain Allow",
    );
    assert!(
        result.credential_findings.iter().any(|f| f.kind == expected),
        "expected at least one finding of kind {:?}, got {:?}",
        expected,
        result.credential_findings,
    );
    assert!(
        result.redacted_payload.is_some(),
        "detection must populate redacted_payload",
    );
}

// ── Test 1 — AWS access key in tool args ─────────────────────────────────────

#[test]
fn aws_access_key_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"data":"my access key is {FAKE_AWS_ACCESS_KEY}, rotate soon"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA1);

    assert_detected(&result, CredentialKind::AwsAccessKey);

    let redacted = result
        .redacted_payload
        .expect("AWS access key must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:AwsAccessKey]"),
        "redacted payload must carry the [REDACTED:AwsAccessKey] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_AWS_ACCESS_KEY),
        "redacted payload must not retain the original AWS access key",
    );
}

// ── Test 2 — GitHub personal access token in tool args ───────────────────────

#[test]
fn github_pat_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"headers":{{"X-Auth":"Bearer {FAKE_GITHUB_PAT}"}}}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA2);

    assert_detected(&result, CredentialKind::GitHubPat);

    let redacted = result
        .redacted_payload
        .expect("GitHub PAT must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:GitHubPat]"),
        "redacted payload must carry the [REDACTED:GitHubPat] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_GITHUB_PAT),
        "redacted payload must not retain the original GitHub PAT",
    );
}

// ── Test 3 — OpenAI key in tool args ─────────────────────────────────────────

#[test]
fn openai_key_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"messages":[{{"role":"user","content":"my key is {FAKE_OPENAI_KEY}"}}]}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA3);

    assert_detected(&result, CredentialKind::OpenAiKey);

    let redacted = result
        .redacted_payload
        .expect("OpenAI key must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:OpenAiKey]"),
        "redacted payload must carry the [REDACTED:OpenAiKey] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_OPENAI_KEY),
        "redacted payload must not retain the original OpenAI key",
    );
}
