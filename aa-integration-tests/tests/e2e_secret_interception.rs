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
//! ## ST-N proxy-path slice (AAASM-1549)
//!
//! The `mod proxy_path` block at the end of this file is the Layer 2
//! counterpart to the SDK/gateway slice above. It drives
//! `aa_proxy::intercept::Interceptor` directly with OpenAI-shaped request
//! bodies and asserts:
//!
//! 1. The proxy's default `CredentialScanner` detects AWS access keys in
//!    the body shapes the proxy will see in production and redacts them
//!    into `[REDACTED:AwsAccessKey]` markers.
//! 2. No raw secret ever appears in an emitted `PipelineEvent::Audit`
//!    when multiple secret kinds are present in a single body.
//! 3. Short high-entropy strings below the `GenericHighEntropy` floor do
//!    not produce findings (no alert fatigue).
//!
//! The data-path assertions in ST-N's original spec
//! (`proxy_aws_key_in_body_redacted_before_forwarding`,
//! `proxy_secret_block_policy_prevents_forwarding`,
//! `proxy_secret_redact_only_credential_findings_in_audit`) require body
//! parsing inside the MitM tunnel, `credential_action` enforcement on
//! flowing bytes, and audit-JSONL writer wiring — none of which exist in
//! `aa-proxy` today. See **AAASM-1566** for the data-path follow-up that
//! will land those features and the corresponding E2E tests.
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
const FAKE_CUSTOM_TOKEN: &str = "MYCO-SECRET-DEADBEEFCAFE0001";

/// Below the `GenericHighEntropy` length floor (20 chars) — must not trip the
/// scanner. 12 alphanumeric characters with no built-in prefix match.
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

// ── Test 4 — Policy-defined custom regex in tool args ────────────────────────

#[test]
fn custom_sensitive_pattern_in_tool_args_is_detected_and_redacted() {
    let payload = format!(r#"{{"data":"internal token = {FAKE_CUSTOM_TOKEN}"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA4);

    assert_detected(&result, CredentialKind::Custom);

    let redacted = result
        .redacted_payload
        .expect("custom-regex match must produce a redacted payload");
    assert!(
        redacted.contains("[REDACTED:Custom]"),
        "redacted payload must carry the [REDACTED:Custom] label, got: {redacted}",
    );
    assert!(
        !redacted.contains(FAKE_CUSTOM_TOKEN),
        "redacted payload must not retain the original custom token",
    );
}

// ── Test 5 — No false positive on short high-entropy string ──────────────────

#[test]
fn short_high_entropy_string_does_not_trigger_scanner() {
    // 12 alphanumeric characters: no AC-literal prefix matches, and the value
    // is below the 20-byte length floor enforced for `GenericHighEntropy`.
    // This guards against alert fatigue (AAASM-1521 acceptance criterion).
    let payload = format!(r#"{{"id":"{SHORT_HIGH_ENTROPY}"}}"#);
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA5);

    assert_clean(&result);
}

// ── Test 6 — Critical security assertion: raw secrets never in redacted output

#[test]
fn redacted_payload_never_contains_any_raw_secret() {
    // Combine four independent secrets in one payload so a single evaluation
    // exercises the multi-finding redaction path. The flagship security
    // invariant for this ST: even one byte of an original secret leaking
    // through is a hard failure.
    //
    // The scanner runs four passes (AC literal, digit sequences, emails,
    // high-entropy). Overlapping findings between passes can produce
    // garbled [REDACTED:Kind] labels in the output — see the engine's
    // `ScanResult::redact()` for reverse-offset replacement semantics.
    // That is acceptable: the redaction primitive's only contract is that
    // raw secret bytes are removed. Asserting on specific label shapes
    // under overlap would be brittle, so this test asserts only the
    // security invariant.
    let payload = format!(
        r#"{{
            "aws": "{FAKE_AWS_ACCESS_KEY}",
            "openai": "{FAKE_OPENAI_KEY}",
            "github": "{FAKE_GITHUB_PAT}",
            "custom": "{FAKE_CUSTOM_TOKEN}"
        }}"#
    );
    let action = tool_call_with_args(&payload);
    let result = evaluate(&action, 0xA6);

    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "scanner-only detection must not deny",
    );
    assert!(
        result.credential_findings.len() >= 4,
        "expected at least one finding per embedded secret (>=4); got {:?}",
        result.credential_findings,
    );

    let redacted = result
        .redacted_payload
        .expect("multi-secret payload must produce a redacted output");

    // Primary security invariant: NO raw secret string appears in the redacted output.
    for (label, raw) in [
        ("AWS access key", FAKE_AWS_ACCESS_KEY),
        ("OpenAI key", FAKE_OPENAI_KEY),
        ("GitHub PAT", FAKE_GITHUB_PAT),
        ("custom token", FAKE_CUSTOM_TOKEN),
    ] {
        assert!(
            !redacted.contains(raw),
            "SECURITY INVARIANT VIOLATED: {label} appears in redacted payload — value would leak to downstream audit / alert / upstream",
        );
    }

    // Sanity check: at least one redaction marker was emitted somewhere in the
    // output. The specific kind / count is not asserted because overlapping
    // findings can collapse adjacent markers under the current redact() logic.
    assert!(
        redacted.contains("[REDACTED:"),
        "redacted payload must contain at least one [REDACTED:Kind] marker, got: {redacted}",
    );
}

// ── Proxy-path slice (AAASM-1549 / ST-N) ─────────────────────────────────────
//
// The tests above drive the gateway's `PolicyEngine` (Layer 1). ST-N covers the
// equivalent **Layer 2** scanner integration carried by `aa_proxy::Interceptor`.
// See the file-level scope note for what this slice does and does not assert.

mod proxy_path {
    use std::time::SystemTime;

    use bytes::Bytes;

    use aa_proxy::intercept::detect::LlmApiPattern;
    use aa_proxy::intercept::event::ProxyEvent;

    /// Build an OpenAI-shaped POST body whose `messages[0].content` embeds the
    /// supplied `payload` substring. Mirrors what an agent's `requests` /
    /// `httpx` POST to `https://api.openai.com/v1/chat/completions` looks like
    /// when no SDK is installed (Layer 2 is the only catch).
    pub(super) fn openai_chat_body(payload: &str) -> Bytes {
        Bytes::from(format!(
            r#"{{"model":"gpt-4","messages":[{{"role":"user","content":"{payload}"}}]}}"#
        ))
    }

    /// Construct a `ProxyEvent` carrying an OpenAI-pattern request body. No
    /// response body — this mirrors the moment after the proxy has parsed the
    /// inbound request and is about to forward it upstream.
    pub(super) fn proxy_event_with_request_body(body: Bytes) -> ProxyEvent {
        ProxyEvent {
            agent_id: Some("proxy-path-test".into()),
            pattern: LlmApiPattern::OpenAi,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            request_body: Some(body),
            response_body: None,
            timestamp: SystemTime::now(),
        }
    }

    // ── Test 1 — AWS access key in a proxy-path body ─────────────────────────

    /// The proxy's `Interceptor` redacts any AWS access key embedded in an
    /// intercepted body via its default `CredentialScanner`. Two assertions:
    ///
    /// 1. The same scanner the proxy uses (`CredentialScanner::new()`, see
    ///    `aa-proxy/src/intercept/mod.rs:37`) produces an `AwsAccessKey`
    ///    finding and a `[REDACTED:AwsAccessKey]`-bearing redaction when fed
    ///    the OpenAI request body shape the proxy will see in production.
    ///
    /// 2. Driving `Interceptor::intercept()` end-to-end with that body emits
    ///    a `PipelineEvent::Audit` whose `Debug` repr never contains the raw
    ///    AWS key. This is the security invariant — any leak in the proxy's
    ///    audit emission would expose the secret to downstream subscribers.
    #[tokio::test]
    async fn aws_key_in_proxy_intercepted_body_is_redacted() {
        use aa_core::{CredentialKind, CredentialScanner};
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!("my access key is {key}", key = super::FAKE_AWS_ACCESS_KEY));
        let body_str = std::str::from_utf8(&body).expect("body must be UTF-8 ASCII");

        // (1) Scanner-level proof: the proxy's default scanner finds + redacts
        //     the AWS key in this exact body shape.
        let scan = CredentialScanner::new().scan(body_str);
        assert!(
            scan.findings.iter().any(|f| f.kind == CredentialKind::AwsAccessKey),
            "default scanner must find AwsAccessKey in proxy body shape, got {:?}",
            scan.findings,
        );
        let redacted = scan.redact(body_str);
        assert!(
            redacted.contains("[REDACTED:AwsAccessKey]"),
            "redacted proxy body must carry the [REDACTED:AwsAccessKey] marker, got: {redacted}",
        );
        assert!(
            !redacted.contains(super::FAKE_AWS_ACCESS_KEY),
            "redacted proxy body must not retain the raw AWS key",
        );

        // (2) Interceptor end-to-end: extraction succeeds on the redacted body
        //     and the emitted PipelineEvent never carries the raw key.
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body.clone());

        let fields = interceptor
            .intercept(&event)
            .await
            .expect("intercept must succeed")
            .expect("OpenAI body must yield extracted LlmFields");
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);

        let pipeline_event = rx.try_recv().expect("audit event must be emitted");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));
        assert!(
            !format!("{pipeline_event:?}").contains(super::FAKE_AWS_ACCESS_KEY),
            "SECURITY INVARIANT: emitted PipelineEvent must not contain the raw AWS key",
        );
    }

    // ── Test 2 — multi-secret security invariant on the proxy path ───────────

    /// Mirrors ST-I's multi-secret test (Test 6 in this file) for the proxy
    /// code path. Combines AWS, OpenAI, and GitHub secrets in one OpenAI
    /// request body so a single `Interceptor::intercept()` exercises the
    /// multi-finding redaction path.
    ///
    /// Asserts only the raw-secret-absence invariant — overlapping AC and
    /// entropy findings can produce garbled `[REDACTED:Kind]` labels at the
    /// boundaries (documented in `project_credential_scanner_overlap`), so
    /// asserting on specific marker shapes would be brittle. The only
    /// contract worth locking down is: no raw secret byte sequence ever
    /// reaches a PipelineEvent subscriber.
    #[tokio::test]
    async fn secret_never_leaks_into_pipeline_event_from_proxy() {
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!(
            "aws={aws} openai={openai} github={github}",
            aws = super::FAKE_AWS_ACCESS_KEY,
            openai = super::FAKE_OPENAI_KEY,
            github = super::FAKE_GITHUB_PAT,
        ));

        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body);

        let _ = interceptor.intercept(&event).await.expect("intercept must succeed");

        let pipeline_event = rx.try_recv().expect("audit event must be emitted");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));

        let event_str = format!("{pipeline_event:?}");
        for (label, raw) in [
            ("AWS access key", super::FAKE_AWS_ACCESS_KEY),
            ("OpenAI key", super::FAKE_OPENAI_KEY),
            ("GitHub PAT", super::FAKE_GITHUB_PAT),
        ] {
            assert!(
                !event_str.contains(raw),
                "SECURITY INVARIANT: emitted proxy PipelineEvent contains raw {label} — would leak to any audit subscriber",
            );
        }
    }

    // ── Test 3 — negative control on the proxy path ──────────────────────────

    /// Mirrors ST-I Test 5 (`short_high_entropy_string_does_not_trigger_scanner`)
    /// for the proxy code path. Guards against alert fatigue: short
    /// high-entropy strings that look secret-shaped but are below the
    /// `GenericHighEntropy` 20-byte floor (and lack an AC literal prefix)
    /// must produce zero findings.
    ///
    /// Two paired assertions:
    ///
    /// 1. The proxy's default scanner returns a clean `ScanResult` on the
    ///    OpenAI body shape with a 12-char alphanumeric payload.
    /// 2. `Interceptor::intercept()` still emits a `PipelineEvent::Audit`
    ///    on the broadcast channel — proving the negative path is a no-op
    ///    on redaction, not a no-op on observation.
    #[tokio::test]
    async fn short_high_entropy_string_does_not_trigger_proxy_scanner() {
        use aa_core::CredentialScanner;
        use aa_proxy::intercept::Interceptor;
        use aa_runtime::pipeline::PipelineEvent;
        use tokio::sync::broadcast;

        let body = openai_chat_body(&format!("id={id}", id = super::SHORT_HIGH_ENTROPY));
        let body_str = std::str::from_utf8(&body).expect("body must be UTF-8 ASCII");

        // (1) Scanner-level: no findings on this short non-prefixed payload.
        let scan = CredentialScanner::new().scan(body_str);
        assert!(
            scan.is_clean(),
            "default scanner must produce zero findings on short high-entropy payload, got {:?}",
            scan.findings,
        );

        // (2) Interceptor sanity: extraction succeeds and an audit event is
        //     still emitted (negative path must not silence observation).
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = proxy_event_with_request_body(body);

        let fields = interceptor
            .intercept(&event)
            .await
            .expect("intercept must succeed")
            .expect("OpenAI body must yield extracted LlmFields");
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);

        let pipeline_event = rx.try_recv().expect("audit event must be emitted on clean path");
        assert!(matches!(pipeline_event, PipelineEvent::Audit(_)));
    }
}
