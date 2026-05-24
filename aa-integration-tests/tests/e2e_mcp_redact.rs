//! F116 ST-Q Part 2 — gateway-level coverage of the response-side
//! `GovernanceAction::ToolResult` path.
//!
//! Loads the `mcp_redact_secrets.yaml` fixture, evaluates a `ToolResult`
//! action whose `result` body embeds a synthetic OpenAI key, and asserts:
//!
//! 1. The credential scanner (Stage 6 of `PolicyEngine::evaluate`) detects
//!    the key in the response body — `credential_findings` is non-empty.
//! 2. `redacted_payload` is `Some(_)` and the raw secret is replaced by a
//!    `[REDACTED:…]` marker.
//! 3. The full original secret never appears in `redacted_payload`.
//! 4. Routing the `EvaluationResult` through
//!    `aa_gateway::service::convert::eval_result_to_response` yields
//!    `Decision::Redact` carrying a `RedactInstructions { rules: [..] }`
//!    payload — the contract the proxy + AAASM-1930 ST-Q-3 hook into.
//!
//! Full proxy E2E (an MCP server returning a real `sk-…` key over the
//! wire, intercepted by `aa-proxy`, and the agent receiving the redacted
//! response) lands in AAASM-1930.

use std::collections::BTreeMap;
use std::path::Path;

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::service::convert::eval_result_to_response;
use aa_gateway::{EvaluationResult, PolicyEngine};
use aa_proto::assembly::common::v1::Decision;

/// Synthetic OpenAI key — uses the documented `sk-test-` prefix so no real
/// secret material ever lives in this fixture.
const FAKE_OPENAI_KEY: &str = "sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890";

fn fixture_path(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/common/fixtures")
        .join(rel)
}

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

fn make_engine() -> PolicyEngine {
    let path = fixture_path("policies/mcp_redact_secrets.yaml");
    let (tx, _rx) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(&path, tx).expect("mcp_redact_secrets.yaml must load cleanly")
}

fn tool_result_with_body(tool_name: &str, body: &str) -> GovernanceAction {
    GovernanceAction::ToolResult {
        tool_name: tool_name.to_string(),
        result: body.to_string(),
    }
}

fn evaluate(action: &GovernanceAction, agent_seed: u8) -> EvaluationResult {
    let engine = make_engine();
    let ctx = make_ctx([agent_seed; 16]);
    engine.evaluate(&ctx, action)
}

#[test]
fn tool_result_with_openai_key_is_redacted_and_surfaces_redact_instructions() {
    // The MCP server "returned" a response body that embeds an OpenAI key.
    let body = format!(r#"{{"items":[{{"snippet":"leaked: {FAKE_OPENAI_KEY}"}}]}}"#);
    let action = tool_result_with_body("search", &body);

    let result = evaluate(&action, 0x11);

    // Stage 6 must catch the key — credential_findings non-empty.
    assert!(
        !result.credential_findings.is_empty(),
        "expected the credential scanner to flag the OpenAI key, got no findings"
    );

    // The raw secret must NEVER survive in the redacted payload.
    let redacted = result
        .redacted_payload
        .as_deref()
        .expect("credential_action=redact_only must produce a redacted_payload when findings are non-empty");
    assert!(
        !redacted.contains(FAKE_OPENAI_KEY),
        "raw OpenAI key leaked into redacted_payload: {redacted}"
    );

    // The decision stays Allow at the engine level — Stage 6 redacts in-memory.
    // It's the convert.rs mapping (eval_result_to_response) that promotes a
    // findings + redacted_payload combination to Decision::Redact on the wire.
    assert_eq!(
        result.decision,
        PolicyResult::Allow,
        "engine decision should remain Allow; convert.rs handles Decision::Redact mapping"
    );

    let response = eval_result_to_response(&result, 0, "data_pattern_scan");
    assert_eq!(
        response.decision,
        Decision::Redact as i32,
        "credential_findings + redacted_payload must map to Decision::Redact"
    );
    let redact = response.redact.expect("Decision::Redact must carry RedactInstructions");
    assert!(
        !redact.rules.is_empty(),
        "RedactInstructions must list at least one rule, got {:?}",
        redact.rules
    );

    // The full key must not leak through the proto response either — neither
    // the rule's field_path nor its replacement string should carry it.
    for rule in &redact.rules {
        assert!(
            !rule.field_path.contains(FAKE_OPENAI_KEY),
            "raw secret leaked into rule.field_path: {}",
            rule.field_path
        );
        assert!(
            !rule.replacement.contains(FAKE_OPENAI_KEY),
            "raw secret leaked into rule.replacement: {}",
            rule.replacement
        );
    }
}
