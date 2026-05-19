//! Cascade test for credential_action most-restrictive-wins (AAASM-1546).
//!
//! When two cascade docs disagree on `credential_action`, the engine must pick
//! the strictest mode (Block > RedactOnly > AlertOnly). A Block in any doc
//! short-circuits the scan with `Deny { "credential detected" }` and never
//! produces a redacted payload.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::policy::document::{CredentialAction, DataPolicy, PolicyDocument};
use aa_gateway::policy::scope::PolicyScope;

fn make_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

fn data_doc(scope: PolicyScope, pattern: &str, action: CredentialAction) -> PolicyDocument {
    PolicyDocument {
        name: None,
        policy_version: None,
        version: None,
        scope,
        network: None,
        schedule: None,
        budget: None,
        data: Some(DataPolicy {
            sensitive_patterns: vec![pattern.to_string()],
            credential_action: action,
        }),
        approval_timeout_secs: 300,
        approval_policy: None,
        tools: HashMap::new(),
        capabilities: None,
    }
}

fn make_ctx(id: u8) -> AgentContext {
    AgentContext {
        agent_id: AgentId::from_bytes([id; 16]),
        session_id: SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
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

fn tool_action(args: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: "leak".to_string(),
        args: args.to_string(),
    }
}

#[test]
fn cascade_block_in_any_doc_wins_over_redact_only() {
    let agent_id = AgentId::from_bytes([7u8; 16]);
    let mut engine = make_engine();
    // Global says redact_only; Agent says block. Block must win.
    engine.load_policy(data_doc(
        PolicyScope::Global,
        r"password=\w+",
        CredentialAction::RedactOnly,
    ));
    engine.load_policy(data_doc(
        PolicyScope::Agent(agent_id),
        r"password=\w+",
        CredentialAction::Block,
    ));

    let ctx = make_ctx(7);
    let action = tool_action("password=hunter2");
    let result = engine.evaluate(&ctx, &action);

    assert_eq!(
        result.decision,
        PolicyResult::Deny {
            reason: "credential detected".into(),
        }
    );
    assert!(!result.credential_findings.is_empty());
    // Block must never produce a redacted payload — the request is rejected outright.
    assert!(result.redacted_payload.is_none());
}
