//! AAASM-3751 — lineage is anchored to the credential-token owner.
//!
//! The reported "cross-tenant policy downgrade" (forge `org_id` to select a
//! more permissive org cascade) is NOT exploitable by a credentialed caller:
//! the registry is keyed by the COMPOSITE `proto_agent_id_to_key`
//! (`org_id/team_id/agent_id`), so forging `org_id` changes the key and
//! `validate_credential_token` rejects the request as impersonation BEFORE the
//! policy engine runs (the valid token resolves to a different registered
//! owner). These tests pin that behaviour with REAL, self-consistent
//! registration — no planted key/record divergence.
//!
//! The `evaluate_one` token-anchored deposit is defense-in-depth on top of that
//! credential check: it re-derives the owner from `req.credential_token` and
//! overwrites the (forgeable) ctx lineage so a credentialed agent is always
//! evaluated against its registered owner's cascade and budget tenancy.

use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::GovernanceLevel;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;

/// Global allow-all + an org-scoped deny for `owner-org`'s `bash`.
fn write_cascade(dir: &std::path::Path) {
    std::fs::write(
        dir.join("000-global-allow-all.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: t-global-allow\n  version: \"0.1.0\"\n\
         spec:\n  tools: {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("100-org-owner-deny-bash.yaml"),
        "apiVersion: agent-assembly.dev/v1alpha1\n\
         kind: GovernancePolicy\n\
         metadata:\n  name: t-owner-deny-bash\n  version: \"0.1.0\"\n\
         spec:\n  scope: org:owner-org\n  tools:\n    bash:\n      allow: false\n",
    )
    .unwrap();
}

fn build_service(dir: &std::path::Path) -> (PolicyServiceImpl, Arc<AgentRegistry>) {
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let registry = Arc::new(AgentRegistry::new());
    let engine = Arc::new(
        PolicyEngine::load_cascade_from_dir(dir, alert_tx)
            .expect("cascade loads")
            .with_registry(Arc::clone(&registry)),
    );
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let service = PolicyServiceImpl::with_registry(
        engine,
        Arc::clone(&registry),
        audit_tx,
        Arc::new(AtomicU64::new(0)),
        [0u8; 32],
    );
    (service, registry)
}

/// Register a SELF-CONSISTENT agent record: the composite key, the stored
/// `org_id`/`team_id`, and the credential token all reflect the same true
/// owner — exactly what the lifecycle Register RPC produces.
fn register_agent(registry: &AgentRegistry, proto_id: &ProtoAgentId, token: &str) {
    let record = AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: "demo".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: token.into(),
        metadata: BTreeMap::new(),
        registered_at: Utc::now(),
        last_heartbeat: Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some(proto_id.team_id.clone()),
        org_id: Some(proto_id.org_id.clone()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
    };
    registry.register(record).unwrap();
}

fn request(proto_id: &ProtoAgentId, token: &str, tool: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(proto_id.clone()),
        credential_token: token.into(),
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool.into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn forged_org_with_valid_token_is_denied_as_impersonation() {
    // The reported cross-tenant downgrade vector: an agent registered in the
    // restrictive `owner-org` presents its valid credential token but forges a
    // permissive `org_id`. The composite key no longer matches, so
    // `validate_credential_token` rejects it as impersonation BEFORE evaluation
    // — the forged cascade is never reached.
    let _tmp = tempfile::tempdir().unwrap();
    write_cascade(_tmp.path());
    let (service, registry) = build_service(_tmp.path());

    let true_id = ProtoAgentId {
        org_id: "owner-org".into(),
        team_id: "owner-team".into(),
        agent_id: "agent-1".into(),
    };
    register_agent(&registry, &true_id, "tok");

    let forged_id = ProtoAgentId {
        org_id: "permissive-org".into(),
        team_id: "owner-team".into(),
        agent_id: "agent-1".into(),
    };
    let resp = service
        .check_action(tonic::Request::new(request(&forged_id, "tok", "bash")))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "forged org_id with a valid token must be denied (got reason: {})",
        resp.reason
    );
    assert_eq!(
        resp.policy_rule, "a2a_identity_verification",
        "denial must come from credential/identity validation, not the policy cascade (reason: {})",
        resp.reason
    );
}

#[tokio::test]
async fn correct_org_with_valid_token_evaluates_registered_cascade() {
    // A correct-org request with the valid token is evaluated against the
    // agent's registered org cascade: `bash` is denied by `owner-org`, while a
    // tool with no rule is allowed — proving the cascade (not a blanket deny)
    // is what decides.
    let _tmp = tempfile::tempdir().unwrap();
    write_cascade(_tmp.path());
    let (service, registry) = build_service(_tmp.path());

    let id = ProtoAgentId {
        org_id: "owner-org".into(),
        team_id: "owner-team".into(),
        agent_id: "agent-1".into(),
    };
    register_agent(&registry, &id, "tok");

    let deny = service
        .check_action(tonic::Request::new(request(&id, "tok", "bash")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        deny.decision,
        Decision::Deny as i32,
        "owner-org denies bash (got reason: {})",
        deny.reason
    );
    assert_ne!(
        deny.policy_rule, "a2a_identity_verification",
        "a correct-org request must reach the cascade, not be blocked by identity validation"
    );

    let allow = service
        .check_action(tonic::Request::new(request(&id, "tok", "web_search")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(
        allow.decision,
        Decision::Allow as i32,
        "owner-org has no rule denying web_search (got reason: {})",
        allow.reason
    );
}
