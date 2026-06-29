//! AAASM-3888 regression — `batch_check` must validate the supplied
//! `credential_token` against the claimed agent's registered token BEFORE any
//! evaluation or side-effect (audit / spend / suspend), exactly as `check_action`
//! does.
//!
//! PolicyService runs under the non-rejecting `enrich` interceptor, so the
//! request-body `{org,team,agent}` triple and `credential_token` are
//! attacker-controlled. Before the fix, `batch_check` looped
//! `evaluate_one` + `record_audit` / `record_spend` / `maybe_suspend_agent`
//! without ever calling `validate_credential_token`, letting a credential-less
//! peer forge a victim identity per batch entry (forged audit, budget-exhaustion
//! spend, victim suspension).
//!
//! These tests drive `batch_check` on the trait impl directly (no tonic server),
//! so the registry, the audit channel, and the budget tracker can all be
//! inspected for side-effects.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::{AuditEntry, AuditEventType};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::convert::hash_to_16;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, BatchCheckRequest, CheckActionRequest, ToolCallContext,
};
use tonic::Request;

/// A tool is allowed but a `suspend`-on-exceed budget is in force, so if
/// `batch_check` were to (wrongly) evaluate a forged request whose victim is
/// already over budget, the victim would be **suspended** — the side-effect these
/// tests assert never happens.
const SUSPEND_POLICY: &str = r#"
version: "1"
tools:
  any_tool:
    allow: true
budget:
  daily_limit_usd: 1.0
  action_on_exceed: suspend
"#;

const VICTIM_ORG: &str = "victim-org";
const VICTIM_TEAM: &str = "victim-team";
const VICTIM_AGENT: &str = "victim";
const VICTIM_TOKEN: &str = "tok_victim";

fn victim_triple() -> ProtoAgentId {
    ProtoAgentId {
        org_id: VICTIM_ORG.into(),
        team_id: VICTIM_TEAM.into(),
        agent_id: VICTIM_AGENT.into(),
    }
}

fn victim_record(agent_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: agent_key,
        name: "victim-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_victim".into(),
        credential_token: VICTIM_TOKEN.into(),
        metadata: std::collections::BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: Vec::new(),
        recent_events: std::collections::VecDeque::new(),
        recent_traces: Vec::new(),
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: Vec::new(),
        parent_key: None,
        enforcement_mode: None,
        org_id: None,
    }
}

/// A batch entry that claims the (public, non-secret) victim triple and presents
/// `token` as the credential.
fn forged_request(token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(victim_triple()),
        credential_token: token.into(),
        trace_id: "forged-trace".into(),
        span_id: "forged-span".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "any_tool".into(),
                tool_source: "attacker".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

/// Build a service with an attached registry + a registered, over-budget victim,
/// returning the service and the receiving end of the audit channel so emitted
/// audit entries can be inspected.
fn service_with_over_budget_victim() -> (
    Arc<PolicyServiceImpl>,
    Arc<AgentRegistry>,
    [u8; 16],
    tokio::sync::mpsc::Receiver<AuditEntry>,
) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", SUSPEND_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let agent_key = proto_agent_id_to_key(&victim_triple());
    registry.register(victim_record(agent_key)).unwrap();

    // Push the victim's budget over the daily limit. The budget key is derived
    // from the request's `agent_id` string (`hash_to_16`), so this is exactly the
    // bucket the forged request would charge.
    let victim_ctx = aa_core::AgentContext {
        agent_id: aa_core::identity::AgentId::from_bytes(hash_to_16(VICTIM_AGENT)),
        session_id: aa_core::identity::SessionId::from_bytes([0u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
        metadata: std::collections::BTreeMap::new(),
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    };
    engine.record_spend(&victim_ctx, 2.0); // exceeds the $1.0 daily limit

    let service = PolicyServiceImpl::with_registry(engine, Arc::clone(&registry), audit_tx, audit_drops, [0u8; 32]);
    (Arc::new(service), registry, agent_key, audit_rx)
}

/// Drain the audit channel, returning whether an impersonation entry and/or a
/// tool-call / budget (policy-violation) entry were emitted.
fn drain_audit(rx: &mut tokio::sync::mpsc::Receiver<AuditEntry>) -> (bool, bool) {
    let mut saw_impersonation = false;
    let mut saw_tool_or_violation = false;
    while let Ok(entry) = rx.try_recv() {
        match entry.event_type() {
            AuditEventType::A2AImpersonationAttempted => saw_impersonation = true,
            AuditEventType::ToolCallIntercepted | AuditEventType::PolicyViolation => saw_tool_or_violation = true,
            _ => {}
        }
    }
    (saw_impersonation, saw_tool_or_violation)
}

#[tokio::test]
async fn batch_check_rejects_empty_credential_token_with_no_side_effects() {
    let (service, registry, agent_key, mut audit_rx) = service_with_over_budget_victim();

    let batch = BatchCheckRequest {
        requests: vec![forged_request("")],
    };
    let resp = service
        .batch_check(Request::new(batch))
        .await
        .expect("batch_check should return a response")
        .into_inner();

    // The forged entry is rejected as an impersonation attempt — never evaluated.
    assert_eq!(resp.responses.len(), 1);
    let r = &resp.responses[0];
    assert_eq!(r.decision, Decision::Deny as i32);
    assert_eq!(r.policy_rule, "a2a_identity_verification");
    assert_eq!(r.reason, "missing credential token");

    // No suspend side-effect: the over-budget victim is still Active. Had
    // batch_check evaluated the forged request, action_on_exceed=suspend would
    // have suspended the victim.
    assert_eq!(
        registry.agent_status(&agent_key).unwrap(),
        AgentStatus::Active,
        "a forged batch entry must not suspend the victim agent",
    );

    // No forged tool-call / budget audit attributed to the victim — only the
    // impersonation rejection itself is recorded.
    let (saw_impersonation, saw_tool_or_violation) = drain_audit(&mut audit_rx);
    assert!(
        saw_impersonation,
        "the rejection must be audited as an impersonation attempt"
    );
    assert!(
        !saw_tool_or_violation,
        "a forged batch entry must not produce a tool-call / budget audit attributed to the victim",
    );
}

#[tokio::test]
async fn batch_check_rejects_mismatched_credential_token_with_no_side_effects() {
    let (service, registry, agent_key, mut audit_rx) = service_with_over_budget_victim();

    let batch = BatchCheckRequest {
        requests: vec![forged_request("wrong-token")],
    };
    let resp = service
        .batch_check(Request::new(batch))
        .await
        .expect("batch_check should return a response")
        .into_inner();

    assert_eq!(resp.responses.len(), 1);
    let r = &resp.responses[0];
    assert_eq!(r.decision, Decision::Deny as i32);
    assert_eq!(r.policy_rule, "a2a_identity_verification");
    assert_eq!(r.reason, "credential token mismatch");

    assert_eq!(
        registry.agent_status(&agent_key).unwrap(),
        AgentStatus::Active,
        "a forged batch entry must not suspend the victim agent",
    );

    let (saw_impersonation, saw_tool_or_violation) = drain_audit(&mut audit_rx);
    assert!(
        saw_impersonation,
        "the rejection must be audited as an impersonation attempt"
    );
    assert!(
        !saw_tool_or_violation,
        "a forged batch entry must not produce a tool-call / budget audit attributed to the victim",
    );
}

#[tokio::test]
async fn batch_check_still_evaluates_a_request_with_a_valid_credential_token() {
    // Positive control: the fix must not over-reject. A legitimate batch entry
    // (correct token, agent under budget) is still evaluated and allowed.
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", SUSPEND_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let agent_key = proto_agent_id_to_key(&victim_triple());
    registry.register(victim_record(agent_key)).unwrap();

    let service = PolicyServiceImpl::with_registry(engine, Arc::clone(&registry), audit_tx, audit_drops, [0u8; 32]);

    let batch = BatchCheckRequest {
        requests: vec![forged_request(VICTIM_TOKEN)],
    };
    let resp = service
        .batch_check(Request::new(batch))
        .await
        .expect("batch_check should return a response")
        .into_inner();

    assert_eq!(resp.responses.len(), 1);
    assert_eq!(
        resp.responses[0].decision,
        Decision::Allow as i32,
        "a valid-token batch entry must still be evaluated and allowed",
    );
}
