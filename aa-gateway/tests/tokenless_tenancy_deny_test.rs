//! AAASM-3992 (completes AAASM-3416) — a tokenless `check_action` that claims a
//! tenant it cannot authenticate must be denied fail-closed, with no budget
//! mutation and no audit write.
//!
//! PolicyService runs under the non-rejecting `enrich` interceptor, so the
//! request-body `{org,team,agent}` triple and `credential_token` are
//! attacker-controlled. An unauthenticated peer at :50051 could send
//! `check_action` with an empty credential token, a novel *unregistered*
//! `{org,team,agent}` triple, and a client-chosen `org_id`. Because no
//! authoritative owner resolves, `authoritative_tenancy` / `authoritative_lineage`
//! would fall back to trusting the client-supplied tenancy — accruing spend
//! against a victim org's budget and forging audit entries under a victim
//! tenant. The fix fails closed for that case while leaving the
//! registered-agent path and untenanted requests unchanged.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use tonic::Request;

const ALLOW_ALL_POLICY: &str = r#"
version: "1"
tools:
  any_tool:
    allow: true
"#;

const REGISTERED_AGENT: &str = "legit-agent";
const REGISTERED_TOKEN: &str = "tok_legit";

fn registered_record(agent_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: agent_key,
        name: "legit".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_legit".into(),
        credential_token: REGISTERED_TOKEN.into(),
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

fn tool_request(agent: ProtoAgentId, token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent),
        credential_token: token.into(),
        trace_id: "trace".into(),
        span_id: "span".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "any_tool".into(),
                tool_source: "src".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

fn service() -> (Arc<PolicyServiceImpl>, tokio::sync::mpsc::Receiver<AuditEntry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_ALL_POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    // A registered agent makes the registry "attached" and non-empty.
    let key = proto_agent_id_to_key(&ProtoAgentId {
        org_id: "legit-org".into(),
        team_id: "legit-team".into(),
        agent_id: REGISTERED_AGENT.into(),
    });
    registry.register(registered_record(key)).unwrap();

    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(engine, registry, audit_tx, audit_drops, [0u8; 32]);
    (Arc::new(service), audit_rx)
}

#[tokio::test]
async fn empty_token_unregistered_with_tenancy_claim_is_denied_without_side_effects() {
    let (service, mut audit_rx) = service();

    // Attacker: empty token, an unregistered triple, but a client-chosen org/team.
    let attacker = ProtoAgentId {
        org_id: "victim-org".into(),
        team_id: "victim-team".into(),
        agent_id: "novel-unregistered".into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(attacker, "")))
        .await
        .expect("check_action returns a response")
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32, "must fail closed");
    assert_eq!(resp.policy_rule, "a2a_identity_verification");
    assert_eq!(resp.reason, "unauthenticated tenancy claim");

    // No audit entry of any kind — the request is rejected before evaluation and
    // this path does not write an impersonation entry either, so the attacker
    // cannot inject anything into the WORM audit chain.
    assert!(
        audit_rx.try_recv().is_err(),
        "a fail-closed tenancy rejection must not write to the audit chain",
    );
}

#[tokio::test]
async fn registered_agent_with_valid_token_still_allowed() {
    let (service, _audit_rx) = service();

    let legit = ProtoAgentId {
        org_id: "legit-org".into(),
        team_id: "legit-team".into(),
        agent_id: REGISTERED_AGENT.into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(legit, REGISTERED_TOKEN)))
        .await
        .expect("check_action returns a response")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "the legitimate registered-agent path must be unaffected",
    );
}

#[tokio::test]
async fn empty_token_unregistered_without_tenancy_claim_passes_through() {
    let (service, _audit_rx) = service();

    // No org/team claim: the lightweight untenanted / unregistered-deployment
    // path. This must NOT be denied by the tenancy fail-closed guard.
    let untenanted = ProtoAgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "untenanted".into(),
    };
    let resp = service
        .check_action(Request::new(tool_request(untenanted, "")))
        .await
        .expect("check_action returns a response")
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "an untenanted tokenless request must still be evaluated normally",
    );
}
