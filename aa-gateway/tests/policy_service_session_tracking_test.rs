//! AAASM-5088 — the gateway's policy service must record every `CheckAction` /
//! `BatchCheck` against the calling agent's session in the registry so
//! `active_sessions` (and the Fleet Active-Sessions surface) populate from real
//! traffic instead of staying empty in production.
//!
//! These drive the trait impl directly (no tonic server) with a registry
//! carrying a registered agent + valid credential token, then inspect the
//! agent's `active_sessions` for the open → count side-effect.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

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

const POLICY: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;

const AGENT_TOKEN: &str = "tok_agent";

fn agent_triple() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    }
}

fn agent_record(agent_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: agent_key,
        name: "session-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: AGENT_TOKEN.into(),
        metadata: std::collections::BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
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
        enforcement_mode_expires_at: None,
        org_id: None,
    }
}

fn request(trace_id: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent_triple()),
        credential_token: AGENT_TOKEN.into(),
        trace_id: trace_id.into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

/// Build a service with an attached registry holding one registered agent.
fn service_with_registered_agent() -> (Arc<PolicyServiceImpl>, Arc<AgentRegistry>, [u8; 16]) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));

    let agent_key = proto_agent_id_to_key(&agent_triple());
    registry.register(agent_record(agent_key)).unwrap();

    let service = PolicyServiceImpl::with_registry(engine, Arc::clone(&registry), audit_tx, audit_drops, [0u8; 32]);
    (Arc::new(service), registry, agent_key)
}

#[tokio::test]
async fn check_action_opens_session_and_increments_actions_count() {
    let (service, registry, agent_key) = service_with_registered_agent();
    let expected_session_id = hex::encode(hash_to_16("trace-a"));

    // First action opens the session at actions_count = 1.
    let resp = service
        .check_action(Request::new(request("trace-a")))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32);

    let record = registry.get(&agent_key).unwrap();
    assert_eq!(
        record.active_sessions.len(),
        1,
        "check_action opens the agent's session"
    );
    assert_eq!(record.active_sessions[0].session_id, expected_session_id);
    assert_eq!(record.active_sessions[0].status, "running");
    assert_eq!(record.active_sessions[0].actions_count, 1);

    // A second action on the same trace increments the same session.
    service.check_action(Request::new(request("trace-a"))).await.unwrap();
    let record = registry.get(&agent_key).unwrap();
    assert_eq!(
        record.active_sessions.len(),
        1,
        "no duplicate session for the same trace"
    );
    assert_eq!(record.active_sessions[0].actions_count, 2);
}

#[tokio::test]
async fn batch_check_records_session_activity_per_entry() {
    let (service, registry, agent_key) = service_with_registered_agent();
    let expected_session_id = hex::encode(hash_to_16("trace-b"));

    let batch = BatchCheckRequest {
        requests: vec![request("trace-b"), request("trace-b")],
    };
    service.batch_check(Request::new(batch)).await.unwrap();

    let record = registry.get(&agent_key).unwrap();
    assert_eq!(record.active_sessions.len(), 1);
    assert_eq!(record.active_sessions[0].session_id, expected_session_id);
    assert_eq!(
        record.active_sessions[0].actions_count, 2,
        "each batch entry increments the session"
    );
}

#[tokio::test]
async fn check_action_with_empty_trace_id_records_no_session() {
    let (service, registry, agent_key) = service_with_registered_agent();

    service.check_action(Request::new(request(""))).await.unwrap();

    let record = registry.get(&agent_key).unwrap();
    assert!(
        record.active_sessions.is_empty(),
        "a request without a trace_id opens no session"
    );
}
