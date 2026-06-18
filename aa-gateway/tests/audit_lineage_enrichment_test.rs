//! AAASM-3377 — full delegation lineage on the CheckAction audit entry.
//!
//! Regression: a child agent's CheckAction audit entry carried only
//! `team_id` + `org_id`; root / parent / depth / delegation_reason /
//! spawned_by_tool were dropped at the `..Lineage::default()` fallback and
//! never sourced from the registry. This test registers a depth-1 child agent
//! and asserts the emitted `AuditEntry` carries the complete lineage.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::identity::AgentId;
use aa_core::AuditEntry;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, LlmCallContext};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use tonic::Request;

const ALLOW_ALL_YAML: &str = r#"
version: "1"
"#;

/// Mirror `registry::convert::proto_agent_id_to_key` so the registered record
/// is keyed the same way the service looks it up.
fn key_for(org: &str, team: &str, agent: &str) -> [u8; 16] {
    let composite = format!("{org}/{team}/{agent}");
    let digest = Sha256::digest(composite.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

fn child_record(key: [u8; 16], parent_key: [u8; 16], root_key: [u8; 16]) -> AgentRecord {
    AgentRecord {
        agent_id: key,
        name: "child".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: "child-token".into(),
        metadata: BTreeMap::new(),
        registered_at: chrono::Utc::now(),
        last_heartbeat: chrono::Utc::now(),
        status: AgentStatus::Active,
        pid: None,
        session_count: 0,
        last_event: None,
        policy_violations_count: 0,
        active_sessions: vec![],
        recent_events: VecDeque::new(),
        recent_traces: vec![],
        layer: None,
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: Some("parent".into()),
        team_id: Some("team".into()),
        depth: 1,
        delegation_reason: Some("summarise results".into()),
        spawned_by_tool: Some("langgraph.subgraph".into()),
        root_agent_id: Some(root_key),
        children: vec![],
        parent_key: Some(parent_key),
        enforcement_mode: None,
        org_id: Some("org".into()),
    }
}

fn make_service(registry: Arc<AgentRegistry>, audit_tx: mpsc::Sender<AuditEntry>) -> PolicyServiceImpl {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_ALL_YAML).unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let audit_drops = Arc::new(AtomicU64::new(0));
    PolicyServiceImpl::with_registry(Arc::new(engine), registry, audit_tx, audit_drops, [0u8; 32])
}

fn llm_request() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "child".into(),
        }),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: "gpt-4o".into(),
                prompt_tokens: 10,
                contains_pii: false,
            })),
        }),
        trace_id: "trace-lineage".into(),
        span_id: "span-lineage".into(),
        credential_token: "child-token".into(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn child_agent_audit_entry_carries_full_lineage() {
    let registry = Arc::new(AgentRegistry::new());

    let parent_key = key_for("org", "team", "parent");
    let child_key = key_for("org", "team", "child");
    let root_key = parent_key; // depth-1 child: parent is the root.

    registry
        .register(child_record(child_key, parent_key, root_key))
        .expect("register child");

    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(Arc::clone(&registry), audit_tx);

    service
        .check_action(Request::new(llm_request()))
        .await
        .expect("check_action ok");

    let entry = audit_rx.recv().await.expect("audit entry emitted");

    assert_eq!(entry.org_id(), Some("org"), "org_id preserved");
    assert_eq!(entry.team_id(), Some("team"), "team_id preserved");
    assert_eq!(
        entry.root_agent_id(),
        Some(AgentId::from_bytes(root_key)),
        "root_agent_id must be sourced from the registry"
    );
    assert_eq!(
        entry.parent_agent_id(),
        Some(AgentId::from_bytes(parent_key)),
        "parent_agent_id must be sourced from the registry"
    );
    assert_eq!(entry.depth(), Some(1), "depth must be sourced from the registry");
    assert_eq!(
        entry.delegation_reason(),
        Some("summarise results"),
        "delegation_reason must be sourced from the registry"
    );
    assert_eq!(
        entry.spawned_by_tool(),
        Some("langgraph.subgraph"),
        "spawned_by_tool must be sourced from the registry"
    );
}
