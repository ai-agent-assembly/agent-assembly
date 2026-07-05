//! AAASM-4133 — agent-scoped controls bind to the token-derived owner, not a
//! client-supplied `agent_id`.
//!
//! `req.agent_id` is client-supplied and forgeable (PolicyService runs under
//! the non-rejecting `enrich` interceptor). A credentialed caller must not be
//! able to dodge its own agent-scoped enforcement override by presenting a
//! different agent's id. These tests drive the gRPC `check_action` path and
//! assert the enforcement mode resolves from the *token owner*, not the claimed
//! id.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_core::{AuditEntry, GovernanceLevel};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::registry::store::AgentRecord;
use aa_gateway::registry::{AgentRegistry, AgentStatus};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use chrono::Utc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

const DENY_BASH_POLICY: &str = r#"
version: "1"
tools:
  bash:
    allow: false
"#;

async fn start_server(policy_yaml: &str) -> (SocketAddr, Arc<AgentRegistry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(
        Arc::clone(&engine),
        Arc::clone(&registry),
        audit_tx,
        audit_drops,
        [0u8; 32],
    );

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, registry)
}

/// Register an agent carrying an explicit credential token and enforcement mode.
fn register(
    registry: &AgentRegistry,
    proto_id: &ProtoAgentId,
    credential_token: &str,
    mode: Option<aa_core::EnforcementMode>,
) {
    let record = AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: proto_id.agent_id.clone(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk".into(),
        credential_token: credential_token.into(),
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
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: mode,
        org_id: None,
    };
    registry.register(record).unwrap();
}

fn bash_request(agent: &ProtoAgentId, credential_token: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(agent.clone()),
        credential_token: credential_token.into(),
        trace_id: format!("trace-{credential_token}"),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "bash".into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        caller_agent_id: None,
    }
}

fn proto(agent_id: &str) -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: agent_id.into(),
    }
}

#[tokio::test]
async fn spoofed_agent_id_cannot_borrow_another_agents_observe_mode() {
    // Owner is enforced (no override → live). Decoy is in Observe mode. A caller
    // authenticated as owner claims the decoy's agent_id to try to inherit the
    // decoy's monitor-only posture and dodge the deny. The enforcement override
    // must resolve from the *token owner*, so the deny is still enforced.
    let (addr, registry) = start_server(DENY_BASH_POLICY).await;
    let owner = proto("owner-agent");
    let decoy = proto("decoy-agent");
    register(&registry, &owner, "token-owner", None);
    register(
        &registry,
        &decoy,
        "token-decoy",
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        // owner's token, but decoy's agent_id.
        .check_action(bash_request(&decoy, "token-owner"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Deny as i32,
        "spoofing the decoy's agent_id must NOT inherit its observe mode — deny must still fire, got {:?}",
        resp.reason
    );
}

#[tokio::test]
async fn honest_observe_mode_agent_is_still_monitored_not_blocked() {
    // Control: the decoy, presenting its OWN token, keeps its observe mode and
    // the deny is rewritten to Allow. This proves the observe posture is real,
    // so the spoof test above is decisive rather than vacuous.
    let (addr, registry) = start_server(DENY_BASH_POLICY).await;
    let decoy = proto("decoy-agent");
    register(
        &registry,
        &decoy,
        "token-decoy",
        Some(aa_core::EnforcementMode::Observe),
    );

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(bash_request(&decoy, "token-decoy"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "an agent presenting its own token keeps its observe mode (deny → allow)",
    );
}
