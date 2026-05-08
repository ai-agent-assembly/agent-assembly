//! Integration tests for the PolicyService gRPC endpoint.
//!
//! Each test starts a tonic server on a random TCP port, connects a client,
//! sends requests, and asserts on responses.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, BatchCheckRequest, CheckActionRequest, ToolCallContext,
};
use tokio::net::TcpListener;
use tonic::transport::Server;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Start a PolicyService gRPC server on a random port and return the address.
async fn start_server(policy_yaml: &str) -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    // Keep the tempfile alive for the duration of the server.
    tokio::spawn(async move {
        let _tmp = tmp; // prevent drop
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // Give the server a moment to start.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

fn tool_call_request(tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-1".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool_name.into(),
                tool_source: "test".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_action_allows_permitted_tool() {
    let addr = start_server(
        r#"
version: "1"
tools:
  web_search:
    allow: true
"#,
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("web_search"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn check_action_denies_blocked_tool() {
    let addr = start_server(
        r#"
version: "1"
tools:
  dangerous:
    allow: false
"#,
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("dangerous"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(!resp.reason.is_empty());
}

#[tokio::test]
async fn check_action_returns_invalid_argument_on_missing_context() {
    let addr = start_server("version: \"1\"\n").await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let bad_req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            agent_id: "a".into(),
            ..Default::default()
        }),
        context: None,
        ..Default::default()
    };

    let err = client.check_action(bad_req).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn check_action_populates_latency_us() {
    let addr = start_server("version: \"1\"\n").await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("any"))
        .await
        .unwrap()
        .into_inner();

    assert!(
        resp.decision_latency_us >= 0,
        "decision_latency_us should be non-negative"
    );
}

#[tokio::test]
async fn batch_check_returns_ordered_responses() {
    let addr = start_server(
        r#"
version: "1"
tools:
  allowed_tool:
    allow: true
  blocked_tool:
    allow: false
"#,
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let batch = BatchCheckRequest {
        requests: vec![
            tool_call_request("allowed_tool"),
            tool_call_request("blocked_tool"),
            tool_call_request("allowed_tool"),
        ],
    };

    let resp = client.batch_check(batch).await.unwrap().into_inner();
    assert_eq!(resp.responses.len(), 3);
    assert_eq!(resp.responses[0].decision, Decision::Allow as i32);
    assert_eq!(resp.responses[1].decision, Decision::Deny as i32);
    assert_eq!(resp.responses[2].decision, Decision::Allow as i32);
}

// ── Budget suspend integration test ────────────────────────────────────────

/// Start a PolicyService with an attached AgentRegistry, returning the address,
/// the engine (for recording spend), and the registry (for verifying suspension).
async fn start_server_with_registry(
    policy_yaml: &str,
) -> (
    SocketAddr,
    Arc<aa_gateway::PolicyEngine>,
    Arc<aa_gateway::registry::AgentRegistry>,
) {
    use aa_gateway::registry::AgentRegistry;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
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

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, engine, registry)
}

#[tokio::test]
async fn check_action_suspends_agent_on_budget_exceeded_with_suspend_policy() {
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::store::AgentRecord;
    use aa_gateway::registry::{AgentStatus, SuspendReason};

    let yaml = r#"
version: "1"
budget:
  daily_limit_usd: 1.0
  action_on_exceed: suspend
"#;
    let (addr, engine, registry) = start_server_with_registry(yaml).await;

    // Pre-register the agent in the registry so suspend_and_notify can find it.
    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    };
    let agent_key = proto_agent_id_to_key(&proto_id);
    let record = AgentRecord {
        agent_id: agent_key,
        name: "budget-test-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_test".into(),
        credential_token: "tok_test".into(),
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
    };
    registry.register(record).unwrap();

    // Push budget over the limit using the engine's budget tracker.
    // The engine uses hash_to_16("agent-1") as the budget key (from request_to_core).
    let agent_ctx = aa_core::AgentContext {
        agent_id: aa_core::identity::AgentId::from_bytes(aa_gateway::service::convert::hash_to_16("agent-1")),
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
    engine.record_spend(&agent_ctx, 2.0); // exceeds $1.0 daily limit

    // Send a CheckAction — should get Deny and trigger suspension.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request("any_tool"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(resp.reason.contains("budget exceeded"));

    // Verify the agent was suspended in the registry.
    let status = registry.agent_status(&agent_key).unwrap();
    assert_eq!(
        status,
        AgentStatus::Suspended(SuspendReason::BudgetExceeded),
        "agent should be suspended after budget-exceeded with action_on_exceed=suspend"
    );
}

#[tokio::test]
async fn check_action_does_not_suspend_agent_on_budget_exceeded_with_deny_policy() {
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::store::AgentRecord;
    use aa_gateway::registry::AgentStatus;

    let yaml = r#"
version: "1"
budget:
  daily_limit_usd: 1.0
  action_on_exceed: deny
"#;
    let (addr, engine, registry) = start_server_with_registry(yaml).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    };
    let agent_key = proto_agent_id_to_key(&proto_id);
    let record = AgentRecord {
        agent_id: agent_key,
        name: "deny-test-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_test".into(),
        credential_token: "tok_test".into(),
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
    };
    registry.register(record).unwrap();

    let agent_ctx = aa_core::AgentContext {
        agent_id: aa_core::identity::AgentId::from_bytes(aa_gateway::service::convert::hash_to_16("agent-1")),
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
    engine.record_spend(&agent_ctx, 2.0);

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request("any_tool"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);

    // Agent should still be Active — deny policy does not suspend.
    let status = registry.agent_status(&agent_key).unwrap();
    assert_eq!(
        status,
        AgentStatus::Active,
        "agent should remain active with action_on_exceed=deny"
    );
}

// ── GatewayClient integration test ──────────────────────────────────────────

#[tokio::test]
async fn gateway_client_check_action_round_trip() {
    let addr = start_server(
        r#"
version: "1"
tools:
  web_search:
    allow: true
"#,
    )
    .await;

    let mut client = aa_runtime::gateway_client::GatewayClient::connect(&format!("http://{addr}"))
        .await
        .unwrap();

    let resp = client.check_action(tool_call_request("web_search")).await.unwrap();

    assert_eq!(resp.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn gateway_client_connect_failure() {
    // Attempt to connect to a port that is not listening.
    let result = aa_runtime::gateway_client::GatewayClient::connect("http://127.0.0.1:1").await;
    assert!(result.is_err(), "should fail to connect to closed port");
}

// ── Governance-level conditional rules (AAASM-1041 / AAASM-206) ──────────────

/// Helper: build an `AgentRecord` with the given `governance_level` and the
/// 16-byte key derived from `proto_id`.
fn level_test_record(
    proto_id: &ProtoAgentId,
    level: aa_core::GovernanceLevel,
) -> aa_gateway::registry::store::AgentRecord {
    use aa_gateway::registry::convert::proto_agent_id_to_key;
    use aa_gateway::registry::store::AgentRecord;
    use aa_gateway::registry::AgentStatus;

    AgentRecord {
        agent_id: proto_agent_id_to_key(proto_id),
        name: "level-test-agent".into(),
        framework: "custom".into(),
        version: "1.0.0".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "pk_test".into(),
        credential_token: "tok_test".into(),
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
        governance_level: level,
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: Vec::new(),
        parent_key: None,
    }
}

/// Start a `PolicyService` with both an `AgentRegistry` AND an `ApprovalQueue`
/// attached, so `RequiresApproval` evaluations can be observed and responded
/// to in-test.
async fn start_server_with_registry_and_approval(
    policy_yaml: &str,
) -> (
    SocketAddr,
    Arc<aa_gateway::registry::AgentRegistry>,
    Arc<aa_runtime::approval::ApprovalQueue>,
) {
    use aa_gateway::registry::AgentRegistry;
    use aa_runtime::approval::ApprovalQueue;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(AgentRegistry::new());
    let approval_queue = ApprovalQueue::new();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry_and_approval(
        engine,
        Arc::clone(&registry),
        Arc::clone(&approval_queue),
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

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, registry, approval_queue)
}

#[tokio::test]
async fn governance_level_rule_fires_for_registered_l2_agent() {
    use aa_runtime::approval::ApprovalDecision;

    // Policy: any tool call must request approval when the agent is L2+.
    let yaml = r#"
version: "1"
tools:
  any_tool:
    allow: true
    requires_approval_if: "governance_level >= L2"
"#;
    let (addr, registry, queue) = start_server_with_registry_and_approval(yaml).await;

    // Register the request's agent at L2Enforce.
    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    };
    registry
        .register(level_test_record(&proto_id, aa_core::GovernanceLevel::L2Enforce))
        .unwrap();

    // Issue the request on a background task so we can inspect the approval
    // queue while the server is blocked on the operator decision.
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let client_task = tokio::spawn(async move { client.check_action(tool_call_request("any_tool")).await });

    // Allow the server time to enqueue the request.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The rule must have fired → exactly one pending entry.
    let pending = queue.list();
    assert_eq!(
        pending.len(),
        1,
        "rule with `governance_level >= L2` must enqueue an approval request for an L2 agent",
    );
    assert_eq!(pending[0].agent_id, "agent-1");

    // Decide approve so the client task can complete cleanly.
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Approved {
                by: "test".to_string(),
                reason: None,
            },
        )
        .unwrap();

    let resp = client_task.await.unwrap().unwrap().into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32);
}

#[tokio::test]
async fn governance_level_rule_does_not_fire_for_registered_l1_agent() {
    // Same policy as above, but the agent is L1Observe — below the L2
    // threshold, so the approval rule must NOT fire and the request must
    // pass through directly with `Decision::Allow`.
    let yaml = r#"
version: "1"
tools:
  any_tool:
    allow: true
    requires_approval_if: "governance_level >= L2"
"#;
    let (addr, registry, queue) = start_server_with_registry_and_approval(yaml).await;

    let proto_id = ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    };
    registry
        .register(level_test_record(&proto_id, aa_core::GovernanceLevel::L1Observe))
        .unwrap();

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(tool_call_request("any_tool"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        resp.decision,
        Decision::Allow as i32,
        "rule should not fire for an L1 agent below the L2 threshold",
    );
    assert!(
        queue.list().is_empty(),
        "no approval entry should have been enqueued for an L1 agent",
    );
}
