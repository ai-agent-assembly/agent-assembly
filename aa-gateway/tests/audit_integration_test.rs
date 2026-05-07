//! Integration tests verifying that policy evaluation and audit RPCs produce
//! correct `AuditEntry` values on the internal channel.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::{AuditEntry, AuditEventType};
use aa_gateway::service::{AuditServiceImpl, PolicyServiceImpl};
use aa_gateway::PolicyEngine;
use aa_proto::assembly::audit::v1::audit_service_client::AuditServiceClient;
use aa_proto::assembly::audit::v1::audit_service_server::AuditServiceServer;
use aa_proto::assembly::audit::v1::{AuditEvent, ReportEventsRequest};
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision, Timestamp};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tonic::transport::Server;

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
  dangerous:
    allow: false
"#;

/// Start a server wired to an audit channel where the receiver is returned so
/// the test can consume and inspect entries.
async fn start_server_with_audit_rx() -> (SocketAddr, mpsc::Receiver<AuditEntry>, Arc<AtomicU64>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY_YAML).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let policy_svc = PolicyServiceImpl::new(Arc::new(engine), audit_tx.clone(), Arc::clone(&audit_drops), [0u8; 32]);
    let audit_svc = AuditServiceImpl::new(audit_tx, Arc::clone(&audit_drops), [0u8; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(policy_svc))
            .add_service(AuditServiceServer::new(audit_svc))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, audit_rx, audit_drops)
}

fn tool_call_request(tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "test-org".into(),
            team_id: "test-team".into(),
            agent_id: "test-agent".into(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: tool_name.into(),
                tool_source: "mcp".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        trace_id: "trace-001".into(),
        span_id: "span-001".into(),
        credential_token: String::new(),
    }
}

// ── Commit 18: check_action produces audit entry with correct fields ────────

#[tokio::test]
async fn check_action_allow_produces_audit_entry() {
    let (addr, mut audit_rx, _drops) = start_server_with_audit_rx().await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("web_search"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32);

    // The audit entry should arrive on the channel.
    let entry = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out waiting for audit entry")
        .expect("channel closed without entry");

    assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
    assert!(entry.timestamp_ns() > 0, "timestamp should be non-zero");

    // Payload should contain the decision and action_type.
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).unwrap();
    assert_eq!(payload["decision"], Decision::Allow as i32);
    assert_eq!(payload["action_type"], ActionType::ToolCall as i32);
}

#[tokio::test]
async fn check_action_deny_produces_policy_violation_event() {
    let (addr, mut audit_rx, _drops) = start_server_with_audit_rx().await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("dangerous"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Deny as i32);

    let entry = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out waiting for audit entry")
        .expect("channel closed without entry");

    assert_eq!(entry.event_type(), AuditEventType::PolicyViolation);
}

// ── Commit 19: ReportEvents RPC produces audit entries ──────────────────────

#[tokio::test]
async fn report_events_ingests_batch() {
    let (addr, mut audit_rx, _drops) = start_server_with_audit_rx().await;
    let mut client = AuditServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let events = vec![
        AuditEvent {
            event_id: "evt-1".into(),
            agent_id: Some(ProtoAgentId {
                org_id: "org".into(),
                team_id: "team".into(),
                agent_id: "agent-1".into(),
            }),
            action_type: ActionType::ToolCall as i32,
            decision: Decision::Allow as i32,
            occurred_at: Some(Timestamp {
                unix_ms: 1_700_000_000_000,
            }),
            trace_id: "trace-r1".into(),
            span_id: "span-r1".into(),
            parent_span_id: String::new(),
            detail: None,
            labels: Default::default(),
            ..Default::default()
        },
        AuditEvent {
            event_id: "evt-2".into(),
            agent_id: Some(ProtoAgentId {
                org_id: "org".into(),
                team_id: "team".into(),
                agent_id: "agent-1".into(),
            }),
            action_type: ActionType::ToolCall as i32,
            decision: Decision::Deny as i32,
            occurred_at: Some(Timestamp {
                unix_ms: 1_700_000_001_000,
            }),
            trace_id: "trace-r2".into(),
            span_id: "span-r2".into(),
            parent_span_id: String::new(),
            detail: None,
            labels: Default::default(),
            ..Default::default()
        },
    ];

    let resp = client
        .report_events(ReportEventsRequest { events })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.event_ids.len(), 2);
    assert_eq!(resp.event_ids[0], "evt-1");
    assert_eq!(resp.event_ids[1], "evt-2");

    // Both entries should arrive on the channel.
    let e1 = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out")
        .expect("channel closed");
    let e2 = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out")
        .expect("channel closed");

    assert_eq!(e1.event_type(), AuditEventType::ToolCallIntercepted);
    assert_eq!(e2.event_type(), AuditEventType::PolicyViolation);
}

// ── Commit 20: StreamEvents RPC produces audit entries ──────────────────────

#[tokio::test]
async fn stream_events_ingests_client_stream() {
    let (addr, mut audit_rx, _drops) = start_server_with_audit_rx().await;
    let mut client = AuditServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let events = vec![
        AuditEvent {
            event_id: "stream-1".into(),
            agent_id: Some(ProtoAgentId {
                org_id: "org".into(),
                team_id: "team".into(),
                agent_id: "agent-s".into(),
            }),
            action_type: ActionType::ToolCall as i32,
            decision: Decision::Allow as i32,
            occurred_at: Some(Timestamp {
                unix_ms: 1_700_000_000_000,
            }),
            trace_id: "trace-s1".into(),
            span_id: "span-s1".into(),
            parent_span_id: String::new(),
            detail: None,
            labels: Default::default(),
            ..Default::default()
        },
        AuditEvent {
            event_id: "stream-2".into(),
            agent_id: Some(ProtoAgentId {
                org_id: "org".into(),
                team_id: "team".into(),
                agent_id: "agent-s".into(),
            }),
            action_type: ActionType::FileOperation as i32,
            decision: Decision::Deny as i32,
            occurred_at: Some(Timestamp {
                unix_ms: 1_700_000_002_000,
            }),
            trace_id: "trace-s2".into(),
            span_id: "span-s2".into(),
            parent_span_id: String::new(),
            detail: None,
            labels: Default::default(),
            ..Default::default()
        },
        AuditEvent {
            event_id: "stream-3".into(),
            agent_id: Some(ProtoAgentId {
                org_id: "org".into(),
                team_id: "team".into(),
                agent_id: "agent-s".into(),
            }),
            action_type: ActionType::ToolCall as i32,
            decision: Decision::Pending as i32,
            occurred_at: Some(Timestamp {
                unix_ms: 1_700_000_003_000,
            }),
            trace_id: "trace-s3".into(),
            span_id: "span-s3".into(),
            parent_span_id: String::new(),
            detail: None,
            labels: Default::default(),
            ..Default::default()
        },
    ];

    let stream = tokio_stream::iter(events);
    let resp = client.stream_events(stream).await.unwrap().into_inner();

    assert_eq!(resp.events_received, 3);

    // All three entries should arrive on the channel.
    let e1 = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out")
        .expect("closed");
    let e2 = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out")
        .expect("closed");
    let e3 = tokio::time::timeout(std::time::Duration::from_secs(2), audit_rx.recv())
        .await
        .expect("timed out")
        .expect("closed");

    assert_eq!(e1.event_type(), AuditEventType::ToolCallIntercepted);
    assert_eq!(e2.event_type(), AuditEventType::PolicyViolation);
    assert_eq!(e3.event_type(), AuditEventType::ApprovalRequested);
}

// ── Task 3 (AAASM-965): lineage populated from AgentRegistry ───────────────

#[tokio::test]
async fn audit_service_populates_lineage_from_registry() {
    use aa_gateway::registry::store::AgentRecord;
    use aa_gateway::registry::{AgentRegistry, AgentStatus};
    use aa_gateway::service::audit_service::AuditServiceImpl;
    use aa_proto::assembly::audit::v1::audit_service_server::AuditService;
    use aa_proto::assembly::audit::v1::{AuditEvent, ReportEventsRequest};
    use aa_proto::assembly::common::v1::{AgentId as ProtoAgentId, Timestamp};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use aa_gateway::registry::convert::proto_agent_id_to_key;

    let registry = Arc::new(AgentRegistry::new());

    let root_bytes = [0x07u8; 16];

    // The proto agent_id that the AuditEvent will carry.
    let proto_agent_id = ProtoAgentId {
        org_id: String::new(),
        team_id: String::new(),
        agent_id: "test-agent-001".to_string(),
    };
    // The registry key must match what ingest_event() will derive (proto_agent_id_to_key).
    let agent_registry_key = proto_agent_id_to_key(&proto_agent_id);

    registry
        .register(AgentRecord {
            agent_id: agent_registry_key,
            name: "test-agent".into(),
            framework: "test".into(),
            version: "0.0.1".into(),
            risk_tier: 0,
            tool_names: vec![],
            public_key: String::new(),
            credential_token: String::new(),
            metadata: BTreeMap::new(),
            registered_at: chrono::Utc::now(),
            last_heartbeat: chrono::Utc::now(),
            status: AgentStatus::Active,
            pid: None,
            session_count: 0,
            last_event: None,
            policy_violations_count: 0,
            active_sessions: vec![],
            recent_events: std::collections::VecDeque::new(),
            recent_traces: vec![],
            layer: None,
            governance_level: aa_core::GovernanceLevel::default(),
            parent_agent_id: Some("parent-placeholder".into()),
            team_id: Some("team-alpha".into()),
            depth: 2,
            delegation_reason: Some("summarise".into()),
            spawned_by_tool: Some("langgraph".into()),
            root_agent_id: Some(root_bytes),
        })
        .unwrap();

    let (tx, mut rx) = mpsc::channel::<aa_core::AuditEntry>(16);
    let drops = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let svc = AuditServiceImpl::new_with_registry(tx, drops, [0u8; 32], registry);

    let event = AuditEvent {
        event_id: "evt-001".into(),
        agent_id: Some(proto_agent_id),
        occurred_at: Some(Timestamp { unix_ms: 1_700_000_000_000 }),
        ..Default::default()
    };

    let req = tonic::Request::new(ReportEventsRequest {
        events: vec![event],
    });
    svc.report_events(req).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let entry = rx.try_recv().expect("entry should have been sent");
    assert_eq!(entry.team_id(), Some("team-alpha"), "team_id from registry");
    assert_eq!(entry.depth(), Some(2), "depth from registry");
    assert_eq!(
        entry.spawned_by_tool(),
        Some("langgraph"),
        "spawned_by_tool from registry"
    );
    assert!(entry.root_agent_id().is_some(), "root_agent_id from registry");
    assert!(
        entry.verify_integrity(),
        "lineage-enriched entry must verify"
    );
}
