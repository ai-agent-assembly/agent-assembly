//! AAASM-3889 regression — `op_control_stream` must authorize the subscriber.
//!
//! Before the fix the endpoint ran under the non-rejecting `enrich` interceptor
//! and never validated a credential nor bound the subscription to the caller, so
//! a credential-less peer could subscribe with an arbitrary `{org,team,agent}`
//! triple and read another tenant's pause/resume/terminate signals + op_ids.
//!
//! These tests wire the production `enrich_interceptor` the same way
//! `server::serve_tcp` does, with an `AgentRegistry` attached, and assert:
//!   * a tokenless subscribe is rejected `Unauthenticated`;
//!   * a valid-token subscribe for a *different* tenant's triple is rejected
//!     `PermissionDenied`; and
//!   * a valid-token subscribe for the caller's own identity is admitted and
//!     receives its agent's halt.

use std::collections::{BTreeMap, VecDeque};
use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::iam::{enrich_interceptor, CREDENTIAL_METADATA_KEY};
use aa_gateway::ops::{OpControlPublisher, SharedOpControlPublisher};
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::{AgentRecord, AgentRegistry, AgentStatus, PolicyEngine};
use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{OpControlSignal, OpControlSubscribeRequest};
use tokio::net::TcpListener;
use tonic::transport::Server;

const TOKEN: &str = "tok_caller";

fn caller_triple() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "caller-org".into(),
        team_id: "caller-team".into(),
        agent_id: "caller-agent".into(),
    }
}

fn victim_triple() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "victim-org".into(),
        team_id: "victim-team".into(),
        agent_id: "victim-agent".into(),
    }
}

fn record(triple: &ProtoAgentId, token: &str) -> AgentRecord {
    AgentRecord {
        agent_id: proto_agent_id_to_key(triple),
        name: "test-agent".into(),
        framework: "custom".into(),
        version: "0.0.1".into(),
        risk_tier: 0,
        tool_names: vec![],
        public_key: "deadbeef".into(),
        credential_token: token.into(),
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
        parent_agent_id: None,
        team_id: Some(triple.team_id.clone()),
        org_id: Some(triple.org_id.clone()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
    }
}

/// Start a PolicyService behind the production `enrich` interceptor with `registry`
/// attached and `publisher` serving `op_control_stream`.
async fn start_server(registry: Arc<AgentRegistry>, publisher: SharedOpControlPublisher) -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry(engine, Arc::clone(&registry), audit_tx, audit_drops, [0u8; 32])
        .with_ops_publisher(publisher);

    let enrich = enrich_interceptor(Arc::clone(&registry));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::with_interceptor(service, enrich))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    addr
}

fn subscribe_req(triple: ProtoAgentId, token: Option<&str>) -> tonic::Request<OpControlSubscribeRequest> {
    let mut req = tonic::Request::new(OpControlSubscribeRequest { agent_id: Some(triple) });
    if let Some(t) = token {
        req.metadata_mut().insert(CREDENTIAL_METADATA_KEY, t.parse().unwrap());
    }
    req
}

#[tokio::test]
async fn op_control_stream_without_a_credential_is_unauthenticated() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(record(&caller_triple(), TOKEN)).unwrap();
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Arc::clone(&registry), Arc::clone(&publisher)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // No credential token in metadata → enrich injects no VerifiedCaller.
    let err = client
        .op_control_stream(subscribe_req(caller_triple(), None))
        .await
        .expect_err("a tokenless subscribe must be rejected");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn op_control_stream_cross_tenant_triple_is_permission_denied() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(record(&caller_triple(), TOKEN)).unwrap();
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Arc::clone(&registry), Arc::clone(&publisher)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // Valid credential, but the subscription targets another tenant's triple.
    let err = client
        .op_control_stream(subscribe_req(victim_triple(), Some(TOKEN)))
        .await
        .expect_err("a cross-tenant subscribe must be rejected");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn op_control_stream_own_identity_is_admitted_and_receives_its_halt() {
    let registry = Arc::new(AgentRegistry::new());
    registry.register(record(&caller_triple(), TOKEN)).unwrap();
    let publisher = Arc::new(OpControlPublisher::new());
    let addr = start_server(Arc::clone(&registry), Arc::clone(&publisher)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    // Valid credential for the caller's own identity → admitted.
    let mut stream = client
        .op_control_stream(subscribe_req(caller_triple(), Some(TOKEN)))
        .await
        .expect("an own-identity subscribe with a valid credential must be admitted")
        .into_inner();

    // Wait for the server-side subscription to register, then publish a halt for
    // the caller's agent and confirm it is delivered.
    for _ in 0..40 {
        if publisher.subscriber_count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let op_id = aa_runtime::op_control::agent_halt_op_id("caller-agent");
    publisher.publish(caller_triple(), op_id.clone(), OpControlSignal::Terminate);

    let msg = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .expect("halt should be delivered to the admitted subscriber")
        .expect("stream ok")
        .expect("stream yields the halt");
    assert_eq!(msg.op_id, op_id);
    assert_eq!(msg.signal, OpControlSignal::Terminate as i32);
}
