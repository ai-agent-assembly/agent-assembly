//! Integration regression tests for the gRPC agent-plane per-RPC auth
//! interceptor (AAASM-3788; advances AAASM-3418/3419/3429).
//!
//! These wire the production interceptor (`aa_gateway::iam::auth_interceptor`)
//! the same way `server::serve_tcp` does and prove that:
//!   * unauthenticated RPCs are rejected fail-closed (approval/secrets/topology),
//!   * a cross-tenant `decide` is rejected,
//!   * a legitimate same-tenant authenticated `decide` succeeds and the audited
//!     `decided_by` is derived from the verified caller (not the request body).

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;

use aa_gateway::iam::{auth_interceptor, CREDENTIAL_METADATA_KEY};
use aa_gateway::secrets::{InMemorySecretsStore, Secret, SecretsStore};
use aa_gateway::service::{ApprovalServiceImpl, SecretsServiceImpl, TopologyServiceImpl};
use aa_gateway::{AgentRecord, AgentRegistry, AgentStatus};

use aa_proto::assembly::approval::v1::approval_service_client::ApprovalServiceClient;
use aa_proto::assembly::approval::v1::approval_service_server::ApprovalServiceServer;
use aa_proto::assembly::approval::v1::{ApprovalDecisionType, DecideRequest, ListPendingRequest};
use aa_proto::assembly::secrets::v1::secrets_service_client::SecretsServiceClient;
use aa_proto::assembly::secrets::v1::secrets_service_server::SecretsServiceServer;
use aa_proto::assembly::secrets::v1::DispatchToolRequest;
use aa_proto::assembly::topology::v1::topology_service_client::TopologyServiceClient;
use aa_proto::assembly::topology::v1::topology_service_server::TopologyServiceServer;
use aa_proto::assembly::topology::v1::GetTeamMembersRequest;

use aa_runtime::approval::{ApprovalLookup, ApprovalQueue, ApprovalRequest};
use tokio::net::TcpListener;
use tonic::transport::Server;
use uuid::Uuid;

/// Build a registered agent record with a credential token and (optional) team.
fn agent_record(agent_id: [u8; 16], token: &str, team: Option<&str>) -> AgentRecord {
    AgentRecord {
        agent_id,
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
        team_id: team.map(|s| s.to_owned()),
        org_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
        children: vec![],
        parent_key: None,
        enforcement_mode: None,
    }
}

fn approval_request(id: Uuid, team: Option<&str>) -> ApprovalRequest {
    ApprovalRequest {
        request_id: id,
        agent_id: "agent-test".to_string(),
        action: "deploy to production".to_string(),
        condition_triggered: "requires-approval".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 300,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: team.map(|s| s.to_owned()),
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

/// Start a gRPC server wiring approval + secrets + topology behind the
/// production fail-closed auth interceptor, sharing `registry`.
async fn start_secured_server(
    registry: Arc<AgentRegistry>,
    queue: Arc<ApprovalQueue>,
    secrets_store: Arc<dyn SecretsStore>,
) -> SocketAddr {
    let approval_svc = ApprovalServiceImpl::new(Arc::clone(&queue));
    let secrets_svc = SecretsServiceImpl::new(secrets_store);
    let (edge_repo, _rx) = aa_gateway::edges::InMemoryEdgeRepo::with_events(Arc::clone(&registry));
    let topology_svc = TopologyServiceImpl::new(Arc::clone(&registry), edge_repo);

    let auth = auth_interceptor(Arc::clone(&registry));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(ApprovalServiceServer::with_interceptor(approval_svc, auth.clone()))
            .add_service(SecretsServiceServer::with_interceptor(secrets_svc, auth.clone()))
            .add_service(TopologyServiceServer::with_interceptor(topology_svc, auth.clone()))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

/// Attach the credential token to a request's metadata.
fn with_token<T>(mut req: tonic::Request<T>, token: &str) -> tonic::Request<T> {
    req.metadata_mut()
        .insert(CREDENTIAL_METADATA_KEY, token.parse().unwrap());
    req
}

#[tokio::test]
async fn approval_list_pending_without_token_is_rejected() {
    let registry = Arc::new(AgentRegistry::new());
    let queue = ApprovalQueue::new();
    let addr = start_secured_server(registry, Arc::clone(&queue), Arc::new(InMemorySecretsStore::new())).await;

    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client.list_pending(ListPendingRequest {}).await.unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn approval_decide_without_token_is_rejected() {
    let registry = Arc::new(AgentRegistry::new());
    let queue = ApprovalQueue::new();
    let id = Uuid::new_v4();
    queue.submit(approval_request(id, Some("team-a")));
    let addr = start_secured_server(registry, Arc::clone(&queue), Arc::new(InMemorySecretsStore::new())).await;

    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .decide(DecideRequest {
            request_id: id.to_string(),
            decision: ApprovalDecisionType::Approved.into(),
            decided_by: "attacker".to_string(),
            reason: String::new(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn approval_decide_same_tenant_succeeds_and_attributes_caller() {
    let registry = Arc::new(AgentRegistry::new());
    let agent_key = [0xABu8; 16];
    registry
        .register(agent_record(agent_key, "tok-team-a", Some("team-a")))
        .unwrap();
    let queue = ApprovalQueue::new();
    let id = Uuid::new_v4();
    queue.submit(approval_request(id, Some("team-a")));
    let addr = start_secured_server(
        Arc::clone(&registry),
        Arc::clone(&queue),
        Arc::new(InMemorySecretsStore::new()),
    )
    .await;

    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .decide(with_token(
            tonic::Request::new(DecideRequest {
                request_id: id.to_string(),
                // Forged operator string in the body must be ignored.
                decided_by: "spoofed-operator".to_string(),
                decision: ApprovalDecisionType::Approved.into(),
                reason: String::new(),
            }),
            "tok-team-a",
        ))
        .await
        .unwrap()
        .into_inner();
    assert!(resp.success, "same-tenant authenticated decide should succeed");

    // The audited `decided_by` is the verified caller's agent UUID, not the body.
    let expected = Uuid::from_bytes(agent_key).to_string();
    match queue.get_by_id(id).expect("decided request is recorded") {
        ApprovalLookup::Resolved(record) => {
            assert_eq!(record.decided_by, expected, "decided_by must derive from the caller");
            assert_ne!(record.decided_by, "spoofed-operator");
        }
        ApprovalLookup::Pending(_) => panic!("request should be resolved after decide"),
    }
}

#[tokio::test]
async fn approval_decide_cross_tenant_is_permission_denied() {
    let registry = Arc::new(AgentRegistry::new());
    // Caller belongs to team-a but the approval belongs to team-b.
    registry
        .register(agent_record([0x01u8; 16], "tok-team-a", Some("team-a")))
        .unwrap();
    let queue = ApprovalQueue::new();
    let id = Uuid::new_v4();
    queue.submit(approval_request(id, Some("team-b")));
    let addr = start_secured_server(
        Arc::clone(&registry),
        Arc::clone(&queue),
        Arc::new(InMemorySecretsStore::new()),
    )
    .await;

    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .decide(with_token(
            tonic::Request::new(DecideRequest {
                request_id: id.to_string(),
                decision: ApprovalDecisionType::Approved.into(),
                decided_by: String::new(),
                reason: String::new(),
            }),
            "tok-team-a",
        ))
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::PermissionDenied);

    // The cross-tenant request must remain undecided (still pending).
    assert!(matches!(queue.get_by_id(id), Some(ApprovalLookup::Pending(_))));
}

#[tokio::test]
async fn secrets_dispatch_without_token_is_rejected() {
    let registry = Arc::new(AgentRegistry::new());
    let queue = ApprovalQueue::new();
    let addr = start_secured_server(registry, queue, Arc::new(InMemorySecretsStore::new())).await;

    let mut client = SecretsServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .dispatch_tool(DispatchToolRequest {
            tool: "call_database".to_string(),
            args_json: serde_json::to_vec(&serde_json::json!({"x": "literal"})).unwrap(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn secrets_dispatch_with_valid_token_resolves() {
    let registry = Arc::new(AgentRegistry::new());
    registry
        .register(agent_record([0x07u8; 16], "tok-secrets", None))
        .unwrap();
    let store = InMemorySecretsStore::new();
    store
        .register(Secret {
            name: "DB_PASSWORD".to_owned(),
            value: "real-secret-abc".to_owned(),
        })
        .unwrap();
    let queue = ApprovalQueue::new();
    let addr = start_secured_server(Arc::clone(&registry), queue, Arc::new(store)).await;

    let mut client = SecretsServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .dispatch_tool(with_token(
            tonic::Request::new(DispatchToolRequest {
                tool: "call_database".to_string(),
                args_json: serde_json::to_vec(&serde_json::json!({"connection_string": "${DB_PASSWORD}"})).unwrap(),
            }),
            "tok-secrets",
        ))
        .await
        .unwrap()
        .into_inner();
    let resolved: serde_json::Value = serde_json::from_slice(&resp.resolved_args_json).unwrap();
    assert_eq!(resolved, serde_json::json!({"connection_string": "real-secret-abc"}));
}

#[tokio::test]
async fn topology_get_team_members_without_token_is_rejected() {
    let registry = Arc::new(AgentRegistry::new());
    let queue = ApprovalQueue::new();
    let addr = start_secured_server(registry, queue, Arc::new(InMemorySecretsStore::new())).await;

    let mut client = TopologyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let err = client
        .get_team_members(GetTeamMembersRequest {
            team_id: "team-a".to_string(),
        })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
