//! Integration test for AAASM-1422: the gateway's policy service ingests
//! in-flight ops into the registry on every check_action call and transitions
//! them Pending → Running on an Allow decision.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_gateway::ops::{OpState, OpsRegistry};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, CheckActionRequest, ToolCallContext};
use tokio::net::TcpListener;
use tonic::transport::Server;

/// Start a PolicyService gRPC server on a random port with the given
/// ops registry attached, returning the bound address.
async fn start_server_with_ops(policy_yaml: &str, ops: Arc<OpsRegistry>) -> SocketAddr {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]).with_ops_registry(ops);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let _tmp = tmp; // keep tempfile alive
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    addr
}

fn request_with_ids(trace_id: &str, span_id: &str, tool_name: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-1".into(),
        }),
        credential_token: "tok".into(),
        trace_id: trace_id.into(),
        span_id: span_id.into(),
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

#[tokio::test]
async fn check_action_allow_registers_op_as_running() {
    let registry = Arc::new(OpsRegistry::new());
    let addr = start_server_with_ops(
        r#"
version: "1"
tools:
  web_search:
    allow: true
"#,
        Arc::clone(&registry),
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(request_with_ids("trace-allow", "span-1", "web_search"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Allow as i32);
    let record = registry
        .get("trace-allow:span-1")
        .expect("op should have been ingested into the registry");
    assert_eq!(record.state, OpState::Running);
}

#[tokio::test]
async fn check_action_deny_leaves_op_pending_until_pr_h() {
    // Deny path doesn't yet transition the op — that's PR-H. For now we
    // assert the Pending entry exists; PR-H will assert Terminated here.
    let registry = Arc::new(OpsRegistry::new());
    let addr = start_server_with_ops(
        r#"
version: "1"
tools:
  dangerous:
    allow: false
"#,
        Arc::clone(&registry),
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let resp = client
        .check_action(request_with_ids("trace-deny", "span-1", "dangerous"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);
    let record = registry
        .get("trace-deny:span-1")
        .expect("op should still be ingested on Deny — only the transition is deferred");
    assert_eq!(record.state, OpState::Pending);
}

#[tokio::test]
async fn check_action_with_empty_trace_id_does_not_ingest() {
    let registry = Arc::new(OpsRegistry::new());
    let addr = start_server_with_ops(
        r#"
version: "1"
tools:
  web_search:
    allow: true
"#,
        Arc::clone(&registry),
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let _ = client
        .check_action(request_with_ids("", "span-1", "web_search"))
        .await
        .unwrap();

    assert!(registry.list().is_empty(), "missing trace_id should skip ingest");
}

#[tokio::test]
async fn check_action_replay_is_idempotent() {
    let registry = Arc::new(OpsRegistry::new());
    let addr = start_server_with_ops(
        r#"
version: "1"
tools:
  web_search:
    allow: true
"#,
        Arc::clone(&registry),
    )
    .await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();
    let req = || request_with_ids("trace-replay", "span-1", "web_search");

    client.check_action(req()).await.unwrap();
    client.check_action(req()).await.unwrap();

    let all = registry.list();
    assert_eq!(
        all.len(),
        1,
        "duplicate trace+span ids should not create a second entry"
    );
    assert_eq!(all[0].state, OpState::Running);
}
