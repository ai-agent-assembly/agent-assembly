//! Test that policy evaluation succeeds even when the audit channel is full.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use tokio::net::TcpListener;
use tonic::transport::Server;

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;

async fn start_server_with_tiny_channel() -> (SocketAddr, Arc<AtomicU64>, tokio::sync::mpsc::Receiver<AuditEntry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY_YAML).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    // Channel capacity of 1 — will fill up quickly.
    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(1);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, Arc::clone(&audit_drops), [0u8; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let drops = Arc::clone(&audit_drops);
    tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    // Wait for server to be ready.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Return the receiver so it stays alive — dropping it would close the channel
    // and cause try_send to return Closed instead of Full.
    (addr, drops, audit_rx)
}

fn make_request() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "test-org".into(),
            team_id: "test-team".into(),
            agent_id: "test-agent".into(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                args_json: "{}".into(),
                target_url: String::new(),
            })),
        }),
        trace_id: "trace-001".into(),
        span_id: "span-001".into(),
        credential_token: String::new(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn policy_evaluation_succeeds_when_audit_channel_full() {
    let (addr, audit_drops, _rx) = start_server_with_tiny_channel().await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // Send multiple requests — the channel(1) will fill after the first.
    // Note: the _audit_rx receiver is never consumed, so all sends after
    // the first will hit try_send Full.
    for _ in 0..5 {
        let response = client.check_action(make_request()).await.unwrap();
        let resp = response.into_inner();
        assert_eq!(resp.decision, Decision::Allow as i32);
    }

    // Some audit entries should have been dropped (channel capacity = 1, no consumer).
    let drops = audit_drops.load(Ordering::Relaxed);
    assert!(drops > 0, "expected some audit drops, got {drops}");
}
