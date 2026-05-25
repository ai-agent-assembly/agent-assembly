//! Integration tests for the approval queue wiring in PolicyServiceImpl.
//!
//! Verifies that check_action() submits RequiresApproval decisions to the
//! ApprovalQueue, blocks until the operator decides, and returns the correct
//! final Allow/Deny response.

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
use aa_runtime::approval::{ApprovalDecision, ApprovalQueue};
use tokio::net::TcpListener;
use tonic::transport::Server;

// ── Helpers ──────────────────────────────────────────────────────────────────

const APPROVAL_POLICY_YAML: &str = r#"
version: "1"
approval_timeout_secs: 5
tools:
  search:
    allow: true
    requires_approval_if: 'tool == "search"'
  allowed_tool:
    allow: true
  blocked_tool:
    allow: false
"#;

/// Start a PolicyService with an approval queue and return the address and queue.
async fn start_server_with_approval(policy_yaml: &str) -> (SocketAddr, Arc<ApprovalQueue>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(aa_gateway::registry::AgentRegistry::new());
    let approval_queue = ApprovalQueue::new();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry_and_approval(
        engine,
        registry,
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
    (addr, approval_queue)
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
        caller_agent_id: None,
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_action_submits_to_approval_queue() {
    let (addr, queue) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // Spawn the check_action call — it will block waiting for approval.
    let client_task = tokio::spawn(async move { client.check_action(tool_call_request("search")).await });

    // Wait briefly for the request to reach the server and be submitted.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Verify the queue has a pending entry.
    let pending = queue.list();
    assert_eq!(pending.len(), 1, "expected one pending approval request");
    assert_eq!(pending[0].agent_id, "agent-1");

    // Approve it so the client unblocks.
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
async fn approval_approved_maps_to_allow() {
    let (addr, queue) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let client_task = tokio::spawn(async move { client.check_action(tool_call_request("search")).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let pending = queue.list();
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: Some("looks safe".to_string()),
            },
        )
        .unwrap();

    let resp = client_task.await.unwrap().unwrap().into_inner();
    assert_eq!(resp.decision, Decision::Allow as i32);
    assert!(!resp.approval_id.is_empty(), "approval_id should be the real queue ID");
}

#[tokio::test]
async fn approval_rejected_maps_to_deny() {
    let (addr, queue) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let client_task = tokio::spawn(async move { client.check_action(tool_call_request("search")).await });

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let pending = queue.list();
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Rejected {
                by: "bob".to_string(),
                reason: "not allowed".to_string(),
            },
        )
        .unwrap();

    let resp = client_task.await.unwrap().unwrap().into_inner();
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "not allowed");
}

#[tokio::test]
async fn approval_timeout_maps_to_deny() {
    // Use a very short timeout so the test doesn't take long.
    let yaml = r#"
version: "1"
approval_timeout_secs: 1
tools:
  search:
    allow: true
    requires_approval_if: 'tool == "search"'
"#;
    let (addr, _queue) = start_server_with_approval(yaml).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // Don't decide — let it time out.
    let resp = client
        .check_action(tool_call_request("search"))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Deny as i32);
    assert!(
        resp.reason.contains("timed out"),
        "expected timeout reason, got: {}",
        resp.reason
    );
}

#[tokio::test]
async fn no_queue_degrades_gracefully() {
    // Use PolicyServiceImpl::new() which has no approval queue.
    let yaml = r#"
version: "1"
approval_timeout_secs: 1
tools:
  search:
    allow: true
    requires_approval_if: 'tool == "search"'
"#;
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    // new() has no approval queue — should degrade gracefully.
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32]);

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

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // Without a queue, RequiresApproval falls through to eval_result_to_response
    // which panics. The degraded mode in maybe_submit_approval returns None,
    // so the caller must handle RequiresApproval without the queue.
    // Since eval_result_to_response now panics on RequiresApproval, this
    // should result in a gRPC INTERNAL error (from the panic).
    let result = client.check_action(tool_call_request("search")).await;
    // The panic in eval_result_to_response is caught by tonic as an internal error.
    assert!(result.is_err(), "expected error when no queue is attached");
}

#[tokio::test]
async fn batch_check_with_mixed_decisions() {
    let (addr, queue) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let batch = BatchCheckRequest {
        requests: vec![
            tool_call_request("allowed_tool"),
            tool_call_request("search"), // requires approval
            tool_call_request("blocked_tool"),
        ],
    };

    // Spawn the batch_check — it will block on the approval request.
    let client_task = tokio::spawn(async move { client.batch_check(batch).await });

    // Wait for the approval to be submitted.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let pending = queue.list();
    assert_eq!(pending.len(), 1, "expected one pending approval request");

    // Approve it.
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Approved {
                by: "operator".to_string(),
                reason: None,
            },
        )
        .unwrap();

    let resp = client_task.await.unwrap().unwrap().into_inner();
    assert_eq!(resp.responses.len(), 3);
    assert_eq!(resp.responses[0].decision, Decision::Allow as i32); // allowed_tool
    assert_eq!(resp.responses[1].decision, Decision::Allow as i32); // search (approved)
    assert_eq!(resp.responses[2].decision, Decision::Deny as i32); // blocked_tool
}
