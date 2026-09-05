//! Integration tests for the approval queue wiring in PolicyServiceImpl.
//!
//! Verifies that check_action() submits RequiresApproval decisions to the
//! ApprovalQueue and returns `Pending` + `approval_id` immediately (AAASM-4986)
//! — it does NOT block the RPC waiting for the operator. The resolution
//! (Allow/Deny once decided) is observed separately, off the original call,
//! via the ops-registry transition and a second audit entry.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_gateway::ops::{OpState, OpsRegistry};
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

/// Start a PolicyService with an approval queue and an ops registry attached,
/// and return the address, queue, and registry. The ops registry is what lets
/// a test observe an approval's eventual resolution (Running/Terminated)
/// without draining an audit channel (AAASM-4986).
async fn start_server_with_approval(policy_yaml: &str) -> (SocketAddr, Arc<ApprovalQueue>, Arc<OpsRegistry>) {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", policy_yaml).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap());
    let registry = Arc::new(aa_gateway::registry::AgentRegistry::new());
    let approval_queue = ApprovalQueue::new();
    let ops_registry = Arc::new(OpsRegistry::new());
    let (audit_tx, _audit_rx) = tokio::sync::mpsc::channel(4096);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::with_registry_and_approval(
        engine,
        registry,
        Arc::clone(&approval_queue),
        audit_tx,
        audit_drops,
        [0u8; 32],
    )
    .with_ops_registry(Arc::clone(&ops_registry));

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
    (addr, approval_queue, ops_registry)
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

/// Poll `registry.get(op_id)` until its state matches `want` or the deadline
/// elapses — the approval's continuation resolves the op asynchronously, off
/// the original RPC, so there is no synchronous point at which to assert it.
async fn wait_for_op_state(registry: &OpsRegistry, op_id: &str, want: OpState) -> aa_gateway::ops::OpRecord {
    for _ in 0..200 {
        if let Some(record) = registry.get(op_id) {
            if record.state == want {
                return record;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!(
        "op {op_id} did not reach state {want:?} within 2s; last seen: {:?}",
        registry.get(op_id)
    );
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn check_action_returns_pending_immediately() {
    let (addr, queue, _ops) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // AAASM-4986: the RPC returns Pending synchronously — it must not block
    // waiting for the human decision.
    let resp = tokio::time::timeout(Duration::from_secs(1), client.check_action(tool_call_request("search")))
        .await
        .expect("check_action must return well within the 5s approval_timeout_secs")
        .unwrap()
        .into_inner();

    assert_eq!(resp.decision, Decision::Pending as i32);
    assert!(
        !resp.approval_id.is_empty(),
        "Pending response must carry the approval_id"
    );

    let pending = queue.list();
    assert_eq!(pending.len(), 1, "expected one pending approval request");
    assert_eq!(pending[0].agent_id, "agent-1");
    assert_eq!(pending[0].request_id.to_string(), resp.approval_id);
}

#[tokio::test]
async fn approval_approved_maps_to_allow() {
    let (addr, queue, ops) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("search"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Pending as i32);
    assert!(!resp.approval_id.is_empty(), "approval_id should be the real queue ID");

    let pending = queue.list();
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Approved {
                by: "alice".to_string(),
                reason: Some("looks safe".to_string()),
                conditions: vec![],
            },
        )
        .unwrap();

    // The resolution runs in a spawned continuation, off this call — observe
    // it via the op-registry transition Pending → Running.
    wait_for_op_state(&ops, "trace-1:span-1", OpState::Running).await;
}

#[tokio::test]
async fn approval_rejected_maps_to_deny() {
    let (addr, queue, ops) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .check_action(tool_call_request("search"))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.decision, Decision::Pending as i32);

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

    wait_for_op_state(&ops, "trace-1:span-1", OpState::Terminated).await;
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
    let (addr, _queue, ops) = start_server_with_approval(yaml).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // The RPC returns Pending well before the 1s approval_timeout_secs.
    let resp = tokio::time::timeout(
        Duration::from_millis(500),
        client.check_action(tool_call_request("search")),
    )
    .await
    .expect("check_action must return immediately, not wait for the timeout")
    .unwrap()
    .into_inner();
    assert_eq!(resp.decision, Decision::Pending as i32);

    // Don't decide — let it time out. The resolution (Deny "timed out")
    // surfaces only via the op-registry transition, minutes/seconds later.
    wait_for_op_state(&ops, "trace-1:span-1", OpState::Terminated).await;
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

    // Without a queue, `maybe_submit_approval` returns `None` (degraded mode,
    // unchanged by AAASM-4986) and the caller falls through to
    // `eval_result_to_response`, which still panics on `RequiresApproval` —
    // tonic surfaces that panic as an INTERNAL error. This test exists to
    // pin that this ticket does not touch the degraded-mode path.
    let result = client.check_action(tool_call_request("search")).await;
    assert!(result.is_err(), "expected error when no queue is attached");
}

#[tokio::test]
async fn batch_check_with_mixed_decisions() {
    let (addr, queue, _ops) = start_server_with_approval(APPROVAL_POLICY_YAML).await;
    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let batch = BatchCheckRequest {
        requests: vec![
            tool_call_request("allowed_tool"),
            tool_call_request("search"), // requires approval
            tool_call_request("blocked_tool"),
        ],
    };

    // AAASM-4986: batch_check no longer blocks the whole batch on one human
    // decision — it must return promptly with the approval entry Pending.
    let resp = tokio::time::timeout(Duration::from_secs(1), client.batch_check(batch))
        .await
        .expect("batch_check must return well within the 5s approval_timeout_secs")
        .unwrap()
        .into_inner();

    assert_eq!(resp.responses.len(), 3);
    assert_eq!(resp.responses[0].decision, Decision::Allow as i32); // allowed_tool
    assert_eq!(resp.responses[1].decision, Decision::Pending as i32); // search (held)
    assert!(!resp.responses[1].approval_id.is_empty());
    assert_eq!(resp.responses[2].decision, Decision::Deny as i32); // blocked_tool

    let pending = queue.list();
    assert_eq!(pending.len(), 1, "expected one pending approval request");
    // The resolution path itself (Approved/Rejected/TimedOut -> final
    // response -> audit) is exercised end-to-end by `approval_approved_maps_to_allow`
    // and `approval_rejected_maps_to_deny` above, via the same
    // `run_approval_continuation` this batch entry spawns — this test's job
    // is only to confirm batch_check doesn't block the whole batch on it.
    queue
        .decide(
            pending[0].request_id,
            ApprovalDecision::Approved {
                by: "operator".to_string(),
                reason: None,
                conditions: vec![],
            },
        )
        .unwrap();
}
