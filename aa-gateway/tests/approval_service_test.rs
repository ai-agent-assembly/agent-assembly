//! Integration tests for the ApprovalService gRPC endpoint.
//!
//! Starts a tonic server on a random TCP port, connects a client,
//! and exercises ListPending, Decide, and WatchApprovals RPCs.

use std::net::SocketAddr;
use std::sync::Arc;

use aa_gateway::service::ApprovalServiceImpl;
use aa_proto::assembly::approval::v1::approval_service_client::ApprovalServiceClient;
use aa_proto::assembly::approval::v1::approval_service_server::ApprovalServiceServer;
use aa_proto::assembly::approval::v1::{
    ApprovalDecisionType, DecideRequest, ListPendingRequest, WatchApprovalsRequest,
};
use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};
use tokio::net::TcpListener;
use tonic::transport::Server;
use uuid::Uuid;

/// Start an ApprovalService gRPC server and return the address + queue handle.
async fn start_server() -> (SocketAddr, Arc<ApprovalQueue>) {
    let queue = ApprovalQueue::new();
    let service = ApprovalServiceImpl::new(Arc::clone(&queue));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(ApprovalServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    (addr, queue)
}

fn make_test_request() -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "agent-test".to_string(),
        action: "deploy to production".to_string(),
        condition_triggered: "requires-tech-lead-approval".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 300,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

#[tokio::test]
async fn list_pending_returns_empty_initially() {
    let (addr, _queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client.list_pending(ListPendingRequest {}).await.unwrap().into_inner();

    assert!(resp.requests.is_empty());
}

#[tokio::test]
async fn list_pending_returns_submitted_request() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let req = make_test_request();
    let expected_id = req.request_id.to_string();
    let (_rid, _fut) = queue.submit(req);

    let resp = client.list_pending(ListPendingRequest {}).await.unwrap().into_inner();

    assert_eq!(resp.requests.len(), 1);
    assert_eq!(resp.requests[0].request_id, expected_id);
    assert_eq!(resp.requests[0].agent_id, "agent-test");
    assert_eq!(resp.requests[0].action, "deploy to production");
}

#[tokio::test]
async fn decide_approve_resolves_request() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let req = make_test_request();
    let request_id = req.request_id.to_string();
    let (_rid, _fut) = queue.submit(req);

    let resp = client
        .decide(DecideRequest {
            request_id: request_id.clone(),
            decision: ApprovalDecisionType::Approved as i32,
            decided_by: "alice".to_string(),
            reason: "looks safe".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.success);
    assert!(resp.error_message.is_empty());

    let list_resp = client.list_pending(ListPendingRequest {}).await.unwrap().into_inner();
    assert!(list_resp.requests.is_empty());
}

#[tokio::test]
async fn decide_reject_resolves_request() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let req = make_test_request();
    let request_id = req.request_id.to_string();
    let (_rid, _fut) = queue.submit(req);

    let resp = client
        .decide(DecideRequest {
            request_id,
            decision: ApprovalDecisionType::Rejected as i32,
            decided_by: "bob".to_string(),
            reason: "too risky".to_string(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(resp.success);

    let list_resp = client.list_pending(ListPendingRequest {}).await.unwrap().into_inner();
    assert!(list_resp.requests.is_empty());
}

#[tokio::test]
async fn decide_unknown_id_returns_failure() {
    let (addr, _queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let resp = client
        .decide(DecideRequest {
            request_id: Uuid::new_v4().to_string(),
            decision: ApprovalDecisionType::Approved as i32,
            decided_by: "alice".to_string(),
            reason: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    assert!(!resp.success);
    assert!(!resp.error_message.is_empty());
}

#[tokio::test]
async fn decide_invalid_uuid_returns_error() {
    let (addr, _queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let result = client
        .decide(DecideRequest {
            request_id: "not-a-uuid".to_string(),
            decision: ApprovalDecisionType::Approved as i32,
            decided_by: "alice".to_string(),
            reason: String::new(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn reject_without_reason_returns_error() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let req = make_test_request();
    let request_id = req.request_id.to_string();
    let (_rid, _fut) = queue.submit(req);

    let result = client
        .decide(DecideRequest {
            request_id,
            decision: ApprovalDecisionType::Rejected as i32,
            decided_by: "bob".to_string(),
            reason: String::new(),
        })
        .await;

    assert!(result.is_err());
    let status = result.unwrap_err();
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn watch_approvals_streams_new_request() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let mut stream = client
        .watch_approvals(WatchApprovalsRequest {})
        .await
        .unwrap()
        .into_inner();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let req = make_test_request();
    let expected_id = req.request_id.to_string();
    let (_rid, _fut) = queue.submit(req);

    let event = tokio::time::timeout(std::time::Duration::from_secs(3), stream.message())
        .await
        .expect("should receive event within 3 seconds")
        .expect("stream should not error")
        .expect("stream should not end");

    assert_eq!(event.request_id, expected_id);
    assert_eq!(event.agent_id, "agent-test");
    assert_eq!(event.action, "deploy to production");
}

#[tokio::test]
async fn watch_approvals_streams_multiple_requests() {
    let (addr, queue) = start_server().await;
    let mut client = ApprovalServiceClient::connect(format!("http://{addr}")).await.unwrap();

    let mut stream = client
        .watch_approvals(WatchApprovalsRequest {})
        .await
        .unwrap()
        .into_inner();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut expected_ids = Vec::new();
    for _ in 0..3 {
        let req = make_test_request();
        expected_ids.push(req.request_id.to_string());
        let (_rid, _fut) = queue.submit(req);
    }

    let mut received_ids = Vec::new();
    for _ in 0..3 {
        let event = tokio::time::timeout(std::time::Duration::from_secs(3), stream.message())
            .await
            .expect("should receive event within 3 seconds")
            .expect("stream should not error")
            .expect("stream should not end");

        received_ids.push(event.request_id);
    }

    expected_ids.sort();
    received_ids.sort();
    assert_eq!(received_ids, expected_ids);
}
