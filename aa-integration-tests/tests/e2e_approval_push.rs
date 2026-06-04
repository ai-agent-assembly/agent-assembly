//! End-to-end: a blocked agent is woken by an `ApprovalResolved` push event
//! instead of polling (Story AAASM-2378, impl AAASM-2385).
//!
//! Wires the production pieces together over a loopback gRPC `InvalidationService`:
//! the gateway [`InvalidationHub`] is installed as the [`ApprovalQueue`]'s
//! resolved-notifier, an Assembly-side [`ApprovalSink`] subscribes over the
//! push channel, and an agent awaits [`ApprovalSink::wait_for_approval`]. When a
//! human verdict is recorded via [`ApprovalQueue::decide`] — the exact call the
//! dashboard's `POST /api/v1/approvals/{id}/approve` handler makes (see
//! `aa-api/src/routes/approvals.rs::approve_action`) — the agent's future
//! resolves with the reviewer's `Decision`.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tonic::transport::Server;
use uuid::Uuid;

use aa_core::PolicyResult;
use aa_gateway::invalidation::{InvalidationHub, InvalidationServiceImpl};
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_proto::assembly::gateway::v1::Decision;
use aa_runtime::approval::{ApprovalDecision, ApprovalQueue, ApprovalRequest, ApprovalResolvedNotifier};
use aa_runtime::approval_sink::ApprovalSink;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};

/// Build a pending approval request with a long timeout so the queue's own
/// auto-expiry never races the human verdict under test.
fn pending_request(request_id: Uuid) -> ApprovalRequest {
    ApprovalRequest {
        request_id,
        agent_id: "agent-approval-push".to_string(),
        action: "tool.wire_transfer".to_string(),
        condition_triggered: "AAASM-2378 e2e".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 300,
        fallback: PolicyResult::Deny {
            reason: "fallback-deny (unused on approve path)".to_string(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn approval_push_wakes_blocked_agent() {
    // Gateway: a hub shared between the InvalidationService and the queue's
    // resolved-notifier, so a human verdict fans out over the push channel.
    let hub = InvalidationHub::new();
    let queue = ApprovalQueue::new();
    let notifier: Arc<dyn ApprovalResolvedNotifier> = hub.clone();
    assert!(queue.set_resolved_notifier(notifier), "notifier installs on first call");

    let service = InvalidationServiceImpl::new(Arc::clone(&hub));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
    let addr = listener.local_addr().expect("local_addr");
    let server = tokio::spawn(async move {
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(InvalidationServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .expect("tonic Server::serve_with_incoming");
    });
    let gateway_url = format!("http://{addr}");

    // Assembly: an ApprovalSink subscribes to the push channel.
    let sink = Arc::new(ApprovalSink::new());
    let dyn_sink: Arc<dyn InvalidationSink> = Arc::clone(&sink) as Arc<dyn InvalidationSink>;
    let client = InvalidationClient::start(gateway_url, "asm-approval".to_string(), vec![dyn_sink]);

    // Wait until the subscription is live so the broadcast actually reaches it.
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.subscriber_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("assembly subscribed");

    // The agent submits its action for approval and blocks on the push future
    // (registered synchronously, before any verdict can race in).
    let request_id = Uuid::new_v4();
    let (id, _local_future) = queue.submit(pending_request(request_id));
    let waiter = sink.wait_for_approval(id.to_string(), Duration::from_secs(5));

    // The human approves via the dashboard → REST → ApprovalQueue::decide.
    queue
        .decide(
            id,
            ApprovalDecision::Approved {
                by: "ops-1".to_string(),
                reason: Some("approved by e2e".to_string()),
            },
        )
        .expect("decide on a pending request succeeds");

    // The blocked agent is woken with the reviewer's verdict over the push
    // channel — no polling.
    let decision = tokio::time::timeout(Duration::from_secs(2), waiter)
        .await
        .expect("agent woken by ApprovalResolved push within deadline");
    assert_eq!(decision, Decision::Approved);
    assert_eq!(sink.waiter_count(), 0, "delivered waiter is cleared");

    client.abort();
    server.abort();
}
