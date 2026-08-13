//! Dispatch test for [`aa_runtime::invalidation_client`] (AAASM-3805).
//!
//! The reconnect/replay end-to-end path is covered by the `aa-integration-tests`
//! crate against the real gateway service; that crate's tests do not run under
//! `-p aa-runtime`, so the client's stream-dispatch logic (the `subscribe_once`
//! match arms and per-subscriber sequence tracking) is otherwise unexercised
//! when measuring this crate alone.
//!
//! This test stands up a minimal in-process `InvalidationService` over loopback
//! that streams one `PolicyInvalidated`, one `ApprovalResolved`, and one
//! empty-payload event, then asserts the client fans each out to its sinks with
//! the correct arguments — proving the L1-cache / approval-wakeup consumer wiring
//! actually applies pushed invalidations.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tokio_stream::Stream;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use aa_proto::assembly::gateway::v1::invalidation_event::Payload;
use aa_proto::assembly::gateway::v1::invalidation_service_server::{InvalidationService, InvalidationServiceServer};
use aa_proto::assembly::gateway::v1::{
    ApprovalResolved, Decision, InvalidationEvent, PolicyInvalidated, SubscribeRequest,
};
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};

/// A mock gateway that, on Subscribe, streams a fixed sequence of events then
/// closes the stream cleanly.
struct MockInvalidationService;

#[tonic::async_trait]
impl InvalidationService for MockInvalidationService {
    type SubscribeStream = Pin<Box<dyn Stream<Item = Result<InvalidationEvent, Status>> + Send>>;

    async fn subscribe(
        &self,
        _request: Request<Streaming<SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let events = vec![
            Ok(InvalidationEvent {
                seq: 1,
                payload: Some(Payload::PolicyInvalidated(PolicyInvalidated {
                    agent_id: "agent-a".to_string(),
                    policy_version: 7,
                })),
            }),
            Ok(InvalidationEvent {
                seq: 2,
                payload: Some(Payload::ApprovalResolved(ApprovalResolved {
                    request_id: "req-1".to_string(),
                    decision: Decision::Approved as i32,
                })),
            }),
            // An event with no payload must be tolerated (forward-compat arm).
            Ok(InvalidationEvent { seq: 3, payload: None }),
        ];
        let stream = tokio_stream::iter(events);
        Ok(Response::new(Box::pin(stream)))
    }
}

/// Records every fan-out call so the test can assert exact dispatch arguments.
#[derive(Default)]
struct RecordingSink {
    policy: Mutex<Vec<String>>,
    approvals: Mutex<Vec<(String, i32)>>,
}

impl InvalidationSink for RecordingSink {
    fn on_policy_invalidated(&self, agent_id: &str) {
        self.policy.lock().unwrap().push(agent_id.to_string());
    }

    fn on_approval_resolved(&self, request_id: &str, decision: Decision) {
        self.approvals
            .lock()
            .unwrap()
            .push((request_id.to_string(), decision as i32));
    }
}

#[tokio::test]
async fn client_fans_pushed_events_out_to_sinks() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
    let addr = listener.local_addr().expect("local_addr");
    let server = tokio::spawn(async move {
        Server::builder()
            .add_service(InvalidationServiceServer::new(MockInvalidationService))
            .serve_with_incoming(TcpListenerStream::new(listener))
            .await
            .expect("mock gateway serve");
    });

    let sink = Arc::new(RecordingSink::default());
    let client = InvalidationClient::start(
        format!("http://{addr}"),
        "asm-test".to_string(),
        vec![Arc::clone(&sink) as Arc<dyn InvalidationSink>],
    );

    // Wait until both meaningful events have been dispatched.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if !sink.policy.lock().unwrap().is_empty() && !sink.approvals.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("client did not dispatch the streamed events within 5s");

    // Stop the client first; on a clean stream close it re-subscribes promptly,
    // so the mock's fixed events may have been delivered more than once. The
    // dispatch contract is about *what* is delivered, not how many times.
    client.abort();
    server.abort();

    let policy = sink.policy.lock().unwrap();
    let approvals = sink.approvals.lock().unwrap();
    assert!(!policy.is_empty(), "expected at least one PolicyInvalidated dispatch");
    assert!(!approvals.is_empty(), "expected at least one ApprovalResolved dispatch");
    assert!(
        policy.iter().all(|a| a == "agent-a"),
        "every PolicyInvalidated must carry the streamed agent id, got {policy:?}"
    );
    assert!(
        approvals
            .iter()
            .all(|(id, d)| id == "req-1" && *d == Decision::Approved as i32),
        "every ApprovalResolved must carry the streamed request id and verdict, got {approvals:?}"
    );
}
