//! End-to-end verification of the approval-push timeout policy
//! (Story AAASM-2378, verification AAASM-2386).
//!
//! An agent subscribes to the push channel and awaits a verdict that never
//! arrives. When the caller-specified deadline elapses, the future must resolve
//! to [`Decision::Pending`] — **not** `Denied`: a timeout is "no human response,
//! decide locally", never an implicit denial. This complements the happy-path
//! `e2e_approval_push` test (impl AAASM-2385) which covers the approve path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tonic::transport::Server;

use aa_gateway::invalidation::{InvalidationHub, InvalidationServiceImpl};
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_proto::assembly::gateway::v1::Decision;
use aa_runtime::approval_sink::ApprovalSink;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};

#[tokio::test(flavor = "multi_thread")]
async fn approval_push_timeout_resolves_pending_not_denied() {
    // Gateway push channel on a loopback port (no verdict will ever be sent).
    let hub = InvalidationHub::new();
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

    // Assembly subscribes to the channel.
    let sink = Arc::new(ApprovalSink::new());
    let dyn_sink: Arc<dyn InvalidationSink> = Arc::clone(&sink) as Arc<dyn InvalidationSink>;
    let client = InvalidationClient::start(gateway_url, "asm-timeout".to_string(), vec![dyn_sink]);

    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.subscriber_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("assembly subscribed");

    // The agent blocks on a verdict with a 100 ms deadline; no human responds.
    let started = Instant::now();
    let decision = sink.wait_for_approval("r1", Duration::from_millis(100)).await;
    let elapsed = started.elapsed();

    // Resolves Pending (the timeout fallback), never Denied, and only after the
    // deadline — the caller, not the channel, decides what Pending means.
    assert_eq!(decision, Decision::Pending, "timeout must not auto-deny");
    assert_ne!(decision, Decision::Denied);
    assert!(
        elapsed >= Duration::from_millis(100),
        "must wait the full deadline before giving up, waited {elapsed:?}"
    );
    assert_eq!(sink.waiter_count(), 0, "timed-out waiter is dropped");

    client.abort();
    server.abort();
}
