//! End-to-end test for the gRPC push-invalidation channel (Story AAASM-2377).
//!
//! Wires the real gateway-side `InvalidationServiceImpl` to the real
//! Assembly-side `InvalidationClient` over a loopback gRPC connection and
//! asserts that a policy invalidation evicts the subscribed L1 cache entry
//! within 100 ms — the security-critical bound that closes the TTL-race window.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpListener;
use tonic::transport::Server;

use aa_gateway::invalidation::{InvalidationHub, InvalidationServiceImpl};
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};
use aa_runtime::l1_cache::PolicyL1Cache;

#[tokio::test]
async fn policy_invalidation_evicts_l1_within_100ms() {
    // ── Real gateway InvalidationService on a loopback port ──────────────────
    let hub = InvalidationHub::new();
    let service = InvalidationServiceImpl::new(Arc::clone(&hub));
    // Bind before spawning so the socket is already listening when the client
    // dials — connections queue even before `serve_with_incoming` runs.
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

    // ── Assembly-side L1 cache, warm with two agents, subscribed to the channel
    let cache: Arc<PolicyL1Cache<bool>> = Arc::new(PolicyL1Cache::new());
    cache.insert("agent-x", true);
    cache.insert("agent-y", true);
    let sink: Arc<dyn InvalidationSink> = Arc::clone(&cache) as Arc<dyn InvalidationSink>;
    let client = InvalidationClient::start(format!("http://{addr}"), "asm-e2e".to_string(), vec![sink]);

    // Wait until the subscriber has registered with the gateway.
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.subscriber_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("client subscribed to gateway within 5 s");

    // ── Mutate policy → gateway pushes a targeted invalidation for agent-x ────
    let start = Instant::now();
    hub.broadcast_policy_invalidated("agent-x", 1);

    tokio::time::timeout(Duration::from_millis(100), async {
        while cache.contains("agent-x") {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("agent-x evicted from L1 within 100 ms");

    assert!(start.elapsed() < Duration::from_millis(100));
    assert!(cache.contains("agent-y"), "unrelated agent-y must stay cached");

    client.abort();
    server.abort();
}
