//! Reconnect/replay verification for the push-invalidation channel
//! (Story AAASM-2377, verification AAASM-2384).
//!
//! Proves the "no lost invalidations across a reconnect" acceptance criterion:
//! a `PolicyInvalidated` broadcast while the Assembly is disconnected is
//! buffered in the gateway's per-subscriber replay ring and delivered when the
//! Assembly reconnects under the same `assembly_id` with `Resubscribe(last_seq)`.

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tonic::transport::Server;

use aa_gateway::invalidation::{InvalidationHub, InvalidationServiceImpl};
use aa_proto::assembly::gateway::v1::invalidation_service_server::InvalidationServiceServer;
use aa_runtime::invalidation_client::{InvalidationClient, InvalidationSink};
use aa_runtime::l1_cache::PolicyL1Cache;

#[tokio::test]
async fn reconnect_replays_invalidation_missed_while_disconnected() {
    // Real gateway InvalidationService on a loopback port.
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

    // First connection: registers subscriber "asm-r", then disconnects.
    let cache_a: Arc<PolicyL1Cache<bool>> = Arc::new(PolicyL1Cache::new());
    let sink_a: Arc<dyn InvalidationSink> = Arc::clone(&cache_a) as Arc<dyn InvalidationSink>;
    let client_a = InvalidationClient::start(gateway_url.clone(), "asm-r".to_string(), vec![sink_a]);
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.subscriber_count() == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("first connection subscribed");
    client_a.abort();

    // Mutation happens while "asm-r" is disconnected — buffered in the replay ring.
    hub.broadcast_policy_invalidated("agent-x", 1);

    // Reconnect under the same assembly_id with a freshly warmed cache. The
    // client opens with last_seq_seen = 0, so the gateway replays the missed
    // event and the entry is evicted.
    let cache_b: Arc<PolicyL1Cache<bool>> = Arc::new(PolicyL1Cache::new());
    cache_b.insert("agent-x", true);
    let sink_b: Arc<dyn InvalidationSink> = Arc::clone(&cache_b) as Arc<dyn InvalidationSink>;
    let client_b = InvalidationClient::start(gateway_url, "asm-r".to_string(), vec![sink_b]);

    tokio::time::timeout(Duration::from_secs(3), async {
        while cache_b.contains("agent-x") {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("missed invalidation replayed on reconnect");

    client_b.abort();
    server.abort();
}
