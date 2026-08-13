//! Reconnect integration test for the Assembly-side audit publisher
//! (AAASM-2392, verifying AAASM-2387).
//!
//! Runs against a real NATS server via `testcontainers-modules`, so it requires
//! Docker. The test proves the AAASM-2387 acceptance criteria end-to-end:
//! events publish over `async-nats` while the server is up, divert to the
//! SQLite buffer during an outage, and replay in FIFO order once the server
//! returns — with nothing lost across the restart.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_core::audit::{AuditEntry, AuditEventType};
use aa_core::{AgentId, SessionId};
use aa_runtime::audit_publisher::{AuditPublisher, NatsAuditSink, NatsConfig};
use aa_storage_sqlite_buffer::EventBuffer;
use tempfile::TempDir;
use testcontainers_modules::nats::Nats;
use testcontainers_modules::testcontainers::core::IntoContainerPort;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use tokio_stream::StreamExt;

/// Reserve an ephemeral host port, then release it so a container can bind it.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Start a NATS container with its client port pinned to `host_port`, so a
/// restart is reachable at the same address the publisher already knows.
async fn start_nats(host_port: u16) -> ContainerAsync<Nats> {
    Nats::default()
        .with_mapped_port(host_port, 4222.tcp())
        .start()
        .await
        .expect("start nats testcontainer (is Docker running?)")
}

/// Build a distinct audit entry tagged with `seq`.
fn entry(seq: u64) -> AuditEntry {
    AuditEntry::new(
        seq,
        seq,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([7u8; 16]),
        SessionId::from_bytes([9u8; 16]),
        format!("{{\"seq\":{seq}}}"),
        [0u8; 32],
    )
}

/// Subscribe a fresh client to every audit subject. The client is returned
/// alongside the subscription so it outlives the borrow.
///
/// Flushes after subscribing so the `SUB` is registered server-side before the
/// caller starts publishing — otherwise early messages can race ahead of the
/// subscription and be missed.
async fn subscribe(url: &str) -> (async_nats::Client, async_nats::Subscriber) {
    let client = async_nats::connect(url).await.expect("subscriber connect");
    let sub = client
        .subscribe("assembly.audit.>")
        .await
        .expect("subscribe to audit subjects");
    client.flush().await.expect("flush subscription to server");
    (client, sub)
}

/// Collect exactly `n` decoded `seq` values from `sub`, waiting up to `timeout`
/// for the full set to arrive. This is a wait-for-delivery poll: async delivery
/// over NATS can still be in flight under CI load, so we keep waiting for the
/// next message until either `n` have arrived or the overall deadline elapses —
/// we never bail on an interim quiet gap between messages.
async fn collect_seqs(sub: &mut async_nats::Subscriber, n: usize, timeout: Duration) -> Vec<u64> {
    let mut seqs = Vec::with_capacity(n);
    let deadline = Instant::now() + timeout;
    while seqs.len() < n {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, sub.next()).await {
            Ok(Some(msg)) => {
                let decoded: AuditEntry = serde_json::from_slice(&msg.payload).expect("decode audit entry");
                seqs.push(decoded.seq());
            }
            // Subscription closed (None) or the overall deadline elapsed: stop.
            _ => break,
        }
    }
    seqs
}

/// Poll the sink's connection state until it matches `want` or the timeout
/// elapses; returns whether the desired state was reached.
async fn wait_for_connection(sink: &NatsAuditSink, want: bool, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if sink.is_connected() == want {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    sink.is_connected() == want
}

#[tokio::test]
async fn buffers_during_outage_and_replays_all_on_reconnect() {
    let host_port = free_port();
    let url = format!("nats://127.0.0.1:{host_port}");
    let tmp = TempDir::new().expect("temp dir");
    let buffer = Arc::new(EventBuffer::new(tmp.path().join("buffer.db"), 100_000).expect("open buffer"));

    // --- Phase 1: NATS up — publish 1000 events, all delivered. ---
    let nats1 = start_nats(host_port).await;
    let sink = Arc::new(
        NatsAuditSink::connect(&NatsConfig {
            url: url.clone(),
            ..Default::default()
        })
        .await
        .expect("connect publisher"),
    );
    let publisher = AuditPublisher::new(sink.clone(), buffer.clone());
    assert!(wait_for_connection(&sink, true, Duration::from_secs(10)).await);

    let (_sub_client1, mut sub1) = subscribe(&url).await;
    for seq in 0..1000 {
        publisher.publish(entry(seq)).await;
    }
    // Wait for the full set to drain — async delivery may still be in flight
    // under CI load. The generous timeout keeps this deterministic and bounded.
    let got1 = collect_seqs(&mut sub1, 1000, Duration::from_secs(120)).await;
    assert_eq!(
        got1.len(),
        1000,
        "all 1000 events should be delivered while NATS is up, but only {} arrived within the timeout",
        got1.len()
    );
    assert_eq!(publisher.buffered_len().unwrap(), 0, "nothing buffered while up");

    // --- Phase 2: NATS down — publish 100 more, all buffered, never blocking. ---
    nats1.rm().await.expect("remove nats1");
    assert!(
        wait_for_connection(&sink, false, Duration::from_secs(30)).await,
        "publisher should observe the disconnect"
    );
    for seq in 1000..1100 {
        publisher.publish(entry(seq)).await;
    }
    assert_eq!(
        publisher.buffered_len().unwrap(),
        100,
        "all 100 events buffered during the outage"
    );

    // --- Phase 3: NATS restarts on the same port — reconnect, flush in FIFO. ---
    let _nats2 = start_nats(host_port).await;
    assert!(
        wait_for_connection(&sink, true, Duration::from_secs(60)).await,
        "publisher should reconnect to the restarted server"
    );
    let (_sub_client2, mut sub2) = subscribe(&url).await;

    let flushed = publisher.flush_pending().await.expect("flush buffered events");
    assert_eq!(flushed, 100, "all buffered events flushed on reconnect");
    assert_eq!(publisher.buffered_len().unwrap(), 0, "buffer fully drained");

    // Wait for the full replayed set to drain before asserting order/count —
    // the replay is async and may still be in flight under CI load.
    let got2 = collect_seqs(&mut sub2, 100, Duration::from_secs(120)).await;
    assert_eq!(
        got2,
        (1000..1100).collect::<Vec<u64>>(),
        "buffered events should replay in FIFO order, but received {} events: {:?}",
        got2.len(),
        got2
    );

    // 1000 (pre-outage) + 100 (replayed) = 1100 events land across the restart.
    assert_eq!(
        got1.len() + got2.len(),
        1100,
        "zero acked events lost across the restart"
    );
}
