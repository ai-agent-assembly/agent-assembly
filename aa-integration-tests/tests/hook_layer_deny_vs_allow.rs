//! AAASM-5783 — a hook-layer deny is distinguishable from an allow in a
//! *retrieved* durable audit entry, and in the frame a live-stream subscriber
//! receives.
//!
//! ## Why this test exists
//!
//! `aa-sdk-client::report_event` is the primitive under every SDK hook-layer
//! audit record. It used to put the outcome tag and the JSON body into proto
//! `labels` and leave `action_type`, `decision` and `detail` at their proto3
//! zero. Nothing downstream reads `labels`, so a deny and an allow reached the
//! durable entry byte-identical apart from their event id. AAASM-5783 moved the
//! classification to the producer; this is the retrieval-side proof.
//!
//! ## What makes the assertion trustworthy
//!
//! The chain is driven with the shipping components at each hop, and the
//! assertion is made over a record **read back out of storage**, not over the
//! value the producer handed in:
//!
//! 1. `AssemblyClient::report_event` builds the proto (the real producer).
//! 2. `aa_runtime::pipeline::run` enriches and classifies it (the real pipeline
//!    loop, including `is_policy_violation`).
//! 3. `enriched_to_audit_entry` converts it (the real conversion).
//! 4. `AuditPublisher` publishes with its NATS sink unreachable, so each entry is
//!    serialised into the on-disk SQLite `EventBuffer` — the durable spill the
//!    shipping runtime uses when NATS is down.
//! 5. `flush_pending` drains the buffer, decoding each entry back out of SQLite.
//!    The decoded entries are what the assertions run against.
//!
//! Step 5 is the load-bearing one: reverting the AAASM-5783 producer change
//! makes the two retrieved entries compare equal on `event_type` and on the
//! payload's `decision`, and this test fails.
//!
//! The live-stream case follows the same rule: the frame asserted on is read
//! back off a real WebSocket connection to the `aa-api` router, not built in the
//! test.

mod common;

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aa_core::storage::{AuditEntry, AuditSink, Result as StorageResult, StorageError};
use aa_core::AuditEventType;
use aa_proto::assembly::audit::v1::AuditEvent;
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::audit_publisher::{enriched_to_audit_entry, AuditPublisher};
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame};
use aa_runtime::pipeline::event::{EnrichedEvent, PipelineEvent};
use aa_runtime::pipeline::{run, PipelineConfig, PipelineMetrics};
use aa_runtime::policy::PolicyRules;
use aa_sdk_client::ipc::{IpcCommand, IpcHandle};
use aa_sdk_client::AssemblyClient;
use aa_storage_sqlite_buffer::EventBuffer;
use async_trait::async_trait;
use tempfile::TempDir;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// The `aa_core::AuditEventType` variant name a denied governed call is tagged
/// with by the SDK adapters (`python-sdk agent_assembly/core/runtime_audit.py`).
const DENY_TAG: &str = "PolicyViolation";
/// The tag an allowed governed call is reported under.
const ALLOW_TAG: &str = "ToolCallIntercepted";

const DENY_DETAILS: &str = r#"{"tool_name":"shell_exec","run_id":"run-1","denied":true,"error":"blocked by policy"}"#;
const ALLOW_DETAILS: &str = r#"{"tool_name":"web_search","run_id":"run-2","denied":false,"result":"3 hits"}"#;

/// An [`AuditSink`] that refuses while `up` is false and records what it accepts
/// once flipped, standing in for NATS being unreachable and then reachable.
///
/// It is the *transport*, not the pipeline: the entries it records were decoded
/// out of the SQLite buffer by `drain_and_send`, so they are retrieved records.
struct TogglableSink {
    up: Mutex<bool>,
    captured: Mutex<Vec<AuditEntry>>,
}

impl TogglableSink {
    fn down() -> Self {
        Self {
            up: Mutex::new(false),
            captured: Mutex::new(Vec::new()),
        }
    }

    fn bring_up(&self) {
        *self.up.lock().unwrap() = true;
    }

    fn captured(&self) -> Vec<AuditEntry> {
        self.captured.lock().unwrap().clone()
    }
}

#[async_trait]
impl AuditSink for TogglableSink {
    async fn emit(&self, event: AuditEntry) -> StorageResult<()> {
        if !*self.up.lock().unwrap() {
            return Err(StorageError::Backend("sink unreachable".to_string()));
        }
        self.captured.lock().unwrap().push(event);
        Ok(())
    }
}

/// Build the two protos the way the shipping producer does: through a real
/// `AssemblyClient::report_event`, read off its IPC command channel.
///
/// The channel stands in for the Unix socket only; `aa-sdk-client`'s own
/// `lifecycle_e2e` test covers the socket hop. What matters here is that the
/// proto is the one `report_event` actually constructs.
/// `report_event` enqueues with a blocking send, so it is driven off the async
/// runtime thread.
async fn produced_events() -> (AuditEvent, AuditEvent) {
    let (tx, mut rx) = mpsc::channel(8);
    tokio::task::spawn_blocking(move || {
        let client = AssemblyClient::new(
            IpcHandle {
                cmd_tx: tx,
                thread: None,
            },
            vec![],
        );
        client
            .report_event(DENY_TAG.to_string(), DENY_DETAILS.to_string())
            .unwrap();
        client
            .report_event(ALLOW_TAG.to_string(), ALLOW_DETAILS.to_string())
            .unwrap();
    })
    .await
    .expect("producer task");

    let mut out = Vec::new();
    while let Ok(IpcCommand::SendEvent(event)) = rx.try_recv() {
        out.push(*event);
    }
    assert_eq!(out.len(), 2, "report_event should have enqueued two events");
    let allow = out.pop().unwrap();
    let deny = out.pop().unwrap();
    (deny, allow)
}

fn pipeline_config() -> PipelineConfig {
    PipelineConfig {
        input_buffer: 64,
        // batch_size 1 so a non-violation flushes immediately; the deny takes
        // the immediate-emit path either way, and the test must not depend on
        // the flush interval to see the allow.
        batch_size: 1,
        flush_interval: Duration::from_millis(10_000),
        broadcast_capacity: 64,
        agent_id: "aaasm-5783-agent".to_string(),
        enforcement: aa_runtime::pipeline::enforcement::EnforcementConfig::default(),
        gateway_fail_closed: true,
        gateway_timeout: Duration::from_secs(5),
        min_sdk_version: None,
    }
}

/// Drive the real pipeline loop over `events` and return what it broadcast.
async fn through_pipeline(events: Vec<AuditEvent>) -> Vec<EnrichedEvent> {
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
    let token = CancellationToken::new();

    let handle = tokio::spawn(run(
        rx,
        broadcast_tx,
        pipeline_config(),
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(PolicyRules::default()),
        new_response_router(),
        ApprovalQueue::new(),
        None,
        aa_runtime::op_control::OpControlStore::new(),
        Arc::new(AtomicU64::new(0)),
        new_verified_identity_store(),
    ));

    let expected = events.len();
    for event in events {
        tx.send((0, IpcFrame::EventReport(event))).await.expect("send event");
    }

    let mut forwarded = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while forwarded.len() < expected && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, broadcast_rx.recv()).await {
            // The pipeline emits its own SDK bypass/tamper record (AAASM-3637)
            // beside each event, because `aa-sdk-client` attaches no SDK-version
            // label. That is a separate governance record about the connection,
            // not the hook-layer record under test here.
            Ok(Ok(PipelineEvent::Audit(enriched))) if enriched.tamper.is_none() => forwarded.push(*enriched),
            Ok(Ok(_)) => {}
            _ => break,
        }
    }

    token.cancel();
    let _ = handle.await;
    forwarded
}

/// Publish `entries` with the sink down so they spill to SQLite, then bring the
/// sink up and drain — returning the entries as decoded back out of the buffer.
async fn round_trip_through_buffer(entries: Vec<AuditEntry>, dir: &TempDir) -> Vec<AuditEntry> {
    let buffer_path: PathBuf = dir.path().join("aaasm-5783-buffer.db");
    let buffer = Arc::new(EventBuffer::new(&buffer_path, 128).expect("open event buffer"));
    let sink = Arc::new(TogglableSink::down());
    let publisher = AuditPublisher::new(sink.clone(), buffer);

    let published = entries.len();
    for entry in entries {
        publisher.publish(entry).await;
    }
    assert_eq!(
        publisher.buffered_len().expect("buffer length"),
        published,
        "with the sink down each entry must reach the on-disk buffer"
    );

    sink.bring_up();
    let flushed = publisher.flush_pending().await.expect("flush");
    assert_eq!(flushed, published, "the buffer must replay what it holds");

    sink.captured()
}

/// Read the durable payload's `decision` and `detail` back out of an entry.
fn payload_of(entry: &AuditEntry) -> serde_json::Value {
    serde_json::from_str(entry.payload()).expect("durable payload should be JSON")
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deny_and_an_allow_differ_in_the_retrieved_durable_entry() {
    let (deny_proto, allow_proto) = produced_events().await;

    let forwarded = through_pipeline(vec![deny_proto, allow_proto]).await;
    assert_eq!(forwarded.len(), 2, "the pipeline should forward both records");

    let entries: Vec<AuditEntry> = forwarded.iter().map(enriched_to_audit_entry).collect();

    let dir = TempDir::new().expect("tempdir");
    let retrieved = round_trip_through_buffer(entries, &dir).await;
    assert_eq!(retrieved.len(), 2, "both entries should come back out of the buffer");

    // FIFO replay preserves the order they were published in.
    let deny = &retrieved[0];
    let allow = &retrieved[1];

    // 1. The governance event type separates them.
    assert_eq!(
        deny.event_type(),
        AuditEventType::PolicyViolation,
        "a retrieved hook-layer deny should be typed as a policy violation"
    );
    assert_eq!(
        allow.event_type(),
        AuditEventType::ToolCallIntercepted,
        "a retrieved hook-layer allow should be typed as an intercepted tool call"
    );
    assert_ne!(deny.event_type(), allow.event_type());

    // 2. The durable payload's decision separates them.
    let deny_payload = payload_of(deny);
    let allow_payload = payload_of(allow);
    let deny_decision = deny_payload["decision"].as_i64().expect("decision");
    let allow_decision = allow_payload["decision"].as_i64().expect("decision");
    assert_eq!(
        deny_decision,
        i64::from(aa_proto::assembly::common::v1::Decision::Deny as i32),
        "the retrieved deny should carry the Deny discriminant, got {deny_payload}"
    );
    assert_eq!(
        allow_decision,
        i64::from(aa_proto::assembly::common::v1::Decision::Allow as i32),
        "the retrieved allow should carry the Allow discriminant, got {allow_payload}"
    );
    assert_ne!(deny_decision, allow_decision);

    // 3. The deny's reason text survives into the durable payload.
    assert_eq!(deny_payload["detail"]["kind"], "policy_violation");
    assert_eq!(deny_payload["detail"]["blocked_action"], DENY_TAG);
    assert_eq!(
        deny_payload["detail"]["reason"], DENY_DETAILS,
        "the deny's reported text should reach the durable payload"
    );

    // 4. The action class is recorded rather than left unspecified, and the two
    //    payloads are not the same document.
    assert_eq!(
        deny_payload["action_type"], "TOOL_CALL",
        "the retrieved deny should record its action class, got {deny_payload}"
    );
    assert_eq!(
        allow_payload["action_type"], "TOOL_CALL",
        "the retrieved allow should record its action class, got {allow_payload}"
    );
    assert_ne!(
        deny_payload, allow_payload,
        "a retrieved deny and allow must not render identically"
    );
}

/// AAASM-5783 acceptance: `is_policy_violation` returns true for a hook-layer
/// deny, observed through the behaviour it gates rather than by calling the
/// private function — a violation bypasses the batch and is broadcast on its
/// own, so a deny arrives even when the batch size is larger than the number of
/// events sent and the flush interval has not elapsed.
#[tokio::test(flavor = "multi_thread")]
async fn a_hook_layer_deny_bypasses_the_batch() {
    let (deny_proto, allow_proto) = produced_events().await;

    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
    let token = CancellationToken::new();

    let mut config = pipeline_config();
    // Larger than the number of events sent, with a flush interval longer than
    // the read window: only the immediate-emit path can deliver inside it.
    config.batch_size = 16;
    config.flush_interval = Duration::from_secs(60);

    let handle = tokio::spawn(run(
        rx,
        broadcast_tx,
        config,
        Arc::new(PipelineMetrics::default()),
        token.clone(),
        Arc::new(PolicyRules::default()),
        new_response_router(),
        ApprovalQueue::new(),
        None,
        aa_runtime::op_control::OpControlStore::new(),
        Arc::new(AtomicU64::new(0)),
        new_verified_identity_store(),
    ));

    tx.send((0, IpcFrame::EventReport(allow_proto)))
        .await
        .expect("send allow");
    tx.send((0, IpcFrame::EventReport(deny_proto)))
        .await
        .expect("send deny");

    // Skip the pipeline's own SDK bypass/tamper records (see `through_pipeline`).
    let mut hook_records = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while hook_records.is_empty() && tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, broadcast_rx.recv()).await {
            Ok(Ok(PipelineEvent::Audit(enriched))) if enriched.tamper.is_none() => hook_records.push(*enriched),
            Ok(Ok(_)) => {}
            _ => break,
        }
    }

    token.cancel();
    let _ = handle.await;

    let first = hook_records
        .first()
        .expect("a deny should be emitted without waiting for the batch flush");
    assert_eq!(
        first.inner.decision,
        aa_proto::assembly::common::v1::Decision::Deny as i32,
        "the record that bypassed the batch should be the deny"
    );
}

/// AAASM-5783 acceptance: a deny and an allow also differ on the live stream.
///
/// The two records are produced and enriched by the same shipping chain as the
/// durable case, then broadcast to a real `aa-api` WebSocket subscriber. The
/// assertions run on the JSON frames read back off the socket.
#[tokio::test(flavor = "multi_thread")]
async fn a_deny_and_an_allow_differ_in_the_frame_read_off_the_live_stream() {
    use futures::StreamExt;

    let (deny_proto, allow_proto) = produced_events().await;
    let forwarded = through_pipeline(vec![deny_proto, allow_proto]).await;
    assert_eq!(forwarded.len(), 2, "the pipeline should forward both records");

    let env = common::TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect should succeed");
    // Let the handler subscribe to the broadcast before anything is sent.
    tokio::time::sleep(Duration::from_millis(100)).await;

    for enriched in forwarded {
        env.events
            .pipeline_sender()
            .send(PipelineEvent::Audit(Box::new(enriched)))
            .expect("broadcast should have a subscriber");
    }

    let mut frames = Vec::new();
    while frames.len() < 2 {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timeout waiting for a WS frame")
            .expect("stream closed unexpectedly")
            .expect("ws error");
        let event: serde_json::Value = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        frames.push(event);
    }

    let deny_frame = &frames[0]["payload"];
    let allow_frame = &frames[1]["payload"];

    assert_eq!(
        deny_frame["decision"], "deny",
        "the deny read off the stream should carry the deny bucket, got {deny_frame}"
    );
    assert_eq!(
        allow_frame["decision"], "allow",
        "the allow read off the stream should carry the allow bucket, got {allow_frame}"
    );
    assert_eq!(deny_frame["status"], "blocked");
    assert_eq!(allow_frame["status"], "running");
    assert_eq!(deny_frame["op_type"], "tool_call");
    assert_ne!(
        deny_frame["decision"], allow_frame["decision"],
        "a deny and an allow must not render identically on the live stream"
    );
}
