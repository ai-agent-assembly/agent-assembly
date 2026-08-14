//! Shared harness for the AAASM-5783 hook-layer record tests.
//!
//! Produces the two records — a deny and an allow — through the shipping
//! producer (`aa-sdk-client::report_event`) and the shipping pipeline loop
//! (`aa_runtime::pipeline::run`), so each test that asserts on a *retrieved*
//! record starts from the same real inputs rather than from a hand-built proto.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_proto::assembly::audit::v1::AuditEvent;
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame};
use aa_runtime::pipeline::event::{EnrichedEvent, PipelineEvent};
use aa_runtime::pipeline::{run, PipelineConfig, PipelineMetrics};
use aa_runtime::policy::PolicyRules;
use aa_sdk_client::ipc::{IpcCommand, IpcHandle};
use aa_sdk_client::AssemblyClient;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// The `aa_core::AuditEventType` variant name a denied governed call is tagged
/// with by the SDK adapters (`python-sdk agent_assembly/core/runtime_audit.py`).
pub const DENY_TAG: &str = "PolicyViolation";
/// The tag an allowed governed call is reported under.
pub const ALLOW_TAG: &str = "ToolCallIntercepted";

pub const DENY_DETAILS: &str =
    r#"{"tool_name":"shell_exec","run_id":"run-1","denied":true,"error":"blocked by policy"}"#;
pub const ALLOW_DETAILS: &str = r#"{"tool_name":"web_search","run_id":"run-2","denied":false,"result":"3 hits"}"#;

/// Build the two protos the way the shipping producer does: through a real
/// `AssemblyClient::report_event`, read off its IPC command channel.
///
/// The channel stands in for the Unix socket only; `aa-sdk-client`'s own
/// `lifecycle_e2e` test covers the socket hop. What matters here is that the
/// proto is the one `report_event` actually constructs.
/// `report_event` enqueues with a blocking send, so it is driven off the async
/// runtime thread.
pub async fn produced_events() -> (AuditEvent, AuditEvent) {
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

pub fn pipeline_config() -> PipelineConfig {
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
pub async fn through_pipeline(events: Vec<AuditEvent>) -> Vec<EnrichedEvent> {
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
