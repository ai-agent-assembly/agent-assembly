//! AAASM-3571 verification — SDK bypass/tamper observability in audit.
//!
//! Drives the public [`aa_runtime::pipeline::run`] loop end-to-end and proves the
//! Story acceptance criteria:
//!
//! 1. A missing/forged/downgraded SDK identity produces a **distinct** tamper
//!    audit event + the `aa_runtime_sdk_tamper_suspected_total` metric.
//! 2. Forged SDK trust markers are **ignored AND flagged**: the raw marker never
//!    survives onto the forwarded event, and a tamper signal is recorded.
//! 3. Bypass observability does **not** change the enforcement decision — a
//!    clean and a tampered event with the same action yield the same forwarded
//!    outcome (the runtime stays authoritative).
//!
//! The run loop is driven on a current-thread Tokio runtime nested inside
//! `metrics::with_local_recorder`, mirroring `audit_publisher::publisher`'s
//! metric test, so the metric assertions never race a global recorder.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_proto::assembly::audit::v1::{audit_event::Detail, AuditEvent, ToolCallDetail};
use aa_proto::assembly::common::v1::ActionType;
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::ipc::{new_response_router, new_verified_identity_store, IpcFrame};
use aa_runtime::pipeline::event::SDK_VERSION_LABEL;
use aa_runtime::pipeline::{run, PipelineConfig, PipelineEvent, PipelineMetrics};
use aa_runtime::policy::PolicyRules;
use metrics_util::debugging::DebuggingRecorder;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// One of the reserved forged trust-marker labels stripped by the runtime.
const FORGED_MARKER: &str = "aa.trusted";

fn verify_config() -> PipelineConfig {
    PipelineConfig {
        input_buffer: 1_024,
        // batch_size 1 so ordinary events flush immediately and the test does
        // not depend on the flush interval.
        batch_size: 1,
        flush_interval: Duration::from_millis(10_000),
        broadcast_capacity: 1_024,
        agent_id: "verify-agent".to_string(),
        enforcement: aa_runtime::pipeline::enforcement::EnforcementConfig::default(),
        gateway_fail_closed: true,
        gateway_timeout: Duration::from_secs(5),
        min_sdk_version: None,
    }
}

/// A clean ToolCall event with a present SDK-version label (no tamper).
fn clean_tool_call() -> AuditEvent {
    let mut event = AuditEvent {
        action_type: ActionType::ToolCall as i32,
        detail: Some(Detail::ToolCall(ToolCallDetail {
            tool_name: "web_search".to_string(),
            ..Default::default()
        })),
        ..Default::default()
    };
    event.labels.insert(SDK_VERSION_LABEL.to_string(), "1.0.0".to_string());
    event
}

/// A ToolCall event with NO SDK-version label — a stripped / bypassed SDK.
fn tool_call_without_sdk_identity() -> AuditEvent {
    AuditEvent {
        action_type: ActionType::ToolCall as i32,
        detail: Some(Detail::ToolCall(ToolCallDetail {
            tool_name: "web_search".to_string(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// A ToolCall event that forges a trust marker hoping to shorten enforcement.
fn tool_call_with_forged_marker() -> AuditEvent {
    let mut event = clean_tool_call();
    event.labels.insert(FORGED_MARKER.to_string(), "true".to_string());
    event
}

/// Spawn the pipeline, send `events`, and collect the events forwarded onto the
/// broadcast channel within a short window. Returns the forwarded events.
async fn drive(events: Vec<AuditEvent>) -> Vec<aa_runtime::pipeline::EnrichedEvent> {
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
    let token = CancellationToken::new();

    let handle = tokio::spawn(run(
        rx,
        broadcast_tx,
        verify_config(),
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

    // Each ordinary event forwards once; a tampered event additionally forwards a
    // distinct tamper event. Collect until the channel goes quiet.
    let mut forwarded = Vec::new();
    while forwarded.len() < expected {
        match tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv()).await {
            Ok(Ok(PipelineEvent::Audit(e))) => forwarded.push(*e),
            Ok(Ok(PipelineEvent::LayerDegradation(_))) => {}
            _ => break,
        }
    }
    // Drain any extra (tamper) events already queued.
    while let Ok(PipelineEvent::Audit(e)) = broadcast_rx.try_recv() {
        forwarded.push(*e);
    }

    token.cancel();
    let _ = tokio::time::timeout(Duration::from_millis(500), handle).await;
    forwarded
}

/// AC1: a missing SDK identity yields a distinct tamper audit event whose
/// verdict is `missing`, plus the dedicated metric.
#[test]
fn missing_sdk_identity_emits_distinct_tamper_event_and_metric() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();

    let forwarded = metrics::with_local_recorder(&recorder, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(drive(vec![tool_call_without_sdk_identity()]))
    });

    // A distinct tamper event (carrying the verdict, with no action detail) is
    // present in addition to the forwarded action event.
    let tamper: Vec<_> = forwarded.iter().filter_map(|e| e.tamper).collect();
    assert_eq!(tamper.len(), 1, "exactly one distinct tamper event");
    assert_eq!(
        tamper[0].verdict,
        aa_security::sdk_identity::SdkIdentityVerdict::Missing
    );

    let metric_present = snapshotter
        .snapshot()
        .into_vec()
        .into_iter()
        .any(|(key, _, _, _)| key.key().name() == "aa_runtime_sdk_tamper_suspected_total");
    assert!(metric_present, "aa_runtime_sdk_tamper_suspected_total recorded");
}

/// AC2: a forged trust marker is stripped from the forwarded event AND flagged.
#[tokio::test]
async fn forged_trust_marker_is_stripped_and_flagged() {
    let forwarded = drive(vec![tool_call_with_forged_marker()]).await;

    // The raw forged marker never survives onto any forwarded event.
    for e in &forwarded {
        assert!(
            !e.inner.labels.contains_key(FORGED_MARKER),
            "forged trust marker must never survive downstream"
        );
    }
    // The forgery is flagged via a distinct tamper event.
    assert!(
        forwarded
            .iter()
            .any(|e| e.tamper.is_some_and(|t| t.forged_trust_markers > 0)),
        "forged trust marker must be flagged in a tamper event"
    );
}

/// AC3: bypass observability does not change the enforcement decision — a clean
/// and a tampered event with the same action are both forwarded identically
/// (the runtime stays authoritative; nothing is dropped or allowed differently).
#[tokio::test]
async fn observability_does_not_change_enforcement_decision() {
    let clean = drive(vec![clean_tool_call()]).await;
    let tampered = drive(vec![tool_call_without_sdk_identity()]).await;

    // The clean event yields exactly its one forwarded action event (no tamper).
    let clean_actions: Vec<_> = clean.iter().filter(|e| e.tamper.is_none()).collect();
    assert_eq!(clean_actions.len(), 1, "clean event forwarded once");
    assert!(
        clean.iter().all(|e| e.tamper.is_none()),
        "clean event has no tamper signal"
    );

    // The tampered event still forwards its action event with the same ToolCall
    // detail preserved — observability added a record, it did not suppress or
    // alter the action.
    let tampered_actions: Vec<_> = tampered.iter().filter(|e| e.tamper.is_none()).collect();
    assert_eq!(
        tampered_actions.len(),
        1,
        "tampered event's action is still forwarded (decision unchanged)"
    );
    let action_detail_kind =
        |e: &aa_runtime::pipeline::EnrichedEvent| matches!(e.inner.detail, Some(Detail::ToolCall(_)));
    assert!(
        action_detail_kind(clean_actions[0]) && action_detail_kind(tampered_actions[0]),
        "both action events carry the same ToolCall detail — same decision"
    );
}
