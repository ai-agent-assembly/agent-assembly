//! AAASM-2568 verification — the `aa-runtime` enforcement gate cannot be bypassed.
//!
//! Drives the public [`aa_runtime::pipeline::run`] loop end-to-end and proves the
//! Story acceptance criteria: every inbound event is scanned + redacted before it
//! is forwarded/audited, on **both** the batch path and the violation path, and
//! the raw secret never leaves the runtime regardless of SDK behaviour.
//!
//! See `verification-reports/verification-report-AAASM-2568.md`.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use aa_proto::assembly::audit::v1::{audit_event::Detail, AuditEvent, ToolCallDetail};
use aa_proto::assembly::common::v1::ActionType;
use aa_runtime::approval::ApprovalQueue;
use aa_runtime::ipc::{new_response_router, IpcFrame};
use aa_runtime::pipeline::{run, PipelineConfig, PipelineEvent, PipelineMetrics};
use aa_runtime::policy::{PolicyRule, PolicyRules};
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

/// An AWS access-key id the credential scanner detects via the `AKIA` literal.
const SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

fn verify_config(batch_size: usize) -> PipelineConfig {
    PipelineConfig {
        input_buffer: 1_024,
        batch_size,
        flush_interval: Duration::from_millis(10_000),
        broadcast_capacity: 1_024,
        agent_id: "verify-agent".to_string(),
        enforcement: aa_runtime::pipeline::enforcement::EnforcementConfig::default(),
    }
}

/// A ToolCall `AuditEvent` whose `args_json` embeds [`SECRET`].
fn tool_call_with_secret() -> AuditEvent {
    AuditEvent {
        action_type: ActionType::ToolCall as i32,
        detail: Some(Detail::ToolCall(ToolCallDetail {
            args_json: format!(r#"{{"api_key": "{SECRET}"}}"#).into_bytes(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Assert that a forwarded pipeline event's `args_json` is redacted, not raw.
fn assert_redacted(event: PipelineEvent) {
    let PipelineEvent::Audit(enriched) = event else {
        panic!("expected a PipelineEvent::Audit");
    };
    let Some(Detail::ToolCall(tc)) = enriched.inner.detail else {
        panic!("expected ToolCall detail");
    };
    let body = String::from_utf8(tc.args_json).expect("redacted text is utf-8");
    assert!(!body.contains(SECRET), "raw secret must never leave the runtime");
    assert!(body.contains("[REDACTED:"), "redaction marker present");
}

/// Spin up the real pipeline with `policy`, push one secret-bearing ToolCall,
/// and return the single forwarded event.
async fn drive_one(policy: PolicyRules) -> PipelineEvent {
    let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
    let metrics = Arc::new(PipelineMetrics::default());
    let token = CancellationToken::new();

    tokio::spawn(run(
        rx,
        broadcast_tx,
        verify_config(1),
        metrics,
        token.clone(),
        Arc::new(policy),
        new_response_router(),
        ApprovalQueue::new(),
        None,
        Arc::new(AtomicU64::new(0)),
    ));

    tx.send((0, IpcFrame::EventReport(tool_call_with_secret())))
        .await
        .expect("send event");
    let event = tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
        .await
        .expect("timed out waiting for forwarded event")
        .expect("broadcast error");
    token.cancel();
    event
}

/// AC: every inbound event is scanned + redacted before forward/audit on the
/// normal (batch) path — no policy rules, so the event is batched then flushed.
#[tokio::test]
async fn gate_redacts_on_batch_path() {
    let event = drive_one(PolicyRules::default()).await;
    assert_redacted(event);
}

/// AC: redaction also happens on the violation path. A rule blocking `TOOL_CALL`
/// routes the secret-bearing event onto the immediate broadcast path, which must
/// still be redacted — the gate is independent of the forwarding decision.
#[tokio::test]
async fn gate_redacts_on_violation_path() {
    let policy = PolicyRules {
        rules: vec![PolicyRule {
            name: "block-tools".to_string(),
            blocked_actions: vec!["TOOL_CALL".to_string()],
            ..Default::default()
        }],
    };
    let event = drive_one(policy).await;
    assert_redacted(event);
}
