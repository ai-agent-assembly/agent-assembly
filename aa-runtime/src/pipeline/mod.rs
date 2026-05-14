//! Event aggregation pipeline — receives IpcFrames, enriches, batches, and fans out.

pub mod event;
pub mod metrics;

pub use event::{EnrichedEvent, EventSource, LayerDegradationInfo, PipelineEvent};
pub use metrics::PipelineMetrics;

use crate::approval::{ApprovalDecision as RuntimeApprovalDecision, ApprovalQueue, ApprovalRequest};
use crate::config::RuntimeConfig;
use crate::gateway_client::GatewayClient;
use crate::ipc::{IpcFrame, IpcResponse, ResponseRouter};
use crate::policy::PolicyRules;
use aa_proto::assembly::audit::v1::{audit_event::Detail, AuditEvent, PolicyViolation};
use aa_proto::assembly::common::v1::{ActionType, Decision};
use aa_proto::assembly::event::v1::ApprovalDecision as ProtoApprovalDecision;
use aa_proto::assembly::policy::v1::CheckActionResponse;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, mpsc, Mutex};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Configuration for the event aggregation pipeline.
///
/// Derived from [`RuntimeConfig`] via [`PipelineConfig::from_runtime_config`].
#[derive(Debug, Clone)]
pub struct PipelineConfig {
    /// Depth of the mpsc inbound channel.
    pub input_buffer: usize,
    /// Maximum events in a batch before an early flush.
    pub batch_size: usize,
    /// Interval between scheduled batch flushes.
    pub flush_interval: Duration,
    /// Capacity of the broadcast ring buffer.
    pub broadcast_capacity: usize,
    /// Agent identity — copied from `RuntimeConfig::agent_id`.
    pub agent_id: String,
}

impl PipelineConfig {
    /// Build a [`PipelineConfig`] from a [`RuntimeConfig`].
    pub fn from_runtime_config(c: &RuntimeConfig) -> Self {
        Self {
            input_buffer: c.pipeline_input_buffer,
            batch_size: c.pipeline_batch_size,
            flush_interval: Duration::from_millis(c.pipeline_flush_interval_ms),
            broadcast_capacity: c.pipeline_broadcast_capacity,
            agent_id: c.agent_id.clone(),
        }
    }
}

/// Start the event aggregation pipeline.
///
/// Consumes `rx` (the inbound IpcFrame channel from the IPC server),
/// enriches and batches events, and fans them out via `broadcast_tx`.
///
/// Returns when `token` is cancelled — flushing any pending batch first.
#[allow(clippy::too_many_arguments)]
pub async fn run(
    mut rx: mpsc::Receiver<(u64, IpcFrame)>,
    broadcast_tx: broadcast::Sender<PipelineEvent>,
    config: PipelineConfig,
    metrics: Arc<PipelineMetrics>,
    token: CancellationToken,
    policy: Arc<PolicyRules>,
    response_router: ResponseRouter,
    approval_queue: Arc<ApprovalQueue>,
    gateway_client: Option<Arc<Mutex<GatewayClient>>>,
    seq: Arc<AtomicU64>,
) {
    let mut batch: Vec<EnrichedEvent> = Vec::with_capacity(config.batch_size);
    let mut ticker = tokio::time::interval(config.flush_interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            biased;

            _ = token.cancelled() => {
                // Drain any remaining batch before exiting.
                if !batch.is_empty() {
                    flush(&mut batch, &broadcast_tx, &metrics);
                }
                break;
            }

            Some((connection_id, frame)) = rx.recv() => {
                match frame {
                    IpcFrame::EventReport(event) => {
                        let enriched = enrich(event, &config.agent_id, connection_id, &seq);
                        tracing::debug!(sequence_number = enriched.sequence_number, connection_id, "event enriched");
                        metrics.record_processed(1);
                        ::metrics::counter!("aa_events_received_total").increment(1);
                        if is_policy_violation(&enriched, &policy) {
                            // Bypass the batch — emit immediately.
                            ::metrics::counter!("aa_policy_violations_total").increment(1);
                            // Push a ViolationAlert back to the originating SDK connection.
                            push_violation_alert(&enriched, &response_router).await;
                            let _ = broadcast_tx.send(PipelineEvent::Audit(Box::new(enriched)));
                        } else {
                            batch.push(enriched);
                            if batch.len() >= config.batch_size {
                                flush(&mut batch, &broadcast_tx, &metrics);
                            }
                        }
                    }
                    IpcFrame::PolicyQuery(req) => {
                        handle_policy_query(
                            connection_id,
                            req,
                            &policy,
                            &approval_queue,
                            &response_router,
                            &gateway_client,
                        )
                        .await;
                    }
                    // ApprovalResponse, Heartbeat: not pipeline events, ignored.
                    _ => {}
                }
            }

            _ = ticker.tick() => {
                if !batch.is_empty() {
                    flush(&mut batch, &broadcast_tx, &metrics);
                }
            }
        }
    }
    tracing::info!("pipeline task stopped");
}

/// Enrich a raw [`AuditEvent`] with runtime-side metadata.
fn enrich(event: AuditEvent, agent_id: &str, connection_id: u64, seq: &AtomicU64) -> EnrichedEvent {
    use std::time::{SystemTime, UNIX_EPOCH};
    let received_at_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as i64;
    let sequence_number = seq.fetch_add(1, Ordering::Relaxed);
    EnrichedEvent {
        inner: event,
        received_at_ms,
        source: EventSource::Sdk,
        agent_id: agent_id.to_string(),
        connection_id,
        sequence_number,
    }
}

/// Returns `true` if this event should bypass batching and be emitted immediately.
///
/// An event is a violation if either:
/// - Its detail is a `PolicyViolation` proto message, or
/// - Any rule in `policy.rules` has a `blocked_actions` entry that matches the
///   event's `action_type` (compared as the proto enum's string name).
fn is_policy_violation(event: &EnrichedEvent, policy: &PolicyRules) -> bool {
    if matches!(event.inner.detail, Some(Detail::Violation(_))) {
        return true;
    }
    let action_str = ActionType::try_from(event.inner.action_type)
        .map(|a| a.as_str_name())
        .unwrap_or("");
    for rule in &policy.rules {
        if rule.blocked_actions.iter().any(|ba| ba == action_str) {
            tracing::warn!(
                rule = %rule.name,
                action = %action_str,
                "policy rule matched — event bypassing batch"
            );
            return true;
        }
    }
    false
}

/// Extract a `PolicyViolation` from an `EnrichedEvent`, if one is present.
///
/// Returns `Some` when the event's detail is `Detail::Violation(_)`.
/// Returns `None` for rule-matched events that have no embedded violation proto —
/// in that case the SDK already knows the action was blocked.
fn extract_violation(event: &EnrichedEvent) -> Option<PolicyViolation> {
    match &event.inner.detail {
        Some(Detail::Violation(v)) => Some(v.clone()),
        _ => None,
    }
}

/// Send a `ViolationAlert` to the SDK connection that originated `event`.
///
/// Looks up the per-connection sender in the `ResponseRouter`. If the connection
/// has already disconnected the entry will be absent and the alert is silently
/// dropped — the connection is gone so there is no point delivering it.
async fn push_violation_alert(event: &EnrichedEvent, router: &crate::ipc::ResponseRouter) {
    let Some(violation) = extract_violation(event) else {
        // Rule-matched events don't carry a PolicyViolation proto; skip.
        return;
    };
    let sender = {
        let map = router.read().await;
        map.get(&event.connection_id).cloned()
    };
    if let Some(tx) = sender {
        if tx.send(IpcResponse::ViolationAlert(violation)).await.is_err() {
            tracing::debug!(
                connection_id = event.connection_id,
                "ViolationAlert dropped — connection already closed"
            );
        }
    }
}

/// Send an [`IpcResponse`] to the SDK connection identified by `connection_id`.
///
/// If the connection has already disconnected the message is silently dropped.
async fn send_ipc_response(connection_id: u64, response: IpcResponse, router: &ResponseRouter) {
    let sender = {
        let map = router.read().await;
        map.get(&connection_id).cloned()
    };
    if let Some(tx) = sender {
        if tx.send(response).await.is_err() {
            tracing::debug!(connection_id, "IpcResponse dropped — connection already closed");
        }
    }
}

/// Evaluate a [`IpcFrame::PolicyQuery`] against the loaded policy and respond.
///
/// When `gateway_client` is `Some`, the request is forwarded to the governance
/// gateway over gRPC. If the gateway call fails, the function falls back to
/// local [`PolicyRules`] evaluation with a warning log.
///
/// Local decision priority (first match wins):
/// 1. `requires_approval_actions` → `PENDING` + submit to [`ApprovalQueue`]; spawn a task to
///    push an [`IpcResponse::ApprovalDecision`] back once the request is resolved.
/// 2. `blocked_actions` → `DENY`.
/// 3. No match → `ALLOW`.
async fn handle_policy_query(
    connection_id: u64,
    req: aa_proto::assembly::policy::v1::CheckActionRequest,
    policy: &PolicyRules,
    approval_queue: &Arc<ApprovalQueue>,
    response_router: &ResponseRouter,
    gateway_client: &Option<Arc<Mutex<GatewayClient>>>,
) {
    // ── Gateway forwarding path ─────────────────────────────────────────
    if let Some(client) = gateway_client {
        let mut guard = client.lock().await;
        match guard.check_action(req.clone()).await {
            Ok(resp) => {
                tracing::debug!(connection_id, decision = resp.decision, "gateway responded");
                send_ipc_response(connection_id, IpcResponse::PolicyResponse(resp), response_router).await;
                return;
            }
            Err(e) => {
                tracing::warn!(
                    connection_id,
                    error = %e,
                    "gateway call failed — falling back to local policy evaluation"
                );
                // Fall through to local evaluation below.
            }
        }
    }

    // ── Local evaluation path ───────────────────────────────────────────
    let action_str = ActionType::try_from(req.action_type)
        .map(|a| a.as_str_name())
        .unwrap_or("");
    let agent_id_str = req
        .agent_id
        .as_ref()
        .map(|a| a.agent_id.as_str())
        .unwrap_or("")
        .to_string();

    // 1. Check requires_approval_actions.
    for rule in &policy.rules {
        if rule.requires_approval_actions.iter().any(|a| a == action_str) {
            let request_id = Uuid::new_v4();
            let submitted_at = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_secs();
            let approval_req = ApprovalRequest {
                request_id,
                agent_id: agent_id_str.clone(),
                action: action_str.to_string(),
                condition_triggered: rule.name.clone(),
                submitted_at,
                timeout_secs: rule.approval_timeout_secs as u64,
                fallback: aa_core::PolicyResult::Deny {
                    reason: "approval timed out".to_string(),
                },
                team_id: None,
                timeout_override_secs: None,
                escalation_role_override: None,
            };
            let (rid, fut) = approval_queue.submit(approval_req);

            send_ipc_response(
                connection_id,
                IpcResponse::PolicyResponse(CheckActionResponse {
                    decision: Decision::Pending as i32,
                    approval_id: rid.to_string(),
                    policy_rule: rule.name.clone(),
                    ..Default::default()
                }),
                response_router,
            )
            .await;

            // Spawn a task that awaits resolution and pushes the decision back.
            let router = Arc::clone(response_router);
            tokio::spawn(async move {
                if let Ok(decision) = fut.await {
                    let (approved, decided_by, reason) = match decision {
                        RuntimeApprovalDecision::Approved { by, reason } => (true, by, reason.unwrap_or_default()),
                        RuntimeApprovalDecision::Rejected { by, reason } => (false, by, reason),
                        RuntimeApprovalDecision::TimedOut { .. } => {
                            (false, "timeout".to_string(), "approval timed out".to_string())
                        }
                    };
                    let decided_at_unix_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or(Duration::ZERO)
                        .as_millis() as i64;
                    let proto = ProtoApprovalDecision {
                        approval_id: rid.to_string(),
                        approved,
                        decided_by,
                        reason,
                        decided_at_unix_ms,
                    };
                    send_ipc_response(connection_id, IpcResponse::ApprovalDecision(proto), &router).await;
                }
            });
            return;
        }
    }

    // 2. Check blocked_actions.
    for rule in &policy.rules {
        if rule.blocked_actions.iter().any(|ba| ba == action_str) {
            send_ipc_response(
                connection_id,
                IpcResponse::PolicyResponse(CheckActionResponse {
                    decision: Decision::Deny as i32,
                    reason: format!("blocked by rule: {}", rule.name),
                    policy_rule: rule.name.clone(),
                    ..Default::default()
                }),
                response_router,
            )
            .await;
            return;
        }
    }

    // 3. Default: allow.
    send_ipc_response(
        connection_id,
        IpcResponse::PolicyResponse(CheckActionResponse {
            decision: Decision::Allow as i32,
            ..Default::default()
        }),
        response_router,
    )
    .await;
}

/// Broadcast all events in `batch` and record metrics.
///
/// Clears `batch` after broadcasting. Errors from `broadcast_tx.send`
/// (all receivers dropped) are silently ignored — the pipeline does not
/// require any active subscribers to operate.
fn flush(batch: &mut Vec<EnrichedEvent>, broadcast_tx: &broadcast::Sender<PipelineEvent>, metrics: &PipelineMetrics) {
    let n = batch.len() as u64;
    for event in batch.drain(..) {
        let _ = broadcast_tx.send(PipelineEvent::Audit(Box::new(event)));
    }
    ::metrics::counter!("aa_events_emitted_total").increment(n);
    metrics.record_batch_size(n);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::PolicyRules;
    use aa_proto::assembly::audit::v1::{audit_event::Detail, AuditEvent, PolicyViolation};

    /// Unwrap a `PipelineEvent::Audit` variant, panicking if it is a different variant.
    fn unwrap_audit(event: PipelineEvent) -> EnrichedEvent {
        match event {
            PipelineEvent::Audit(e) => *e,
            other => panic!("expected PipelineEvent::Audit, got {other:?}"),
        }
    }

    fn make_audit_event() -> AuditEvent {
        AuditEvent::default()
    }

    fn make_policy_violation_event() -> AuditEvent {
        AuditEvent {
            detail: Some(Detail::Violation(PolicyViolation {
                policy_rule: "test-rule".to_string(),
                blocked_action: "test-action".to_string(),
                reason: "test-reason".to_string(),
                latency_ms: 0,
            })),
            ..Default::default()
        }
    }

    #[test]
    fn enrich_sets_agent_id() {
        let event = make_audit_event();
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "my-agent", 0, &seq);
        assert_eq!(enriched.agent_id, "my-agent");
    }

    #[test]
    fn enrich_sets_received_at_ms_positive() {
        let event = make_audit_event();
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert!(enriched.received_at_ms > 0);
    }

    #[test]
    fn enrich_sets_source_to_sdk() {
        let event = make_audit_event();
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert_eq!(enriched.source, EventSource::Sdk);
    }

    #[test]
    fn is_policy_violation_true_for_violation_detail() {
        let event = make_policy_violation_event();
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert!(is_policy_violation(&enriched, &PolicyRules::default()));
    }

    #[test]
    fn is_policy_violation_false_for_normal_event() {
        let event = make_audit_event(); // detail = None
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert!(!is_policy_violation(&enriched, &PolicyRules::default()));
    }

    #[test]
    fn flush_empty_batch_does_nothing() {
        let (tx, _rx) = broadcast::channel::<PipelineEvent>(16);
        let metrics = PipelineMetrics::default();
        let mut batch: Vec<EnrichedEvent> = vec![];
        flush(&mut batch, &tx, &metrics);
        assert_eq!(metrics.last_batch_size(), 0);
        assert_eq!(metrics.processed(), 0);
    }

    #[test]
    fn flush_broadcasts_all_events_and_records_batch_size() {
        let (tx, mut rx) = broadcast::channel::<PipelineEvent>(16);
        let metrics = PipelineMetrics::default();
        let seq = AtomicU64::new(0);
        let mut batch = vec![
            enrich(make_audit_event(), "a", 0, &seq),
            enrich(make_audit_event(), "b", 0, &seq),
        ];
        flush(&mut batch, &tx, &metrics);
        assert!(batch.is_empty());
        assert_eq!(metrics.last_batch_size(), 2);
        // Both events were sent and are receivable.
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
    }

    #[test]
    fn from_runtime_config_copies_all_fields() {
        let runtime_config = RuntimeConfig {
            agent_id: "test-agent".to_string(),
            worker_threads: 0,
            shutdown_timeout_secs: 30,
            ipc_max_connections: 64,
            pipeline_input_buffer: 5_000,
            pipeline_batch_size: 50,
            pipeline_flush_interval_ms: 200,
            pipeline_broadcast_capacity: 512,
            metrics_addr: "0.0.0.0:8080".to_string(),
            policy_path: None,
            gateway_endpoint: None,
            correlation_window_ms: 5_000,
            correlation_interval_ms: 1_000,
        };

        let pipeline_config = PipelineConfig::from_runtime_config(&runtime_config);

        assert_eq!(pipeline_config.input_buffer, runtime_config.pipeline_input_buffer);
        assert_eq!(pipeline_config.batch_size, runtime_config.pipeline_batch_size);
        assert_eq!(
            pipeline_config.flush_interval,
            Duration::from_millis(runtime_config.pipeline_flush_interval_ms)
        );
        assert_eq!(
            pipeline_config.broadcast_capacity,
            runtime_config.pipeline_broadcast_capacity
        );
        assert_eq!(pipeline_config.agent_id, runtime_config.agent_id);
    }

    #[test]
    fn pipeline_config_is_clone() {
        let pipeline_config = PipelineConfig {
            input_buffer: 5_000,
            batch_size: 50,
            flush_interval: Duration::from_millis(200),
            broadcast_capacity: 512,
            agent_id: "test-agent".to_string(),
        };

        let cloned = pipeline_config.clone();

        assert_eq!(cloned.agent_id, pipeline_config.agent_id);
    }

    // -----------------------------------------------------------------------
    // Integration test helpers
    // -----------------------------------------------------------------------

    fn test_config(batch_size: usize, flush_interval_ms: u64) -> PipelineConfig {
        PipelineConfig {
            input_buffer: 1_024,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            broadcast_capacity: 1_024,
            agent_id: "test-agent".to_string(),
        }
    }

    fn normal_event() -> AuditEvent {
        AuditEvent::default()
    }

    fn violation_event() -> AuditEvent {
        AuditEvent {
            detail: Some(Detail::Violation(PolicyViolation {
                policy_rule: "rule".to_string(),
                blocked_action: "action".to_string(),
                reason: "reason".to_string(),
                latency_ms: 0,
            })),
            ..Default::default()
        }
    }

    // -----------------------------------------------------------------------
    // Integration tests — spin up a real run() task
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn batch_flushes_on_size_threshold() {
        let config = test_config(3, 10_000); // batch_size=3, very long interval (won't fire)
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send 3 events — batch threshold reached, should flush before interval
        for _ in 0..3 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }

        // All 3 events should arrive within a short time
        for _ in 0..3 {
            tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
                .await
                .expect("timed out waiting for event")
                .expect("broadcast error");
        }
        assert_eq!(metrics.processed(), 3);
        token.cancel();
    }

    #[tokio::test]
    async fn batch_flushes_on_interval() {
        let config = test_config(100, 50); // batch_size=100 (won't reach), interval=50ms
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send 5 events (less than batch_size=100) — should arrive after interval flush
        for _ in 0..5 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }

        for _ in 0..5 {
            tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
                .await
                .expect("timed out waiting for event from interval flush")
                .expect("broadcast error");
        }
        assert_eq!(metrics.processed(), 5);
        token.cancel();
    }

    #[tokio::test]
    async fn policy_violation_bypasses_batch() {
        // batch_size=100, very long interval — only a violation should arrive
        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send a violation — should arrive immediately, bypassing batch
        tx.send((0, IpcFrame::EventReport(violation_event()))).await.unwrap();

        let event = unwrap_audit(
            tokio::time::timeout(Duration::from_millis(200), broadcast_rx.recv())
                .await
                .expect("violation event should arrive immediately, before any flush interval")
                .expect("broadcast error"),
        );

        assert!(matches!(event.inner.detail, Some(Detail::Violation(_))));
        assert_eq!(metrics.processed(), 1);
        token.cancel();
    }

    #[tokio::test]
    async fn cancellation_flushes_pending_batch() {
        let config = test_config(100, 10_000); // large batch, long interval
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        let handle = tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send 5 events (batch won't flush yet)
        for _ in 0..5 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }

        // Wait until the run loop has processed all 5 events before cancelling,
        // so they are guaranteed to be in the pending batch when the flush fires.
        let deadline = std::time::Instant::now() + Duration::from_millis(200);
        loop {
            if metrics.processed() == 5 {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "events were not processed within 200ms"
            );
            tokio::task::yield_now().await;
        }
        token.cancel();

        // Wait for pipeline to stop
        tokio::time::timeout(Duration::from_millis(500), handle)
            .await
            .expect("pipeline did not stop after cancellation")
            .expect("pipeline task panicked");

        // All 5 events should be in the broadcast channel
        let mut received = 0;
        while broadcast_rx.try_recv().is_ok() {
            received += 1;
        }
        assert_eq!(received, 5, "expected 5 events flushed on cancellation");
    }

    #[tokio::test]
    async fn non_event_frames_ignored() {
        let config = test_config(100, 50);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send non-event frames
        tx.send((0, IpcFrame::Heartbeat)).await.unwrap();

        // Give run loop a moment to process
        tokio::time::sleep(Duration::from_millis(20)).await;

        // No events processed
        assert_eq!(metrics.processed(), 0);
        token.cancel();
    }

    #[tokio::test]
    async fn rule_match_bypasses_batch() {
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::ActionType;

        // Create a policy that blocks FILE_OPERATION
        let policy = std::sync::Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "block-files".to_string(),
                blocked_actions: vec![ActionType::FileOperation.as_str_name().to_string()],
                ..Default::default()
            }],
        });

        // batch_size=100, very long interval — only a rule-matched event should arrive immediately
        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            policy,
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Build an AuditEvent with action_type = FILE_OPERATION
        let event = AuditEvent {
            action_type: ActionType::FileOperation as i32,
            ..Default::default()
        };
        tx.send((0, IpcFrame::EventReport(event))).await.unwrap();

        // Should arrive immediately (before flush interval)
        let received = unwrap_audit(
            tokio::time::timeout(Duration::from_millis(200), broadcast_rx.recv())
                .await
                .expect("rule-matched event should bypass batch and arrive immediately")
                .expect("broadcast error"),
        );

        assert_eq!(received.source, EventSource::Sdk);
        assert_eq!(metrics.processed(), 1);
        token.cancel();
    }

    #[tokio::test]
    async fn non_matching_action_stays_in_batch() {
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::ActionType;

        // Policy only blocks FILE_OPERATION
        let policy = std::sync::Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "block-files".to_string(),
                blocked_actions: vec![ActionType::FileOperation.as_str_name().to_string()],
                ..Default::default()
            }],
        });

        // batch_size=100, very long interval — event should NOT arrive before timeout
        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            policy,
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Yield briefly so the pipeline's interval fires its immediate first tick
        // (tokio::time::interval ticks once immediately on creation).
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Build a TOOL_CALL event — not blocked by the policy
        let event = AuditEvent {
            action_type: ActionType::ToolCall as i32,
            ..Default::default()
        };
        tx.send((0, IpcFrame::EventReport(event))).await.unwrap();

        // Should NOT arrive before the flush interval (100ms timeout)
        let result = tokio::time::timeout(Duration::from_millis(100), broadcast_rx.recv()).await;
        assert!(
            result.is_err(),
            "non-matching event should stay in batch, not arrive immediately"
        );

        token.cancel();
    }

    #[tokio::test]
    async fn sequence_numbers_are_consecutive_within_a_batch() {
        // batch_size=3 so we get a single flush of 3 events and can check ordering.
        let config = test_config(3, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        for _ in 0..3 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }

        let mut seq_numbers = Vec::new();
        for _ in 0..3 {
            let event = unwrap_audit(
                tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
                    .await
                    .expect("timed out waiting for event")
                    .expect("broadcast error"),
            );
            seq_numbers.push(event.sequence_number);
        }

        // Sequence numbers must be strictly monotonically increasing, starting at 0.
        assert_eq!(
            seq_numbers,
            vec![0, 1, 2],
            "expected consecutive sequence numbers 0, 1, 2"
        );
        token.cancel();
    }

    #[tokio::test]
    async fn sequence_numbers_are_monotonic_across_batches() {
        // Two separate batch flushes — sequence counter must not reset between them.
        let config = test_config(2, 10_000); // batch_size=2
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // First batch of 2
        for _ in 0..2 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }
        let first_batch: Vec<u64> = {
            let mut v = Vec::new();
            for _ in 0..2 {
                let e = unwrap_audit(
                    tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
                        .await
                        .expect("timed out waiting for first batch")
                        .expect("broadcast error"),
                );
                v.push(e.sequence_number);
            }
            v
        };

        // Second batch of 2
        for _ in 0..2 {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }
        let second_batch: Vec<u64> = {
            let mut v = Vec::new();
            for _ in 0..2 {
                let e = unwrap_audit(
                    tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
                        .await
                        .expect("timed out waiting for second batch")
                        .expect("broadcast error"),
                );
                v.push(e.sequence_number);
            }
            v
        };

        assert_eq!(first_batch, vec![0, 1]);
        assert_eq!(
            second_batch,
            vec![2, 3],
            "sequence counter must not reset between batches"
        );
        token.cancel();
    }

    #[tokio::test]
    #[ignore]
    async fn pipeline_load_benchmark() {
        // Run with: cargo test -p aa-runtime -- --ignored pipeline_load_benchmark --nocapture
        const EVENT_COUNT: u64 = 100_000;

        let config = test_config(100, 10);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(10_000);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(10_000);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(PolicyRules::default()),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Spawn a receiver that drains the broadcast channel
        tokio::spawn(async move { while broadcast_rx.recv().await.is_ok() {} });

        let start = std::time::Instant::now();

        for _ in 0..EVENT_COUNT {
            tx.send((0, IpcFrame::EventReport(normal_event()))).await.unwrap();
        }

        // Wait until all events are processed
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        loop {
            if metrics.processed() >= EVENT_COUNT {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!(
                    "load benchmark timeout: only {} / {} events processed",
                    metrics.processed(),
                    EVENT_COUNT
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let elapsed = start.elapsed();
        println!(
            "pipeline_load_benchmark: {} events in {:?} ({:.0} events/sec)",
            EVENT_COUNT,
            elapsed,
            EVENT_COUNT as f64 / elapsed.as_secs_f64()
        );

        assert!(elapsed.as_secs() < 5, "100k events took more than 5s: {:?}", elapsed);
        token.cancel();
    }

    // -----------------------------------------------------------------------
    // PolicyQuery handling tests
    // -----------------------------------------------------------------------

    /// Helper: build a router with a live receiver for `connection_id = 0`.
    fn make_router_with_receiver() -> (ResponseRouter, tokio::sync::mpsc::Receiver<IpcResponse>) {
        let router = crate::ipc::new_response_router();
        let (tx, rx) = tokio::sync::mpsc::channel::<IpcResponse>(16);
        router.try_write().unwrap().insert(0, tx);
        (router, rx)
    }

    fn policy_query_frame(action_type: aa_proto::assembly::common::v1::ActionType) -> IpcFrame {
        IpcFrame::PolicyQuery(aa_proto::assembly::policy::v1::CheckActionRequest {
            action_type: action_type as i32,
            ..Default::default()
        })
    }

    #[tokio::test]
    async fn policy_query_no_rules_responds_allow() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            Arc::new(PolicyRules::default()),
            router,
            approval_queue,
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Allow as i32);
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    #[tokio::test]
    async fn policy_query_blocked_action_responds_deny() {
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let policy = Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "block-tool".to_string(),
                blocked_actions: vec![ActionType::ToolCall.as_str_name().to_string()],
                ..Default::default()
            }],
        });

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            policy,
            router,
            approval_queue,
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Deny as i32);
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    #[tokio::test]
    async fn policy_query_requires_approval_responds_pending_and_adds_to_queue() {
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let policy = Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "approve-tool".to_string(),
                requires_approval_actions: vec![ActionType::ToolCall.as_str_name().to_string()],
                approval_timeout_secs: 60,
                ..Default::default()
            }],
        });

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let queue_ref = Arc::clone(&approval_queue);

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            policy,
            router,
            approval_queue,
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Pending as i32);
            assert!(!r.approval_id.is_empty(), "approval_id should be set");
        } else {
            panic!("expected PolicyResponse(PENDING), got {resp:?}");
        }

        // One pending entry should now be in the queue.
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert_eq!(queue_ref.list().len(), 1);

        token.cancel();
    }

    #[tokio::test]
    async fn policy_query_pending_resolution_pushes_approval_decision() {
        use crate::approval::ApprovalDecision as RuntimeApprovalDecision;
        use crate::policy::{PolicyRule, PolicyRules};
        use aa_proto::assembly::common::v1::ActionType;

        let policy = Arc::new(PolicyRules {
            rules: vec![PolicyRule {
                name: "approve-tool".to_string(),
                requires_approval_actions: vec![ActionType::ToolCall.as_str_name().to_string()],
                approval_timeout_secs: 60,
                ..Default::default()
            }],
        });

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let queue_ref = Arc::clone(&approval_queue);

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            policy,
            router,
            approval_queue,
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        // Send the query — get back PENDING with approval_id.
        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();
        let pending_resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");
        let approval_id = if let IpcResponse::PolicyResponse(r) = pending_resp {
            uuid::Uuid::parse_str(&r.approval_id).expect("invalid UUID in approval_id")
        } else {
            panic!("expected PolicyResponse(PENDING), got {pending_resp:?}");
        };

        // Approve it via the queue.
        queue_ref
            .decide(
                approval_id,
                RuntimeApprovalDecision::Approved {
                    by: "test-operator".to_string(),
                    reason: Some("looks safe".to_string()),
                },
            )
            .expect("decide should succeed");

        // The spawned resolution task should push an ApprovalDecision response.
        let decision_resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("ApprovalDecision push timed out")
            .expect("channel closed");

        if let IpcResponse::ApprovalDecision(proto) = decision_resp {
            assert!(proto.approved);
            assert_eq!(proto.decided_by, "test-operator");
            assert_eq!(proto.approval_id, approval_id.to_string());
        } else {
            panic!("expected IpcResponse::ApprovalDecision, got {decision_resp:?}");
        }

        token.cancel();
    }
}
