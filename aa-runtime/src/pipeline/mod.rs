//! Event aggregation pipeline — receives IpcFrames, enriches, batches, and fans out.

pub mod enforcement;
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
    /// Runtime scan/redact enforcement config — derived from `RuntimeConfig`.
    pub enforcement: enforcement::EnforcementConfig,
    /// Deny a policy check when the gateway is configured but unreachable,
    /// instead of falling back to permissive local evaluation (AAASM-3110).
    /// Copied from [`RuntimeConfig::gateway_fail_closed`]; defaults to `true`.
    pub gateway_fail_closed: bool,
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
            enforcement: enforcement::EnforcementConfig::from_runtime_config(c),
            gateway_fail_closed: c.gateway_fail_closed,
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

    // GATE (AAASM-2568): one precompiled scanner, constructed once and reused
    // for every event. The runtime is the authoritative scan/redact point.
    // The size-cap / oversized policy are operator-tunable via RuntimeConfig
    // (AAASM-2619); the fail-closed default is preserved when unset.
    let scanner = enforcement::RuntimeScanner::with_config(config.enforcement.clone());

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
                        let mut enriched = enrich(event, &config.agent_id, connection_id, &seq);
                        // GATE: scan + redact + normalize before any forward or
                        // audit, on every path. Unconditional — no SDK signal can
                        // skip this.
                        scanner.enforce(&mut enriched);
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
                            config.gateway_fail_closed,
                            &broadcast_tx,
                            &seq,
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
/// gateway over gRPC. The gateway is the authoritative decision point.
///
/// **Fail-closed (AAASM-3110):** when the gateway is configured but the call
/// fails (unreachable / timeout / transport error) and `fail_closed` is set,
/// the check is **denied** rather than silently falling back to permissive
/// local evaluation. Allow-on-fallback is only used when the gateway is not
/// configured at all, or when `fail_closed` is `false` (observe / disabled
/// posture).
///
/// Local decision priority (first match wins):
/// 1. `requires_approval_actions` → `PENDING` + submit to [`ApprovalQueue`]; spawn a task to
///    push an [`IpcResponse::ApprovalDecision`] back once the request is resolved.
/// 2. `blocked_actions` → `DENY`.
/// 3. No match → `ALLOW`.
#[allow(clippy::too_many_arguments)]
async fn handle_policy_query(
    connection_id: u64,
    req: aa_proto::assembly::policy::v1::CheckActionRequest,
    policy: &PolicyRules,
    approval_queue: &Arc<ApprovalQueue>,
    response_router: &ResponseRouter,
    gateway_client: &Option<Arc<Mutex<GatewayClient>>>,
    fail_closed: bool,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    sequence_counter: &AtomicU64,
) {
    // ── Gateway forwarding path ─────────────────────────────────────────
    match try_gateway_forward(
        connection_id,
        &req,
        gateway_client,
        response_router,
        broadcast_tx,
        sequence_counter,
    )
    .await
    {
        // Gateway answered (allow/deny/approval) — response already sent.
        GatewayOutcome::Handled => return,
        // Gateway configured but unreachable: fail closed in enforce posture
        // instead of leaking through to a permissive local default (AAASM-3110).
        GatewayOutcome::Failed if fail_closed => {
            tracing::warn!(
                connection_id,
                "gateway unreachable and fail-closed enabled — denying action"
            );
            send_ipc_response(
                connection_id,
                IpcResponse::PolicyResponse(CheckActionResponse {
                    decision: Decision::Deny as i32,
                    reason: "gateway unreachable; denied by fail-closed policy".to_string(),
                    ..Default::default()
                }),
                response_router,
            )
            .await;
            return;
        }
        // No gateway configured, or observe/disabled posture — fall through to
        // local evaluation.
        GatewayOutcome::NoClient | GatewayOutcome::Failed => {}
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
    if try_local_approval(
        connection_id,
        action_str,
        &agent_id_str,
        policy,
        approval_queue,
        response_router,
    )
    .await
    {
        return;
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

/// Outcome of attempting to forward a policy check to the gateway.
///
/// The caller ([`handle_policy_query`]) distinguishes these so it can fail
/// **closed** when a configured gateway is unreachable, rather than treating
/// every non-`Handled` outcome as "fall back and allow" (AAASM-3110).
enum GatewayOutcome {
    /// The gateway answered and a response was already sent to the SDK.
    Handled,
    /// No gateway client is configured — pure local-evaluation mode.
    NoClient,
    /// A gateway client is configured but the RPC failed (unreachable, timeout,
    /// transport error). The caller decides allow-fallback vs fail-closed deny.
    Failed,
}

/// Forward the request to the governance gateway over gRPC when a client is
/// configured. See [`GatewayOutcome`] for how the caller interprets the result.
async fn try_gateway_forward(
    connection_id: u64,
    req: &aa_proto::assembly::policy::v1::CheckActionRequest,
    gateway_client: &Option<Arc<Mutex<GatewayClient>>>,
    response_router: &ResponseRouter,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    sequence_counter: &AtomicU64,
) -> GatewayOutcome {
    let Some(client) = gateway_client else {
        return GatewayOutcome::NoClient;
    };
    let mut guard = client.lock().await;
    match guard.check_action(req.clone()).await {
        Ok(resp) => {
            tracing::debug!(connection_id, decision = resp.decision, "gateway responded");
            // On Deny: surface a structured PolicyViolation event into
            // the broadcast pipeline so the Live Ops dashboard sees the
            // policy-engine evaluation latency. AAASM-1421 added the
            // proto field; this is where it gets populated.
            if resp.decision == aa_proto::assembly::common::v1::Decision::Deny as i32 {
                emit_gateway_violation(req, &resp, connection_id, broadcast_tx, sequence_counter);
            }
            send_ipc_response(connection_id, IpcResponse::PolicyResponse(resp), response_router).await;
            GatewayOutcome::Handled
        }
        Err(e) => {
            tracing::warn!(
                connection_id,
                error = %e,
                "gateway call failed"
            );
            GatewayOutcome::Failed
        }
    }
}

/// Apply the local `requires_approval_actions` rules. When a rule matches,
/// submits an [`ApprovalRequest`], responds `PENDING`, spawns a task that
/// pushes the eventual decision back, and returns `true`. Returns `false`
/// when no rule requires approval for `action_str`.
async fn try_local_approval(
    connection_id: u64,
    action_str: &str,
    agent_id_str: &str,
    policy: &PolicyRules,
    approval_queue: &Arc<ApprovalQueue>,
    response_router: &ResponseRouter,
) -> bool {
    for rule in &policy.rules {
        if !rule.requires_approval_actions.iter().any(|a| a == action_str) {
            continue;
        }
        let request_id = Uuid::new_v4();
        let submitted_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::ZERO)
            .as_secs();
        let approval_req = ApprovalRequest {
            request_id,
            agent_id: agent_id_str.to_string(),
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
        return true;
    }
    false
}

/// Emit a structured `PolicyViolation` `AuditEvent` after the gateway
/// returns `Decision::Deny`. The event carries the gateway's evaluation
/// latency (`decision_latency_us` → ms) so the Live Ops dashboard can
/// display real timing for policy-blocked operations.
fn emit_gateway_violation(
    req: &aa_proto::assembly::policy::v1::CheckActionRequest,
    resp: &aa_proto::assembly::policy::v1::CheckActionResponse,
    connection_id: u64,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    sequence_counter: &AtomicU64,
) {
    use aa_proto::assembly::audit::v1::{audit_event::Detail, AuditEvent, PolicyViolation};
    use aa_proto::assembly::common::v1::ActionType;

    let action_name = ActionType::try_from(req.action_type)
        .map(|a| a.as_str_name())
        .unwrap_or("ACTION_UNSPECIFIED")
        .to_string();
    let agent_id_str = req
        .agent_id
        .as_ref()
        .map(|a| a.agent_id.as_str())
        .unwrap_or("")
        .to_string();

    let event = AuditEvent {
        action_type: req.action_type,
        decision: resp.decision,
        trace_id: req.trace_id.clone(),
        span_id: req.span_id.clone(),
        detail: Some(Detail::Violation(PolicyViolation {
            policy_rule: resp.policy_rule.clone(),
            blocked_action: action_name,
            reason: resp.reason.clone(),
            // The gateway reports decision latency in microseconds; the
            // proto schema (AAASM-1421) carries milliseconds. Integer
            // division truncates — sub-millisecond decisions report as 0,
            // which is the correct floor.
            latency_ms: resp.decision_latency_us / 1_000,
        })),
        ..AuditEvent::default()
    };

    let enriched = enrich(event, &agent_id_str, connection_id, sequence_counter);
    if broadcast_tx.send(PipelineEvent::Audit(Box::new(enriched))).is_err() {
        // All subscribers dropped — same silent-drop behaviour as flush().
        tracing::trace!("dropped synthetic violation event; no subscribers");
    }
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
    fn emit_gateway_violation_on_deny_pushes_structured_audit_event() {
        use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
        use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse};

        let (tx, mut rx) = broadcast::channel::<PipelineEvent>(4);
        let seq = AtomicU64::new(0);
        let req = CheckActionRequest {
            agent_id: Some(ProtoAgentId {
                agent_id: "support-agent".into(),
                ..Default::default()
            }),
            credential_token: String::new(),
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            action_type: ActionType::FileOperation as i32,
            context: Default::default(),
            caller_agent_id: None,
        };
        let resp = CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: "blocked by policy".into(),
            policy_rule: "no-secrets".into(),
            approval_id: String::new(),
            redact: None,
            // Gateway reports microseconds; expect 12000us → 12ms after the /1000 conversion.
            decision_latency_us: 12_000,
        };

        emit_gateway_violation(&req, &resp, 99, &tx, &seq);

        let event = rx.try_recv().expect("expected one event on the channel");
        let enriched = unwrap_audit(event);
        assert_eq!(enriched.agent_id, "support-agent");
        assert_eq!(enriched.connection_id, 99);

        match enriched.inner.detail {
            Some(Detail::Violation(v)) => {
                assert_eq!(v.policy_rule, "no-secrets");
                assert_eq!(v.blocked_action, "FILE_OPERATION");
                assert_eq!(v.reason, "blocked by policy");
                assert_eq!(v.latency_ms, 12);
            }
            other => panic!("expected Violation detail, got {other:?}"),
        }
    }

    #[test]
    fn emit_gateway_violation_sub_millisecond_decision_floors_to_zero() {
        use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
        use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse};

        let (tx, mut rx) = broadcast::channel::<PipelineEvent>(4);
        let seq = AtomicU64::new(0);
        let req = CheckActionRequest {
            agent_id: Some(ProtoAgentId {
                agent_id: "fast-agent".into(),
                ..Default::default()
            }),
            credential_token: String::new(),
            trace_id: String::new(),
            span_id: String::new(),
            action_type: ActionType::ToolCall as i32,
            context: Default::default(),
            caller_agent_id: None,
        };
        let resp = CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: "fast-block".into(),
            policy_rule: "rule".into(),
            approval_id: String::new(),
            redact: None,
            // 0.5 ms == 500 us — integer division truncates to 0 ms.
            decision_latency_us: 500,
        };

        emit_gateway_violation(&req, &resp, 1, &tx, &seq);

        let event = rx.try_recv().expect("expected one event on the channel");
        match unwrap_audit(event).inner.detail {
            Some(Detail::Violation(v)) => assert_eq!(v.latency_ms, 0),
            other => panic!("expected Violation detail, got {other:?}"),
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
            nats_config_path: None,
            audit_buffer_path: std::path::PathBuf::from("/tmp/aa-audit-buffer-test.db"),
            enforcement_max_field_bytes: enforcement::DEFAULT_MAX_FIELD_BYTES,
            gateway_fail_closed: true,
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
            enforcement: enforcement::EnforcementConfig::default(),
            gateway_fail_closed: true,
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
            enforcement: enforcement::EnforcementConfig::default(),
            gateway_fail_closed: true,
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

    #[tokio::test(start_paused = true)]
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

        // `tokio::time::interval` fires an immediate first tick on creation. With the
        // clock paused, let the run loop start and absorb that empty flush before we
        // send the event, so the first tick cannot race ahead and flush our event.
        tokio::task::yield_now().await;

        // Build a TOOL_CALL event — not blocked by the policy
        let event = AuditEvent {
            action_type: ActionType::ToolCall as i32,
            ..Default::default()
        };
        tx.send((0, IpcFrame::EventReport(event))).await.unwrap();

        // Wait until the run loop has enqueued the event into the batch.
        while metrics.processed() == 0 {
            tokio::task::yield_now().await;
        }

        // Advancing virtual time by less than the flush interval must NOT flush the
        // batch — the non-matching event has to stay batched.
        tokio::time::advance(Duration::from_millis(100)).await;
        assert!(
            broadcast_rx.try_recv().is_err(),
            "non-matching event should stay in batch, not arrive before flush interval"
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

    /// AAASM-3110: when a gateway is configured but unreachable and the runtime
    /// is in the fail-closed (enforce) posture, a policy check must be DENIED —
    /// never silently allowed by the permissive local default.
    #[tokio::test]
    async fn gateway_unreachable_fail_closed_responds_deny() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000); // gateway_fail_closed = true
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();

        // Lazy client to a port that never listens → check_action fails.
        let gateway = Arc::new(Mutex::new(crate::gateway_client::GatewayClient::connect_lazy(
            "http://127.0.0.1:1",
        )));

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            Arc::new(PolicyRules::default()),
            router,
            approval_queue,
            Some(gateway),
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Deny as i32,
                "gateway unreachable in fail-closed posture must deny"
            );
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3110: in the observe/disabled posture (`gateway_fail_closed = false`)
    /// a gateway-unreachable check falls back to permissive local evaluation,
    /// which allows when no local rule matches.
    #[tokio::test]
    async fn gateway_unreachable_fail_open_falls_back_to_local_allow() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let mut config = test_config(100, 10_000);
        config.gateway_fail_closed = false;
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();

        let gateway = Arc::new(Mutex::new(crate::gateway_client::GatewayClient::connect_lazy(
            "http://127.0.0.1:1",
        )));

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            Arc::new(PolicyRules::default()),
            router,
            approval_queue,
            Some(gateway),
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Allow as i32,
                "fail-open posture should fall back to local allow"
            );
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

    // -----------------------------------------------------------------------
    // GATE: runtime enforcement runs before forward/audit on every path
    // (AAASM-2568)
    // -----------------------------------------------------------------------

    /// An AWS access-key id the credential scanner detects via the `AKIA` literal.
    const GATE_SECRET: &str = "AKIAIOSFODNN7EXAMPLE";

    /// A ToolCall `AuditEvent` whose `args_json` embeds [`GATE_SECRET`].
    fn tool_call_with_secret() -> AuditEvent {
        use aa_proto::assembly::audit::v1::ToolCallDetail;
        AuditEvent {
            action_type: ActionType::ToolCall as i32,
            detail: Some(Detail::ToolCall(ToolCallDetail {
                args_json: format!(r#"{{"api_key": "{GATE_SECRET}"}}"#).into_bytes(),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Assert an audited pipeline event's `args_json` was redacted, not raw.
    fn assert_args_redacted(event: PipelineEvent) {
        let enriched = unwrap_audit(event);
        let Some(Detail::ToolCall(tc)) = enriched.inner.detail else {
            panic!("expected ToolCall detail");
        };
        let body = String::from_utf8(tc.args_json).expect("redacted text is utf-8");
        assert!(!body.contains(GATE_SECRET), "raw secret must not leave the runtime");
        assert!(body.contains("[REDACTED:"), "redaction marker present");
    }

    #[tokio::test]
    async fn secret_is_redacted_on_batch_path() {
        let config = test_config(1, 10_000); // flush at size 1; interval won't fire
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

        tx.send((0, IpcFrame::EventReport(tool_call_with_secret())))
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
            .await
            .expect("timed out waiting for batched event")
            .expect("broadcast error");
        assert_args_redacted(event);
        token.cancel();
    }

    #[tokio::test]
    async fn secret_is_redacted_on_violation_path() {
        use crate::policy::{PolicyRule, PolicyRules};

        // batch_size=100, long interval — only the violation should arrive,
        // exercising the immediate-broadcast path.
        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();

        // A rule blocking TOOL_CALL actions routes the secret-bearing event
        // onto the violation broadcast path instead of the batch.
        let policy = PolicyRules {
            rules: vec![PolicyRule {
                name: "block-tools".to_string(),
                blocked_actions: vec!["TOOL_CALL".to_string()],
                ..Default::default()
            }],
        };

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics.clone(),
            token.clone(),
            Arc::new(policy),
            crate::ipc::new_response_router(),
            crate::approval::ApprovalQueue::new(),
            None,
            Arc::new(AtomicU64::new(0)),
        ));

        tx.send((0, IpcFrame::EventReport(tool_call_with_secret())))
            .await
            .unwrap();

        let event = tokio::time::timeout(Duration::from_millis(500), broadcast_rx.recv())
            .await
            .expect("timed out waiting for violation event")
            .expect("broadcast error");
        assert_args_redacted(event);
        token.cancel();
    }
}
