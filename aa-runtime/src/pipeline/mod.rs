//! Event aggregation pipeline — receives IpcFrames, enriches, batches, and fans out.

pub mod enforcement;
pub mod event;
pub mod metrics;

pub use event::{EnrichedEvent, EventSource, LayerDegradationInfo, PipelineEvent};
pub use metrics::PipelineMetrics;

use crate::approval::{ApprovalDecision as RuntimeApprovalDecision, ApprovalQueue, ApprovalRequest};
use crate::config::RuntimeConfig;
use crate::gateway_client::GatewayClient;
use crate::ipc::{IpcFrame, IpcResponse, ResponseRouter, VerifiedIdentityStore};
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
    /// Per-RPC deadline for each gateway policy query. Bounds how long a hung
    /// gateway can block the runtime's policy checks before the query is treated
    /// as a failure and routed into the fail-closed path (AAASM-3987). Derived
    /// from [`RuntimeConfig::gateway_timeout_ms`].
    pub gateway_timeout: Duration,
    /// Minimum supported SDK version. When set, an observed SDK version below it
    /// is classified as a downgrade (AAASM-3640). `None` imposes no floor.
    pub min_sdk_version: Option<String>,
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
            gateway_timeout: Duration::from_millis(c.gateway_timeout_ms),
            // No operator-configurable SDK version floor yet; downgrade
            // detection activates once a minimum is wired into RuntimeConfig.
            min_sdk_version: None,
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
    op_control: crate::op_control::OpControlStore,
    seq: Arc<AtomicU64>,
    verified_identities: VerifiedIdentityStore,
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
                        // skip this. The outcome also reports any forged trust
                        // markers stripped (AAASM-3630).
                        let outcome = scanner.enforce(&mut enriched);
                        // AAASM-3640: recompute the SDK-identity verdict against
                        // the handshake-verified identity for this connection
                        // (Unverifiable when the connection never authenticated).
                        let verified = resolve_verified_identity(&verified_identities, connection_id).await;
                        let verdict = aa_security::sdk_identity::classify(
                            &enriched.observed_sdk_identity,
                            &verified,
                            config.min_sdk_version.as_deref(),
                        );
                        // AAASM-3637: a flagged verdict (Missing/Forged/Downgraded)
                        // OR a forged trust marker is a distinct bypass/tamper
                        // signal — emit its own audit record + metric, purely
                        // observational (the enforcement decision below is
                        // unchanged, runtime stays authoritative).
                        emit_tamper_signal(verdict, &outcome, &enriched, &broadcast_tx, &seq);
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
                            &op_control,
                            &config.agent_id,
                            config.gateway_fail_closed,
                            config.gateway_timeout,
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
    let observed_sdk_identity = observe_sdk_identity(&event);
    EnrichedEvent {
        inner: event,
        received_at_ms,
        source: EventSource::Sdk,
        agent_id: agent_id.to_string(),
        connection_id,
        sequence_number,
        observed_sdk_identity,
        // No tamper signal at ingest; set on the dedicated tamper event in run().
        tamper: None,
    }
}

/// Read the SDK identity an agent *claimed* out of the (attacker-controlled)
/// `labels` map (AAASM-3625).
///
/// `present` is set when the reserved [`event::SDK_VERSION_LABEL`] key exists;
/// the label value is carried as the claimed version. This is an untrusted
/// claim transported for server-side recomputation — the label is **not**
/// removed here (that is sanitization's job) and is **never** honoured as a
/// trust grant.
fn observe_sdk_identity(event: &AuditEvent) -> aa_security::sdk_identity::ObservedSdkIdentity {
    match event.labels.get(event::SDK_VERSION_LABEL) {
        Some(version) => aa_security::sdk_identity::ObservedSdkIdentity {
            present: true,
            version: Some(version.clone()),
        },
        None => aa_security::sdk_identity::ObservedSdkIdentity::missing(),
    }
}

/// Resolve the AAASM-3569 handshake-verified SDK identity for `connection_id`
/// (AAASM-3640).
///
/// Returns the identity the authenticated handshake established for the
/// connection, or [`VerifiedSdkIdentity::none`] when the connection has no
/// entry — i.e. it never completed a handshake, or its source has no IPC
/// handshake (eBPF / proxy events use `connection_id` 0). Falling back to
/// `none` keeps the verdict at `Unverifiable` rather than guessing, so there is
/// no regression for non-handshake paths.
async fn resolve_verified_identity(
    store: &VerifiedIdentityStore,
    connection_id: u64,
) -> aa_security::sdk_identity::VerifiedSdkIdentity {
    store
        .read()
        .await
        .get(&connection_id)
        .cloned()
        .unwrap_or_else(aa_security::sdk_identity::VerifiedSdkIdentity::none)
}

/// Emit a distinct "bypass/tamper suspected" audit event + metric (AAASM-3637).
///
/// Fires when the server-recomputed `verdict` is a tamper signal
/// (Missing / Forged / VersionDowngraded) **or** the enforcement stage stripped
/// forged trust markers. The emission is purely observational: it does not alter
/// the allow/deny outcome for `source` (the runtime stays authoritative).
///
/// The record is a dedicated [`EnrichedEvent`] that preserves `source`'s agent
/// identity and lineage (so the audit subject is keyed correctly) but carries no
/// action `detail` — it is a tamper observation, not an intercepted action — and
/// a `tamper` annotation the audit payload serialises into an `sdk_identity`
/// section (AAASM-3637). The metric `aa_runtime_sdk_tamper_suspected_total` is
/// labelled by the verdict kind for alerting.
fn emit_tamper_signal(
    verdict: aa_security::sdk_identity::SdkIdentityVerdict,
    outcome: &enforcement::EnforcementOutcome,
    source: &EnrichedEvent,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    seq: &AtomicU64,
) {
    let forged = outcome.forged_trust_markers;
    if !verdict.is_suspected_tamper() && forged == 0 {
        return;
    }

    ::metrics::counter!("aa_runtime_sdk_tamper_suspected_total", "kind" => verdict.as_str()).increment(1);

    // A tamper observation carries the originating agent's identity/lineage but
    // no action detail — it records the bypass, not the action.
    let mut tamper_inner = AuditEvent {
        event_id: Uuid::new_v4().to_string(),
        agent_id: source.inner.agent_id.clone(),
        ..Default::default()
    };
    tamper_inner.session_id = source.inner.session_id.clone();
    tamper_inner.team_id = source.inner.team_id.clone();

    let tamper_event = EnrichedEvent {
        inner: tamper_inner,
        received_at_ms: source.received_at_ms,
        source: source.source.clone(),
        agent_id: source.agent_id.clone(),
        connection_id: source.connection_id,
        sequence_number: seq.fetch_add(1, Ordering::Relaxed),
        observed_sdk_identity: source.observed_sdk_identity.clone(),
        tamper: Some(event::TamperSignal {
            verdict,
            forged_trust_markers: forged,
        }),
    };

    tracing::warn!(
        verdict = verdict.as_str(),
        forged_trust_markers = forged,
        connection_id = source.connection_id,
        "SDK bypass/tamper suspected"
    );
    let _ = broadcast_tx.send(PipelineEvent::Audit(Box::new(tamper_event)));
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
    op_control: &crate::op_control::OpControlStore,
    agent_id: &str,
    fail_closed: bool,
    gateway_timeout: Duration,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    sequence_counter: &AtomicU64,
) {
    // ── Op-control kill switch (AAASM-3491; hardened AAASM-3873) ─────────
    // Consult the operator-driven op lifecycle BEFORE any policy evaluation:
    // a terminated op must fast-fail and a paused op must block, regardless of
    // what the policy would otherwise decide.
    //
    // AAASM-3873: the kill switch must not be evadable via an agent-supplied
    // trace_id. The op-specific id ("{trace_id}:{span_id}") is built from
    // attacker-controlled request fields, so a non-cooperative SDK could omit or
    // alter trace_id to dodge a terminate/pause. We therefore always consult
    // halts bound to a *server-side* identity — a global kill switch and an
    // agent-scoped halt keyed by the agent identity the runtime itself knows
    // (`agent_id`) — on every request. The op-specific id is an additional,
    // finer-grained match used only when a trace_id is actually supplied; it can
    // never reduce coverage. An empty/absent or forged trace_id therefore no
    // longer bypasses an active agent-level or global halt. (Defeating a halt
    // scoped to a *specific* op by claiming a different op remains inherent to
    // the advisory SDK fast-path — an unlabelled request cannot be attributed to
    // that op — but the operator's agent-wide and global kill switches are now
    // unbypassable.)
    let mut halt_op_ids = vec![
        crate::op_control::GLOBAL_HALT_OP_ID.to_string(),
        crate::op_control::agent_halt_op_id(agent_id),
    ];
    if !req.trace_id.is_empty() {
        halt_op_ids.push(format!("{}:{}", req.trace_id, req.span_id));
    }
    if op_control_halts(connection_id, &halt_op_ids, op_control, response_router).await {
        return;
    }

    // ── Gateway forwarding path ─────────────────────────────────────────
    match try_gateway_forward(
        connection_id,
        &req,
        gateway_client,
        gateway_timeout,
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

/// Enforce the op-control kill switch across all `op_ids` bound to this request
/// before the action proceeds.
///
/// `op_ids` carries the server-side halt keys (global + agent-scoped) plus the
/// optional op-specific key (AAASM-3873). A halt on **any** of them applies —
/// terminate takes priority over pause.
///
/// Returns `true` when the action was **halted** and a response already sent —
/// the caller must stop processing. Returns `false` when every key is runnable
/// (no signal, or a pause that was subsequently resumed).
///
/// - **Terminated:** fast-fail the in-flight action with a `Deny`
///   (`OpTerminatedError`); the kill switch reached the agent.
/// - **Paused:** cooperatively block until the gateway pushes a resume (the op
///   leaves the store) or a terminate. This parks the per-tool check on the
///   store's change notification rather than busy-polling, so a paused agent
///   makes no further progress until the operator resumes it.
async fn op_control_halts(
    connection_id: u64,
    op_ids: &[String],
    op_control: &crate::op_control::OpControlStore,
    response_router: &ResponseRouter,
) -> bool {
    use crate::op_control::OpState;
    loop {
        // Register interest before reading state so a resume/terminate that
        // lands during this iteration cannot be missed (see `changed`).
        let changed = op_control.changed();

        // Scan every bound key. A terminate on any key wins outright; otherwise
        // remember the first paused key so the action blocks until it changes.
        let mut terminated_op: Option<&str> = None;
        let mut paused_op: Option<&str> = None;
        for op_id in op_ids {
            match op_control.state(op_id) {
                Some(OpState::Terminated) => {
                    terminated_op = Some(op_id);
                    break;
                }
                Some(OpState::Paused) if paused_op.is_none() => paused_op = Some(op_id),
                _ => {}
            }
        }

        if let Some(op_id) = terminated_op {
            ::metrics::counter!("aa_op_control_terminations_total").increment(1);
            tracing::warn!(connection_id, op_id, "op terminated by operator — fast-failing action");
            send_ipc_response(
                connection_id,
                IpcResponse::PolicyResponse(CheckActionResponse {
                    decision: Decision::Deny as i32,
                    reason: "OpTerminatedError: operator terminated this op via the live kill switch".to_string(),
                    ..Default::default()
                }),
                response_router,
            )
            .await;
            return true;
        }

        match paused_op {
            Some(op_id) => {
                ::metrics::counter!("aa_op_control_pauses_total").increment(1);
                tracing::info!(
                    connection_id,
                    op_id,
                    "op paused by operator — blocking action until resume"
                );
                // Wait for the next signal, then re-evaluate. A resume removes
                // the entry (loop reads `None` → runnable); a terminate upgrades
                // it (loop fast-fails on the next pass).
                changed.await;
            }
            None => return false,
        }
    }
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
///
/// The RPC is bounded by `gateway_timeout` (AAASM-3987): a gateway that accepts
/// the connection but then stops responding would otherwise hold the shared
/// client lock — and the single pipeline loop — forever, stalling *every*
/// agent's policy checks (a runtime-wide head-of-line DoS). On elapse the query
/// is treated as a failure ([`GatewayOutcome::Failed`]), the same as a transport
/// error, so the caller's fail-closed path applies. Dropping the timed-out
/// future also releases the client lock, so a subsequent stuck query cannot
/// wedge for longer than one deadline.
/// Collapse a gateway decision code that the SDK path does not understand to a
/// fail-closed `Deny` (AAASM-4020).
///
/// The SDK/runtime enforcement path only acts on `Allow`, `Deny`, and
/// `Pending`. Any other code — `Unspecified`, a `Redact` verdict the runtime
/// cannot apply on this path, or an out-of-range value from a newer gateway —
/// is rewritten to `Deny` so an unknown verdict never relays through as an
/// implicit allow. Mirrors `aa-proxy::mcp_enforce::decision_from_response`.
fn normalize_gateway_decision(resp: &mut CheckActionResponse) {
    let recognized = matches!(
        Decision::try_from(resp.decision),
        Ok(Decision::Allow | Decision::Deny | Decision::Pending)
    );
    if !recognized {
        resp.decision = Decision::Deny as i32;
    }
}

async fn try_gateway_forward(
    connection_id: u64,
    req: &aa_proto::assembly::policy::v1::CheckActionRequest,
    gateway_client: &Option<Arc<Mutex<GatewayClient>>>,
    gateway_timeout: Duration,
    response_router: &ResponseRouter,
    broadcast_tx: &broadcast::Sender<PipelineEvent>,
    sequence_counter: &AtomicU64,
) -> GatewayOutcome {
    let Some(client) = gateway_client else {
        return GatewayOutcome::NoClient;
    };
    let mut guard = client.lock().await;
    let call = tokio::time::timeout(gateway_timeout, guard.check_action(req.clone())).await;
    match call {
        Ok(Ok(mut resp)) => {
            // AAASM-4020: normalize the decision before relaying it to the SDK.
            // Only Allow/Deny/Pending are valid verdicts on this path; an
            // Unspecified, out-of-range, or otherwise unrecognized code
            // collapses to a fail-closed Deny rather than being forwarded
            // verbatim (mirrors aa-proxy::mcp_enforce::decision_from_response).
            normalize_gateway_decision(&mut resp);
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
        Ok(Err(e)) => {
            tracing::warn!(
                connection_id,
                error = %e,
                "gateway call failed"
            );
            GatewayOutcome::Failed
        }
        Err(_elapsed) => {
            // The gateway accepted but did not answer within the deadline —
            // treat identically to a transport failure so the fail-closed path
            // denies (in enforce posture) instead of hanging (AAASM-3987).
            ::metrics::counter!("aa_gateway_policy_query_timeouts_total").increment(1);
            tracing::warn!(
                connection_id,
                timeout_ms = gateway_timeout.as_millis() as u64,
                "gateway policy query timed out — treating as failure"
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
    use aa_proto::assembly::policy::v1::OpControlSignal;

    #[test]
    fn normalize_gateway_decision_collapses_unknown_to_deny() {
        // AAASM-4020: only Allow/Deny/Pending survive; everything else (an
        // Unspecified, a Redact verdict, or an out-of-range code) becomes Deny.
        for kept in [Decision::Allow, Decision::Deny, Decision::Pending] {
            let mut resp = CheckActionResponse {
                decision: kept as i32,
                ..Default::default()
            };
            normalize_gateway_decision(&mut resp);
            assert_eq!(resp.decision, kept as i32);
        }
        for code in [Decision::Unspecified as i32, Decision::Redact as i32, 9999] {
            let mut resp = CheckActionResponse {
                decision: code,
                ..Default::default()
            };
            normalize_gateway_decision(&mut resp);
            assert_eq!(
                resp.decision,
                Decision::Deny as i32,
                "code {code} should collapse to Deny"
            );
        }
    }

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
    fn enrich_reads_claimed_sdk_version_from_label() {
        let mut event = make_audit_event();
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "1.4.0".to_string());
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert!(enriched.observed_sdk_identity.present);
        assert_eq!(enriched.observed_sdk_identity.version.as_deref(), Some("1.4.0"));
    }

    #[test]
    fn enrich_marks_missing_sdk_identity_when_label_absent() {
        let event = make_audit_event();
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert!(!enriched.observed_sdk_identity.present);
        assert!(enriched.observed_sdk_identity.version.is_none());
    }

    #[tokio::test]
    async fn resolve_verified_identity_returns_stored_entry() {
        let store = crate::ipc::new_verified_identity_store();
        store
            .write()
            .await
            .insert(7, aa_security::sdk_identity::VerifiedSdkIdentity::with_version("1.2.3"));

        let resolved = resolve_verified_identity(&store, 7).await;
        assert_eq!(resolved.version.as_deref(), Some("1.2.3"));
    }

    #[tokio::test]
    async fn resolve_verified_identity_falls_back_to_none_when_absent() {
        let store = crate::ipc::new_verified_identity_store();
        // No handshake recorded for connection 99 → Unverifiable downstream.
        let resolved = resolve_verified_identity(&store, 99).await;
        assert!(resolved.version.is_none());
        assert!(!resolved.is_available());
    }

    #[test]
    fn enrich_preserves_the_claimed_sdk_version_label_on_the_event() {
        // The claim is transported to the classifier, not consumed here —
        // sanitization is a separate step (AAASM-3630).
        let mut event = make_audit_event();
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "2.0.0".to_string());
        let seq = AtomicU64::new(0);
        let enriched = enrich(event, "agent", 0, &seq);
        assert_eq!(
            enriched.inner.labels.get(event::SDK_VERSION_LABEL).map(String::as_str),
            Some("2.0.0")
        );
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
            agent_team_id: String::new(),
            agent_org_id: String::new(),
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
            gateway_timeout_ms: crate::config::DEFAULT_GATEWAY_TIMEOUT_MS,
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
        assert_eq!(
            pipeline_config.gateway_timeout,
            Duration::from_millis(runtime_config.gateway_timeout_ms)
        );
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
            gateway_timeout: Duration::from_secs(5),
            min_sdk_version: None,
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
            // Generous default for tests that don't exercise the deadline; the
            // hanging-gateway regression test overrides this with a short value.
            gateway_timeout: Duration::from_secs(5),
            min_sdk_version: None,
        }
    }

    fn normal_event() -> AuditEvent {
        // A well-behaved SDK presents its version, so the run loop draws no
        // tamper signal (Unverifiable, not flagged) and forwards only the
        // action event. Tamper-path behaviour is covered by the dedicated
        // emit_tamper_signal tests and aaasm_3571_tamper_observability.
        let mut event = AuditEvent::default();
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "1.0.0".to_string());
        event
    }

    fn violation_event() -> AuditEvent {
        let mut event = AuditEvent {
            detail: Some(Detail::Violation(PolicyViolation {
                policy_rule: "rule".to_string(),
                blocked_action: "action".to_string(),
                reason: "reason".to_string(),
                latency_ms: 0,
            })),
            ..Default::default()
        };
        // Present SDK version → no tamper signal, so the violation path forwards
        // only the violation event.
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "1.0.0".to_string());
        event
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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

    #[test]
    fn emit_tamper_signal_broadcasts_distinct_event_and_metric_for_missing() {
        use aa_security::sdk_identity::SdkIdentityVerdict;
        use metrics_exporter_prometheus::PrometheusBuilder;

        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(8);
        let seq = AtomicU64::new(0);
        let source = enrich(normal_event(), "agent", 0, &seq);
        let outcome = enforcement::EnforcementOutcome::default();

        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        ::metrics::with_local_recorder(&recorder, || {
            emit_tamper_signal(SdkIdentityVerdict::Missing, &outcome, &source, &broadcast_tx, &seq);
        });

        // A distinct tamper audit event is broadcast.
        let event = unwrap_audit(broadcast_rx.try_recv().expect("tamper event broadcast"));
        let tamper = event.tamper.expect("tamper annotation present");
        assert_eq!(tamper.verdict, SdkIdentityVerdict::Missing);
        assert_eq!(tamper.forged_trust_markers, 0);
        // It is a tamper observation, not an action.
        assert!(event.inner.detail.is_none());

        // The dedicated metric is incremented, labelled by kind.
        let rendered = handle.render();
        assert!(rendered.contains("aa_runtime_sdk_tamper_suspected_total"));
        assert!(rendered.contains("kind=\"missing\""));
    }

    #[test]
    fn emit_tamper_signal_fires_for_forged_markers_even_when_verdict_ok() {
        use aa_security::sdk_identity::SdkIdentityVerdict;

        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(8);
        let seq = AtomicU64::new(0);
        let source = enrich(normal_event(), "agent", 0, &seq);
        let outcome = enforcement::EnforcementOutcome {
            forged_trust_markers: 1,
            ..Default::default()
        };

        emit_tamper_signal(SdkIdentityVerdict::Ok, &outcome, &source, &broadcast_tx, &seq);

        let event = unwrap_audit(broadcast_rx.try_recv().expect("tamper event broadcast"));
        let tamper = event.tamper.expect("tamper annotation present");
        assert_eq!(tamper.verdict, SdkIdentityVerdict::Ok);
        assert_eq!(tamper.forged_trust_markers, 1);
    }

    #[test]
    fn emit_tamper_signal_is_silent_when_clean() {
        use aa_security::sdk_identity::SdkIdentityVerdict;

        let (broadcast_tx, mut broadcast_rx) = broadcast::channel::<PipelineEvent>(8);
        let seq = AtomicU64::new(0);
        let source = enrich(normal_event(), "agent", 0, &seq);
        let outcome = enforcement::EnforcementOutcome::default();

        // Ok verdict + no forged markers → no emission.
        emit_tamper_signal(SdkIdentityVerdict::Ok, &outcome, &source, &broadcast_tx, &seq);
        // Unverifiable is also not a tamper signal.
        emit_tamper_signal(SdkIdentityVerdict::Unverifiable, &outcome, &source, &broadcast_tx, &seq);

        assert!(
            broadcast_rx.try_recv().is_err(),
            "no tamper event for a clean/unverifiable event"
        );
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        // `tokio::time::interval` fires an immediate first tick on creation. With the
        // clock paused, let the run loop start and absorb that empty flush before we
        // send the event, so the first tick cannot race ahead and flush our event.
        tokio::task::yield_now().await;

        // Build a TOOL_CALL event — not blocked by the policy. Carries the SDK
        // version label so it draws no tamper signal (which would bypass the
        // batch and break this batching assertion).
        let mut event = AuditEvent {
            action_type: ActionType::ToolCall as i32,
            ..Default::default()
        };
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "1.0.0".to_string());
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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

    /// Build a per-tool PolicyQuery tagged with the trace/span that compose
    /// `op_id` ("{trace_id}:{span_id}"), so the op-control store can address it.
    fn policy_query_frame_for_op(
        action_type: aa_proto::assembly::common::v1::ActionType,
        trace_id: &str,
        span_id: &str,
    ) -> IpcFrame {
        IpcFrame::PolicyQuery(aa_proto::assembly::policy::v1::CheckActionRequest {
            action_type: action_type as i32,
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            ..Default::default()
        })
    }

    /// AAASM-3491: a gateway terminate for the running op must **halt** the
    /// agent — the in-flight per-tool check fast-fails with `OpTerminatedError`
    /// even though no policy rule blocks the action. This is the core
    /// regression: before the op-control consumer, terminate was a silent
    /// allow-through.
    #[tokio::test]
    async fn op_control_terminate_halts_running_agent_tool_call() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        // Operator terminates the op via the gateway kill switch; the
        // subscriber records it in the store before the next tool check.
        op_control.apply("trace-1:span-1", OpControlSignal::Terminate);

        tokio::spawn(run(
            rx,
            broadcast_tx,
            config,
            metrics,
            token.clone(),
            // Empty policy: nothing here would deny — only the kill switch does.
            Arc::new(PolicyRules::default()),
            router,
            approval_queue,
            None,
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        tx.send((0, policy_query_frame_for_op(ActionType::ToolCall, "trace-1", "span-1")))
            .await
            .unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Deny as i32, "terminated op must be denied");
            assert!(
                r.reason.contains("OpTerminatedError"),
                "deny reason must name OpTerminatedError, got: {}",
                r.reason
            );
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3491: a paused op blocks the per-tool check; once the operator
    /// resumes it, the same check completes (here: allowed by the empty policy).
    /// Proves cooperative pause/resume reaches the running agent.
    #[tokio::test]
    async fn op_control_pause_blocks_then_resume_releases_tool_call() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        op_control.apply("trace-2:span-2", OpControlSignal::Pause);
        let store_for_resume = op_control.clone();

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
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        tx.send((0, policy_query_frame_for_op(ActionType::ToolCall, "trace-2", "span-2")))
            .await
            .unwrap();

        // While paused, the check must NOT have answered yet.
        assert!(
            tokio::time::timeout(Duration::from_millis(100), resp_rx.recv())
                .await
                .is_err(),
            "paused op must block the tool check until resume"
        );

        // Operator resumes; the blocked check should now complete.
        store_for_resume.apply("trace-2:span-2", OpControlSignal::Resume);

        let resp = tokio::time::timeout(Duration::from_millis(500), resp_rx.recv())
            .await
            .expect("resume did not release the blocked check")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Allow as i32, "resumed op must proceed");
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3873: an agent-level terminate must halt the agent even when the
    /// request carries **no** trace_id. The kill switch is bound to the
    /// server-side agent identity the runtime knows (`test-agent`), not the
    /// agent-supplied trace_id — so an SDK that omits trace_id (the old bypass)
    /// cannot dodge it.
    #[tokio::test]
    async fn op_control_agent_terminate_halts_with_empty_trace_id() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000); // agent_id = "test-agent"
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        // Operator terminates the whole agent (server-side identity), not a
        // specific op.
        op_control.apply(
            &crate::op_control::agent_halt_op_id("test-agent"),
            OpControlSignal::Terminate,
        );

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
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        // policy_query_frame leaves trace_id empty — the pre-fix path skipped
        // op-control entirely here, letting the action through.
        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Deny as i32,
                "agent-level terminate must deny even with empty trace_id"
            );
            assert!(r.reason.contains("OpTerminatedError"));
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3873: forging trace_id to an unknown value must not dodge an
    /// agent-level terminate either — the agent-scoped halt still applies.
    #[tokio::test]
    async fn op_control_agent_terminate_halts_with_altered_trace_id() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        op_control.apply(
            &crate::op_control::agent_halt_op_id("test-agent"),
            OpControlSignal::Terminate,
        );

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
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        // Attacker presents a forged trace_id that matches no op halt.
        tx.send((
            0,
            policy_query_frame_for_op(ActionType::ToolCall, "forged-trace", "forged-span"),
        ))
        .await
        .unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Deny as i32,
                "agent-level terminate must deny despite a forged trace_id"
            );
            assert!(r.reason.contains("OpTerminatedError"));
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3873: an agent-level pause blocks a check that carries no trace_id;
    /// resuming the agent releases it. Mirrors the per-op pause/resume test but
    /// over the trace_id-independent agent-scoped key.
    #[tokio::test]
    async fn op_control_agent_pause_blocks_then_resume_with_empty_trace_id() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        let agent_key = crate::op_control::agent_halt_op_id("test-agent");
        op_control.apply(&agent_key, OpControlSignal::Pause);
        let store_for_resume = op_control.clone();

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
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        // Empty trace_id — still blocked by the agent-scoped pause.
        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        assert!(
            tokio::time::timeout(Duration::from_millis(100), resp_rx.recv())
                .await
                .is_err(),
            "agent-level pause must block the check until resume"
        );

        store_for_resume.apply(&agent_key, OpControlSignal::Resume);

        let resp = tokio::time::timeout(Duration::from_millis(500), resp_rx.recv())
            .await
            .expect("resume did not release the blocked check")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(r.decision, Decision::Allow as i32, "resumed agent must proceed");
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
    }

    /// AAASM-3873: scoping is precise — a terminate on a *different* op must not
    /// over-block an unrelated request. A request with no trace_id is allowed
    /// while another op sits Terminated in the store, proving per-op halts are
    /// not treated as agent-wide (no false positives from the new agent/global
    /// consultation).
    #[tokio::test]
    async fn op_control_other_op_terminate_does_not_block_normal_request() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};

        let config = test_config(100, 10_000);
        let (tx, rx) = mpsc::channel::<(u64, IpcFrame)>(64);
        let (broadcast_tx, _rx) = broadcast::channel::<PipelineEvent>(64);
        let metrics = Arc::new(PipelineMetrics::default());
        let token = CancellationToken::new();
        let (router, mut resp_rx) = make_router_with_receiver();
        let approval_queue = crate::approval::ApprovalQueue::new();
        let op_control = crate::op_control::OpControlStore::new();

        // A specific (unrelated) op is terminated.
        op_control.apply("other-trace:other-span", OpControlSignal::Terminate);

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
            op_control,
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        // A normal request with its own trace_id (and the empty-trace case is
        // covered above) must still be allowed — the other op's halt is not
        // agent-wide.
        tx.send((
            0,
            policy_query_frame_for_op(ActionType::ToolCall, "my-trace", "my-span"),
        ))
        .await
        .unwrap();

        let resp = tokio::time::timeout(Duration::from_millis(200), resp_rx.recv())
            .await
            .expect("response timed out")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Allow as i32,
                "an unrelated op terminate must not block a normal request"
            );
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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

    /// AAASM-3987: a gateway that *accepts* the connection but never answers
    /// `check_action` (a wedged/hung gateway) must not block the policy check
    /// forever. The per-RPC deadline turns the hang into a failure, so in the
    /// fail-closed (enforce) posture the check is DENIED — and, critically, it
    /// resolves within roughly the deadline rather than never. Without the
    /// deadline this test would hang: the shared client lock and single pipeline
    /// loop would be pinned on the stuck RPC, stalling every agent (head-of-line
    /// DoS).
    #[tokio::test]
    async fn gateway_hang_fail_closed_denies_within_deadline() {
        use aa_proto::assembly::common::v1::{ActionType, Decision};
        use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
        use aa_proto::assembly::policy::v1::{
            BatchCheckRequest, BatchCheckResponse, CheckActionRequest as ProtoReq, CheckActionResponse as ProtoResp,
            OpControlMessage, OpControlSubscribeRequest,
        };
        use tonic::{Request, Response, Status};

        // Stub gateway: accepts the RPC but parks the handler far beyond the
        // test's lifetime — models a gateway that stopped responding.
        struct HangingGateway;

        #[tonic::async_trait]
        impl PolicyService for HangingGateway {
            async fn check_action(&self, _request: Request<ProtoReq>) -> Result<Response<ProtoResp>, Status> {
                tokio::time::sleep(Duration::from_secs(3_600)).await;
                Ok(Response::new(ProtoResp::default()))
            }

            async fn batch_check(
                &self,
                _request: Request<BatchCheckRequest>,
            ) -> Result<Response<BatchCheckResponse>, Status> {
                Err(Status::unimplemented("not exercised by this test"))
            }

            type OpControlStreamStream =
                std::pin::Pin<Box<dyn tokio_stream::Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

            async fn op_control_stream(
                &self,
                _request: Request<OpControlSubscribeRequest>,
            ) -> Result<Response<Self::OpControlStreamStream>, Status> {
                Err(Status::unimplemented("not exercised by this test"))
            }
        }

        // Bind first (socket is listening), then serve on a background task.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_token = CancellationToken::new();
        let server_shutdown = server_token.clone();
        tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let _ = tonic::transport::Server::builder()
                .add_service(PolicyServiceServer::new(HangingGateway))
                .serve_with_incoming_shutdown(incoming, server_shutdown.cancelled())
                .await;
        });
        // Give the serve loop a moment to start handling the h2 handshake.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let client = crate::gateway_client::GatewayClient::connect(&format!("http://{addr}"))
            .await
            .expect("client should connect to the listening (but hanging) stub");
        let gateway = Arc::new(Mutex::new(client));

        // Short deadline so the test resolves quickly; fail-closed posture.
        let mut config = test_config(100, 10_000);
        config.gateway_timeout = Duration::from_millis(300);

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
            Some(gateway),
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
        ));

        tx.send((0, policy_query_frame(ActionType::ToolCall))).await.unwrap();

        // The 300ms deadline must yield a Deny well inside 2s — proving the check
        // does not wait on the hung gateway forever.
        let resp = tokio::time::timeout(Duration::from_secs(2), resp_rx.recv())
            .await
            .expect("hung gateway must not block the policy check past the deadline")
            .expect("channel closed");

        if let IpcResponse::PolicyResponse(r) = resp {
            assert_eq!(
                r.decision,
                Decision::Deny as i32,
                "hung gateway in fail-closed posture must deny via the RPC deadline"
            );
        } else {
            panic!("expected PolicyResponse, got {resp:?}");
        }
        token.cancel();
        server_token.cancel();
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
        let mut event = AuditEvent {
            action_type: ActionType::ToolCall as i32,
            detail: Some(Detail::ToolCall(ToolCallDetail {
                args_json: format!(r#"{{"api_key": "{GATE_SECRET}"}}"#).into_bytes(),
                ..Default::default()
            })),
            ..Default::default()
        };
        // Present SDK version → no tamper event, so this redaction test sees only
        // the single forwarded action event.
        event
            .labels
            .insert(event::SDK_VERSION_LABEL.to_string(), "1.0.0".to_string());
        event
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
            crate::op_control::OpControlStore::new(),
            Arc::new(AtomicU64::new(0)),
            crate::ipc::new_verified_identity_store(),
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
