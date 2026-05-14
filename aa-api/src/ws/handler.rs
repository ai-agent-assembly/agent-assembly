//! WebSocket upgrade and event dispatch handler.

use std::time::Duration;

use crate::models::ws_payloads::{ApprovalPayload, BudgetAlertPayload, EventPayload, ViolationPayload};
use crate::models::{EventType, GovernanceEvent};
use crate::state::AppState;
use crate::ws::params::WsQueryParams;
use axum::body::Bytes;
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, WebSocketUpgrade};
use axum::response::IntoResponse;
use axum::Extension;
use futures::stream::SplitSink;
use futures::{SinkExt, StreamExt};

/// Interval between server-initiated ping frames.
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// `GET /api/v1/ws/events` — upgrade to WebSocket and stream events.
///
/// Initiates a WebSocket connection for real-time governance event streaming.
///
/// ## Protocol
///
/// 1. Client sends an HTTP GET with `Upgrade: websocket` headers.
/// 2. Server responds with `101 Switching Protocols` and upgrades the connection.
/// 3. Server sends `GovernanceEvent` JSON objects as text frames.
/// 4. Server sends periodic ping frames (every 30s); client must respond with pong.
/// 5. Either side may close the connection with a close frame.
///
/// ## Replay
///
/// The server maintains a circular buffer of the last 1000 events. Pass the
/// `since` query parameter with a previously received event `id` to replay
/// all buffered events after that id before switching to live streaming.
///
/// ## Event Types
///
/// Filter events using the `types` query parameter (comma-separated):
/// - `violation` — audit / pipeline events (policy violations)
/// - `approval` — human-in-the-loop approval requests
/// - `budget` — budget threshold alerts
///
/// All types are streamed when the parameter is omitted.
#[utoipa::path(
    get,
    path = "/api/v1/ws/events",
    params(WsQueryParams),
    responses(
        (status = 101, description = "WebSocket upgrade successful. Server streams GovernanceEvent JSON text frames."),
        (status = 200, description = "Event message schema (delivered as WebSocket text frames, not as an HTTP response body).", body = GovernanceEvent),
        (status = 400, description = "Bad request (invalid query parameters)")
    ),
    tag = "events"
)]
pub async fn ws_events_handler(
    ws: WebSocketUpgrade,
    Query(params): Query<WsQueryParams>,
    Extension(state): Extension<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, params, state))
}

/// Drive a single WebSocket connection: replay, then stream live events.
async fn handle_socket(socket: WebSocket, params: WsQueryParams, state: AppState) {
    let (sender, mut receiver) = socket.split();
    let sender = std::sync::Arc::new(tokio::sync::Mutex::new(sender));

    let allowed_types = params.event_types();
    let agent_filter = params.agent_id.clone();

    // Replay buffered events if `since` was provided.
    if let Some(since_id) = params.since {
        let events = state.replay_buffer.events_since(since_id);
        let replay_sender = sender.clone();
        for event in events {
            if !matches_filter(&event, &allowed_types, agent_filter.as_deref()) {
                continue;
            }
            if send_event(&replay_sender, &event).await.is_err() {
                return;
            }
        }
    }

    // Subscribe to live broadcast channels.
    let mut pipeline_rx = state.events.subscribe_pipeline();
    let mut approval_rx = state.events.subscribe_approvals();
    let mut budget_rx = state.events.subscribe_budget();

    let live_sender = sender.clone();
    let ping_sender = sender.clone();

    // Spawn ping/pong keep-alive task.
    let pong_received = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
    let pong_flag = pong_received.clone();

    let ping_handle = tokio::spawn(async move {
        loop {
            tokio::time::sleep(PING_INTERVAL).await;
            // Check that client responded to the previous ping.
            if !pong_flag.load(std::sync::atomic::Ordering::Relaxed) {
                tracing::debug!("pong timeout — closing WebSocket");
                let _ = ping_sender.lock().await.close().await;
                return;
            }
            pong_flag.store(false, std::sync::atomic::Ordering::Relaxed);
            if ping_sender
                .lock()
                .await
                .send(Message::Ping(Bytes::new()))
                .await
                .is_err()
            {
                return;
            }
        }
    });

    // Spawn reader task to track pong responses and detect client close.
    let reader_pong = pong_received.clone();
    let reader_handle = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            match msg {
                Message::Pong(_) => {
                    reader_pong.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    // Event sequence counter for GovernanceEvent ids.
    let next_id = state.next_event_id.clone();

    // Main event dispatch loop.
    loop {
        let event = tokio::select! {
            Ok(pipeline_ev) = pipeline_rx.recv() => {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(GovernanceEvent {
                    id,
                    event_type: EventType::Violation,
                    agent_id: extract_pipeline_agent_id(&pipeline_ev),
                    payload: serde_json::to_value(EventPayload::Violation(
                        build_violation_payload(&pipeline_ev),
                    ))
                    .unwrap_or_default(),
                    timestamp: chrono::Utc::now(),
                })
            }
            Ok(approval_ev) = approval_rx.recv() => {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(GovernanceEvent {
                    id,
                    event_type: EventType::Approval,
                    agent_id: approval_ev.agent_id.clone(),
                    payload: serde_json::to_value(EventPayload::Approval(
                        build_approval_payload(&approval_ev),
                    ))
                    .unwrap_or_default(),
                    timestamp: chrono::Utc::now(),
                })
            }
            Ok(budget_ev) = budget_rx.recv() => {
                let id = next_id.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Some(GovernanceEvent {
                    id,
                    event_type: EventType::Budget,
                    agent_id: format!("{:02x?}", budget_ev.agent_id.as_bytes()),
                    payload: serde_json::to_value(EventPayload::Budget(
                        build_budget_alert_payload(&budget_ev),
                    ))
                    .unwrap_or_default(),
                    timestamp: chrono::Utc::now(),
                })
            }
            else => None,
        };

        let Some(event) = event else { break };

        // Store in replay buffer before filtering.
        state.replay_buffer.push(event.clone());

        if !matches_filter(&event, &allowed_types, agent_filter.as_deref()) {
            continue;
        }

        if send_event(&live_sender, &event).await.is_err() {
            break;
        }
    }

    ping_handle.abort();
    reader_handle.abort();
}

/// Check whether an event passes the client's type and agent filters.
fn matches_filter(event: &GovernanceEvent, types: &[EventType], agent_id: Option<&str>) -> bool {
    if !types.contains(&event.event_type) {
        return false;
    }
    if let Some(filter_agent) = agent_id {
        if event.agent_id != filter_agent {
            return false;
        }
    }
    true
}

/// Extract the agent id from a pipeline event.
fn extract_pipeline_agent_id(ev: &aa_runtime::pipeline::event::PipelineEvent) -> String {
    match ev {
        aa_runtime::pipeline::event::PipelineEvent::Audit(enriched) => enriched.agent_id.clone(),
        aa_runtime::pipeline::event::PipelineEvent::LayerDegradation(info) => {
            format!("system:{}", info.layer)
        }
    }
}

/// Build a structured `ViolationPayload` from a `PipelineEvent` so the
/// Live Ops dashboard receives op-level metadata (op type, target
/// resource, lifecycle status, etc.) rather than a Debug-format string.
///
/// `latency_ms` is sourced from the relevant `Detail` variant when
/// available (LLM / tool / network / process); `FileOp`, `Violation`,
/// and `Approval` details don't carry an end-to-end latency and leave
/// the field as `None`. `call_stack` is intentionally absent — that
/// requires a proto-level addition tracked elsewhere.
fn build_violation_payload(ev: &aa_runtime::pipeline::event::PipelineEvent) -> ViolationPayload {
    use aa_runtime::pipeline::event::{EventSource, PipelineEvent};

    match ev {
        PipelineEvent::Audit(enriched) => {
            let source = match enriched.source {
                EventSource::Sdk => "sdk",
                EventSource::EBpf => "ebpf",
                EventSource::Proxy => "proxy",
            }
            .to_string();

            let op_type = action_type_label(enriched.inner.action_type);
            let status = decision_label(enriched.inner.decision);
            let team = if enriched.inner.team_id.is_empty() {
                None
            } else {
                Some(enriched.inner.team_id.clone())
            };
            let (resource, latency_ms) = detail_op_fields(enriched.inner.detail.as_ref());

            ViolationPayload::Audit {
                source,
                received_at_ms: enriched.received_at_ms,
                sequence_number: enriched.sequence_number,
                op_type,
                resource,
                status,
                latency_ms,
                team,
            }
        }
        PipelineEvent::LayerDegradation(info) => ViolationPayload::LayerDegradation {
            layer: info.layer.clone(),
            reason: info.reason.clone(),
            remaining_layers: info.remaining_layers.clone(),
        },
    }
}

/// Map the proto `ActionType` enum (raw `i32`) to the dashboard's
/// op-type string. Returns `None` when the value is unspecified or
/// outside the enum's known range so the field is omitted from JSON.
fn action_type_label(raw: i32) -> Option<String> {
    use aa_proto::assembly::common::v1::ActionType;
    let action_type = ActionType::try_from(raw).ok()?;
    let label = match action_type {
        ActionType::LlmCall => "llm_call",
        ActionType::ToolCall => "tool_call",
        ActionType::FileOperation => "file_op",
        ActionType::NetworkCall => "network",
        ActionType::ProcessExec => "process",
        ActionType::AgentSpawn => "spawn",
        ActionType::ActionUnspecified => return None,
    };
    Some(label.to_string())
}

/// Build a structured `ApprovalPayload` from the runtime's
/// `ApprovalRequest`. The schema fields map 1:1 to the source struct's
/// public fields; routing-metadata fields on `ApprovalRequest` (team
/// id, escalation overrides, fallback policy) are intentionally not
/// surfaced — they're internal queue routing details, not part of the
/// dashboard contract.
fn build_approval_payload(ev: &aa_runtime::approval::ApprovalRequest) -> ApprovalPayload {
    ApprovalPayload {
        request_id: ev.request_id.to_string(),
        action: ev.action.clone(),
        condition_triggered: ev.condition_triggered.clone(),
        submitted_at: ev.submitted_at,
        timeout_secs: ev.timeout_secs,
    }
}

/// Build a structured `BudgetAlertPayload` from the gateway's
/// `BudgetAlert`. The schema fields map 1:1 to the source struct's
/// alert-relevant fields; agent / team identifiers stay on the outer
/// `GovernanceEvent` envelope.
fn build_budget_alert_payload(ev: &aa_gateway::budget::types::BudgetAlert) -> BudgetAlertPayload {
    BudgetAlertPayload {
        threshold_pct: ev.threshold_pct,
        spent_usd: ev.spent_usd,
        limit_usd: ev.limit_usd,
    }
}

/// Map the proto `Decision` enum (raw `i32`) to the dashboard's
/// `OperationStatus` discriminant. Treats Allow / Redact as `running`
/// (the action proceeded); Deny → `blocked`; Pending → `pending`.
fn decision_label(raw: i32) -> Option<String> {
    use aa_proto::assembly::common::v1::Decision;
    let decision = Decision::try_from(raw).ok()?;
    let label = match decision {
        Decision::Allow | Decision::Redact => "running",
        Decision::Deny => "blocked",
        Decision::Pending => "pending",
        Decision::Unspecified => return None,
    };
    Some(label.to_string())
}

/// Extract per-detail resource + latency fields. The resource label
/// is the most-identifying string per variant (model / tool name /
/// path / host / command / blocked action); latency comes from the
/// variants that carry an end-to-end duration.
///
/// `FileOpDetail.latency_ms` and `PolicyViolation.latency_ms` are
/// read here so the wire path is ready for when measurement
/// instrumentation lands (AAASM-1425 for eBPF FileOp timing,
/// AAASM-1426 for gateway-side PolicyViolation timing). Until those
/// land, both fields default to `0` and we surface them as `None`
/// so the dashboard keeps its existing placeholder behaviour.
fn detail_op_fields(
    detail: Option<&aa_proto::assembly::audit::v1::audit_event::Detail>,
) -> (Option<String>, Option<u64>) {
    use aa_proto::assembly::audit::v1::audit_event::Detail;

    /// Returns `Some(ms)` when the proto latency field is positive,
    /// or `None` when zero (default / unmeasured) — keeps the
    /// dashboard's existing zero-as-placeholder semantics intact.
    fn nonzero_latency(latency_ms: i64) -> Option<u64> {
        if latency_ms > 0 {
            u64::try_from(latency_ms).ok()
        } else {
            None
        }
    }

    let Some(detail) = detail else {
        return (None, None);
    };
    match detail {
        Detail::LlmCall(d) => (Some(d.model.clone()), nonzero_latency(d.latency_ms)),
        Detail::ToolCall(d) => (Some(d.tool_name.clone()), nonzero_latency(d.latency_ms)),
        Detail::FileOp(d) => (Some(d.path.clone()), nonzero_latency(d.latency_ms)),
        Detail::Network(d) => (Some(format!("{}:{}", d.host, d.port)), nonzero_latency(d.latency_ms)),
        Detail::Process(d) => (Some(d.command.clone()), nonzero_latency(d.duration_ms)),
        Detail::Violation(d) => (Some(d.blocked_action.clone()), nonzero_latency(d.latency_ms)),
        Detail::Approval(_) => (None, None),
    }
}

/// Serialise a governance event and send it as a WebSocket text frame.
async fn send_event(
    sender: &std::sync::Arc<tokio::sync::Mutex<SplitSink<WebSocket, Message>>>,
    event: &GovernanceEvent,
) -> Result<(), ()> {
    let json = serde_json::to_string(event).map_err(|_| ())?;
    sender
        .lock()
        .await
        .send(Message::Text(json.into()))
        .await
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_proto::assembly::audit::v1::{
        audit_event::Detail, AuditEvent, FileOpDetail, LayerDegradationEvent, LlmCallDetail, NetworkCallDetail,
        PolicyViolation, ProcessExecDetail, ToolCallDetail,
    };
    use aa_proto::assembly::common::v1::{ActionType, Decision};
    use aa_runtime::pipeline::event::{EnrichedEvent, EventSource, LayerDegradationInfo, PipelineEvent};
    use std::boxed::Box;

    fn make_audit_event(
        action_type: ActionType,
        decision: Decision,
        team_id: &str,
        detail: Option<Detail>,
    ) -> AuditEvent {
        AuditEvent {
            event_id: "evt-1".into(),
            agent_id: None,
            occurred_at: None,
            action_type: action_type.into(),
            decision: decision.into(),
            trace_id: "trace-1".into(),
            span_id: "span-1".into(),
            parent_span_id: String::new(),
            detail,
            labels: Default::default(),
            root_agent_id: String::new(),
            parent_agent_id: String::new(),
            team_id: team_id.into(),
            session_id: String::new(),
            delegation_reason: String::new(),
            spawned_by_tool: String::new(),
            depth: 0,
        }
    }

    fn pipeline_audit(
        action_type: ActionType,
        decision: Decision,
        team_id: &str,
        detail: Option<Detail>,
    ) -> PipelineEvent {
        PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: make_audit_event(action_type, decision, team_id, detail),
            received_at_ms: 1_700_000_000_000,
            source: EventSource::Sdk,
            agent_id: "support-agent".into(),
            connection_id: 0,
            sequence_number: 42,
        }))
    }

    /// Test-only flattened view of the `Audit` variant for ergonomic asserts.
    struct AuditFields {
        source: String,
        sequence_number: u64,
        op_type: Option<String>,
        resource: Option<String>,
        status: Option<String>,
        latency_ms: Option<u64>,
        team: Option<String>,
    }

    fn unwrap_audit_fields(p: ViolationPayload) -> AuditFields {
        match p {
            ViolationPayload::Audit {
                source,
                received_at_ms: _,
                sequence_number,
                op_type,
                resource,
                status,
                latency_ms,
                team,
            } => AuditFields {
                source,
                sequence_number,
                op_type,
                resource,
                status,
                latency_ms,
                team,
            },
            ViolationPayload::LayerDegradation { .. } => panic!("expected Audit variant"),
        }
    }

    #[test]
    fn audit_llm_call_maps_model_and_latency() {
        let ev = pipeline_audit(
            ActionType::LlmCall,
            Decision::Allow,
            "support",
            Some(Detail::LlmCall(LlmCallDetail {
                model: "gpt-4o".into(),
                prompt_tokens: 100,
                completion_tokens: 50,
                latency_ms: 834,
                pii_detected: false,
                pii_redacted: false,
                provider: "openai".into(),
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.source, "sdk");
        assert_eq!(fields.sequence_number, 42);
        assert_eq!(fields.op_type.as_deref(), Some("llm_call"));
        assert_eq!(fields.resource.as_deref(), Some("gpt-4o"));
        assert_eq!(fields.status.as_deref(), Some("running"));
        assert_eq!(fields.latency_ms, Some(834));
        assert_eq!(fields.team.as_deref(), Some("support"));
    }

    #[test]
    fn audit_tool_call_maps_tool_name() {
        let ev = pipeline_audit(
            ActionType::ToolCall,
            Decision::Deny,
            "",
            Some(Detail::ToolCall(ToolCallDetail {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                latency_ms: 41,
                succeeded: false,
                error_message: "blocked by policy".into(),
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.op_type.as_deref(), Some("tool_call"));
        assert_eq!(fields.resource.as_deref(), Some("web_search"));
        assert_eq!(fields.status.as_deref(), Some("blocked"));
        assert_eq!(fields.latency_ms, Some(41));
        assert_eq!(fields.team, None, "empty team_id should serialize as None");
    }

    #[test]
    fn audit_file_op_maps_path_no_latency() {
        let ev = pipeline_audit(
            ActionType::FileOperation,
            Decision::Allow,
            "",
            Some(Detail::FileOp(FileOpDetail {
                operation: "read".into(),
                path: "/etc/passwd".into(),
                bytes: 1024,
                source: "sdk_hook".into(),
                latency_ms: 0,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.op_type.as_deref(), Some("file_op"));
        assert_eq!(fields.resource.as_deref(), Some("/etc/passwd"));
        assert_eq!(fields.latency_ms, None);
    }

    #[test]
    fn audit_network_call_maps_host_port() {
        let ev = pipeline_audit(
            ActionType::NetworkCall,
            Decision::Allow,
            "",
            Some(Detail::Network(NetworkCallDetail {
                host: "example.com".into(),
                port: 443,
                protocol: "https".into(),
                latency_ms: 220,
                status_code: 200,
                succeeded: true,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.resource.as_deref(), Some("example.com:443"));
        assert_eq!(fields.latency_ms, Some(220));
    }

    #[test]
    fn audit_process_exec_maps_command_and_duration() {
        let ev = pipeline_audit(
            ActionType::ProcessExec,
            Decision::Allow,
            "",
            Some(Detail::Process(ProcessExecDetail {
                command: "/bin/sh".into(),
                args: vec!["-c".into(), "echo hi".into()],
                exit_code: 0,
                duration_ms: 12,
                succeeded: true,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.op_type.as_deref(), Some("process"));
        assert_eq!(fields.resource.as_deref(), Some("/bin/sh"));
        assert_eq!(fields.latency_ms, Some(12));
    }

    #[test]
    fn audit_policy_violation_resource_is_blocked_action() {
        let ev = pipeline_audit(
            ActionType::ToolCall,
            Decision::Deny,
            "",
            Some(Detail::Violation(PolicyViolation {
                policy_rule: "no-secrets".into(),
                blocked_action: "read /etc/shadow".into(),
                reason: "policy denied".into(),
                latency_ms: 0,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.resource.as_deref(), Some("read /etc/shadow"));
        assert_eq!(fields.status.as_deref(), Some("blocked"));
    }

    #[test]
    fn audit_file_op_with_nonzero_latency_maps_through() {
        let ev = pipeline_audit(
            ActionType::FileOperation,
            Decision::Allow,
            "",
            Some(Detail::FileOp(FileOpDetail {
                operation: "read".into(),
                path: "/etc/passwd".into(),
                bytes: 1024,
                source: "ebpf".into(),
                latency_ms: 42,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.latency_ms, Some(42));
    }

    #[test]
    fn audit_policy_violation_with_nonzero_latency_maps_through() {
        let ev = pipeline_audit(
            ActionType::ToolCall,
            Decision::Deny,
            "",
            Some(Detail::Violation(PolicyViolation {
                policy_rule: "no-secrets".into(),
                blocked_action: "read /etc/shadow".into(),
                reason: "policy denied".into(),
                latency_ms: 7,
            })),
        );
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.latency_ms, Some(7));
    }

    #[test]
    fn audit_pending_decision_maps_to_pending_status() {
        let ev = pipeline_audit(ActionType::ToolCall, Decision::Pending, "", None);
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.status.as_deref(), Some("pending"));
    }

    #[test]
    fn audit_redact_decision_maps_to_running_status() {
        let ev = pipeline_audit(ActionType::ToolCall, Decision::Redact, "", None);
        let fields = unwrap_audit_fields(build_violation_payload(&ev));
        assert_eq!(fields.status.as_deref(), Some("running"));
    }

    #[test]
    fn layer_degradation_passes_through() {
        let _unused = LayerDegradationEvent {
            agent_id: String::new(),
            session_id: String::new(),
            timestamp_ns: 0,
            layer: String::new(),
            reason: String::new(),
            remaining_layers: vec![],
        };
        let ev = PipelineEvent::LayerDegradation(LayerDegradationInfo {
            layer: "ebpf".into(),
            reason: "uprobe attach failed".into(),
            remaining_layers: vec!["proxy".into(), "sdk".into()],
        });
        match build_violation_payload(&ev) {
            ViolationPayload::LayerDegradation {
                layer,
                reason,
                remaining_layers,
            } => {
                assert_eq!(layer, "ebpf");
                assert_eq!(reason, "uprobe attach failed");
                assert_eq!(remaining_layers, vec!["proxy".to_string(), "sdk".to_string()]);
            }
            ViolationPayload::Audit { .. } => panic!("expected LayerDegradation variant"),
        }
    }

    #[test]
    fn approval_payload_maps_request_fields() {
        use aa_core::PolicyResult;
        use aa_runtime::approval::ApprovalRequest;
        use uuid::Uuid;

        let request_id = Uuid::new_v4();
        let request = ApprovalRequest {
            request_id,
            agent_id: "support-agent".into(),
            action: "send_external_email".into(),
            condition_triggered: "outbound_email_to_unknown_domain".into(),
            submitted_at: 1_700_000_000,
            timeout_secs: 300,
            fallback: PolicyResult::Allow,
            team_id: Some("support".into()),
            timeout_override_secs: None,
            escalation_role_override: None,
        };

        let payload = build_approval_payload(&request);
        assert_eq!(payload.request_id, request_id.to_string());
        assert_eq!(payload.action, "send_external_email");
        assert_eq!(payload.condition_triggered, "outbound_email_to_unknown_domain");
        assert_eq!(payload.submitted_at, 1_700_000_000);
        assert_eq!(payload.timeout_secs, 300);

        // JSON-shape check — the discriminator + fields must match the
        // ApprovalPayload OpenAPI schema (no extra fields leaking through).
        let json = serde_json::to_value(EventPayload::Approval(payload)).unwrap();
        assert_eq!(json["action"], "send_external_email");
        assert_eq!(json["timeout_secs"], 300);
        assert!(json.get("team_id").is_none(), "internal routing fields must not leak");
        assert!(json.get("fallback").is_none(), "internal routing fields must not leak");
    }

    #[test]
    fn budget_alert_payload_maps_amount_fields() {
        use aa_core::AgentId;
        use aa_gateway::budget::types::BudgetAlert;

        let alert = BudgetAlert {
            agent_id: AgentId::from_bytes([0u8; 16]),
            team_id: Some("support".into()),
            threshold_pct: 95,
            spent_usd: 47.21,
            limit_usd: 50.00,
        };

        let payload = build_budget_alert_payload(&alert);
        assert_eq!(payload.threshold_pct, 95);
        assert!((payload.spent_usd - 47.21).abs() < f64::EPSILON);
        assert!((payload.limit_usd - 50.00).abs() < f64::EPSILON);

        // JSON-shape check.
        let json = serde_json::to_value(EventPayload::Budget(payload)).unwrap();
        assert_eq!(json["threshold_pct"], 95);
        assert!(json.get("agent_id").is_none(), "agent_id lives on the outer envelope");
        assert!(json.get("team_id").is_none(), "team_id is not part of the schema");
    }
}
