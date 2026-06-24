//! Conversion from a pipeline [`EnrichedEvent`] (wrapping a proto
//! [`AuditEvent`](aa_proto::assembly::audit::v1::AuditEvent)) into a governance
//! [`AuditEntry`](aa_core::storage::AuditEntry) ready for NATS publishing.
//!
//! The pipeline broadcast channel carries SDK/eBPF/proxy interception events as
//! proto [`AuditEvent`]s. The [`AuditPublisher`](super::AuditPublisher) speaks
//! governance [`AuditEntry`]s, so this module bridges the two: it maps the
//! proto action discriminant to an [`AuditEventType`], derives the agent /
//! session identity and tenant lineage that the NATS subject is keyed on, and
//! serialises a non-secret JSON payload summarising the action.
//!
//! ## Independence from the approval audit stream
//!
//! These entries originate from `PipelineEvent::Audit` interception events and
//! are a *disjoint* set from the approval-decision entries emitted by
//! [`ApprovalQueue`](crate::approval::ApprovalQueue). Each logical audit event
//! is therefore published exactly once — see [`runtime`](crate::runtime) for
//! the wiring and the no-double-publish test.
//!
//! ## Hash chain
//!
//! Pipeline-audit entries are *not* part of the approval queue's per-decision
//! hash chain — they are an independent stream produced concurrently from
//! kernel/SDK/proxy sources with no shared ordering authority. Each entry is
//! constructed with a genesis (`[0u8; 32]`) previous-hash; downstream storage
//! keys on `(agent, session, seq)` and the monotonic `sequence_number` carried
//! from the pipeline, not on chain linkage.

use aa_core::audit::Lineage;
use aa_core::storage::AuditEntry;
use aa_core::{AgentId, AuditEventType, SessionId};
use aa_proto::assembly::audit::v1::audit_event::Detail;
use aa_proto::assembly::audit::v1::AuditEvent;
use aa_proto::assembly::common::v1::ActionType;
use sha2::{Digest, Sha256};

use crate::pipeline::event::{EnrichedEvent, EventSource};

/// Genesis previous-hash sentinel used for every pipeline-audit entry (see the
/// module-level "Hash chain" note for why these are not chained).
const GENESIS_HASH: [u8; 32] = [0u8; 32];

/// Convert an [`EnrichedEvent`] from the pipeline broadcast channel into a
/// governance [`AuditEntry`] suitable for the [`AuditPublisher`](super::AuditPublisher).
///
/// The mapping is total: every event yields an entry (the audit trail must not
/// silently drop interception events). The proto action discriminant selects
/// the [`AuditEventType`] via [`event_type_for`]; identity and lineage are
/// derived from the proto agent id and lineage fields.
pub fn enriched_to_audit_entry(event: &EnrichedEvent) -> AuditEntry {
    let proto = &event.inner;
    let event_type = event_type_for(proto);
    let agent_id = derive_agent_id(event);
    let session_id = derive_session_id(event);
    let lineage = derive_lineage(proto);
    let payload = build_payload(event);
    let timestamp_ns = timestamp_ns_for(event);

    AuditEntry::new_with_lineage(
        event.sequence_number,
        timestamp_ns,
        event_type,
        agent_id,
        session_id,
        payload,
        GENESIS_HASH,
        lineage,
    )
}

/// Map a proto [`AuditEvent`] to the governance [`AuditEventType`].
///
/// The `action_type` discriminant drives the mapping. A populated
/// `Detail::Violation` overrides it to [`AuditEventType::PolicyViolation`] so a
/// blocked action is categorised by its outcome rather than its action class.
fn event_type_for(proto: &AuditEvent) -> AuditEventType {
    // A structured policy violation is recorded as a violation regardless of
    // which action class triggered it.
    if matches!(proto.detail, Some(Detail::Violation(_))) {
        return AuditEventType::PolicyViolation;
    }
    match ActionType::try_from(proto.action_type).unwrap_or(ActionType::ActionUnspecified) {
        // Tool / MCP invocations and file/network/process syscalls are all
        // governance "tool call intercepted" events at the audit tier — the
        // action class is preserved in the payload's `action_type` field.
        ActionType::ToolCall
        | ActionType::FileOperation
        | ActionType::NetworkCall
        | ActionType::ProcessExec
        | ActionType::LlmCall
        | ActionType::ToolResult => AuditEventType::ToolCallIntercepted,
        // A spawned child agent is recorded as an A2A interception.
        ActionType::AgentSpawn => AuditEventType::A2ACallIntercepted,
        // Unspecified / unknown discriminants fall back to the generic
        // interception type rather than being dropped.
        ActionType::ActionUnspecified => AuditEventType::ToolCallIntercepted,
    }
}

/// Derive a 16-byte [`AgentId`] from the event.
///
/// Prefers parsing the proto composite agent id's inner `agent_id` string as a
/// UUID (the canonical on-wire form). When that field is empty or not a UUID it
/// falls back to a SHA-256 truncation of the enriched event's `agent_id`
/// string — the same stable derivation the approval path uses (`hash_to_16`).
fn derive_agent_id(event: &EnrichedEvent) -> AgentId {
    if let Some(proto_agent) = &event.inner.agent_id {
        if let Ok(uuid) = proto_agent.agent_id.parse::<uuid::Uuid>() {
            return AgentId::from_bytes(*uuid.as_bytes());
        }
        if !proto_agent.agent_id.is_empty() {
            return AgentId::from_bytes(hash_to_16(&proto_agent.agent_id));
        }
    }
    AgentId::from_bytes(hash_to_16(&event.agent_id))
}

/// Derive a 16-byte [`SessionId`] from the proto `session_id` string (UUID when
/// parseable, otherwise a SHA-256 truncation). Falls back to the proto
/// `event_id` so each event is still attributable to a session bucket.
fn derive_session_id(event: &EnrichedEvent) -> SessionId {
    let raw = if !event.inner.session_id.is_empty() {
        &event.inner.session_id
    } else {
        &event.inner.event_id
    };
    if let Ok(uuid) = raw.parse::<uuid::Uuid>() {
        return SessionId::from_bytes(*uuid.as_bytes());
    }
    SessionId::from_bytes(hash_to_16(raw))
}

/// Derive the audit [`Lineage`] (org/team for the NATS subject tenant, plus the
/// delegation context) from the proto event's lineage fields.
fn derive_lineage(proto: &AuditEvent) -> Lineage {
    let org_id = proto
        .agent_id
        .as_ref()
        .map(|a| a.org_id.clone())
        .filter(|s| !s.is_empty());
    // Prefer the composite agent id's team, falling back to the top-level
    // lineage `team_id` carried for legacy events.
    let team_id = proto
        .agent_id
        .as_ref()
        .map(|a| a.team_id.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| Some(proto.team_id.clone()).filter(|s| !s.is_empty()));

    Lineage {
        org_id,
        team_id,
        delegation_reason: Some(proto.delegation_reason.clone()).filter(|s| !s.is_empty()),
        spawned_by_tool: Some(proto.spawned_by_tool.clone()).filter(|s| !s.is_empty()),
        depth: (proto.depth != 0).then_some(proto.depth),
        // Root/parent agent ids are UUID-encoded strings on the wire; only
        // attach them when they parse, to keep the entry's identity bytes well-formed.
        root_agent_id: parse_optional_agent_id(&proto.root_agent_id),
        parent_agent_id: parse_optional_agent_id(&proto.parent_agent_id),
    }
}

/// Parse an optional UUID-encoded agent id string into an [`AgentId`].
fn parse_optional_agent_id(raw: &str) -> Option<AgentId> {
    raw.parse::<uuid::Uuid>()
        .ok()
        .map(|u| AgentId::from_bytes(*u.as_bytes()))
}

/// Build the non-secret JSON payload for the entry.
///
/// Carries the event id, the action class, the interception source, the
/// proto decision, and a per-detail summary. Detail summaries deliberately copy
/// only metadata fields (tool names, paths, hosts) — never raw `args_json`
/// bytes, which the producer is contractually required to scan/redact and which
/// this audit tier must not re-expand.
///
/// When the event carries a tamper signal (AAASM-3637), an `sdk_identity`
/// section records the server-recomputed verdict and the count of stripped
/// forged trust markers so the bypass/tamper trail is queryable.
fn build_payload(event: &EnrichedEvent) -> String {
    let proto = &event.inner;
    let action = ActionType::try_from(proto.action_type)
        .unwrap_or(ActionType::ActionUnspecified)
        .as_str_name();
    let detail = detail_summary(&proto.detail);
    let mut payload = serde_json::json!({
        "event_id": proto.event_id,
        "action_type": action,
        "source": source_label(&event.source),
        "decision": proto.decision,
        "detail": detail,
    });
    if let Some(tamper) = &event.tamper {
        payload["sdk_identity"] = serde_json::json!({
            "tamper_suspected": true,
            "verdict": tamper.verdict.as_str(),
            "forged_trust_markers": tamper.forged_trust_markers,
        });
    }
    payload.to_string()
}

/// Summarise the proto detail oneof as a small JSON object, copying only
/// non-secret metadata fields.
fn detail_summary(detail: &Option<Detail>) -> serde_json::Value {
    match detail {
        Some(Detail::LlmCall(d)) => serde_json::json!({
            "kind": "llm_call", "model": d.model, "provider": d.provider,
        }),
        Some(Detail::ToolCall(d)) => serde_json::json!({
            "kind": "tool_call", "tool_name": d.tool_name, "tool_source": d.tool_source,
            "succeeded": d.succeeded,
        }),
        Some(Detail::FileOp(d)) => serde_json::json!({
            "kind": "file_op", "operation": d.operation, "path": d.path, "source": d.source,
        }),
        Some(Detail::Network(d)) => serde_json::json!({
            "kind": "network_call", "host": d.host, "port": d.port, "protocol": d.protocol,
        }),
        Some(Detail::Process(d)) => serde_json::json!({
            "kind": "process_exec", "command": d.command, "exit_code": d.exit_code,
        }),
        Some(Detail::Violation(d)) => serde_json::json!({
            "kind": "policy_violation", "policy_rule": d.policy_rule,
            "blocked_action": d.blocked_action, "reason": d.reason,
        }),
        Some(Detail::Approval(d)) => serde_json::json!({
            "kind": "approval", "approval_id": d.approval_id, "approved": d.approved,
        }),
        None => serde_json::Value::Null,
    }
}

/// Stable string label for the interception source.
fn source_label(source: &EventSource) -> &'static str {
    match source {
        EventSource::Sdk => "sdk",
        EventSource::EBpf => "ebpf",
        EventSource::Proxy => "proxy",
    }
}

/// Convert the enriched event's wall-clock receive time (Unix milliseconds) to
/// the nanosecond timestamp the [`AuditEntry`] records. Negative values (clock
/// skew) clamp to `0`.
fn timestamp_ns_for(event: &EnrichedEvent) -> u64 {
    let ms = event.received_at_ms.max(0) as u64;
    ms.saturating_mul(1_000_000)
}

/// Hash a string into a 16-byte identifier via SHA-256 truncation.
///
/// Mirrors the approval queue's `hash_to_16` so a given agent-id string maps to
/// the same [`AgentId`] bytes across both the approval and pipeline audit paths.
fn hash_to_16(s: &str) -> [u8; 16] {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_proto::assembly::audit::v1::{
        ApprovalEvent, FileOpDetail, LlmCallDetail, NetworkCallDetail, PolicyViolation, ProcessExecDetail,
        ToolCallDetail,
    };
    use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;

    /// Build an enriched event wrapping a proto `AuditEvent` with the given
    /// action type, detail, and source.
    fn enriched(action: ActionType, detail: Option<Detail>, source: EventSource) -> EnrichedEvent {
        EnrichedEvent {
            inner: AuditEvent {
                event_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
                action_type: action as i32,
                detail,
                ..AuditEvent::default()
            },
            received_at_ms: 1_700,
            source,
            agent_id: "test-agent".to_string(),
            connection_id: 1,
            sequence_number: 7,
            observed_sdk_identity: Default::default(),
            tamper: None,
        }
    }

    fn payload_json(entry: &AuditEntry) -> serde_json::Value {
        serde_json::from_str(entry.payload()).expect("payload is valid JSON")
    }

    #[test]
    fn tool_call_maps_to_tool_call_intercepted() {
        let detail = Some(Detail::ToolCall(ToolCallDetail {
            tool_name: "web_search".to_string(),
            tool_source: "mcp".to_string(),
            succeeded: true,
            ..ToolCallDetail::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::ToolCall, detail, EventSource::Sdk));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        let p = payload_json(&entry);
        assert_eq!(p["action_type"], "TOOL_CALL");
        assert_eq!(p["source"], "sdk");
        assert_eq!(p["detail"]["kind"], "tool_call");
        assert_eq!(p["detail"]["tool_name"], "web_search");
    }

    #[test]
    fn llm_call_maps_to_tool_call_intercepted_with_model() {
        let detail = Some(Detail::LlmCall(LlmCallDetail {
            model: "gpt-4o".to_string(),
            provider: "openai".to_string(),
            ..LlmCallDetail::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::LlmCall, detail, EventSource::Sdk));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        let p = payload_json(&entry);
        assert_eq!(p["action_type"], "LLM_CALL");
        assert_eq!(p["detail"]["model"], "gpt-4o");
    }

    #[test]
    fn file_operation_maps_to_tool_call_intercepted_with_path() {
        let detail = Some(Detail::FileOp(FileOpDetail {
            operation: "read".to_string(),
            path: "/etc/passwd".to_string(),
            source: "ebpf".to_string(),
            ..FileOpDetail::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::FileOperation, detail, EventSource::EBpf));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        let p = payload_json(&entry);
        assert_eq!(p["action_type"], "FILE_OPERATION");
        assert_eq!(p["source"], "ebpf");
        assert_eq!(p["detail"]["path"], "/etc/passwd");
    }

    #[test]
    fn network_call_maps_with_host_and_port() {
        let detail = Some(Detail::Network(NetworkCallDetail {
            host: "api.example.com".to_string(),
            port: 443,
            protocol: "https".to_string(),
            ..NetworkCallDetail::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::NetworkCall, detail, EventSource::Proxy));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        let p = payload_json(&entry);
        assert_eq!(p["action_type"], "NETWORK_CALL");
        assert_eq!(p["source"], "proxy");
        assert_eq!(p["detail"]["host"], "api.example.com");
        assert_eq!(p["detail"]["port"], 443);
    }

    #[test]
    fn process_exec_maps_with_command() {
        let detail = Some(Detail::Process(ProcessExecDetail {
            command: "/bin/sh".to_string(),
            exit_code: 0,
            ..ProcessExecDetail::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::ProcessExec, detail, EventSource::EBpf));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
        let p = payload_json(&entry);
        assert_eq!(p["action_type"], "PROCESS_EXEC");
        assert_eq!(p["detail"]["command"], "/bin/sh");
    }

    #[test]
    fn agent_spawn_maps_to_a2a_call_intercepted() {
        let entry = enriched_to_audit_entry(&enriched(ActionType::AgentSpawn, None, EventSource::Sdk));
        assert_eq!(entry.event_type(), AuditEventType::A2ACallIntercepted);
        assert_eq!(payload_json(&entry)["action_type"], "AGENT_SPAWN");
    }

    #[test]
    fn policy_violation_detail_overrides_action_type() {
        // Even on a TOOL_CALL action, a populated violation detail records a
        // PolicyViolation governance event.
        let detail = Some(Detail::Violation(PolicyViolation {
            policy_rule: "no-egress".to_string(),
            blocked_action: "network".to_string(),
            reason: "blocked host".to_string(),
            ..PolicyViolation::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::ToolCall, detail, EventSource::Proxy));
        assert_eq!(entry.event_type(), AuditEventType::PolicyViolation);
        let p = payload_json(&entry);
        assert_eq!(p["detail"]["kind"], "policy_violation");
        assert_eq!(p["detail"]["policy_rule"], "no-egress");
    }

    #[test]
    fn approval_detail_summarised() {
        let detail = Some(Detail::Approval(ApprovalEvent {
            approval_id: "a-1".to_string(),
            approved: true,
            ..ApprovalEvent::default()
        }));
        let entry = enriched_to_audit_entry(&enriched(ActionType::ToolCall, detail, EventSource::Sdk));
        let p = payload_json(&entry);
        assert_eq!(p["detail"]["kind"], "approval");
        assert_eq!(p["detail"]["approved"], true);
    }

    #[test]
    fn unspecified_action_falls_back_to_intercepted_not_dropped() {
        let entry = enriched_to_audit_entry(&enriched(ActionType::ActionUnspecified, None, EventSource::Sdk));
        assert_eq!(entry.event_type(), AuditEventType::ToolCallIntercepted);
    }

    #[test]
    fn sequence_number_and_timestamp_are_carried() {
        let entry = enriched_to_audit_entry(&enriched(ActionType::ToolCall, None, EventSource::Sdk));
        assert_eq!(entry.seq(), 7);
        // received_at_ms 1_700 → 1_700 * 1_000_000 ns.
        assert_eq!(entry.timestamp_ns(), 1_700_000_000);
    }

    #[test]
    fn negative_timestamp_clamps_to_zero() {
        let mut event = enriched(ActionType::ToolCall, None, EventSource::Sdk);
        event.received_at_ms = -5;
        let entry = enriched_to_audit_entry(&event);
        assert_eq!(entry.timestamp_ns(), 0);
    }

    #[test]
    fn agent_id_uuid_parsed_from_proto_when_present() {
        let uuid = uuid::Uuid::new_v4();
        let mut event = enriched(ActionType::ToolCall, None, EventSource::Sdk);
        event.inner.agent_id = Some(ProtoAgentId {
            agent_id: uuid.to_string(),
            ..ProtoAgentId::default()
        });
        let entry = enriched_to_audit_entry(&event);
        assert_eq!(entry.agent_id().as_bytes(), uuid.as_bytes());
    }

    #[test]
    fn agent_id_falls_back_to_hash_of_enriched_agent_string() {
        // No proto agent id → SHA-256 truncation of the enriched agent_id,
        // matching the approval path's hash_to_16 derivation.
        let event = enriched(ActionType::ToolCall, None, EventSource::Sdk);
        let entry = enriched_to_audit_entry(&event);
        assert_eq!(entry.agent_id().as_bytes(), &hash_to_16("test-agent"));
    }

    #[test]
    fn lineage_org_and_team_drive_tenant() {
        let mut event = enriched(ActionType::ToolCall, None, EventSource::Sdk);
        event.inner.agent_id = Some(ProtoAgentId {
            org_id: "acme".to_string(),
            team_id: "payments".to_string(),
            agent_id: uuid::Uuid::new_v4().to_string(),
        });
        let entry = enriched_to_audit_entry(&event);
        assert_eq!(entry.org_id(), Some("acme"));
        assert_eq!(entry.team_id(), Some("payments"));
        // The NATS subject derived from this entry must carry the org tenant.
        assert!(super::super::subject_for(&entry).starts_with("assembly.audit.acme."));
    }

    #[test]
    fn entry_integrity_holds() {
        let entry = enriched_to_audit_entry(&enriched(ActionType::ToolCall, None, EventSource::Sdk));
        assert!(entry.verify_integrity());
    }
}
