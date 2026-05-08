//! Proto ↔ core type conversions for the PolicyService gRPC layer.
//!
//! Bridges the structural gap between protobuf message types
//! (`CheckActionRequest`, `CheckActionResponse`) and the core domain types
//! (`AgentContext`, `GovernanceAction`, `PolicyResult`).

use aa_core::identity::{AgentId, SessionId};
use aa_core::time::Timestamp;
use aa_core::{AgentContext, FileMode, GovernanceAction, PolicyResult};
use aa_proto::assembly::approval::v1::{ApprovalDecisionType, ApprovalEvent, DecideRequest, PendingApproval};
use aa_proto::assembly::common::v1::Decision;
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::{CheckActionRequest, CheckActionResponse, RedactInstructions, RedactRule};
use aa_runtime::approval::PendingApprovalRequest;
use aa_runtime::approval::{ApprovalDecision, ApprovalRequest, ApprovalRequestId};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::engine::EvaluationResult;

/// Errors arising from malformed or incomplete proto requests.
#[derive(Debug, thiserror::Error)]
pub enum ConvertError {
    /// The `agent_id` field is missing from the request.
    #[error("missing agent_id")]
    MissingAgentId,
    /// The `context` oneof field is missing or empty.
    #[error("missing action context")]
    MissingContext,
    /// The file operation string is not one of "read", "write", "append", "delete".
    #[error("unknown file operation: {0}")]
    UnknownFileOp(String),
}

/// Hash a string into a 16-byte identifier using SHA-256 truncation.
///
/// Proto identity fields are variable-length strings; core identity types are
/// fixed `[u8; 16]`. This deterministic mapping avoids collisions in practice
/// while satisfying the type constraint.
pub fn hash_to_16(s: &str) -> [u8; 16] {
    let digest = Sha256::digest(s.as_bytes());
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Convert a [`CheckActionRequest`] into the core domain pair
/// ([`AgentContext`], [`GovernanceAction`]).
pub fn request_to_core(req: &CheckActionRequest) -> Result<(AgentContext, GovernanceAction), ConvertError> {
    // --- Agent context ---
    let proto_agent = req.agent_id.as_ref().ok_or(ConvertError::MissingAgentId)?;
    let agent_id = AgentId::from_bytes(hash_to_16(&proto_agent.agent_id));
    let session_id = SessionId::from_bytes(hash_to_16(&req.trace_id));

    let mut metadata = BTreeMap::new();
    if !proto_agent.org_id.is_empty() {
        metadata.insert("org_id".into(), proto_agent.org_id.clone());
    }
    if !proto_agent.team_id.is_empty() {
        metadata.insert("team_id".into(), proto_agent.team_id.clone());
    }
    if !req.credential_token.is_empty() {
        metadata.insert("credential_token".into(), req.credential_token.clone());
    }
    if !req.span_id.is_empty() {
        metadata.insert("span_id".into(), req.span_id.clone());
    }

    let ctx = AgentContext {
        agent_id,
        session_id,
        pid: 0, // not available in proto — set to 0
        started_at: Timestamp::from_nanos(0),
        metadata,
        // Provisional default — overwritten by the gateway service layer
        // with the agent's registered level before the engine sees it.
        governance_level: aa_core::GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    };

    // --- Governance action ---
    let context = req.context.as_ref().ok_or(ConvertError::MissingContext)?;
    let action_oneof = context.action.as_ref().ok_or(ConvertError::MissingContext)?;

    let action = match action_oneof {
        Action::ToolCall(tc) => GovernanceAction::ToolCall {
            name: tc.tool_name.clone(),
            args: String::from_utf8_lossy(&tc.args_json).into_owned(),
        },
        Action::FileOp(fo) => {
            let mode = match fo.operation.as_str() {
                "read" => FileMode::Read,
                "write" | "create" => FileMode::Write,
                "append" => FileMode::Append,
                "delete" => FileMode::Delete,
                other => return Err(ConvertError::UnknownFileOp(other.to_string())),
            };
            GovernanceAction::FileAccess {
                path: fo.path.clone(),
                mode,
            }
        }
        Action::NetworkCall(nc) => {
            let url = format!("{}://{}:{}", nc.protocol, nc.host, nc.port);
            GovernanceAction::NetworkRequest {
                url,
                method: "CONNECT".into(),
            }
        }
        Action::ProcessExec(pe) => {
            let command = if pe.args.is_empty() {
                pe.command.clone()
            } else {
                format!("{} {}", pe.command, pe.args.join(" "))
            };
            GovernanceAction::ProcessExec { command }
        }
        Action::LlmCall(lc) => {
            let args = serde_json::json!({
                "model": lc.model,
                "prompt_tokens": lc.prompt_tokens,
                "contains_pii": lc.contains_pii,
            })
            .to_string();
            GovernanceAction::ToolCall {
                name: "llm_call".into(),
                args,
            }
        }
    };

    Ok((ctx, action))
}

/// Convert an [`EvaluationResult`] into a [`CheckActionResponse`].
///
/// `latency_us` is the measured evaluation wall time in microseconds.
/// `policy_rule` is the identifier of the rule that triggered (empty for Allow).
///
/// When the engine detected credential/PII findings and produced a redacted payload,
/// the response uses `Decision::Redact` with the redacted field paths.
pub fn eval_result_to_response(eval: &EvaluationResult, latency_us: i64, policy_rule: &str) -> CheckActionResponse {
    // If the scanner produced redaction findings, return REDACT with instructions.
    if !eval.credential_findings.is_empty() {
        let rules: Vec<RedactRule> = eval
            .credential_findings
            .iter()
            .map(|f| RedactRule {
                field_path: format!("$.{:?}", f.kind),
                replacement: "[REDACTED]".into(),
            })
            .collect();
        return CheckActionResponse {
            decision: Decision::Redact as i32,
            reason: "sensitive data detected".into(),
            policy_rule: "data_pattern_scan".into(),
            approval_id: String::new(),
            redact: Some(RedactInstructions { rules }),
            decision_latency_us: latency_us,
        };
    }

    match &eval.decision {
        PolicyResult::Allow => CheckActionResponse {
            decision: Decision::Allow as i32,
            reason: String::new(),
            policy_rule: String::new(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: latency_us,
        },
        PolicyResult::Deny { reason } => CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: reason.clone(),
            policy_rule: policy_rule.to_string(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: latency_us,
        },
        PolicyResult::RequiresApproval { .. } => {
            panic!(
                "RequiresApproval must be handled before conversion — \
                 use approval_decision_to_response() after submitting to the ApprovalQueue"
            );
        }
    }
}

/// Convert a [`PolicyResult`] into a [`CheckActionResponse`].
///
/// Convenience wrapper for tests and callers that only have a `PolicyResult`
/// (no redaction findings).
pub fn result_to_response(result: &PolicyResult, latency_us: i64, policy_rule: &str) -> CheckActionResponse {
    let eval = EvaluationResult {
        decision: result.clone(),
        redacted_payload: None,
        credential_findings: Vec::new(),
        deny_action: None,
    };
    eval_result_to_response(&eval, latency_us, policy_rule)
}

/// Convert an [`ApprovalDecision`] into a [`CheckActionResponse`].
///
/// Maps `Approved` → `Decision::Allow`, `Rejected` → `Decision::Deny`,
/// `TimedOut` → decision derived from the fallback `PolicyResult`.
/// The real `approval_id` from the queue is included in all cases.
pub fn approval_decision_to_response(
    decision: &ApprovalDecision,
    approval_id: &ApprovalRequestId,
    latency_us: i64,
    policy_rule: &str,
) -> CheckActionResponse {
    let id_str = approval_id.to_string();
    match decision {
        ApprovalDecision::Approved { .. } => CheckActionResponse {
            decision: Decision::Allow as i32,
            reason: String::new(),
            policy_rule: policy_rule.to_string(),
            approval_id: id_str,
            redact: None,
            decision_latency_us: latency_us,
        },
        ApprovalDecision::Rejected { reason, .. } => CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: reason.clone(),
            policy_rule: policy_rule.to_string(),
            approval_id: id_str,
            redact: None,
            decision_latency_us: latency_us,
        },
        ApprovalDecision::TimedOut { fallback } => {
            let (proto_decision, reason) = match fallback {
                PolicyResult::Allow => (Decision::Allow, String::new()),
                PolicyResult::Deny { reason } => (Decision::Deny, reason.clone()),
                PolicyResult::RequiresApproval { .. } => (Decision::Deny, "approval timed out".to_string()),
            };
            CheckActionResponse {
                decision: proto_decision as i32,
                reason,
                policy_rule: policy_rule.to_string(),
                approval_id: id_str,
                redact: None,
                decision_latency_us: latency_us,
            }
        }
    }
}

/// Convert a [`PendingApprovalRequest`] (from `ApprovalQueue::list()`) into its
/// proto representation.
pub fn pending_to_proto(p: &PendingApprovalRequest) -> PendingApproval {
    let team_id = p.team_id.clone().unwrap_or_default();
    let routing_status = p.routing_status.clone().unwrap_or_else(|| {
        p.team_id
            .as_ref()
            .map_or_else(|| "no_team_id".to_string(), |tid| format!("routed:{tid}"))
    });
    PendingApproval {
        request_id: p.request_id.to_string(),
        agent_id: p.agent_id.clone(),
        action: p.action.clone(),
        condition_triggered: p.condition_triggered.clone(),
        submitted_at: p.submitted_at,
        timeout_secs: p.timeout_secs,
        team_id,
        routing_status,
    }
}

/// Convert an [`ApprovalRequest`] (from the broadcast channel) into a proto
/// [`ApprovalEvent`] for streaming to WatchApprovals subscribers.
pub fn approval_event_to_proto(req: &ApprovalRequest) -> ApprovalEvent {
    ApprovalEvent {
        request_id: req.request_id.to_string(),
        agent_id: req.agent_id.clone(),
        action: req.action.clone(),
        condition_triggered: req.condition_triggered.clone(),
        submitted_at: req.submitted_at,
        timeout_secs: req.timeout_secs,
    }
}

/// Errors specific to approval decision conversion.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalConvertError {
    /// The `request_id` field is not a valid UUID.
    #[error("invalid request_id UUID: {0}")]
    InvalidRequestId(#[from] uuid::Error),
    /// The `decision` field is unspecified or unknown.
    #[error("decision type is unspecified")]
    UnspecifiedDecision,
    /// REJECTED decision requires a non-empty reason.
    #[error("rejection reason is required")]
    MissingRejectionReason,
}

/// Convert a proto [`DecideRequest`] into the core types needed to call
/// [`ApprovalQueue::decide`].
pub fn decide_request_to_core(
    req: &DecideRequest,
) -> Result<(ApprovalRequestId, ApprovalDecision), ApprovalConvertError> {
    let id: ApprovalRequestId = req.request_id.parse()?;

    let decision_type =
        ApprovalDecisionType::try_from(req.decision).unwrap_or(ApprovalDecisionType::DecisionUnspecified);

    let decision = match decision_type {
        ApprovalDecisionType::Approved => ApprovalDecision::Approved {
            by: req.decided_by.clone(),
            reason: if req.reason.is_empty() {
                None
            } else {
                Some(req.reason.clone())
            },
        },
        ApprovalDecisionType::Rejected => {
            if req.reason.is_empty() {
                return Err(ApprovalConvertError::MissingRejectionReason);
            }
            ApprovalDecision::Rejected {
                by: req.decided_by.clone(),
                reason: req.reason.clone(),
            }
        }
        ApprovalDecisionType::DecisionUnspecified => {
            return Err(ApprovalConvertError::UnspecifiedDecision);
        }
    };

    Ok((id, decision))
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn make_pending(team_id: Option<&str>) -> PendingApprovalRequest {
        PendingApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "delete_file".to_string(),
            condition_triggered: "requires_approval".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 300,
            team_id: team_id.map(str::to_string),
            routing_status: None,
        }
    }

    #[test]
    fn pending_to_proto_with_team_id_sets_routed_status() {
        let p = make_pending(Some("team-x"));
        let proto = pending_to_proto(&p);
        assert_eq!(proto.team_id, "team-x");
        assert_eq!(proto.routing_status, "routed:team-x");
    }

    #[test]
    fn pending_to_proto_without_team_id_sets_no_team_id_status() {
        let p = make_pending(None);
        let proto = pending_to_proto(&p);
        assert_eq!(proto.team_id, "");
        assert_eq!(proto.routing_status, "no_team_id");
    }
}
