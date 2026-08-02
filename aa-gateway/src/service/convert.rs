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
        Action::ToolResult(tr) => GovernanceAction::ToolResult {
            tool_name: tr.tool_name.clone(),
            result: String::from_utf8_lossy(&tr.result_json).into_owned(),
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
/// Mapping rules:
/// * `decision == Deny` → `Decision::Deny` (covers `credential_action: block`,
///   which short-circuits with findings *and* a Deny verdict).
/// * findings non-empty *and* `redacted_payload.is_some()` →
///   `Decision::Redact` (covers `credential_action: redact_only`).
/// * findings non-empty *and* `redacted_payload.is_none()` →
///   `Decision::Allow` (covers `credential_action: alert_only`, where the
///   payload is forwarded unmodified; the alert side-effect is wired
///   separately).
/// * everything else falls through to the underlying `PolicyResult`.
pub fn eval_result_to_response(eval: &EvaluationResult, latency_us: i64, policy_rule: &str) -> CheckActionResponse {
    // Deny short-circuits everything, including the findings-driven Redact path,
    // so `credential_action: block` returns a hard Deny even though findings exist.
    if let PolicyResult::Deny { reason } = &eval.decision {
        return CheckActionResponse {
            decision: Decision::Deny as i32,
            reason: reason.clone(),
            policy_rule: policy_rule.to_string(),
            approval_id: String::new(),
            redact: None,
            decision_latency_us: latency_us,
        };
    }

    // Findings + redacted payload → Redact instructions.
    if !eval.credential_findings.is_empty() && eval.redacted_payload.is_some() {
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
        PolicyResult::Deny { .. } => unreachable!("Deny is handled by the short-circuit above"),
        PolicyResult::RequiresApproval { .. } => {
            panic!(
                "RequiresApproval must be handled before conversion — \
                 use approval_decision_to_response() after submitting to the ApprovalQueue"
            );
        }
    }
}

/// Derive the canonical 5-way runtime verdict (ADR-0018 item A, AAASM-5100) for
/// the decision an action actually received, as the lowercase wire string the
/// read-side deserializes into `aa_api::models::verdict::RuntimeVerdict`.
///
/// The verdict is a *finer* label emitted **alongside** the proto
/// [`Decision`] — it never changes what is allowed or blocked. The proto enum is
/// intentionally coarse: it folds a scoped-but-permitted action into `Allow` and
/// a DLP-scrubbed-but-forwarded action into `Redact`; this function recovers the
/// distinction the dashboard renders.
///
/// The verdict is written into the audit payload JSON as a string rather than a
/// typed field because the `RuntimeVerdict` enum lives in `aa-api`, which depends
/// on `aa-gateway` (not the reverse) — so the gateway cannot name the type, and
/// the audit payload is a JSON string in any case. `aa-api`'s read-side
/// (`entry_to_decision_row`) parses the string back into the enum.
///
/// Mapping (from the *recorded* proto `decision`, plus the finer signals the
/// gateway holds at audit-write time):
/// * `Deny`    → `"deny"`   — blocked outright.
/// * `Pending` → `"pending"`— held awaiting human approval.
/// * `Redact`  → `"scrub"`  — permitted, but the DLP layer rewrote the payload
///   (secrets/PII stripped, ADR 0015) before forwarding. Distinct from `allow`.
/// * `Allow` + `narrowed`   → `"narrow"` — permitted, but a policy match scoped
///   the action down (a narrower cascade allow-list still admitted it) rather
///   than blocking. Distinct from `deny` so the UI shows partial success.
/// * `Allow`                → `"allow"` — permitted unchanged.
/// * anything else (`Unspecified` / out-of-range) → `"deny"`, matching the
///   fail-closed collapse the enforcement paths already apply to unknown codes.
pub fn runtime_verdict(decision: i32, narrowed: bool) -> &'static str {
    match Decision::try_from(decision) {
        Ok(Decision::Allow) if narrowed => "narrow",
        Ok(Decision::Allow) => "allow",
        Ok(Decision::Redact) => "scrub",
        Ok(Decision::Pending) => "pending",
        Ok(Decision::Deny) => "deny",
        // Unspecified, or an out-of-range code from a newer peer — fail closed,
        // mirroring `normalize_gateway_decision` / `decision_from_response`.
        _ => "deny",
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
        canonical_findings: vec![],
        deny_action: None,
        policy_doc_id: None,
        narrowed: false,
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
/// `ApprovalQueue::decide`.
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
            // The gRPC decide contract does not yet carry approval conditions
            // (AAASM-5095 extends the HTTP contract only); record none.
            conditions: Vec::new(),
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
            target_role: None,
            routed_at: None,
            escalate_at: None,
            routing_history: vec![],
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

    #[test]
    fn eval_with_deny_and_findings_maps_to_decision_deny() {
        // credential_action: block → engine returns Deny *and* findings populated.
        // The wire response must still be Decision::Deny — no Redact instructions.
        let eval = EvaluationResult {
            decision: PolicyResult::Deny {
                reason: "credential detected".into(),
            },
            redacted_payload: None,
            credential_findings: vec![aa_security::CredentialFinding::from_regex_match(0, 4)],
            canonical_findings: vec![],
            deny_action: None,
            policy_doc_id: None,
            narrowed: false,
        };
        let resp = eval_result_to_response(&eval, 0, "data_pattern_scan");
        assert_eq!(resp.decision, Decision::Deny as i32);
        assert_eq!(resp.reason, "credential detected");
        assert!(resp.redact.is_none());
    }

    #[test]
    fn eval_with_allow_and_findings_but_no_redacted_payload_maps_to_allow() {
        // credential_action: alert_only → engine returns Allow + findings but
        // leaves redacted_payload = None. The wire response must be
        // Decision::Allow so the payload is forwarded unmodified.
        let eval = EvaluationResult {
            decision: PolicyResult::Allow,
            redacted_payload: None,
            credential_findings: vec![aa_security::CredentialFinding::from_regex_match(0, 4)],
            canonical_findings: vec![],
            deny_action: None,
            policy_doc_id: None,
            narrowed: false,
        };
        let resp = eval_result_to_response(&eval, 0, "");
        assert_eq!(resp.decision, Decision::Allow as i32);
        assert!(resp.redact.is_none());
    }

    // ── runtime_verdict — 5-way vocabulary (ADR-0018 item A, AAASM-5100) ──────

    #[test]
    fn runtime_verdict_maps_each_decision_to_its_wire_label() {
        // A plain (un-narrowed) allow, a scrub (proto Redact), a pending, and a
        // deny each map to their distinct 5-way label.
        assert_eq!(runtime_verdict(Decision::Allow as i32, false), "allow");
        assert_eq!(runtime_verdict(Decision::Redact as i32, false), "scrub");
        assert_eq!(runtime_verdict(Decision::Pending as i32, false), "pending");
        assert_eq!(runtime_verdict(Decision::Deny as i32, false), "deny");
    }

    #[test]
    fn runtime_verdict_narrowed_allow_is_narrow_not_allow() {
        // The `narrowed` signal turns a permitted action into `narrow` — a
        // policy scoped it down rather than blocking. Distinct from a plain
        // allow so the UI can render partial success.
        assert_eq!(runtime_verdict(Decision::Allow as i32, true), "narrow");
        assert_ne!(
            runtime_verdict(Decision::Allow as i32, true),
            runtime_verdict(Decision::Allow as i32, false)
        );
    }

    #[test]
    fn runtime_verdict_scrub_is_distinct_from_allow() {
        // A DLP-scrubbed action is still forwarded (proto Redact), but its
        // verdict must be `scrub`, never `allow` — scrubbed traffic is visible.
        assert_ne!(
            runtime_verdict(Decision::Redact as i32, false),
            runtime_verdict(Decision::Allow as i32, false)
        );
    }

    #[test]
    fn runtime_verdict_narrow_is_distinct_from_deny() {
        // A narrowed action was permitted, not blocked — its verdict must not
        // collapse onto `deny`.
        assert_ne!(
            runtime_verdict(Decision::Allow as i32, true),
            runtime_verdict(Decision::Deny as i32, false)
        );
    }

    #[test]
    fn runtime_verdict_unknown_decision_fails_closed_to_deny() {
        // An Unspecified or out-of-range code fails closed, mirroring the
        // enforcement paths' unknown-decision collapse. `narrowed` on an unknown
        // code is meaningless and must not upgrade it to `narrow`.
        assert_eq!(runtime_verdict(Decision::Unspecified as i32, false), "deny");
        assert_eq!(runtime_verdict(9999, false), "deny");
        assert_eq!(runtime_verdict(9999, true), "deny");
    }

    #[test]
    fn request_to_core_maps_tool_result_action() {
        // A ToolResult CheckAction (the second-pass evaluation the proxy issues
        // on a tool's response) must map to GovernanceAction::ToolResult with
        // the response body decoded from result_json bytes.
        use aa_proto::assembly::common::v1::AgentId as ProtoAgentId;
        use aa_proto::assembly::policy::v1::{action_context::Action, ActionContext, ToolResultContext};

        let req = CheckActionRequest {
            agent_id: Some(ProtoAgentId {
                org_id: String::new(),
                team_id: String::new(),
                agent_id: "agent-1".into(),
            }),
            context: Some(ActionContext {
                action: Some(Action::ToolResult(ToolResultContext {
                    tool_name: "web_search".into(),
                    tool_source: "mcp".into(),
                    result_json: br#"{"hits":3}"#.to_vec(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        };

        let (_ctx, action) = request_to_core(&req).expect("conversion must succeed");
        match action {
            GovernanceAction::ToolResult { tool_name, result } => {
                assert_eq!(tool_name, "web_search");
                assert_eq!(result, r#"{"hits":3}"#);
            }
            other => panic!("expected ToolResult action, got {other:?}"),
        }
    }

    #[test]
    fn approval_timed_out_with_requires_approval_fallback_denies() {
        // A TimedOut decision whose fallback is itself RequiresApproval cannot
        // re-enter the approval queue, so it must collapse to a hard Deny with
        // an explanatory reason rather than loop.
        let id: ApprovalRequestId = Uuid::new_v4().to_string().parse().unwrap();
        let decision = ApprovalDecision::TimedOut {
            fallback: PolicyResult::RequiresApproval { timeout_secs: 30 },
        };
        let resp = approval_decision_to_response(&decision, &id, 0, "rule-x");
        assert_eq!(resp.decision, Decision::Deny as i32);
        assert_eq!(resp.reason, "approval timed out");
    }

    #[test]
    fn held_approval_records_decision_latency_not_the_approval_wait() {
        // AAASM-5100 item B — semantic guardrail. A held/approval-pending action
        // may wait minutes for a human, but the recorded latency must be the
        // scanner's DECISION time (the `latency_us` measured in `evaluate_one`
        // around `engine.evaluate`, BEFORE the blocking wait), NOT the wall-clock
        // until the operator responds.
        //
        // `approval_decision_to_response` is the sole path that builds the final
        // response for a resolved approval, and it is called with that
        // pre-computed decision latency. Whatever the approval wait was, the
        // response carries exactly the decision latency it was given, and the
        // derived `latency_ms` (ms floor) follows it — never the human wait.
        let id: ApprovalRequestId = Uuid::new_v4().to_string().parse().unwrap();
        let decision_latency_us: i64 = 1_500; // measured decision time: 1.5 ms
        let approved = ApprovalDecision::Approved {
            by: "operator".into(),
            reason: None,
            conditions: Vec::new(),
        };

        let resp = approval_decision_to_response(&approved, &id, decision_latency_us, "needs-approval");

        // The recorded latency is the decision time it was handed, not the wait.
        assert_eq!(resp.decision_latency_us, decision_latency_us);
        // An approved approval is a permitted, un-narrowed action → `allow`, and
        // the ms latency floors the decision time (1500us → 1ms), independent of
        // however long the human took.
        assert_eq!(runtime_verdict(resp.decision, false), "allow");
        assert_eq!((resp.decision_latency_us.max(0) as u64) / 1_000, 1);
    }

    #[test]
    fn decide_request_unspecified_decision_is_an_error() {
        let req = DecideRequest {
            request_id: Uuid::new_v4().to_string(),
            decision: ApprovalDecisionType::DecisionUnspecified as i32,
            decided_by: "alice".into(),
            reason: String::new(),
        };
        let err = decide_request_to_core(&req).unwrap_err();
        assert!(matches!(err, ApprovalConvertError::UnspecifiedDecision));
    }
}
