//! Unit tests for `aa_gateway::service::convert` — proto ↔ core type conversions.

use aa_core::{FileMode, GovernanceAction, PolicyResult};
use aa_gateway::engine::EvaluationResult;
use aa_gateway::service::convert::{
    approval_decision_to_response, eval_result_to_response, request_to_core, result_to_response, ConvertError,
};
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, FileOpContext, LlmCallContext, NetworkCallContext,
    ProcessExecContext, ToolCallContext,
};
use aa_runtime::approval::ApprovalDecision;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn base_request(action: Action) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org-1".into(),
            team_id: "team-a".into(),
            agent_id: "agent-42".into(),
        }),
        credential_token: "tok".into(),
        trace_id: "trace-1".into(),
        span_id: "span-1".into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext { action: Some(action) }),
        caller_agent_id: None,
    }
}

// ── Inbound conversion tests ─────────────────────────────────────────────────

#[test]
fn tool_call_context_converts_to_governance_action() {
    let req = base_request(Action::ToolCall(ToolCallContext {
        tool_name: "web_search".into(),
        tool_source: "mcp".into(),
        args_json: b"{\"q\":\"rust\"}".to_vec(),
        target_url: String::new(),
    }));
    let (ctx, action) = request_to_core(&req).unwrap();
    assert!(!ctx.metadata.is_empty());
    match action {
        GovernanceAction::ToolCall { name, args } => {
            assert_eq!(name, "web_search");
            assert!(args.contains("rust"));
        }
        other => panic!("expected ToolCall, got {:?}", other),
    }
}

#[test]
fn file_op_read_converts_to_file_access() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "read".into(),
        path: "/etc/passwd".into(),
        is_sensitive_path: true,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::FileAccess { path, mode } => {
            assert_eq!(path, "/etc/passwd");
            assert_eq!(mode, FileMode::Read);
        }
        other => panic!("expected FileAccess, got {:?}", other),
    }
}

#[test]
fn file_op_write_converts_to_file_access() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "write".into(),
        path: "/tmp/out.txt".into(),
        is_sensitive_path: false,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::FileAccess { mode, .. } => assert_eq!(mode, FileMode::Write),
        other => panic!("expected FileAccess, got {:?}", other),
    }
}

#[test]
fn file_op_delete_converts_to_file_access() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "delete".into(),
        path: "/tmp/junk".into(),
        is_sensitive_path: false,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::FileAccess { mode, .. } => assert_eq!(mode, FileMode::Delete),
        other => panic!("expected FileAccess, got {:?}", other),
    }
}

#[test]
fn network_call_converts_to_network_request() {
    let req = base_request(Action::NetworkCall(NetworkCallContext {
        host: "api.openai.com".into(),
        port: 443,
        protocol: "https".into(),
        in_allowlist: true,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::NetworkRequest { url, method } => {
            assert_eq!(url, "https://api.openai.com:443");
            assert_eq!(method, "CONNECT");
        }
        other => panic!("expected NetworkRequest, got {:?}", other),
    }
}

#[test]
fn process_exec_converts_to_process_exec() {
    let req = base_request(Action::ProcessExec(ProcessExecContext {
        command: "ls".into(),
        args: vec!["-la".into(), "/tmp".into()],
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::ProcessExec { command } => {
            assert_eq!(command, "ls -la /tmp");
        }
        other => panic!("expected ProcessExec, got {:?}", other),
    }
}

#[test]
fn llm_call_converts_to_tool_call() {
    let req = base_request(Action::LlmCall(LlmCallContext {
        model: "gpt-4o".into(),
        prompt_tokens: 500,
        contains_pii: false,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::ToolCall { name, args } => {
            assert_eq!(name, "llm_call");
            assert!(args.contains("gpt-4o"));
        }
        other => panic!("expected ToolCall, got {:?}", other),
    }
}

#[test]
fn missing_agent_id_returns_error() {
    let req = CheckActionRequest {
        agent_id: None,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "t".into(),
                ..Default::default()
            })),
        }),
        ..Default::default()
    };
    let err = request_to_core(&req).unwrap_err();
    assert!(matches!(err, ConvertError::MissingAgentId));
}

#[test]
fn missing_context_returns_error() {
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            agent_id: "a".into(),
            ..Default::default()
        }),
        context: None,
        ..Default::default()
    };
    let err = request_to_core(&req).unwrap_err();
    assert!(matches!(err, ConvertError::MissingContext));
}

// ── Additional inbound conversion tests ─────────────────────────────────────

#[test]
fn file_op_create_maps_to_write_mode() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "create".into(),
        path: "/tmp/new.txt".into(),
        is_sensitive_path: false,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::FileAccess { mode, .. } => assert_eq!(mode, FileMode::Write),
        other => panic!("expected FileAccess, got {:?}", other),
    }
}

#[test]
fn file_op_append_converts_to_append_mode() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "append".into(),
        path: "/var/log/app.log".into(),
        is_sensitive_path: false,
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::FileAccess { mode, .. } => assert_eq!(mode, FileMode::Append),
        other => panic!("expected FileAccess, got {:?}", other),
    }
}

#[test]
fn unknown_file_op_returns_error() {
    let req = base_request(Action::FileOp(FileOpContext {
        operation: "chmod".into(),
        path: "/tmp/f".into(),
        is_sensitive_path: false,
    }));
    let err = request_to_core(&req).unwrap_err();
    assert!(matches!(err, ConvertError::UnknownFileOp(ref s) if s == "chmod"));
}

#[test]
fn process_exec_with_empty_args_uses_command_only() {
    let req = base_request(Action::ProcessExec(ProcessExecContext {
        command: "whoami".into(),
        args: vec![],
    }));
    let (_, action) = request_to_core(&req).unwrap();
    match action {
        GovernanceAction::ProcessExec { command } => assert_eq!(command, "whoami"),
        other => panic!("expected ProcessExec, got {:?}", other),
    }
}

#[test]
fn missing_action_oneof_returns_missing_context() {
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            agent_id: "a".into(),
            ..Default::default()
        }),
        context: Some(ActionContext { action: None }),
        ..Default::default()
    };
    let err = request_to_core(&req).unwrap_err();
    assert!(matches!(err, ConvertError::MissingContext));
}

#[test]
fn metadata_populated_from_org_team_credential_span() {
    let req = base_request(Action::ToolCall(ToolCallContext {
        tool_name: "t".into(),
        ..Default::default()
    }));
    let (ctx, _) = request_to_core(&req).unwrap();
    assert_eq!(ctx.metadata.get("org_id").unwrap(), "org-1");
    assert_eq!(ctx.metadata.get("team_id").unwrap(), "team-a");
    assert_eq!(ctx.metadata.get("credential_token").unwrap(), "tok");
    assert_eq!(ctx.metadata.get("span_id").unwrap(), "span-1");
}

#[test]
fn empty_metadata_fields_are_omitted() {
    let req = CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            agent_id: "a".into(),
            org_id: String::new(),
            team_id: String::new(),
        }),
        credential_token: String::new(),
        trace_id: "t".into(),
        span_id: String::new(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "t".into(),
                ..Default::default()
            })),
        }),
        caller_agent_id: None,
    };
    let (ctx, _) = request_to_core(&req).unwrap();
    assert!(ctx.metadata.is_empty());
}

// ── Outbound conversion tests ────────────────────────────────────────────────

#[test]
fn eval_result_with_credential_findings_returns_redact() {
    let eval = EvaluationResult {
        decision: PolicyResult::Allow,
        redacted_payload: Some("redacted text".into()),
        credential_findings: vec![aa_core::CredentialFinding::from_regex_match(0, 10)],
        deny_action: None,
    };
    let resp = eval_result_to_response(&eval, 77, "");
    assert_eq!(resp.decision, Decision::Redact as i32);
    assert_eq!(resp.reason, "sensitive data detected");
    assert_eq!(resp.policy_rule, "data_pattern_scan");
    assert!(resp.redact.is_some());
    let redact = resp.redact.unwrap();
    assert_eq!(redact.rules.len(), 1);
    assert_eq!(redact.rules[0].replacement, "[REDACTED]");
    assert_eq!(resp.decision_latency_us, 77);
}

#[test]
fn allow_result_to_response() {
    let resp = result_to_response(&PolicyResult::Allow, 42, "");
    assert_eq!(resp.decision, Decision::Allow as i32);
    assert!(resp.reason.is_empty());
    assert_eq!(resp.decision_latency_us, 42);
}

#[test]
fn deny_result_to_response() {
    let resp = result_to_response(
        &PolicyResult::Deny {
            reason: "blocked".into(),
        },
        100,
        "tool_deny",
    );
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "blocked");
    assert_eq!(resp.policy_rule, "tool_deny");
    assert_eq!(resp.decision_latency_us, 100);
}

#[test]
#[should_panic(expected = "RequiresApproval must be handled before conversion")]
fn requires_approval_result_to_response_panics() {
    let _ = result_to_response(
        &PolicyResult::RequiresApproval { timeout_secs: 30 },
        50,
        "approval_cond",
    );
}

// ── ApprovalDecision → CheckActionResponse tests ────────────────────────────

#[test]
fn approved_decision_maps_to_allow() {
    let id = uuid::Uuid::new_v4();
    let decision = ApprovalDecision::Approved {
        by: "alice".to_string(),
        reason: Some("looks good".to_string()),
    };
    let resp = approval_decision_to_response(&decision, &id, 55, "requires_approval");
    assert_eq!(resp.decision, Decision::Allow as i32);
    assert!(resp.reason.is_empty());
    assert_eq!(resp.approval_id, id.to_string());
    assert_eq!(resp.decision_latency_us, 55);
    assert_eq!(resp.policy_rule, "requires_approval");
}

#[test]
fn rejected_decision_maps_to_deny() {
    let id = uuid::Uuid::new_v4();
    let decision = ApprovalDecision::Rejected {
        by: "bob".to_string(),
        reason: "not allowed".to_string(),
    };
    let resp = approval_decision_to_response(&decision, &id, 88, "requires_approval");
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "not allowed");
    assert_eq!(resp.approval_id, id.to_string());
    assert_eq!(resp.decision_latency_us, 88);
}

#[test]
fn timed_out_decision_with_deny_fallback() {
    let id = uuid::Uuid::new_v4();
    let decision = ApprovalDecision::TimedOut {
        fallback: PolicyResult::Deny {
            reason: "approval timed out".to_string(),
        },
    };
    let resp = approval_decision_to_response(&decision, &id, 120, "requires_approval");
    assert_eq!(resp.decision, Decision::Deny as i32);
    assert_eq!(resp.reason, "approval timed out");
    assert_eq!(resp.approval_id, id.to_string());
}

#[test]
fn timed_out_decision_with_allow_fallback() {
    let id = uuid::Uuid::new_v4();
    let decision = ApprovalDecision::TimedOut {
        fallback: PolicyResult::Allow,
    };
    let resp = approval_decision_to_response(&decision, &id, 200, "requires_approval");
    assert_eq!(resp.decision, Decision::Allow as i32);
    assert!(resp.reason.is_empty());
    assert_eq!(resp.approval_id, id.to_string());
}
