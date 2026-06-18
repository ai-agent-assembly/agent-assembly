//! AAASM-3376 — trace context (trace_id / span_id) persisted in the
//! CheckAction audit entry payload.
//!
//! Regression: the live `CheckAction` handler stored only
//! `session_id = SHA256(trace_id)[:16]` (a one-way hash) and dropped the raw
//! `trace_id` and the per-action `span_id`. These tests drive `check_action`
//! and assert that both survive on the emitted `AuditEntry`'s payload.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, LlmCallContext};
use tokio::sync::mpsc;
use tonic::Request;

const ALLOW_ALL_YAML: &str = r#"
version: "1"
"#;

fn make_service(audit_tx: mpsc::Sender<AuditEntry>) -> PolicyServiceImpl {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", ALLOW_ALL_YAML).unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let audit_drops = Arc::new(AtomicU64::new(0));
    PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32])
}

fn llm_request(trace_id: &str, span_id: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-1".into(),
        }),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: "gpt-4o".into(),
                prompt_tokens: 10,
                contains_pii: false,
            })),
        }),
        trace_id: trace_id.into(),
        span_id: span_id.into(),
        credential_token: String::new(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn trace_id_and_span_id_persisted_in_audit_payload() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    service
        .check_action(Request::new(llm_request("trace-abc-123", "span-xyz-789")))
        .await
        .expect("check_action ok");

    let entry = audit_rx.recv().await.expect("audit entry emitted");
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("payload is JSON");

    assert_eq!(
        payload.get("trace_id").and_then(|v| v.as_str()),
        Some("trace-abc-123"),
        "raw trace_id must be persisted in the audit payload"
    );
    assert_eq!(
        payload.get("span_id").and_then(|v| v.as_str()),
        Some("span-xyz-789"),
        "span_id must be persisted in the audit payload"
    );
}

#[tokio::test]
async fn empty_trace_and_span_are_null_in_payload() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    service
        .check_action(Request::new(llm_request("", "")))
        .await
        .expect("check_action ok");

    let entry = audit_rx.recv().await.expect("audit entry emitted");
    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("payload is JSON");

    // Empty trace/span serialise as JSON null (absent value), never as "".
    assert!(
        payload.get("trace_id").map(|v| v.is_null()).unwrap_or(true),
        "empty trace_id must be null in the payload"
    );
    assert!(
        payload.get("span_id").map(|v| v.is_null()).unwrap_or(true),
        "empty span_id must be null in the payload"
    );
}
