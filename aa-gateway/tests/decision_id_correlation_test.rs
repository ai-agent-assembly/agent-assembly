//! AAASM-5002 — `CheckActionResponse.decision_id` joins the caller's response
//! to its exact `AuditEntry`.
//!
//! Regression: neither `CheckActionResponse` nor the on-disk `AuditEntry`
//! carried any id at all, so an operator had no way to locate the audit
//! record for a given SDK-returned decision short of approximate wall-clock
//! time plus a single-agent assumption. These tests drive `check_action` /
//! `batch_check` directly and assert the SAME id appears on both halves.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, BatchCheckRequest, CheckActionRequest, LlmCallContext};
use tokio::sync::mpsc;
use tonic::Request;
use uuid::Uuid;

const ALLOW_ALL_YAML: &str = aa_gateway::policy::resolve::ALLOW_ALL_TEMPLATE;

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

// (a)+(b)+(c) — present, well-formed, and joined to the audit entry as a
// first-class field (not stuffed into the payload).
#[tokio::test]
async fn decision_id_is_well_formed_and_joins_the_audit_entry() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    let resp = service
        .check_action(Request::new(llm_request("trace-1", "span-1")))
        .await
        .expect("check_action ok")
        .into_inner();

    assert!(!resp.decision_id.is_empty(), "decision_id must be present");
    assert!(
        Uuid::parse_str(&resp.decision_id).is_ok(),
        "decision_id must be a well-formed UUID"
    );

    let entry = audit_rx.recv().await.expect("audit entry emitted");
    assert_eq!(
        entry.decision_id(),
        Some(resp.decision_id.as_str()),
        "the audit entry's decision_id must equal the caller's response decision_id"
    );

    let payload: serde_json::Value = serde_json::from_str(entry.payload()).expect("payload is JSON");
    assert!(
        payload.get("decision_id").is_none(),
        "decision_id must be first-class on AuditEntry, not duplicated into payload"
    );
}

// (d) — per-decision, not per-service or per-request-shape: two identical
// successive requests must not share a decision_id.
#[tokio::test]
async fn successive_identical_requests_get_distinct_decision_ids() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    let resp1 = service
        .check_action(Request::new(llm_request("trace-1", "span-1")))
        .await
        .expect("check_action ok")
        .into_inner();
    let resp2 = service
        .check_action(Request::new(llm_request("trace-1", "span-1")))
        .await
        .expect("check_action ok")
        .into_inner();

    assert_ne!(
        resp1.decision_id, resp2.decision_id,
        "two distinct decisions must not share an id, even for identical requests"
    );

    let entry1 = audit_rx.recv().await.expect("first audit entry emitted");
    let entry2 = audit_rx.recv().await.expect("second audit entry emitted");
    assert_eq!(entry1.decision_id(), Some(resp1.decision_id.as_str()));
    assert_eq!(entry2.decision_id(), Some(resp2.decision_id.as_str()));
}

// (f) — a gateway-minted id is independent of the caller-supplied trace_id:
// an empty trace_id must still produce a decision_id. This is the claim that
// separates a gateway-minted id from one derived from trace_id/span_id.
#[tokio::test]
async fn empty_trace_id_still_gets_a_decision_id() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    let resp = service
        .check_action(Request::new(llm_request("", "")))
        .await
        .expect("check_action ok")
        .into_inner();

    assert!(
        !resp.decision_id.is_empty(),
        "decision_id must be present even when the caller supplied no trace_id"
    );
    let entry = audit_rx.recv().await.expect("audit entry emitted");
    assert_eq!(entry.decision_id(), Some(resp.decision_id.as_str()));
}

// (e) — batch_check mints one id per entry, not one per batch.
#[tokio::test]
async fn batch_check_mints_a_distinct_decision_id_per_entry() {
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(16);
    let service = make_service(audit_tx);

    let batch = BatchCheckRequest {
        requests: vec![llm_request("trace-a", "span-a"), llm_request("trace-b", "span-b")],
    };
    let resp = service
        .batch_check(Request::new(batch))
        .await
        .expect("batch_check ok")
        .into_inner();

    assert_eq!(resp.responses.len(), 2);
    assert_ne!(
        resp.responses[0].decision_id, resp.responses[1].decision_id,
        "two batch entries must not share a decision_id"
    );
    assert!(!resp.responses[0].decision_id.is_empty());
    assert!(!resp.responses[1].decision_id.is_empty());

    let entry_a = audit_rx.recv().await.expect("first audit entry emitted");
    let entry_b = audit_rx.recv().await.expect("second audit entry emitted");
    assert_eq!(entry_a.decision_id(), Some(resp.responses[0].decision_id.as_str()));
    assert_eq!(entry_b.decision_id(), Some(resp.responses[1].decision_id.as_str()));
}
