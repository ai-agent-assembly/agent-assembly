//! AAASM-3353 — LLM-call budget accrual in the live `CheckAction` handler.
//!
//! Regression: the gRPC handler used to call only `engine.evaluate` (which
//! *reads* accumulated spend at Stage 7) but never *recorded* spend, so daily /
//! monthly budget limits never fired. These tests drive `check_action` directly
//! and assert that spend accrues and a later call is denied once the limit is
//! exceeded.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, LlmCallContext};
use tokio::sync::mpsc;
use tonic::Request;

/// Daily limit of $0.50. A single gpt-4o call with 200k prompt tokens costs
/// `0.005 * 200 = $1.00`, which exceeds the limit on the *next* check.
const BUDGET_YAML: &str = r#"
version: "1"
budget:
  daily_limit_usd: 0.5
  action_on_exceed: deny
"#;

/// A daily limit small enough that the server-side prompt-token floor priced for
/// a *single* `prompt_tokens: 0` call (AAASM-4125) already exceeds it on the next
/// check — proving the floored call accrued spend rather than pricing to $0.
const TINY_BUDGET_YAML: &str = r#"
version: "1"
budget:
  daily_limit_usd: 0.001
  action_on_exceed: deny
"#;

fn make_service(audit_tx: mpsc::Sender<AuditEntry>) -> PolicyServiceImpl {
    make_service_with_budget(BUDGET_YAML, audit_tx)
}

fn make_service_with_budget(budget_yaml: &str, audit_tx: mpsc::Sender<AuditEntry>) -> PolicyServiceImpl {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", budget_yaml).unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    let audit_drops = Arc::new(AtomicU64::new(0));
    PolicyServiceImpl::new(Arc::new(engine), audit_tx, audit_drops, [0u8; 32])
}

fn llm_call_request(model: &str, prompt_tokens: i32) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-1".into(),
        }),
        action_type: ActionType::LlmCall as i32,
        context: Some(ActionContext {
            action: Some(Action::LlmCall(LlmCallContext {
                model: model.into(),
                prompt_tokens,
                contains_pii: false,
            })),
        }),
        trace_id: "trace-budget".into(),
        span_id: "span-budget".into(),
        credential_token: String::new(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn llm_spend_accrues_and_later_call_is_denied_once_limit_exceeded() {
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let service = make_service(audit_tx);

    // First call: spend is $0 at evaluation, so it is allowed. It then accrues
    // $1.00 (gpt-4o, 200k prompt tokens) against the agent's daily budget.
    let first = service
        .check_action(Request::new(llm_call_request("gpt-4o", 200_000)))
        .await
        .expect("first check_action ok")
        .into_inner();
    assert_eq!(
        first.decision,
        Decision::Allow as i32,
        "first call must be allowed (no spend recorded yet)"
    );

    // Second call: accumulated spend ($1.00) now exceeds the $0.50 daily limit,
    // so Stage 7 denies it. Without accrual this would (incorrectly) be allowed.
    let second = service
        .check_action(Request::new(llm_call_request("gpt-4o", 200_000)))
        .await
        .expect("second check_action ok")
        .into_inner();
    assert_eq!(
        second.decision,
        Decision::Deny as i32,
        "second call must be denied once accrued spend exceeds the daily limit"
    );
    assert!(
        second.reason.contains("budget"),
        "deny reason must reference the budget, got: {}",
        second.reason
    );
}

#[tokio::test]
async fn zero_prompt_tokens_still_accrues_spend_and_engages_cap() {
    // AAASM-4125 fail-closed: `prompt_tokens` is client-supplied. A declared `0`
    // (or a negative / omitted value) used to price the pre-execution call to
    // $0.00, tripping the `cost <= 0.0` accrual short-circuit so NO spend accrued
    // — an agent that always sent `prompt_tokens: 0` had unmetered LLM spend
    // indefinitely, even for a known priced model. A non-positive count must now
    // be floored to a conservative server-side minimum so the call still accrues
    // and the daily/monthly cap engages.
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let service = make_service_with_budget(TINY_BUDGET_YAML, audit_tx);

    // First call: spend is $0 at evaluation, so it is allowed. Despite the
    // client declaring `prompt_tokens: 0` for a known priced model (gpt-4o), it
    // must accrue the floored cost against the tiny daily budget.
    let first = service
        .check_action(Request::new(llm_call_request("gpt-4o", 0)))
        .await
        .expect("first check_action ok")
        .into_inner();
    assert_eq!(
        first.decision,
        Decision::Allow as i32,
        "first zero-token call must be allowed (no spend recorded yet)"
    );

    // Second call: the floored spend from the first call now exceeds the tiny
    // daily limit, so Stage 7 denies it. Before the fix this stayed allowed
    // forever because a client-declared 0 priced to $0 and never accrued.
    let second = service
        .check_action(Request::new(llm_call_request("gpt-4o", 0)))
        .await
        .expect("second check_action ok")
        .into_inner();
    assert_eq!(
        second.decision,
        Decision::Deny as i32,
        "zero-token spend must accrue and eventually hit the daily cap"
    );
    assert!(
        second.reason.contains("budget"),
        "deny reason must reference the budget, got: {}",
        second.reason
    );
}

#[tokio::test]
async fn unknown_model_accrues_fallback_spend_and_engages_cap() {
    // AAASM-4069 fail-closed: an unrecognised model name must NOT price to
    // $0.00. Previously it did, so no spend accrued and the daily/monthly cap
    // was bypassed entirely — an agent could pick any model outside the
    // built-in pricing table for unlimited unmetered spend. It must now be
    // priced at the conservative fallback rate so spend accrues and the cap
    // engages just like a known model.
    let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let service = make_service(audit_tx);

    // First call: spend is $0 at evaluation, so it is allowed. It then accrues
    // the fallback-priced cost (1M prompt tokens at the costliest-known rate,
    // ~$15) against the agent's $0.50 daily budget.
    let first = service
        .check_action(Request::new(llm_call_request("some-unknown-model", 1_000_000)))
        .await
        .expect("first check_action ok")
        .into_inner();
    assert_eq!(
        first.decision,
        Decision::Allow as i32,
        "first unknown-model call must be allowed (no spend recorded yet)"
    );

    // Second call: accrued fallback spend now exceeds the $0.50 daily limit, so
    // Stage 7 denies it. Before the fix this stayed allowed forever.
    let second = service
        .check_action(Request::new(llm_call_request("some-unknown-model", 1_000_000)))
        .await
        .expect("second check_action ok")
        .into_inner();
    assert_eq!(
        second.decision,
        Decision::Deny as i32,
        "unknown-model spend must accrue and eventually hit the daily cap"
    );
    assert!(
        second.reason.contains("budget"),
        "deny reason must reference the budget, got: {}",
        second.reason
    );
}
