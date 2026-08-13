//! AAASM-3356 — audit `seq` recovery across process restarts.
//!
//! Regression: the service seeded `seq: AtomicU64::new(0)` and, on restart,
//! recovered the hash-chain head but NOT the seq, so sequence numbers restarted
//! at 0 and produced duplicates in the WORM log. `with_initial_seq` (seeded from
//! `AuditWriter::read_last_seq`) fixes this. This test drives `check_action`
//! across a simulated restart and asserts the seq continues monotonically.

use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyService;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use tokio::sync::mpsc;
use tonic::Request;

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;

fn make_engine() -> Arc<PolicyEngine> {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY_YAML).unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    Arc::new(PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap())
}

fn tool_call_request() -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "org".into(),
            team_id: "team".into(),
            agent_id: "agent-1".into(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                args_json: b"{}".to_vec(),
                target_url: String::new(),
            })),
        }),
        trace_id: "trace-seq".into(),
        span_id: "span-seq".into(),
        credential_token: String::new(),
        caller_agent_id: None,
    }
}

#[tokio::test]
async fn seq_continues_monotonically_after_restart() {
    let engine = make_engine();

    // ── First "process": emit two entries (seq 0 and 1). ───────────────────
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let drops = Arc::new(AtomicU64::new(0));
    let svc = PolicyServiceImpl::new(Arc::clone(&engine), audit_tx, drops, [0u8; 32]);

    svc.check_action(Request::new(tool_call_request())).await.unwrap();
    svc.check_action(Request::new(tool_call_request())).await.unwrap();
    drop(svc); // close the tx so the receiver drains to completion

    let mut first_run_seqs = Vec::new();
    while let Some(entry) = audit_rx.recv().await {
        first_run_seqs.push(entry.seq());
    }
    assert_eq!(first_run_seqs, vec![0, 1], "first run must emit seqs 0 and 1");
    let last_seq = *first_run_seqs.last().unwrap();

    // ── Restart: seed the new service from last_seq + 1. ───────────────────
    let (audit_tx2, mut audit_rx2) = mpsc::channel::<AuditEntry>(4096);
    let drops2 = Arc::new(AtomicU64::new(0));
    let svc2 = PolicyServiceImpl::new(Arc::clone(&engine), audit_tx2, drops2, [0u8; 32]).with_initial_seq(last_seq + 1);

    svc2.check_action(Request::new(tool_call_request())).await.unwrap();
    drop(svc2);

    let mut second_run_seqs = Vec::new();
    while let Some(entry) = audit_rx2.recv().await {
        second_run_seqs.push(entry.seq());
    }

    assert_eq!(
        second_run_seqs,
        vec![2],
        "post-restart seq must continue at {} (no duplicate of {:?})",
        last_seq + 1,
        first_run_seqs
    );
}

#[tokio::test]
async fn without_recovery_seq_would_duplicate() {
    // Demonstrates the bug shape: a fresh service WITHOUT `with_initial_seq`
    // restarts the counter at 0, duplicating the previous run's seqs.
    let engine = make_engine();

    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let drops = Arc::new(AtomicU64::new(0));
    let svc = PolicyServiceImpl::new(Arc::clone(&engine), audit_tx, drops, [0u8; 32]);
    svc.check_action(Request::new(tool_call_request())).await.unwrap();
    drop(svc);
    let first = audit_rx.recv().await.unwrap().seq();
    assert_eq!(first, 0);

    let (audit_tx2, mut audit_rx2) = mpsc::channel::<AuditEntry>(4096);
    let drops2 = Arc::new(AtomicU64::new(0));
    let svc2 = PolicyServiceImpl::new(Arc::clone(&engine), audit_tx2, drops2, [0u8; 32]);
    svc2.check_action(Request::new(tool_call_request())).await.unwrap();
    drop(svc2);
    let second = audit_rx2.recv().await.unwrap().seq();

    // Without recovery the second run also starts at 0 — a duplicate.
    assert_eq!(second, 0, "fresh service (no recovery) duplicates seq 0");
}
