//! AAASM-3363 — `AuditService` `seq` recovery across process restarts.
//!
//! Sibling bug to AAASM-3356: `AuditServiceImpl` keeps its OWN `seq` atomic,
//! independent of `PolicyServiceImpl`. It also seeded `seq: AtomicU64::new(0)`
//! and recovered the hash-chain head but NOT the seq on restart, so
//! `AuditService`-emitted events restarted at seq 0 and produced duplicates in
//! the WORM log. `with_initial_seq` (seeded from `AuditWriter::read_last_seq`)
//! fixes this. This test drives `report_events` across a simulated restart and
//! asserts the seq continues monotonically.

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::iam::VerifiedCaller;
use aa_gateway::registry::convert::proto_agent_id_to_key;
use aa_gateway::service::AuditServiceImpl;
use aa_proto::assembly::audit::v1::audit_service_server::AuditService;
use aa_proto::assembly::audit::v1::{AuditEvent, ReportEventsRequest};
use aa_proto::assembly::common::v1::{AgentId as ProtoAgentId, Decision};
use tokio::sync::mpsc;
use tonic::Request;

fn proto_agent() -> ProtoAgentId {
    ProtoAgentId {
        org_id: "org".into(),
        team_id: "team".into(),
        agent_id: "agent-1".into(),
    }
}

fn report_request() -> ReportEventsRequest {
    ReportEventsRequest {
        events: vec![AuditEvent {
            event_id: "evt-seq".into(),
            agent_id: Some(proto_agent()),
            decision: Decision::Allow as i32,
            trace_id: "trace-seq".into(),
            span_id: "span-seq".into(),
            ..Default::default()
        }],
    }
}

/// Wrap a `report_request` in a `Request` carrying a `VerifiedCaller` bound to the
/// same agent identity, as the fail-closed auth interceptor would (AAASM-3869).
fn authed_report_request() -> Request<ReportEventsRequest> {
    let mut req = Request::new(report_request());
    req.extensions_mut().insert(VerifiedCaller {
        agent_key: proto_agent_id_to_key(&proto_agent()),
        team_id: Some("team".into()),
        org_id: Some("org".into()),
    });
    req
}

#[tokio::test]
async fn audit_service_seq_continues_monotonically_after_restart() {
    // ── First "process": emit two entries (seq 0 and 1). ───────────────────
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let drops = Arc::new(AtomicU64::new(0));
    let svc = AuditServiceImpl::new(audit_tx, drops, [0u8; 32]);

    svc.report_events(authed_report_request()).await.unwrap();
    svc.report_events(authed_report_request()).await.unwrap();
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
    let svc2 = AuditServiceImpl::new(audit_tx2, drops2, [0u8; 32]).with_initial_seq(last_seq + 1);

    svc2.report_events(authed_report_request()).await.unwrap();
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
async fn audit_service_without_recovery_seq_would_duplicate() {
    // Demonstrates the bug shape: a fresh service WITHOUT `with_initial_seq`
    // restarts the counter at 0, duplicating the previous run's seqs.
    let (audit_tx, mut audit_rx) = mpsc::channel::<AuditEntry>(4096);
    let drops = Arc::new(AtomicU64::new(0));
    let svc = AuditServiceImpl::new(audit_tx, drops, [0u8; 32]);
    svc.report_events(authed_report_request()).await.unwrap();
    drop(svc);
    let first = audit_rx.recv().await.unwrap().seq();
    assert_eq!(first, 0);

    let (audit_tx2, mut audit_rx2) = mpsc::channel::<AuditEntry>(4096);
    let drops2 = Arc::new(AtomicU64::new(0));
    let svc2 = AuditServiceImpl::new(audit_tx2, drops2, [0u8; 32]);
    svc2.report_events(authed_report_request()).await.unwrap();
    drop(svc2);
    let second = audit_rx2.recv().await.unwrap().seq();

    // Without recovery the second run also starts at 0 — a duplicate.
    assert_eq!(second, 0, "fresh service (no recovery) duplicates seq 0");
}
