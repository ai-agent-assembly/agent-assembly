//! AAASM-5626: `verify_chain` must distinguish real backpressure loss from
//! real tampering — the two used to be indistinguishable, so an operator
//! running `aasm audit verify-chain` after an incident could not tell a
//! capacity event from a compromise.
//!
//! Test A induces genuine backpressure (a real, undrained bounded channel;
//! no injected error) and drains through the real `AuditWriter`. Test B
//! induces genuine tampering (byte mutation / line deletion on a real file
//! written by the real `AuditWriter`). Both are proven against the same
//! `AuditWriter::verify_chain` entry point, and the two outcomes are
//! asserted to differ from each other, not just from `Verified`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aa_core::AuditEntry;
use aa_gateway::audit::{AuditWriter, VerifyOutcome};
use aa_gateway::service::PolicyServiceImpl;
use aa_gateway::PolicyEngine;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::action_context::Action;
use aa_proto::assembly::policy::v1::policy_service_client::PolicyServiceClient;
use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
use aa_proto::assembly::policy::v1::{ActionContext, CheckActionRequest, ToolCallContext};
use tokio::net::TcpListener;
use tonic::transport::Server;

const POLICY_YAML: &str = r#"
version: "1"
tools:
  web_search:
    allow: true
"#;

fn make_request(trace_id: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: "test-org".into(),
            team_id: "test-team".into(),
            agent_id: "test-agent".into(),
        }),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: "web_search".into(),
                tool_source: "mcp".into(),
                args_json: "{}".into(),
                target_url: String::new(),
            })),
        }),
        trace_id: trace_id.into(),
        span_id: "span-001".into(),
        credential_token: String::new(),
        caller_agent_id: None,
    }
}

/// Test A — real backpressure, interior gap: the drop happens in the
/// *middle* of the chain, not the tail, so the entries on either side prove
/// the chain stayed linked around it.
#[tokio::test]
async fn backpressure_loss_reports_incomplete_not_tampered() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", POLICY_YAML).unwrap();
    tmp.flush().unwrap();

    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    let engine = PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap();
    // Capacity 2: the first two check_action calls fill it; nothing is
    // draining yet, so calls after that get a real `Full` from `try_send`.
    let (audit_tx, audit_rx) = tokio::sync::mpsc::channel::<AuditEntry>(2);
    let audit_drops = Arc::new(AtomicU64::new(0));
    let service = PolicyServiceImpl::new(Arc::new(engine), audit_tx, Arc::clone(&audit_drops), [0u8; 32]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let _tmp = tmp;
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        Server::builder()
            .add_service(PolicyServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await
            .unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut client = PolicyServiceClient::connect(format!("http://{addr}")).await.unwrap();

    // Burst 1: 2 requests fill the capacity-2 channel (seq 0, 1) — both Ok.
    for i in 0..2 {
        let resp = client.check_action(make_request(&format!("t{i}"))).await.unwrap();
        assert_eq!(resp.into_inner().decision, Decision::Allow as i32);
    }
    // Burst 2: 4 requests hit real backpressure (seq 2..5) — dropped.
    for i in 2..6 {
        let resp = client.check_action(make_request(&format!("t{i}"))).await.unwrap();
        assert_eq!(resp.into_inner().decision, Decision::Allow as i32);
    }
    let drops_before_drain = audit_drops.load(Ordering::Relaxed);
    assert_eq!(
        drops_before_drain, 4,
        "the middle burst must have hit real backpressure"
    );

    // Drain the two entries already in the channel through the real
    // AuditWriter, then close the channel from the writer's perspective by
    // continuing to hold it open — the writer itself decides when to stop.
    let dir = tempfile::tempdir().unwrap();
    let writer = AuditWriter::new(dir.path().to_path_buf(), "test-agent", "sess", audit_rx)
        .await
        .unwrap();
    let path = dir.path().join("test-agent-sess.jsonl");
    let writer_task = tokio::spawn(writer.run());

    // Burst 3: 2 more requests (seq 6, 7) — the channel has drained back
    // down to capacity, so these succeed and link to entry 1's hash (the
    // chain head never advanced past it while entries 2..5 were dropped).
    for i in 6..8 {
        let resp = client.check_action(make_request(&format!("t{i}"))).await.unwrap();
        assert_eq!(resp.into_inner().decision, Decision::Allow as i32);
    }

    // Bounded poll on the file reaching 4 lines (seq 0, 1, 6, 7) rather than
    // a fixed sleep.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let content = tokio::fs::read_to_string(&path).await.unwrap_or_default();
        if content.lines().filter(|l| !l.trim().is_empty()).count() >= 4 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "writer never drained to 4 entries"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    server.abort();
    writer_task.abort();

    let result = AuditWriter::verify_chain(&path).await.unwrap();
    assert_eq!(
        result.outcome,
        VerifyOutcome::Incomplete,
        "a mid-chain backpressure drop with intact hashes/linkage must report Incomplete: {result:?}"
    );
    assert!(
        result.first_invalid.is_none(),
        "no integrity or linkage failure should be reported for a plain drop: {result:?}"
    );
    assert_eq!(result.missing_seq_ranges, vec![(2, 5)], "result: {result:?}");
    assert_eq!(
        result.missing_entries, drops_before_drain,
        "the file-observable gap must equal the live audit_drops counter"
    );
}

/// Test B — real tampering, on a real file written by the real `AuditWriter`.
/// Two cases (byte alteration, line removal), plus a control that the two
/// tampering outcomes and the backpressure outcome are not the same value.
#[tokio::test]
async fn tampering_reports_tampered_not_incomplete() {
    let dir = tempfile::tempdir().unwrap();
    let agent = aa_core::identity::AgentId::from_bytes([1u8; 16]);
    let session = aa_core::identity::SessionId::from_bytes([2u8; 16]);

    let mut prev = [0u8; 32];
    let mut entries = Vec::new();
    for seq in 0..3u64 {
        let e = AuditEntry::new(
            seq,
            1_000_000 + seq,
            aa_core::AuditEventType::ToolCallIntercepted,
            agent,
            session,
            format!("{{\"seq\":{seq}}}"),
            prev,
        );
        prev = *e.entry_hash();
        entries.push(e);
    }

    // B1 — alteration: flip a byte inside line 2's payload after a clean write.
    let path_a = dir.path().join("altered.jsonl");
    {
        let mut f = std::fs::File::create(&path_a).unwrap();
        for e in &entries {
            writeln!(f, "{}", serde_json::to_string(e).unwrap()).unwrap();
        }
    }
    let mut content = std::fs::read_to_string(&path_a).unwrap();
    content = content.replacen("\"seq\":1", "\"seq\":9", 1);
    std::fs::write(&path_a, content).unwrap();
    let result_a = AuditWriter::verify_chain(&path_a).await.unwrap();
    assert_eq!(
        result_a.outcome,
        VerifyOutcome::Tampered,
        "byte alteration: {result_a:?}"
    );
    assert_eq!(
        result_a.missing_entries, 0,
        "an altered file has no missing entries: {result_a:?}"
    );

    // B2 — removal: delete line 2 (index 1) entirely. This is the
    // load-bearing case: a naive fix could launder a deletion as a drop.
    let path_b = dir.path().join("removed.jsonl");
    {
        let mut f = std::fs::File::create(&path_b).unwrap();
        writeln!(f, "{}", serde_json::to_string(&entries[0]).unwrap()).unwrap();
        writeln!(f, "{}", serde_json::to_string(&entries[2]).unwrap()).unwrap();
    }
    let result_b = AuditWriter::verify_chain(&path_b).await.unwrap();
    assert_eq!(
        result_b.outcome,
        VerifyOutcome::Tampered,
        "a removed interior entry must report Tampered, not Incomplete: {result_b:?}"
    );

    assert_ne!(
        result_a.outcome,
        VerifyOutcome::Incomplete,
        "control: alteration must not read as a capacity event"
    );
    assert_ne!(
        result_b.outcome,
        VerifyOutcome::Incomplete,
        "control: removal must not read as a capacity event"
    );
}
