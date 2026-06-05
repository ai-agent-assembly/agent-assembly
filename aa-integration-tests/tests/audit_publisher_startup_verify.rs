//! AAASM-2594 — e2e verification of the aa-runtime audit-publisher wiring
//! (Story AAASM-2547).
//!
//! Composes the same pieces `runtime::run` wires together — `ApprovalQueue::with_audit`
//! → `mpsc::Receiver<AuditEntry>` drain → `AuditPublisher` (`NatsAuditSink` +
//! `EventBuffer`) — against a real NATS container, then triggers a governance
//! decision (an approval submission) and asserts the resulting audit event lands
//! on `assembly.audit.<tenant>.<agent>`.
//!
//! The unconfigured / NATS-less path (publisher disabled, no startup failure) is
//! covered by the unit tests in `aa-runtime` (`build_audit_publisher_disabled_*`,
//! config parsing); this test exercises the live producer path.
//!
//! Requires Docker. Gated behind the `audit-publisher` feature.
#![cfg(feature = "audit-publisher")]

use std::sync::Arc;
use std::time::Duration;

use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};
use aa_runtime::audit_publisher::{AuditPublisher, NatsAuditSink, NatsConfig};
use aa_storage_sqlite_buffer::EventBuffer;
use futures::StreamExt;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governance_decision_produces_nats_audit_message() {
    // ---- NATS container ---------------------------------------------------
    let nats_cmd = NatsServerCmd::default().with_jetstream();
    let nats = Nats::default().with_cmd(&nats_cmd).start().await.expect("start nats");
    let nats_port = nats.get_host_port_ipv4(4222).await.expect("nats port");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    // Subscribe to the audit subject before anything is published.
    let sub_client = async_nats::connect(&nats_url).await.expect("subscriber connect");
    let mut subscription = sub_client.subscribe("assembly.audit.>").await.expect("subscribe");
    sub_client.flush().await.expect("flush subscription");

    // ---- Publisher, composed as runtime::run does ------------------------
    let config = NatsConfig {
        url: nats_url.clone(),
        ..Default::default()
    };
    let sink = NatsAuditSink::connect(&config).await.expect("connect sink");
    let buffer_dir = tempfile::tempdir().expect("tempdir");
    let buffer = Arc::new(EventBuffer::new(buffer_dir.path().join("audit-buffer.db"), 1024).expect("buffer"));
    let publisher = Arc::new(AuditPublisher::new(Arc::new(sink), buffer));

    // Wire the approval queue's audit stream into the publisher (the drain task).
    let (audit_tx, mut audit_rx) = tokio::sync::mpsc::channel(64);
    let queue = ApprovalQueue::with_audit(audit_tx, [0u8; 32]);
    let drain_publisher = Arc::clone(&publisher);
    let drain = tokio::spawn(async move {
        while let Some(entry) = audit_rx.recv().await {
            drain_publisher.publish(entry).await;
        }
    });

    // ---- Governance decision: submitting an approval emits an audit entry --
    let (_id, _fut) = queue.submit(ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "acme/bot".to_string(),
        action: "read_file /etc/passwd".to_string(),
        condition_triggered: "sensitive-file-access".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 30,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    });

    // ---- Assert it reached NATS on the audit subject ----------------------
    let message = tokio::time::timeout(Duration::from_secs(10), subscription.next())
        .await
        .expect("an audit message should arrive within 10s")
        .expect("subscription should stay open");

    let subject = message.subject.to_string();
    assert!(
        subject.starts_with("assembly.audit."),
        "expected assembly.audit.<tenant>.<agent>, got {subject}"
    );
    let body = String::from_utf8_lossy(&message.payload);
    assert!(
        body.contains("read_file"),
        "audit payload should carry the governance action: {body}"
    );

    drain.abort();
}
