//! AAASM-5783 — a hook-layer deny and allow retrieved as rows from `audit_logs`.
//!
//! This is the strongest form of the AAASM-5783 evidence: the two records travel
//! the shipping durable path end to end — producer, pipeline, conversion, the
//! real `NatsAuditSink`, a live NATS JetStream server, the gateway's audit
//! consumer — and the assertions run on rows read back out of Postgres with
//! `SELECT`.
//!
//! ADR 0033 §6 defines *Observed* as "a durable event attributed to the action".
//! What this test establishes is that a hook-layer record becomes such a row,
//! and that a deny's row differs from an allow's. Read the assertion list before
//! citing it. The row separates the two on `tool_name`, which carries the
//! governance event type. Two things it does *not* carry are asserted at the
//! bottom of the test rather than described, so neither can drift silently:
//! `audit_logs.decision` reads `review` for both rows, and `audit_logs.agent_id`
//! is blank. Both are pre-existing gaps in the consumer's column mapping, and
//! the second one bears directly on the *attributed* half of §6 — see the
//! comments there for where the attribution does survive.
//!
//! Requires Docker. Gated behind the `audit-consumer` feature, matching
//! `audit_consumer_verify.rs`:
//!
//! ```text
//! cargo nextest run -p aa-integration-tests --features audit-consumer \
//!     --test hook_layer_durable_row
//! ```
#![cfg(feature = "audit-consumer")]

mod common;

use std::time::{Duration, Instant};

use aa_core::storage::AuditSink;
use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_runtime::audit_publisher::{enriched_to_audit_entry, NatsAuditSink};
use aa_storage_postgres::PostgresPoolConfig;
use common::hook_layer::{produced_events, through_pipeline};
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;

/// One `audit_logs` row, as read back.
#[derive(Debug, sqlx::FromRow, PartialEq, Eq)]
struct AuditLogRow {
    agent_id: String,
    tool_name: String,
    decision: String,
}

/// Poll until `audit_logs` holds at least `target` rows or the deadline passes.
async fn wait_for_rows(pool: &sqlx::PgPool, target: i64, deadline: Duration) -> Vec<AuditLogRow> {
    let start = Instant::now();
    loop {
        let rows: Vec<AuditLogRow> =
            sqlx::query_as::<_, AuditLogRow>("SELECT agent_id, tool_name, decision FROM audit_logs ORDER BY ts ASC")
                .fetch_all(pool)
                .await
                .expect("select audit_logs");
        if rows.len() as i64 >= target || start.elapsed() >= deadline {
            return rows;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_hook_layer_deny_and_allow_land_as_distinguishable_audit_log_rows() {
    // ---- Containers -------------------------------------------------------
    let pg = Postgres::default().start().await.expect("start postgres");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");

    let nats_cmd = NatsServerCmd::default().with_jetstream();
    let nats = Nats::default().with_cmd(&nats_cmd).start().await.expect("start nats");
    let nats_port = nats.get_host_port_ipv4(4222).await.expect("nats port");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    // ---- Gateway-side consumer -------------------------------------------
    let shutdown = CancellationToken::new();
    let handle = spawn(
        AuditConsumerConfig::new(
            nats_url.clone(),
            PostgresPoolConfig {
                url: pg_url.clone(),
                ..Default::default()
            },
        ),
        shutdown.clone(),
    )
    .await
    .expect("spawn consumer");

    // ---- Runtime-side production -----------------------------------------
    let (deny_proto, allow_proto) = produced_events().await;
    let forwarded = through_pipeline(vec![deny_proto, allow_proto]).await;
    assert_eq!(forwarded.len(), 2, "the pipeline should forward both records");

    let client = async_nats::connect(&nats_url).await.expect("nats connect");
    let sink = NatsAuditSink::new(client);
    for enriched in &forwarded {
        sink.emit(enriched_to_audit_entry(enriched))
            .await
            .expect("publish to nats");
    }

    // ---- Retrieval --------------------------------------------------------
    let pool = sqlx::PgPool::connect(&pg_url).await.expect("assert pool");
    let rows = wait_for_rows(&pool, 2, Duration::from_secs(60)).await;
    eprintln!("AAASM-5783 retrieved audit_logs rows: {rows:#?}");
    assert_eq!(rows.len(), 2, "both hook-layer records should reach audit_logs");

    let deny = &rows[0];
    let allow = &rows[1];

    assert_eq!(
        deny.tool_name, "PolicyViolation",
        "the retrieved deny row should carry the policy-violation event type"
    );
    assert_eq!(
        allow.tool_name, "ToolCallIntercepted",
        "the retrieved allow row should carry the intercepted-tool-call event type"
    );
    assert_ne!(deny, allow, "a retrieved deny row and allow row must not be identical");

    // Two limitations of this tier, asserted rather than described so neither
    // can drift silently, and so a reader cannot mistake this row for more than
    // it carries. Both are pre-existing and outside AAASM-5783's scope.
    //
    // 1. `audit_logs` has no column for the proto decision, so both rows read
    //    `review`. A reader that needs the verdict takes it from the entry's
    //    payload upstream of this table.
    assert_eq!(deny.decision, "review");
    assert_eq!(allow.decision, "review");
    // 2. `audit_logs.agent_id` is blank for a pipeline-published entry. The
    //    consumer reads a *string* `agent_id` off the JSON (`audit_log_record`
    //    in `aa-gateway/src/audit_consumer.rs`), while `AuditEntry` serialises
    //    its `AgentId` as a 16-byte array. So this row is durable but not
    //    attributed at the column level — attribution survives inside the entry
    //    (`AuditEntry::agent_id`) and on the NATS subject, which `subject_for`
    //    keys on the agent, but it does not reach this table. Anyone reasoning
    //    about ADR 0033 §6 *Observed* — "a durable event attributed to the
    //    action" — has to take the attribution from one of those, not from here.
    assert_eq!(
        deny.agent_id, "",
        "the agent id does not reach the audit_logs column today"
    );
    assert_eq!(allow.agent_id, "");

    shutdown.cancel();
    handle.shutdown().await;
}
