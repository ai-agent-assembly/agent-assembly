//! End-to-end test for the gateway NATS→Postgres audit consumer (AAASM-2388).
//!
//! Spins up real NATS (JetStream) and Postgres containers via testcontainers,
//! publishes events to `assembly.audit.>`, runs the consumer, and asserts that
//! every event lands in `audit_logs` and that duplicate `event_id`s collapse to
//! a single row (idempotency).
//!
//! Requires Docker. Compiled only under the `audit-consumer` feature; the
//! sustained 50k-events/sec throughput benchmark lives in the verification
//! subtask (AAASM-2394).
#![cfg(feature = "audit-consumer")]

use std::time::Duration;

use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_storage_postgres::PostgresPoolConfig;
use serde_json::json;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Number of distinct events published in the "all land" phase.
const EVENT_COUNT: usize = 1000;
/// Times the single duplicate event is republished.
const DUPLICATE_REPUBLISHES: usize = 50;

/// Count rows currently in `audit_logs`.
async fn count_rows(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_logs")
        .fetch_one(pool)
        .await
        .expect("count query")
}

/// Poll `audit_logs` until it holds at least `target` rows or we give up.
async fn wait_for_count(pool: &sqlx::PgPool, target: i64) -> i64 {
    for _ in 0..150 {
        let count = count_rows(pool).await;
        if count >= target {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    count_rows(pool).await
}

/// Publish one JSON audit event to the audit subject and wait for its ack.
async fn publish_event(js: &async_nats::jetstream::Context, event: &serde_json::Value) {
    let payload = serde_json::to_vec(event).expect("serialize event");
    js.publish("assembly.audit.acme.bot", payload.into())
        .await
        .expect("publish")
        .await
        .expect("pub-ack");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consumer_drains_all_events_and_dedupes_by_event_id() {
    // ---- Bring up NATS (JetStream) + Postgres -----------------------------
    let pg = Postgres::default().start().await.expect("start postgres");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");

    let nats_cmd = NatsServerCmd::default().with_jetstream();
    let nats = Nats::default().with_cmd(&nats_cmd).start().await.expect("start nats");
    let nats_port = nats.get_host_port_ipv4(4222).await.expect("nats port");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    // ---- Start the consumer (creates the stream + durable consumer) -------
    let config = AuditConsumerConfig::new(
        nats_url.clone(),
        PostgresPoolConfig {
            url: pg_url.clone(),
            ..Default::default()
        },
    );
    let shutdown = CancellationToken::new();
    let handle = spawn(config, shutdown.clone()).await.expect("spawn consumer");

    // ---- Publish EVENT_COUNT distinct events ------------------------------
    let client = async_nats::connect(&nats_url).await.expect("nats connect");
    let js = async_nats::jetstream::new(client);
    for _ in 0..EVENT_COUNT {
        publish_event(
            &js,
            &json!({
                "event_id": Uuid::new_v4().to_string(),
                "kind": "tool_call",
                "agent_id": "acme/bot",
                "action": "fs.read",
                "decision": "allow",
                "ts": "2026-06-04T12:00:00Z",
            }),
        )
        .await;
    }

    // Every distinct event must land exactly once.
    let landed = wait_for_count(&pool(&pg_url).await, EVENT_COUNT as i64).await;
    assert_eq!(
        landed, EVENT_COUNT as i64,
        "all published events should land in audit_logs"
    );

    // ---- Idempotency: republish ONE event_id many times -------------------
    let duplicate = json!({
        "event_id": Uuid::new_v4().to_string(),
        "kind": "tool_call",
        "agent_id": "acme/bot",
        "action": "fs.write",
        "decision": "deny",
        "ts": "2026-06-04T12:34:56Z",
    });
    for _ in 0..DUPLICATE_REPUBLISHES {
        publish_event(&js, &duplicate).await;
    }

    // The duplicate adds exactly one row regardless of how often it is sent.
    let after_dupes = wait_for_count(&pool(&pg_url).await, EVENT_COUNT as i64 + 1).await;
    assert_eq!(
        after_dupes,
        EVENT_COUNT as i64 + 1,
        "duplicate event_id must collapse to a single audit_logs row"
    );

    handle.shutdown().await;
}

/// Open a throwaway pool for assertions.
async fn pool(url: &str) -> sqlx::PgPool {
    sqlx::PgPool::connect(url).await.expect("connect for assertions")
}
