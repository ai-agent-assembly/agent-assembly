//! AAASM-2609 — gateway-restart audit durability (at-least-once, zero loss).
//!
//! Proves the Epic AAASM-2350 acceptance criterion *"restarting the gateway
//! loses zero acked audit events"* with a dedicated end-to-end test rather than
//! relying on it holding by construction.
//!
//! The scenario kills the gateway audit consumer **mid-stream** — while it is
//! still draining a large backlog and before every message has been acked — and
//! then restarts a fresh consumer **bound to the same durable pull-consumer**.
//! The test asserts that after the restart every published event lands in
//! `audit_logs` exactly once:
//!
//! * **Zero loss** — every one of the `N` published events lands in
//!   `audit_logs`. The first consumer acks (and thus advances the durable
//!   cursor) only after a successful Postgres write; everything it had not yet
//!   acked when it died is still owned by JetStream and is delivered to the
//!   restarted consumer.
//! * **Exactly once** — `audit_logs` holds exactly `N` rows, one per distinct
//!   `event_id`. Any message redelivered after the crash collapses on the
//!   `event_id` primary key via `INSERT … ON CONFLICT (event_id) DO NOTHING`,
//!   so a redelivery never double-inserts.
//! * **Redeliveries are accounted for** — the cumulative
//!   `aa_audit_consumer_inserted_total` across both consumer lifetimes equals
//!   `N` (no event inserted twice).
//!
//! ## Status — durability regression guard (AAASM-3073 fixed)
//!
//! This test previously failed because the consumer used `AckPolicy::All` and
//! acked only the last message of each batch, which is safe only while processing
//! order matches stream-sequence order. On restart the redelivered + still-pending
//! messages no longer arrive in strict sequence order, so an `AckPolicy::All` ack
//! on a high-sequence batch acknowledged lower sequences that were never persisted
//! — they were dropped and never redelivered. AAASM-3073 fixed that by switching
//! to `AckPolicy::Explicit` and acking each message only after its own row is
//! persisted, so the assertions below now hold and this is the live durability
//! regression guard the Epic AC always needed.
//!
//! Requires Docker. Gated behind the `audit-consumer` feature. Run explicitly:
//!
//! ```text
//! cargo nextest run -p aa-integration-tests --features audit-consumer \
//!     --test e2e_gateway_restart_durability
//! ```
#![cfg(feature = "audit-consumer")]

use std::time::{Duration, Instant};

use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_storage_postgres::PostgresPoolConfig;
use async_nats::jetstream::stream::{Config as StreamConfig, StorageType};
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::json;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Total distinct events published before the consumer ever starts. Sized well
/// above one batch (1024) so the mid-stream crash is guaranteed to leave a large
/// un-acked tail in JetStream for the restarted consumer to pick up.
const EVENTS: usize = 4_000;
/// Publish in bounded chunks so in-flight pubacks stay capped.
const PUBLISH_CHUNK: usize = 500;
/// Overall budget for the restarted consumer to recover the remainder. Comfortably
/// exceeds the consumer's 30s `ack_wait` so genuine redelivery has time to occur.
const RECOVERY_DEADLINE: Duration = Duration::from_secs(120);

/// Read a single unlabeled metric value out of Prometheus text exposition.
fn metric_value(rendered: &str, name: &str) -> f64 {
    rendered
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if line.starts_with('#') {
                return None;
            }
            let rest = line.strip_prefix(name)?;
            rest.strip_prefix(' ')?.trim().parse::<f64>().ok()
        })
        .unwrap_or(0.0)
}

/// Count rows currently in `audit_logs`.
async fn count_rows(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_logs")
        .fetch_one(pool)
        .await
        .expect("count query")
}

/// Poll `audit_logs` until it holds at least `target` rows or the deadline.
async fn wait_for_count(pool: &sqlx::PgPool, target: i64, deadline: Duration) -> i64 {
    let start = Instant::now();
    loop {
        let count = count_rows(pool).await;
        if count >= target || start.elapsed() >= deadline {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Poll `audit_logs` until at least one row appears (the consumer has started
/// draining) or the deadline elapses; return the count observed.
async fn wait_for_first_rows(pool: &sqlx::PgPool, deadline: Duration) -> i64 {
    let start = Instant::now();
    loop {
        let count = count_rows(pool).await;
        if count > 0 || start.elapsed() >= deadline {
            return count;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

// Durability regression guard (AAASM-3073 fixed). The assertions are
// intentionally strict: they encode the at-least-once contract this Epic
// promises. The consumer now acks each message individually under
// AckPolicy::Explicit, so a restart redelivers and re-persists the un-acked tail
// with zero loss and exactly-once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_restart_loses_zero_acked_audit_events() {
    // A Prometheus recorder so the consumer's insert/duplicate counters can be
    // read back across both consumer lifetimes (counters are process-global and
    // therefore cumulative over the crash + restart).
    let prometheus = PrometheusBuilder::new()
        .install_recorder()
        .expect("install prometheus recorder");

    // ---- Containers -------------------------------------------------------
    let pg = Postgres::default().start().await.expect("start postgres");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");

    let nats_cmd = NatsServerCmd::default().with_jetstream();
    let nats = Nats::default().with_cmd(&nats_cmd).start().await.expect("start nats");
    let nats_port = nats.get_host_port_ipv4(4222).await.expect("nats port");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    // ---- Pre-create the AUDIT stream with FILE storage --------------------
    // File storage mirrors the production deployment: the durable cursor and the
    // set of delivered-but-un-acked messages survive the consumer's death, which
    // is what makes the restart recover the in-flight tail.
    let client = async_nats::connect(&nats_url).await.expect("nats connect");
    let js = async_nats::jetstream::new(client);
    js.create_stream(StreamConfig {
        name: "AUDIT".to_string(),
        subjects: vec!["assembly.audit.>".to_string()],
        storage: StorageType::File,
        ..Default::default()
    })
    .await
    .expect("create file stream");

    // ---- Publish ALL events up front (before any consumer runs) -----------
    // Each event carries a distinct `event_id` so a clean run yields exactly
    // `EVENTS` rows; this is the population whose durability we assert.
    let mut remaining = EVENTS;
    while remaining > 0 {
        let chunk = remaining.min(PUBLISH_CHUNK);
        let mut acks = Vec::with_capacity(chunk);
        for _ in 0..chunk {
            let payload = serde_json::to_vec(&json!({
                "event_id": Uuid::new_v4().to_string(),
                "kind": "tool_call",
                "agent_id": "acme/bot",
                "action": "fs.read",
                "decision": "allow",
                "ts": "2026-06-04T12:00:00Z",
            }))
            .expect("serialize");
            acks.push(
                js.publish("assembly.audit.acme.bot", payload.into())
                    .await
                    .expect("publish"),
            );
        }
        for ack in acks {
            ack.await.expect("pub-ack");
        }
        remaining -= chunk;
    }

    let pool = sqlx::PgPool::connect(&pg_url).await.expect("assert pool");

    // ---- Consumer lifetime #1: start draining, then crash mid-stream ------
    let config = AuditConsumerConfig::new(
        nats_url.clone(),
        PostgresPoolConfig {
            url: pg_url.clone(),
            ..Default::default()
        },
    );
    let shutdown_1 = CancellationToken::new();
    let handle_1 = spawn(config.clone(), shutdown_1.clone())
        .await
        .expect("spawn consumer #1");

    // Kill the consumer the instant the first rows land: at that point only a
    // small prefix has been persisted/acked, so a large tail (thousands of
    // events) is still owned by the durable consumer / pending in JetStream.
    let drained_at_crash = wait_for_first_rows(&pool, Duration::from_secs(60)).await;
    assert!(
        drained_at_crash > 0,
        "consumer #1 should have drained at least one row before we simulate the crash"
    );
    assert!(
        (drained_at_crash as usize) < EVENTS,
        "consumer #1 drained all {EVENTS} events before the crash could fire ({drained_at_crash}); \
         raise EVENTS so the crash lands mid-stream"
    );

    // Simulate the crash: cancel the token to stop the producer pulling, then
    // await task exit so no orphan writer races the restarted consumer.
    handle_1.shutdown().await;

    let after_crash = count_rows(&pool).await;
    assert!(
        (after_crash as usize) < EVENTS,
        "the crash must leave events unpersisted ({after_crash}/{EVENTS} already landed); \
         the restart would otherwise have nothing to recover"
    );

    // ---- Consumer lifetime #2: restart and recover the remainder ----------
    // A fresh consumer binds to the SAME durable name (`AuditConsumerConfig`
    // defaults it), so JetStream resumes delivery from the un-acked tail.
    let shutdown_2 = CancellationToken::new();
    let handle_2 = spawn(config, shutdown_2.clone())
        .await
        .expect("spawn consumer #2 (restart)");

    let landed = wait_for_count(&pool, EVENTS as i64, RECOVERY_DEADLINE).await;

    // ---- Assertions: zero loss, exactly once ------------------------------
    assert_eq!(
        landed, EVENTS as i64,
        "every published event must land in audit_logs after the restart (zero acked loss)"
    );

    // No event was inserted twice: the distinct-id count equals the population.
    let distinct = sqlx::query_scalar::<_, i64>("SELECT count(DISTINCT event_id) FROM audit_logs")
        .fetch_one(&pool)
        .await
        .expect("distinct count query");
    assert_eq!(
        distinct, EVENTS as i64,
        "audit_logs must hold exactly one row per distinct event_id (exactly-once)"
    );

    // Cumulative inserts across both lifetimes equal N — the ON CONFLICT guard
    // means a redelivered, already-persisted message never counts as a second
    // insert, and a lost message never counts at all.
    let rendered = prometheus.render();
    let inserted_total = metric_value(&rendered, "aa_audit_consumer_inserted_total");
    let duplicates_total = metric_value(&rendered, "aa_audit_duplicates_total");
    eprintln!(
        "AAASM-2609 restart durability: published {EVENTS}; consumer #1 persisted {after_crash} \
         before the crash; restart recovered to {landed}/{EVENTS} rows ({distinct} distinct); \
         cumulative inserts {inserted_total}, redelivery duplicates {duplicates_total}."
    );
    assert_eq!(
        inserted_total as u64, EVENTS as u64,
        "cumulative first-time inserts across crash + restart must equal the published count"
    );

    handle_2.shutdown().await;
}
