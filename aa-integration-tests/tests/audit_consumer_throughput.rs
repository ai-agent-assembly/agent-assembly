//! AAASM-2563 — throughput benchmark for the batched gateway audit consumer.
//!
//! Measures the consumer pipeline (NATS JetStream → consumer → Postgres) drain
//! rate after the batching fix (multi-row INSERT + one ack per batch). The
//! JetStream stream uses **memory storage** so the measurement reflects pipeline
//! capacity rather than the host's disk-fsync speed (a 50k file-storage run on a
//! virtualized dev-box disk is fsync-bound, not consumer-bound).
//!
//! Publishes all events first, then spawns the consumer and times the drain in
//! isolation. Asserts every event lands; the achieved rate is logged (not
//! hard-gated, to avoid a flaky perf gate on shared CI runners).
//!
//! Requires Docker. Gated behind the `audit-consumer` feature. Event count is
//! overridable via `AA_AUDIT_THROUGHPUT_EVENTS`.
#![cfg(feature = "audit-consumer")]

use std::time::{Duration, Instant};

use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_storage_postgres::PostgresPoolConfig;
use async_nats::jetstream::stream::{Config as StreamConfig, StorageType};
use serde_json::json;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Default events for the benchmark; override with `AA_AUDIT_THROUGHPUT_EVENTS`.
const DEFAULT_EVENTS: usize = 20_000;
/// Publish in bounded chunks so in-flight pubacks stay capped (accumulating tens
/// of thousands of un-awaited JetStream pubacks is the publisher's bottleneck,
/// not the consumer's).
const PUBLISH_CHUNK: usize = 1_000;

fn event_count() -> usize {
    std::env::var("AA_AUDIT_THROUGHPUT_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EVENTS)
}

async fn count_rows(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM audit_logs")
        .fetch_one(pool)
        .await
        .expect("count query")
}

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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consumer_sustains_high_throughput() {
    let events = event_count();

    // ---- Containers -------------------------------------------------------
    let pg = Postgres::default().start().await.expect("start postgres");
    let pg_port = pg.get_host_port_ipv4(5432).await.expect("pg port");
    let pg_url = format!("postgres://postgres:postgres@127.0.0.1:{pg_port}/postgres");

    let nats_cmd = NatsServerCmd::default().with_jetstream();
    let nats = Nats::default().with_cmd(&nats_cmd).start().await.expect("start nats");
    let nats_port = nats.get_host_port_ipv4(4222).await.expect("nats port");
    let nats_url = format!("nats://127.0.0.1:{nats_port}");

    // ---- Pre-create the AUDIT stream with MEMORY storage ------------------
    let client = async_nats::connect(&nats_url).await.expect("nats connect");
    let js = async_nats::jetstream::new(client);
    js.create_stream(StreamConfig {
        name: "AUDIT".to_string(),
        subjects: vec!["assembly.audit.>".to_string()],
        storage: StorageType::Memory,
        ..Default::default()
    })
    .await
    .expect("create memory stream");

    // ---- Publish all events first (publish phase, bounded in-flight) ------
    let publish_start = Instant::now();
    let mut remaining = events;
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
    let publish_secs = publish_start.elapsed().as_secs_f64();

    // ---- Spawn the consumer and time the drain in isolation --------------
    let drain_start = Instant::now();
    let config = AuditConsumerConfig::new(
        nats_url.clone(),
        PostgresPoolConfig {
            url: pg_url.clone(),
            ..Default::default()
        },
    );
    let shutdown = CancellationToken::new();
    let handle = spawn(config, shutdown.clone()).await.expect("spawn consumer");

    let pool = sqlx::PgPool::connect(&pg_url).await.expect("assert pool");
    let landed = wait_for_count(&pool, events as i64, Duration::from_secs(120)).await;
    let drain_secs = drain_start.elapsed().as_secs_f64();

    eprintln!(
        "AAASM-2563 throughput (memory stream): publish {events} in {publish_secs:.2}s = \
         {:.0}/s; consumer drained {events} in {drain_secs:.2}s = {:.0}/s",
        events as f64 / publish_secs,
        events as f64 / drain_secs,
    );
    assert_eq!(landed, events as i64, "every published event must land in audit_logs");

    handle.shutdown().await;
}
