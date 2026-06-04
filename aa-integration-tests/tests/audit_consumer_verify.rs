//! AAASM-2394 — acceptance verification for the gateway NATS audit consumer
//! (Story AAASM-2388).
//!
//! Brings up real NATS (JetStream) + Postgres via testcontainers, installs a
//! Prometheus recorder so the consumer's metrics can be read back, and verifies:
//!
//! * **Throughput / all-land** — every published event reaches `audit_logs`,
//!   and the achieved drain rate is measured and reported.
//! * **Backpressure depth metric** — `aa_audit_consumer_channel_depth` is
//!   exposed and returns to 0 once the backlog is drained (no unbounded growth).
//! * **Idempotency counter** — republishing one `event_id` 100× adds exactly one
//!   row and bumps `aa_audit_duplicates_total` by 99.
//!
//! Requires Docker. Gated behind the `audit-consumer` feature.
#![cfg(feature = "audit-consumer")]

use std::time::{Duration, Instant};

use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_storage_postgres::PostgresPoolConfig;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::json;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Default events published in the throughput phase. Overridable via
/// `AA_AUDIT_VERIFY_EVENTS` to drive the pipeline toward the Story's 50k/sec
/// target on a fast box; the default keeps CI runtime bounded.
const DEFAULT_THROUGHPUT_EVENTS: usize = 5_000;
/// Times the single duplicate event is republished.
const DUPLICATE_REPUBLISHES: usize = 100;

/// Resolve the throughput event count from the environment.
fn throughput_events() -> usize {
    std::env::var("AA_AUDIT_VERIFY_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_THROUGHPUT_EVENTS)
}

/// Read a single unlabeled metric value out of Prometheus text exposition.
fn metric_value(rendered: &str, name: &str) -> Option<f64> {
    rendered.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let rest = line.strip_prefix(name)?;
        // We emit no labels, so the value follows a single space.
        rest.strip_prefix(' ')?.trim().parse::<f64>().ok()
    })
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Publish many copies of one event, pipelining the publishes and awaiting all
/// acks at the end.
async fn publish_all(js: &async_nats::jetstream::Context, events: &[serde_json::Value]) {
    let mut acks = Vec::with_capacity(events.len());
    for event in events {
        let payload = serde_json::to_vec(event).expect("serialize");
        acks.push(
            js.publish("assembly.audit.acme.bot", payload.into())
                .await
                .expect("publish"),
        );
    }
    for ack in acks {
        ack.await.expect("pub-ack");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn verify_throughput_dedupe_and_channel_depth() {
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

    // ---- Consumer ---------------------------------------------------------
    let config = AuditConsumerConfig::new(
        nats_url.clone(),
        PostgresPoolConfig {
            url: pg_url.clone(),
            ..Default::default()
        },
    );
    let shutdown = CancellationToken::new();
    let handle = spawn(config, shutdown.clone()).await.expect("spawn consumer");

    let client = async_nats::connect(&nats_url).await.expect("nats connect");
    let js = async_nats::jetstream::new(client);
    let pool = sqlx::PgPool::connect(&pg_url).await.expect("assert pool");

    // ---- Throughput: publish `throughput` distinct events -----------------
    let throughput = throughput_events();
    let events: Vec<serde_json::Value> = (0..throughput)
        .map(|_| {
            json!({
                "event_id": Uuid::new_v4().to_string(),
                "kind": "tool_call",
                "agent_id": "acme/bot",
                "action": "fs.read",
                "decision": "allow",
                "ts": "2026-06-04T12:00:00Z",
            })
        })
        .collect();

    let start = Instant::now();
    publish_all(&js, &events).await;
    let landed = wait_for_count(&pool, throughput as i64, Duration::from_secs(300)).await;
    let elapsed = start.elapsed();
    let rate = throughput as f64 / elapsed.as_secs_f64();
    eprintln!(
        "AAASM-2394 throughput: {throughput} events publisher->NATS->consumer->Postgres in \
         {:.2}s = {:.0} events/sec",
        elapsed.as_secs_f64(),
        rate
    );
    assert_eq!(
        landed, throughput as i64,
        "every published event must land in audit_logs"
    );

    // ---- Idempotency: republish ONE event_id DUPLICATE_REPUBLISHES times --
    let duplicate = json!({
        "event_id": Uuid::new_v4().to_string(),
        "kind": "tool_call",
        "agent_id": "acme/bot",
        "action": "fs.write",
        "decision": "deny",
        "ts": "2026-06-04T12:34:56Z",
    });
    let dupes = vec![duplicate; DUPLICATE_REPUBLISHES];
    publish_all(&js, &dupes).await;

    // Exactly one new row regardless of how often the event_id is republished.
    let after = wait_for_count(&pool, throughput as i64 + 1, Duration::from_secs(60)).await;
    assert_eq!(
        after,
        throughput as i64 + 1,
        "a republished event_id must collapse to a single row"
    );

    // The duplicate counter must reach DUPLICATE_REPUBLISHES - 1 once all
    // copies have been processed (1 insert + 99 conflicts).
    let mut duplicates = 0.0;
    for _ in 0..100 {
        duplicates = metric_value(&prometheus.render(), "aa_audit_duplicates_total").unwrap_or(0.0);
        if duplicates >= (DUPLICATE_REPUBLISHES - 1) as f64 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        duplicates as u64,
        (DUPLICATE_REPUBLISHES - 1) as u64,
        "aa_audit_duplicates_total must count every conflicting republish"
    );

    // ---- Backpressure depth metric: exposed and drained to 0 --------------
    let rendered = prometheus.render();
    let depth =
        metric_value(&rendered, "aa_audit_consumer_channel_depth").expect("channel-depth gauge must be exposed");
    assert_eq!(depth, 0.0, "channel depth must return to 0 after the backlog drains");

    handle.shutdown().await;
}
