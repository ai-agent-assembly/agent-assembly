//! AAASM-2607 — combined full-pipeline throughput e2e.
//!
//! Per-stage throughput was verified separately (the publisher side, and the
//! consumer drain in `audit_consumer_throughput.rs` / `audit_consumer_verify.rs`),
//! but the **whole** audit pipeline was never driven end-to-end in one run. This
//! test does exactly that: it runs the real `aa-runtime` [`AuditPublisher`] (over
//! the production [`NatsAuditSink`]) **concurrently** with the real `aa-gateway`
//! audit consumer, against one shared NATS + Postgres, and confirms the
//! end-to-end target:
//!
//! * **Sustained ≥ 50k events/sec for ~60s** end-to-end
//!   (publisher → NATS → consumer → Postgres). The achieved end-to-end rate is
//!   always measured and logged.
//! * **All-land** — every event the publisher accepted reaches `audit_logs`.
//! * **Bounded backpressure** — `aa_audit_consumer_channel_depth`, sampled
//!   throughout the run, never exceeds the consumer's bounded channel capacity
//!   (no unbounded growth) and returns to 0 once the backlog drains.
//!
//! Why this is the *real* pipeline, not a re-publish of the consumer test: events
//! are produced by `AuditPublisher::publish(AuditEntry)` going through the
//! production `NatsAuditSink` (core-NATS publish to `assembly.audit.<tenant>.<agent>`),
//! captured by the JetStream stream, and drained by the gateway consumer — all at
//! the same time, so the publisher and consumer contend for the same broker.
//!
//! The JetStream stream uses **memory storage** so the measurement reflects
//! pipeline capacity rather than the host's disk-fsync speed (a 50k file-storage
//! run on a virtualized dev-box disk is fsync-bound, not pipeline-bound).
//!
//! ## Perf gate (dev box vs CI)
//!
//! The 50k/sec assertion is **opt-in via `AA_COMBINED_ENFORCE_RATE=1`** so that a
//! macOS Docker-Desktop dev box — whose VM/network overhead can cap raw
//! throughput below a Linux runner even when the pipeline is correct — does not
//! force a red on otherwise-healthy code. CI runs with the flag set (under
//! `--all-features` / Coverage on Linux) and enforces the AC's 50k threshold. The
//! all-land and bounded-channel-depth correctness assertions run **unconditionally**.
//!
//! Requires Docker. Gated behind the `audit-consumer` feature.
#![cfg(feature = "audit-consumer")]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aa_core::audit::{AuditEntry, AuditEventType};
use aa_core::{AgentId, SessionId};
use aa_gateway::audit_consumer::{spawn, AuditConsumerConfig};
use aa_runtime::audit_publisher::{AuditPublisher, NatsAuditSink};
use aa_storage_postgres::PostgresPoolConfig;
use aa_storage_sqlite_buffer::EventBuffer;
use async_nats::jetstream::stream::{Config as StreamConfig, StorageType};
use metrics_exporter_prometheus::PrometheusBuilder;
use testcontainers_modules::nats::{Nats, NatsServerCmd};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// The AC's end-to-end target rate.
const TARGET_RATE: f64 = 50_000.0;
/// The AC's sustained window: ~60s at the target rate.
const TARGET_SECONDS: u64 = 60;
/// Default event volume = ~60s of load at the 50k/sec target, so the run
/// measures a sustained end-to-end rate over the AC's window rather than a short
/// burst. Override with `AA_COMBINED_EVENTS`.
const DEFAULT_EVENTS: u64 = TARGET_RATE as u64 * TARGET_SECONDS; // 3_000_000
/// Concurrent publisher tasks all sharing one `AuditPublisher`. A handful of
/// tasks keep enough publishes in flight to saturate the broker without the
/// single-task await-per-publish ceiling.
const PUBLISHER_TASKS: usize = 8;
/// Bounded chunk each publisher task claims at a time, so no single task
/// monopolises the runtime.
const PUBLISH_CHUNK: u64 = 512;

/// Resolve the total event volume from the environment.
fn total_events() -> u64 {
    std::env::var("AA_COMBINED_EVENTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_EVENTS)
}

/// Whether to hard-gate the 50k/sec assertion (set in CI; off on the dev box).
fn enforce_rate() -> bool {
    matches!(std::env::var("AA_COMBINED_ENFORCE_RATE").as_deref(), Ok("1"))
}

/// Read a single unlabeled metric value out of Prometheus text exposition.
fn metric_value(rendered: &str, name: &str) -> Option<f64> {
    rendered.lines().find_map(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return None;
        }
        let rest = line.strip_prefix(name)?;
        // The consumer emits this gauge with no labels, so the value follows a
        // single space.
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

/// Build one audit entry whose serialized body is unique per `n`.
///
/// The write-boundary sanitizer keeps only vetted top-level keys, so the
/// consumer derives each row's primary key (a v5 UUID) from the *sanitized*
/// body. The `payload` field survives sanitization, so embedding a fresh UUID
/// there guarantees a distinct primary key per event — no false dedupe.
fn unique_entry(n: u64) -> AuditEntry {
    let payload = format!("{{\"i\":{n},\"nonce\":\"{}\"}}", Uuid::new_v4());
    AuditEntry::new(
        n,
        n,
        AuditEventType::ToolCallIntercepted,
        AgentId::from_bytes([7u8; 16]),
        SessionId::from_bytes([9u8; 16]),
        payload,
        [0u8; 32],
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn combined_pipeline_sustains_target_throughput() {
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

    // ---- Pre-create the AUDIT stream with MEMORY storage ------------------
    // The consumer's `get_or_create_stream` then binds to this existing stream,
    // so the throughput measurement is not bound by dev-box disk fsync.
    let stream_client = async_nats::connect(&nats_url).await.expect("nats connect");
    let js = async_nats::jetstream::new(stream_client);
    js.create_stream(StreamConfig {
        name: "AUDIT".to_string(),
        subjects: vec!["assembly.audit.>".to_string()],
        storage: StorageType::Memory,
        ..Default::default()
    })
    .await
    .expect("create memory stream");

    // ---- Spawn the real gateway consumer ----------------------------------
    let config = AuditConsumerConfig::new(
        nats_url.clone(),
        PostgresPoolConfig {
            url: pg_url.clone(),
            ..Default::default()
        },
    );
    let consumer_channel_capacity = config.channel_capacity;
    let consumer_batch_size = config.batch_size;
    let shutdown = CancellationToken::new();
    let consumer = spawn(config, shutdown.clone()).await.expect("spawn consumer");

    // ---- Build the real aa-runtime AuditPublisher -------------------------
    // A real NATS client wrapped by the production NatsAuditSink, with an on-disk
    // SQLite fallback buffer (which must stay empty: NATS is up the whole run).
    let buffer_dir = tempfile::TempDir::new().expect("temp dir");
    let buffer = Arc::new(EventBuffer::new(buffer_dir.path().join("buffer.db"), 1_000_000).expect("open buffer"));
    let pub_client = async_nats::connect(&nats_url).await.expect("publisher nats connect");
    let sink = Arc::new(NatsAuditSink::new(pub_client));
    let publisher = Arc::new(AuditPublisher::new(sink, buffer.clone()));

    // ---- Concurrent full-pipeline run -------------------------------------
    // Drive a *fixed volume* (≈ 60s of load at the 50k/sec target) through
    // publisher + consumer running at the same time, and measure the end-to-end
    // rate as `events / time-until-every-row-lands`. This directly answers the
    // AC ("sustain ≥ 50k/sec for ~60s end-to-end") instead of timing a
    // wall-clock publish window whose post-window backlog drain would skew the
    // denominator.
    let events = total_events();
    let next = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));

    // Sample the channel-depth gauge throughout the run so we catch unbounded
    // growth *while it happens*, not just at the (drained) end.
    let depth_sampler = {
        let prometheus = prometheus.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let mut max_depth = 0.0_f64;
            while !stop.load(Ordering::Relaxed) {
                if let Some(depth) = metric_value(&prometheus.render(), "aa_audit_consumer_channel_depth") {
                    max_depth = max_depth.max(depth);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            max_depth
        })
    };

    // Concurrent producers claim disjoint id ranges from one shared counter and
    // publish until the fixed volume is exhausted. The consumer is already
    // draining, so publisher and consumer contend for the broker the whole time.
    let run_start = Instant::now();
    let mut tasks = Vec::with_capacity(PUBLISHER_TASKS);
    for _ in 0..PUBLISHER_TASKS {
        let publisher = publisher.clone();
        let next = next.clone();
        tasks.push(tokio::spawn(async move {
            loop {
                let start = next.fetch_add(PUBLISH_CHUNK, Ordering::Relaxed);
                if start >= events {
                    break;
                }
                let end = (start + PUBLISH_CHUNK).min(events);
                for n in start..end {
                    publisher.publish(unique_entry(n)).await;
                }
            }
        }));
    }
    for task in tasks {
        task.await.expect("publisher task");
    }
    let publish_elapsed = run_start.elapsed();

    // NATS was up the whole run, so nothing should have spilled to the buffer.
    let buffered = publisher.buffered_len().expect("buffer len");
    assert_eq!(
        buffered, 0,
        "NATS was up the entire run; no events should have buffered"
    );

    // ---- Wait for every event to land, then measure the end-to-end rate ----
    // The deadline scales with the volume so a larger run is not cut short: at
    // worst the consumer drains at a fraction of the target, so allow ample
    // headroom beyond the AC window.
    let pool = sqlx::PgPool::connect(&pg_url).await.expect("assert pool");
    let drain_deadline = Duration::from_secs((events / 10_000).max(TARGET_SECONDS) + 60);
    let landed = wait_for_count(&pool, events as i64, drain_deadline).await;
    let end_to_end_elapsed = run_start.elapsed();

    // Stop the sampler and collect the peak channel depth observed.
    stop.store(true, Ordering::Relaxed);
    let max_depth = depth_sampler.await.expect("depth sampler");

    let publish_rate = events as f64 / publish_elapsed.as_secs_f64();
    let end_to_end_rate = events as f64 / end_to_end_elapsed.as_secs_f64();
    eprintln!(
        "AAASM-2607 combined pipeline: {events} events publisher->NATS->consumer->Postgres | \
         publish phase {:.1}s ({publish_rate:.0}/s) | end-to-end {:.1}s ({end_to_end_rate:.0}/s) | \
         peak channel depth {max_depth:.0} (capacity {consumer_channel_capacity} + batch \
         {consumer_batch_size}) | landed {landed} | enforce_rate={}",
        publish_elapsed.as_secs_f64(),
        end_to_end_elapsed.as_secs_f64(),
        enforce_rate(),
    );

    // ---- Correctness assertions (always enforced) -------------------------
    assert_eq!(
        landed, events as i64,
        "every published event must land in audit_logs (no loss, no false dedupe)"
    );

    // Bounded backpressure: the producer awaits room on a bounded channel, so the
    // in-flight depth can never exceed capacity + one greedily-coalesced batch.
    // Unbounded growth would blow past this — the structural bottleneck the
    // ticket asks us to rule out.
    let depth_ceiling = (consumer_channel_capacity + consumer_batch_size) as f64;
    assert!(
        max_depth <= depth_ceiling,
        "channel depth {max_depth} exceeded the bounded ceiling {depth_ceiling}: unbounded growth in the combined pipeline"
    );

    // The gauge must drain back to 0 once the backlog is gone.
    let final_depth =
        metric_value(&prometheus.render(), "aa_audit_consumer_channel_depth").expect("channel-depth gauge exposed");
    assert_eq!(
        final_depth, 0.0,
        "channel depth must return to 0 after the backlog drains"
    );

    // ---- Throughput gate (opt-in; CI enforces, dev box logs) --------------
    if enforce_rate() {
        assert!(
            end_to_end_rate >= TARGET_RATE,
            "combined end-to-end rate {end_to_end_rate:.0}/s is below the AC target {TARGET_RATE:.0}/s"
        );
    }

    consumer.shutdown().await;
}
