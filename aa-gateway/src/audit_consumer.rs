//! Gateway-side NATS JetStream audit-event consumer (AAASM-2388).
//!
//! Phase 1 keeps the audit consumer *inside* the gateway as a pair of Tokio
//! tasks rather than a separate deployable (spec line 7460). A **producer**
//! task drains the `assembly.audit.>` JetStream subject into a bounded
//! [`mpsc`] channel; a **DB-writer** task coalesces messages into batches, runs
//! the write-boundary [`sanitize`] pass, and persists them through
//! `aa-storage-postgres`.
//!
//! The design decisions:
//!
//! * **Throughput via batching (AAASM-2563).** The writer drains the channel
//!   into batches of up to `batch_size`, writes each batch with a single
//!   multi-row `INSERT … ON CONFLICT (event_id) DO NOTHING`, and acks the whole
//!   batch with one JetStream ack — one DB round-trip and one ack per batch
//!   instead of per event.
//! * **Idempotency.** A normal event becomes an [`AuditLogRecord`] keyed by the
//!   event's own `event_id`; `ON CONFLICT (event_id) DO NOTHING` deduplicates
//!   retries and intra-batch repeats. Each conflict bumps
//!   `aa_audit_duplicates_total`.
//! * **At-least-once.** The pull-consumer uses `AckPolicy::All`; the batch's
//!   last message is acked only after the whole batch persists, which — in
//!   stream order — acknowledges every message up to it. A failed batch is left
//!   un-acked so NATS redelivers after `ack_wait`.
//! * **Backpressure.** The channel is bounded; when it is full the producer
//!   *awaits* room (`send().await`) rather than dropping, so large bursts queue
//!   durably in JetStream instead of entering redelivery cycles. The in-flight
//!   depth is exposed as `aa_audit_consumer_channel_depth`.
//! * **Graceful shutdown.** Cancelling the [`CancellationToken`] stops the
//!   producer, which drops its channel sender; the writer then drains the
//!   remaining batches and exits.
//!
//! This module is compiled only under the `audit-consumer` feature, which pulls
//! the held-back `async-nats` + `aa-storage-postgres` dependencies.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aa_storage_postgres::{AuditLogRecord, PgAuditSink, PgLifecycleStore, PostgresPool, PostgresPoolConfig};
use async_nats::jetstream::{self, consumer};
use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::sanitizer::{sanitize, RawAuditEvent, SanitizeOutcome, SanitizedAuditEvent};

/// Wildcard subject every audit event is published under.
const SUBJECT: &str = "assembly.audit.>";
/// JetStream stream that captures the audit subject.
const STREAM_NAME: &str = "AUDIT";
/// Durable pull-consumer name, so restarts resume where they left off.
const DURABLE_NAME: &str = "aa-gateway-audit-consumer";
/// Default bound on the producer→writer channel (spec/AC: 8192).
const DEFAULT_CHANNEL_CAPACITY: usize = 8192;
/// Default max events coalesced into one multi-row INSERT + one batch ack.
const DEFAULT_BATCH_SIZE: usize = 1024;
/// How long an un-acked message waits before JetStream redelivers it.
const ACK_WAIT: Duration = Duration::from_secs(30);

/// Counter: events INSERTed for the first time.
const METRIC_INSERTED: &str = "aa_audit_consumer_inserted_total";
/// Counter: events whose `event_id` already existed (ON CONFLICT matched).
const METRIC_DUPLICATES: &str = "aa_audit_duplicates_total";
/// Counter: heartbeat events collapsed into a last-seen update.
const METRIC_HEARTBEATS: &str = "aa_audit_consumer_heartbeats_total";
/// Counter: times the producer had to await channel room (backpressure).
const METRIC_BACKPRESSURE: &str = "aa_audit_consumer_backpressure_total";
/// Counter: batches left un-acked because a DB write failed.
const METRIC_WRITE_ERRORS: &str = "aa_audit_consumer_write_errors_total";
/// Counter: messages dropped because their payload was not valid JSON.
const METRIC_DECODE_ERRORS: &str = "aa_audit_consumer_decode_errors_total";
/// Gauge: current in-flight depth of the producer→writer channel.
const METRIC_CHANNEL_DEPTH: &str = "aa_audit_consumer_channel_depth";
/// Histogram: number of events coalesced into each batch.
const METRIC_BATCH_SIZE: &str = "aa_audit_consumer_batch_size";

/// Stable namespace for deriving an id when an event omits a parseable
/// `event_id`, so identical bodies still collide on the primary key.
const EVENT_ID_NAMESPACE: Uuid = Uuid::from_u128(0x6161_6173_6d32_3338_3861_7564_6974_6964);

/// A durable JetStream pull-consumer over the audit subject.
type PullConsumer = consumer::Consumer<consumer::pull::Config>;

/// Runtime configuration for the audit consumer.
#[derive(Debug, Clone)]
pub struct AuditConsumerConfig {
    /// NATS server URL (e.g. `nats://127.0.0.1:4222`).
    pub nats_url: String,
    /// Postgres connection settings for the audit sink.
    pub postgres: PostgresPoolConfig,
    /// Bound on the producer→writer channel.
    pub channel_capacity: usize,
    /// Max events coalesced into one multi-row INSERT + one batch ack.
    pub batch_size: usize,
    /// JetStream stream name.
    pub stream_name: String,
    /// Durable consumer name.
    pub durable_name: String,
    /// Subject to subscribe to.
    pub subject: String,
}

impl AuditConsumerConfig {
    /// Build a config with default stream/subject/capacity for the given
    /// NATS URL and Postgres settings.
    pub fn new(nats_url: impl Into<String>, postgres: PostgresPoolConfig) -> Self {
        Self {
            nats_url: nats_url.into(),
            postgres,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
            batch_size: DEFAULT_BATCH_SIZE,
            stream_name: STREAM_NAME.to_string(),
            durable_name: DURABLE_NAME.to_string(),
            subject: SUBJECT.to_string(),
        }
    }

    /// Build a config from the environment, returning `None` (consumer
    /// disabled) when either `AA_AUDIT_NATS_URL` or `AA_AUDIT_POSTGRES_URL` is
    /// unset.
    pub fn from_env() -> Option<Self> {
        let nats_url = std::env::var("AA_AUDIT_NATS_URL").ok()?;
        let pg_url = std::env::var("AA_AUDIT_POSTGRES_URL").ok()?;
        let postgres = PostgresPoolConfig {
            url: pg_url,
            ..Default::default()
        };
        Some(Self::new(nats_url, postgres))
    }
}

/// Errors that can occur while bringing the consumer up.
#[derive(Debug, thiserror::Error)]
pub enum AuditConsumerError {
    /// Opening the Postgres pool failed.
    #[error("postgres connection failed: {0}")]
    Postgres(#[source] sqlx::Error),
    /// Applying the embedded migrations failed.
    #[error("postgres migration failed: {0}")]
    Migrate(#[source] sqlx::migrate::MigrateError),
    /// Connecting to NATS failed.
    #[error("NATS connect failed: {0}")]
    NatsConnect(#[source] async_nats::ConnectError),
    /// Creating/binding the JetStream stream or consumer failed.
    #[error("JetStream setup failed: {0}")]
    JetStream(String),
}

/// Handle to the running consumer: cancel via the token and await both tasks.
pub struct AuditConsumerHandle {
    producer: JoinHandle<()>,
    writer: JoinHandle<()>,
    shutdown: CancellationToken,
}

impl AuditConsumerHandle {
    /// The shutdown token; cancelling it drains and stops the consumer.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Signal shutdown and wait for the producer and writer to finish draining.
    pub async fn shutdown(self) {
        self.shutdown.cancel();
        let _ = self.producer.await;
        let _ = self.writer.await;
    }
}

/// Boot-wiring convenience: build a config from the environment and spawn the
/// consumer, returning `None` when it is not configured (env vars unset).
///
/// A startup failure is logged and returns `None` rather than propagating, so a
/// misconfigured consumer never prevents the gateway from serving.
pub async fn spawn_from_env() -> Option<AuditConsumerHandle> {
    let config = AuditConsumerConfig::from_env()?;
    match spawn(config, CancellationToken::new()).await {
        Ok(handle) => Some(handle),
        Err(err) => {
            tracing::warn!(error = %err, "audit consumer disabled — failed to start");
            None
        }
    }
}

/// Connect to NATS and Postgres, ensure the stream/consumer exist, and spawn
/// the producer + DB-writer tasks. Returns once both are running.
pub async fn spawn(
    config: AuditConsumerConfig,
    shutdown: CancellationToken,
) -> Result<AuditConsumerHandle, AuditConsumerError> {
    let pool = PostgresPool::connect(&config.postgres)
        .await
        .map_err(AuditConsumerError::Postgres)?;
    pool.migrate().await.map_err(AuditConsumerError::Migrate)?;
    let sink = PgAuditSink::new(pool.clone());
    let lifecycle = PgLifecycleStore::new(pool);

    let client = async_nats::connect(&config.nats_url)
        .await
        .map_err(AuditConsumerError::NatsConnect)?;
    let js = jetstream::new(client);
    let stream = js
        .get_or_create_stream(jetstream::stream::Config {
            name: config.stream_name.clone(),
            subjects: vec![config.subject.clone()],
            ..Default::default()
        })
        .await
        .map_err(|e| AuditConsumerError::JetStream(e.to_string()))?;
    let consumer = stream
        .get_or_create_consumer(
            &config.durable_name,
            consumer::pull::Config {
                durable_name: Some(config.durable_name.clone()),
                // AckPolicy::All lets one ack cover a whole contiguous batch.
                ack_policy: consumer::AckPolicy::All,
                ack_wait: ACK_WAIT,
                // Batched acking keeps up to channel_capacity + batch_size
                // messages delivered-but-un-acked in flight. The server's
                // default max_ack_pending (1000) would throttle below that and
                // stall delivery; raise it to match — our real backpressure is
                // the bounded channel (`send().await`), not this cap.
                max_ack_pending: (config.channel_capacity + config.batch_size) as i64,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| AuditConsumerError::JetStream(e.to_string()))?;

    let (tx, rx) = mpsc::channel::<jetstream::Message>(config.channel_capacity);
    let depth = Arc::new(AtomicI64::new(0));

    let producer = tokio::spawn(run_producer(consumer, tx, Arc::clone(&depth), shutdown.clone()));
    let writer = tokio::spawn(run_writer(rx, sink, lifecycle, depth, config.batch_size));

    tracing::info!(
        subject = %config.subject,
        stream = %config.stream_name,
        "audit consumer started"
    );
    Ok(AuditConsumerHandle {
        producer,
        writer,
        shutdown,
    })
}

/// Record a successful enqueue: bump the in-flight depth gauge.
fn record_enqueued(depth: &Arc<AtomicI64>) {
    let depth_now = depth.fetch_add(1, Ordering::Relaxed) + 1;
    metrics::gauge!(METRIC_CHANNEL_DEPTH).set(depth_now as f64);
}

/// Producer task: pull from JetStream into the bounded channel.
///
/// Enqueues with `try_send`; when the channel is full it *awaits* room
/// (cancellable) rather than dropping, so bursts queue durably in JetStream
/// instead of entering redelivery cycles. Cancellation or a closed channel stops
/// the loop; dropping `tx` then signals the writer to drain and exit.
async fn run_producer(
    consumer: PullConsumer,
    tx: mpsc::Sender<jetstream::Message>,
    depth: Arc<AtomicI64>,
    shutdown: CancellationToken,
) {
    let mut messages = match consumer.messages().await {
        Ok(messages) => messages,
        Err(err) => {
            tracing::error!(%err, "audit consumer: failed to open JetStream message stream");
            return;
        }
    };

    loop {
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => {
                tracing::info!("audit consumer: shutdown signalled, stopping producer");
                break;
            }
            next = messages.next() => match next {
                Some(Ok(message)) => match tx.try_send(message) {
                    Ok(()) => record_enqueued(&depth),
                    Err(mpsc::error::TrySendError::Closed(_message)) => {
                        tracing::warn!("audit consumer: writer channel closed, stopping producer");
                        break;
                    }
                    Err(mpsc::error::TrySendError::Full(message)) => {
                        // Channel full: await room rather than dropping. Bursts
                        // stay buffered in JetStream; a cancel ends the wait.
                        metrics::counter!(METRIC_BACKPRESSURE).increment(1);
                        tokio::select! {
                            biased;
                            _ = shutdown.cancelled() => {
                                tracing::info!("audit consumer: shutdown while awaiting channel room");
                                break;
                            }
                            result = tx.send(message) => match result {
                                Ok(()) => record_enqueued(&depth),
                                Err(_) => {
                                    tracing::warn!("audit consumer: writer channel closed, stopping producer");
                                    break;
                                }
                            }
                        }
                    }
                },
                Some(Err(err)) => {
                    tracing::warn!(%err, "audit consumer: error pulling message");
                }
                None => {
                    tracing::info!("audit consumer: JetStream message stream ended");
                    break;
                }
            },
        }
    }
}

/// DB-writer task: coalesce messages into batches, persist each batch with one
/// multi-row INSERT, and ack the whole batch with one JetStream ack.
///
/// Exits when the channel is closed (producer gone) after draining every
/// buffered message.
async fn run_writer(
    mut rx: mpsc::Receiver<jetstream::Message>,
    sink: PgAuditSink,
    lifecycle: PgLifecycleStore,
    depth: Arc<AtomicI64>,
    batch_size: usize,
) {
    let mut batch: Vec<jetstream::Message> = Vec::with_capacity(batch_size);
    while let Some(first) = rx.recv().await {
        batch.clear();
        batch.push(first);
        // Greedily coalesce whatever else is already buffered, up to batch_size.
        while batch.len() < batch_size {
            match rx.try_recv() {
                Ok(message) => batch.push(message),
                Err(_) => break,
            }
        }

        let drained = batch.len() as i64;
        let depth_now = depth.fetch_sub(drained, Ordering::Relaxed) - drained;
        metrics::gauge!(METRIC_CHANNEL_DEPTH).set(depth_now.max(0) as f64);
        metrics::histogram!(METRIC_BATCH_SIZE).record(drained as f64);

        process_batch(&batch, &sink, &lifecycle).await;
    }
    tracing::info!("audit consumer: channel drained, writer exiting");
}

/// A message classified into the storage operation it maps to.
enum Classified {
    /// A normal audit row to INSERT.
    Audit(AuditLogRecord),
    /// A heartbeat collapsed into an agent last-seen touch.
    Heartbeat {
        /// Agent the heartbeat belongs to.
        agent_id: String,
        /// Heartbeat timestamp, if the event carried one.
        ts: Option<DateTime<Utc>>,
    },
}

/// Decode + sanitize one message payload into its storage operation.
fn classify(payload: &[u8]) -> Result<Classified, serde_json::Error> {
    let value: Value = serde_json::from_slice(payload)?;
    Ok(match sanitize(RawAuditEvent::new(value)) {
        SanitizeOutcome::Audit(event) => Classified::Audit(audit_log_record(&event)),
        SanitizeOutcome::Heartbeat(heartbeat) => Classified::Heartbeat {
            agent_id: heartbeat.agent_id,
            ts: parse_ts(&heartbeat.last_heartbeat_at),
        },
    })
}

/// Persist one batch, then ack it. On any DB error the batch is left un-acked so
/// JetStream redelivers it — idempotent because the `event_id` PK collapses
/// retries.
async fn process_batch(batch: &[jetstream::Message], sink: &PgAuditSink, lifecycle: &PgLifecycleStore) {
    let mut records = Vec::with_capacity(batch.len());
    let mut heartbeats = Vec::new();
    for message in batch {
        match classify(&message.payload) {
            Ok(Classified::Audit(record)) => records.push(record),
            Ok(Classified::Heartbeat { agent_id, ts }) => heartbeats.push((agent_id, ts)),
            Err(err) => {
                // Malformed payloads can't be retried into validity; drop them
                // (the batch ack covers them) and surface the count.
                metrics::counter!(METRIC_DECODE_ERRORS).increment(1);
                tracing::warn!(%err, "audit consumer: dropping undecodable message");
            }
        }
    }

    let submitted = records.len() as u64;
    if submitted > 0 {
        match sink.insert_audit_logs(&records).await {
            Ok(inserted) => {
                metrics::counter!(METRIC_INSERTED).increment(inserted);
                metrics::counter!(METRIC_DUPLICATES).increment(submitted - inserted);
            }
            Err(err) => {
                metrics::counter!(METRIC_WRITE_ERRORS).increment(1);
                tracing::warn!(%err, "audit consumer: batch insert failed, leaving batch un-acked");
                return;
            }
        }
    }

    for (agent_id, ts) in &heartbeats {
        if let Err(err) = lifecycle.touch_last_heartbeat(agent_id, *ts).await {
            metrics::counter!(METRIC_WRITE_ERRORS).increment(1);
            tracing::warn!(%err, "audit consumer: heartbeat touch failed, leaving batch un-acked");
            return;
        }
    }
    if !heartbeats.is_empty() {
        metrics::counter!(METRIC_HEARTBEATS).increment(heartbeats.len() as u64);
    }

    // AckPolicy::All: acking the last message acks the whole contiguous batch.
    if let Some(last) = batch.last() {
        if let Err(err) = last.ack().await {
            tracing::warn!(%err, "audit consumer: ack failed after successful batch write");
        }
    }
}

/// Map a sanitized audit event onto the `audit_logs` columns, using its
/// `event_id` as the primary key for idempotency.
fn audit_log_record(event: &SanitizedAuditEvent) -> AuditLogRecord {
    let value = event.as_value();
    AuditLogRecord {
        event_id: extract_event_id(value),
        agent_id: string_field(value, "agent_id").unwrap_or_default(),
        tool_name: string_field(value, "action")
            .or_else(|| string_field(value, "event_type"))
            .unwrap_or_else(|| "unknown".to_string()),
        decision: string_field(value, "decision").unwrap_or_else(|| "review".to_string()),
        latency_ms: None,
        ts: extract_ts(value).unwrap_or_else(Utc::now),
    }
}

/// Read a parseable `event_id`, falling back to a deterministic v5 UUID over
/// the event body so malformed senders still dedupe by content.
fn extract_event_id(value: &Value) -> Uuid {
    if let Some(id) = value
        .get("event_id")
        .and_then(Value::as_str)
        .and_then(|s| Uuid::parse_str(s).ok())
    {
        return id;
    }
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    Uuid::new_v5(&EVENT_ID_NAMESPACE, &bytes)
}

/// Borrow a top-level string field as an owned `String`.
fn string_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

/// Resolve the event timestamp from `ts` or `timestamp`.
fn extract_ts(value: &Value) -> Option<DateTime<Utc>> {
    value.get("ts").or_else(|| value.get("timestamp")).and_then(parse_ts)
}

/// Parse a timestamp value: RFC 3339 string, or epoch seconds/milliseconds.
fn parse_ts(value: &Value) -> Option<DateTime<Utc>> {
    match value {
        Value::String(s) => DateTime::parse_from_rfc3339(s).ok().map(|dt| dt.with_timezone(&Utc)),
        Value::Number(number) => {
            let raw = number.as_i64()?;
            if raw >= 1_000_000_000_000 {
                DateTime::from_timestamp_millis(raw)
            } else {
                DateTime::from_timestamp(raw, 0)
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// RFC 3339 string parsed straight to a `DateTime<Utc>` for comparisons.
    fn utc(rfc3339: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(rfc3339).unwrap().with_timezone(&Utc)
    }

    /// Sanitize a JSON object into an audit event, panicking on a heartbeat.
    fn audit_event(value: Value) -> SanitizedAuditEvent {
        match sanitize(RawAuditEvent::new(value)) {
            SanitizeOutcome::Audit(event) => event,
            SanitizeOutcome::Heartbeat(_) => panic!("expected an audit event, got a heartbeat"),
        }
    }

    #[test]
    fn record_uses_event_id_as_primary_key() {
        let id = "550e8400-e29b-41d4-a716-446655440000";
        let record = audit_log_record(&audit_event(json!({
            "kind": "tool_call",
            "event_id": id,
            "agent_id": "acme/bot",
            "action": "fs.read",
            "decision": "deny",
            "ts": "2026-06-04T12:00:00Z",
        })));
        assert_eq!(record.event_id, Uuid::parse_str(id).unwrap());
        assert_eq!(record.agent_id, "acme/bot");
        assert_eq!(record.tool_name, "fs.read");
        assert_eq!(record.decision, "deny");
        assert!(record.latency_ms.is_none());
        assert_eq!(record.ts, utc("2026-06-04T12:00:00Z"));
    }

    #[test]
    fn record_falls_back_to_event_type_and_review() {
        // No `action` → tool_name uses event_type; no `decision` → "review".
        let record = audit_log_record(&audit_event(json!({
            "kind": "tool_call",
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "agent_id": "acme/bot",
            "event_type": "tool_call_intercepted",
        })));
        assert_eq!(record.tool_name, "tool_call_intercepted");
        assert_eq!(record.decision, "review");
    }

    #[test]
    fn record_tool_name_unknown_without_action_or_event_type() {
        let record = audit_log_record(&audit_event(json!({
            "kind": "tool_call",
            "event_id": "550e8400-e29b-41d4-a716-446655440000",
            "agent_id": "acme/bot",
        })));
        assert_eq!(record.tool_name, "unknown");
    }

    #[test]
    fn missing_event_id_falls_back_to_stable_content_hash() {
        // Same body → same id (retries dedupe); different body → different id.
        let a = json!({"kind": "tool_call", "agent_id": "acme/bot", "action": "fs.read"});
        let b = json!({"kind": "tool_call", "agent_id": "acme/other", "action": "fs.read"});
        assert_eq!(extract_event_id(&a), extract_event_id(&a));
        assert_ne!(extract_event_id(&a), extract_event_id(&b));
    }

    #[test]
    fn invalid_event_id_falls_back_deterministically() {
        let value = json!({"event_id": "not-a-uuid", "agent_id": "acme/bot"});
        assert_eq!(extract_event_id(&value), extract_event_id(&value));
    }

    #[test]
    fn parse_ts_accepts_rfc3339_and_epochs() {
        assert_eq!(
            parse_ts(&json!("2026-06-04T12:00:00Z")).unwrap(),
            utc("2026-06-04T12:00:00Z")
        );
        assert_eq!(
            parse_ts(&json!(1_000_000_000_i64)).unwrap(),
            DateTime::from_timestamp(1_000_000_000, 0).unwrap()
        );
        assert_eq!(
            parse_ts(&json!(1_700_000_000_000_i64)).unwrap(),
            DateTime::from_timestamp_millis(1_700_000_000_000).unwrap()
        );
        assert!(parse_ts(&Value::Null).is_none());
        assert!(parse_ts(&json!("not a date")).is_none());
    }

    #[test]
    fn extract_ts_prefers_ts_then_timestamp() {
        assert_eq!(
            extract_ts(&json!({"timestamp": "2026-01-01T00:00:00Z"})).unwrap(),
            utc("2026-01-01T00:00:00Z")
        );
        assert!(extract_ts(&json!({"agent_id": "x"})).is_none());
    }
}
