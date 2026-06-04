//! Gateway-side NATS JetStream audit-event consumer (AAASM-2388).
//!
//! Phase 1 keeps the audit consumer *inside* the gateway as a pair of Tokio
//! tasks rather than a separate deployable (spec line 7460). A **producer**
//! task drains the `assembly.audit.>` JetStream subject and hands each message
//! to a bounded [`mpsc`] channel; a **DB-writer** task pulls from that channel,
//! runs the write-boundary [`sanitize`] pass, and persists the result through
//! `aa-storage-postgres`.
//!
//! The design decisions:
//!
//! * **Idempotency.** A normal event becomes an [`AuditLogRecord`] whose `id`
//!   is the event's own `event_id`, so the table's `ON CONFLICT (id) DO NOTHING`
//!   primary key deduplicates retries. A conflict bumps
//!   `aa_audit_duplicates_total`.
//! * **At-least-once.** The JetStream pull-consumer uses explicit ack; a message
//!   is acked only after its DB write succeeds. A failed write is left un-acked
//!   so NATS redelivers it after `ack_wait`.
//! * **Backpressure.** The channel is bounded. When it is full the producer uses
//!   `try_send` and, on `Full`, drops the message *un-acked* — NATS redelivers
//!   later once the writer has caught up — and bumps a backpressure counter. The
//!   in-flight depth is exposed as `aa_audit_consumer_channel_depth`.
//! * **Graceful shutdown.** Cancelling the [`CancellationToken`] stops the
//!   producer, which drops its channel sender; the writer then drains the
//!   remaining messages and exits.
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
/// How long an un-acked message waits before JetStream redelivers it.
const ACK_WAIT: Duration = Duration::from_secs(30);

/// Counter: events INSERTed for the first time.
const METRIC_INSERTED: &str = "aa_audit_consumer_inserted_total";
/// Counter: events whose `event_id` already existed (ON CONFLICT matched).
const METRIC_DUPLICATES: &str = "aa_audit_duplicates_total";
/// Counter: heartbeat events collapsed into a last-seen update.
const METRIC_HEARTBEATS: &str = "aa_audit_consumer_heartbeats_total";
/// Counter: messages dropped un-acked because the channel was full.
const METRIC_BACKPRESSURE: &str = "aa_audit_consumer_backpressure_total";
/// Counter: messages left un-acked because the DB write failed.
const METRIC_WRITE_ERRORS: &str = "aa_audit_consumer_write_errors_total";
/// Gauge: current in-flight depth of the producer→writer channel.
const METRIC_CHANNEL_DEPTH: &str = "aa_audit_consumer_channel_depth";

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
                ack_policy: consumer::AckPolicy::Explicit,
                ack_wait: ACK_WAIT,
                ..Default::default()
            },
        )
        .await
        .map_err(|e| AuditConsumerError::JetStream(e.to_string()))?;

    let (tx, rx) = mpsc::channel::<jetstream::Message>(config.channel_capacity);
    let depth = Arc::new(AtomicI64::new(0));

    let producer = tokio::spawn(run_producer(consumer, tx, Arc::clone(&depth), shutdown.clone()));
    let writer = tokio::spawn(run_writer(rx, sink, lifecycle, depth));

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

/// Producer task: pull from JetStream and `try_send` into the bounded channel.
///
/// A full channel drops the message un-acked (NATS redelivers after `ack_wait`),
/// applying backpressure without blocking the pull loop. Cancellation or a
/// closed channel stops the loop; dropping `tx` then signals the writer to
/// drain and exit.
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
                    Ok(()) => {
                        let depth_now = depth.fetch_add(1, Ordering::Relaxed) + 1;
                        metrics::gauge!(METRIC_CHANNEL_DEPTH).set(depth_now as f64);
                    }
                    Err(mpsc::error::TrySendError::Full(_message)) => {
                        // Leave un-acked: JetStream redelivers after ack_wait
                        // once the writer drains the channel.
                        metrics::counter!(METRIC_BACKPRESSURE).increment(1);
                    }
                    Err(mpsc::error::TrySendError::Closed(_message)) => {
                        tracing::warn!("audit consumer: writer channel closed, stopping producer");
                        break;
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

/// DB-writer task: sanitize each message, persist it, and ack on success.
///
/// Exits when the channel is closed (producer gone) after draining every
/// buffered message.
async fn run_writer(
    mut rx: mpsc::Receiver<jetstream::Message>,
    sink: PgAuditSink,
    lifecycle: PgLifecycleStore,
    depth: Arc<AtomicI64>,
) {
    while let Some(message) = rx.recv().await {
        let depth_now = depth.fetch_sub(1, Ordering::Relaxed) - 1;
        metrics::gauge!(METRIC_CHANNEL_DEPTH).set(depth_now.max(0) as f64);

        match process_message(&message, &sink, &lifecycle).await {
            Ok(()) => {
                if let Err(err) = message.ack().await {
                    tracing::warn!(%err, "audit consumer: ack failed after successful write");
                }
            }
            Err(err) => {
                // Do not ack — JetStream redelivers after ack_wait.
                metrics::counter!(METRIC_WRITE_ERRORS).increment(1);
                tracing::warn!(%err, "audit consumer: write failed, leaving message un-acked");
            }
        }
    }
    tracing::info!("audit consumer: channel drained, writer exiting");
}

/// Errors raised while processing a single message (before ack).
#[derive(Debug, thiserror::Error)]
enum ProcessError {
    /// The message payload was not valid JSON.
    #[error("decode failed: {0}")]
    Decode(#[source] serde_json::Error),
    /// The storage write failed.
    #[error("storage write failed: {0}")]
    Storage(String),
}

/// Decode → sanitize → persist one message. Audit events INSERT a row;
/// heartbeats collapse into a last-seen touch.
async fn process_message(
    message: &jetstream::Message,
    sink: &PgAuditSink,
    lifecycle: &PgLifecycleStore,
) -> Result<(), ProcessError> {
    let value: Value = serde_json::from_slice(&message.payload).map_err(ProcessError::Decode)?;
    match sanitize(RawAuditEvent::new(value)) {
        SanitizeOutcome::Audit(event) => {
            let record = audit_log_record(&event);
            let inserted = sink
                .insert_audit_log(&record)
                .await
                .map_err(|e| ProcessError::Storage(e.to_string()))?;
            if inserted {
                metrics::counter!(METRIC_INSERTED).increment(1);
            } else {
                metrics::counter!(METRIC_DUPLICATES).increment(1);
            }
            Ok(())
        }
        SanitizeOutcome::Heartbeat(heartbeat) => {
            let ts = parse_ts(&heartbeat.last_heartbeat_at);
            lifecycle
                .touch_last_heartbeat(&heartbeat.agent_id, ts)
                .await
                .map_err(|e| ProcessError::Storage(e.to_string()))?;
            metrics::counter!(METRIC_HEARTBEATS).increment(1);
            Ok(())
        }
    }
}

/// Map a sanitized audit event onto the `audit_logs` columns, using its
/// `event_id` as the primary key for idempotency.
fn audit_log_record(event: &SanitizedAuditEvent) -> AuditLogRecord {
    let value = event.as_value();
    AuditLogRecord {
        id: extract_event_id(value),
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
