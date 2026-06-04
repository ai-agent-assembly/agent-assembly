//! [`PgAuditSink`] — append-only, metadata-only audit emission against Postgres.

use aa_core::audit::AuditEventType;
use aa_storage::{AuditEntry, AuditSink, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err};

/// A fully-resolved `audit_logs` row, ready to INSERT verbatim.
///
/// Unlike [`AuditEntry`] — which the sink hashes into a row — this carries the
/// columns directly. The async audit consumer (AAASM-2388) builds one from a
/// sanitized event, carrying the event's own `event_id` as the
/// [`event_id`](Self::event_id) primary key so that `ON CONFLICT (event_id)
/// DO NOTHING` gives idempotency on retried publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditLogRecord {
    /// Primary key — the event's `event_id`, the idempotency key.
    pub event_id: Uuid,
    /// Canonical agent identifier (stored verbatim in the `TEXT` column).
    pub agent_id: String,
    /// Action surface recorded in `tool_name`.
    pub tool_name: String,
    /// Coarse governance posture recorded in `decision`.
    pub decision: String,
    /// Optional decision latency; `None` leaves the column NULL.
    pub latency_ms: Option<i32>,
    /// Event timestamp.
    pub ts: DateTime<Utc>,
}

/// Postgres-backed [`AuditSink`].
///
/// Each entry becomes one row in `audit_logs`. Per the "don't store" rule the
/// table is metadata-only: the entry's `payload` is never written. The
/// governance event-type discriminant is recorded as the action surface
/// (`tool_name`) and a coarse posture (`decision`); `latency_ms` is left NULL
/// because the entry carries no timing.
#[derive(Clone)]
pub struct PgAuditSink {
    pool: PostgresPool,
}

impl PgAuditSink {
    /// Build an audit sink over an existing pool.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// INSERT a pre-resolved [`AuditLogRecord`], deduplicating on its primary key.
    ///
    /// Returns `Ok(true)` when a new row was written and `Ok(false)` when the
    /// `event_id` already existed (`ON CONFLICT (event_id) DO NOTHING` matched
    /// zero rows). The async audit consumer uses the boolean to count duplicates
    /// without a second round-trip.
    pub async fn insert_audit_log(&self, record: &AuditLogRecord) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, latency_ms, ts) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(record.event_id)
        .bind(&record.agent_id)
        .bind(&record.tool_name)
        .bind(&record.decision)
        .bind(record.latency_ms)
        .bind(record.ts)
        .execute(self.pool.pool())
        .await
        .map_err(backend_err)?;
        Ok(result.rows_affected() == 1)
    }
}

/// Coarse governance posture recorded in `audit_logs.decision`.
fn decision_label(event_type: AuditEventType) -> &'static str {
    match event_type {
        AuditEventType::PolicyViolation
        | AuditEventType::CredentialLeakBlocked
        | AuditEventType::ApprovalDenied
        | AuditEventType::ApprovalTimedOut
        | AuditEventType::AgentForceDeregistered
        | AuditEventType::MessageBlocked
        | AuditEventType::A2AImpersonationAttempted
        | AuditEventType::SandboxFilesystemBlocked
        | AuditEventType::SandboxCpuTimeout
        | AuditEventType::SandboxOomKilled
        | AuditEventType::BudgetLimitExceeded => "deny",
        AuditEventType::ApprovalGranted
        | AuditEventType::ApprovalRouted
        | AuditEventType::ToolDispatched
        | AuditEventType::SandboxStarted
        | AuditEventType::SandboxTerminated => "allow",
        AuditEventType::ToolCallIntercepted
        | AuditEventType::ApprovalRequested
        | AuditEventType::ApprovalEscalated
        | AuditEventType::BudgetLimitApproached
        | AuditEventType::A2ACallIntercepted => "review",
    }
}

#[async_trait]
impl AuditSink for PgAuditSink {
    async fn emit(&self, event: AuditEntry) -> Result<()> {
        // Derive a stable event_id from the entry hash so re-emitting the same
        // entry is idempotent rather than duplicating: the UNIQUE event_id key
        // makes `ON CONFLICT` collapse a retried publish to a single row.
        let mut event_id_bytes = [0u8; 16];
        event_id_bytes.copy_from_slice(&event.entry_hash()[..16]);
        let event_id = uuid::Uuid::from_bytes(event_id_bytes);

        let ns = event.timestamp_ns();
        let ts = chrono::DateTime::from_timestamp((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
            .unwrap_or_default();

        sqlx::query(
            "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, latency_ms, ts) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(event_id)
        .bind(agent_id_to_text(&event.agent_id()))
        .bind(event.event_type().as_str())
        .bind(decision_label(event.event_type()))
        .bind(None::<i32>)
        .bind(ts)
        .execute(self.pool.pool())
        .await
        .map_err(backend_err)?;
        Ok(())
    }
}
