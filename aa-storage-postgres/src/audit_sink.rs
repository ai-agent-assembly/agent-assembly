//! [`PgAuditSink`] — append-only, metadata-only audit emission against Postgres.

use std::collections::HashSet;

use aa_core::audit::AuditEventType;
use aa_storage::{AuditEntry, AuditSink, Result};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err, SYSTEM_ORG};

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

    /// INSERT a pre-resolved [`AuditLogRecord`] under the verified tenant
    /// `org_id`, via an RLS-scoped connection that stamps the row's `org_id`.
    ///
    /// `org_id` must be the verified tenant of the event (never client input).
    /// Returns `Ok(true)` when a new row was written and `Ok(false)` on an
    /// `event_id` conflict, matching [`Self::insert_audit_log`].
    pub async fn insert_audit_log_for_tenant(&self, org_id: Uuid, record: &AuditLogRecord) -> Result<bool> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let result = sqlx::query(
            "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, latency_ms, ts, org_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (event_id) DO NOTHING",
        )
        .bind(record.event_id)
        .bind(&record.agent_id)
        .bind(&record.tool_name)
        .bind(&record.decision)
        .bind(record.latency_ms)
        .bind(record.ts)
        .bind(org_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(result.rows_affected() == 1)
    }

    /// INSERT a pre-resolved [`AuditLogRecord`], deduplicating on its primary key.
    ///
    /// Returns `Ok(true)` when a new row was written and `Ok(false)` when the
    /// `event_id` already existed (`ON CONFLICT (event_id) DO NOTHING` matched
    /// zero rows). The async audit consumer uses the boolean to count duplicates
    /// without a second round-trip.
    pub async fn insert_audit_log(&self, record: &AuditLogRecord) -> Result<bool> {
        // Org-less insert scopes to the reserved system org (org_id defaults to
        // it); tenant callers use `insert_audit_log_for_tenant`.
        self.insert_audit_log_for_tenant(SYSTEM_ORG, record).await
    }

    /// Batch-INSERT audit rows in a single multi-row statement, deduplicating by
    /// `event_id` both **within** the batch (keep first occurrence) and against
    /// existing rows (`ON CONFLICT (event_id) DO NOTHING`).
    ///
    /// Returns the number of **new** rows written. Callers derive the duplicate
    /// count as `records.len() - returned` — covering both repeated `event_id`s
    /// inside the batch and ones already in the table. This is the hot path for
    /// the async consumer (AAASM-2563): one round-trip per batch instead of one
    /// per event.
    pub async fn insert_audit_logs(&self, records: &[AuditLogRecord]) -> Result<u64> {
        if records.is_empty() {
            return Ok(0);
        }
        // Drop intra-batch duplicate keys so a single statement never conflicts
        // on the same row twice (which `ON CONFLICT DO NOTHING` would reject).
        let mut seen = HashSet::with_capacity(records.len());
        let unique: Vec<&AuditLogRecord> = records.iter().filter(|r| seen.insert(r.event_id)).collect();

        let mut builder = sqlx::QueryBuilder::new(
            "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, latency_ms, ts) ",
        );
        builder.push_values(unique.iter(), |mut row, record| {
            row.push_bind(record.event_id)
                .push_bind(&record.agent_id)
                .push_bind(&record.tool_name)
                .push_bind(&record.decision)
                .push_bind(record.latency_ms)
                .push_bind(record.ts);
        });
        builder.push(" ON CONFLICT (event_id) DO NOTHING");

        // Org-less batch scopes to the reserved system org (org_id column
        // defaults to it); rows are written under that tenant.
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
        let result = builder.build().execute(&mut *tx).await.map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(result.rows_affected())
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
        | AuditEventType::SandboxHostFnRateLimited
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

        // The AuditSink trait carries no org; the event scopes to the reserved
        // system org (org_id column defaults to it). Tenant-aware audit writes
        // use `insert_audit_log_for_tenant`. Scoped through the system-org GUC so
        // the write passes FORCE RLS.
        let mut tx = self.pool.begin_for_tenant(SYSTEM_ORG).await.map_err(backend_err)?;
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
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }
}
