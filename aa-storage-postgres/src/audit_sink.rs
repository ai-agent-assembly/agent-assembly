//! [`PgAuditSink`] — append-only, metadata-only audit emission against Postgres.

use aa_core::audit::AuditEventType;
use aa_storage::{AuditEntry, AuditSink, Result};
use async_trait::async_trait;

use crate::pool::PostgresPool;
use crate::support::{agent_id_to_text, backend_err};

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
        // Derive a stable row id from the entry hash so re-emitting the same
        // entry is idempotent rather than duplicating.
        let mut id_bytes = [0u8; 16];
        id_bytes.copy_from_slice(&event.entry_hash()[..16]);
        let id = uuid::Uuid::from_bytes(id_bytes);

        let ns = event.timestamp_ns();
        let ts = chrono::DateTime::from_timestamp((ns / 1_000_000_000) as i64, (ns % 1_000_000_000) as u32)
            .unwrap_or_default();

        sqlx::query(
            "INSERT INTO audit_logs (id, agent_id, tool_name, decision, latency_ms, ts) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(id)
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
