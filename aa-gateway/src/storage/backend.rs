//! Async trait abstracting persistence for the gateway control plane.

use async_trait::async_trait;

use aa_core::identity::AgentId;

use super::agent::{AgentFilter, AgentRecord};
use super::audit::{AuditEvent, AuditFilter};
use super::error::StorageResult;
use super::health::StorageHealth;
use super::metric::{Metric, MetricPoint, MetricQuery};
use super::policy::{PolicyDocument, PolicyMeta, PolicyVersion};
use super::retention::{RetentionPolicy, RetentionStats};

/// Persistence contract used by the gateway runtime.
///
/// Concrete implementations land in later Epic-18 stories:
///
/// - SQLite backend — Epic 18 S-B
/// - PostgreSQL backend — Epic 18 S-C
///
/// Business logic must only depend on this trait. Importing a database
/// driver (`sqlx`, `rusqlite`, …) anywhere outside the `storage` module is
/// prohibited by the parent Story's acceptance criteria.
#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    /// Append a single audit event.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   when the backend rejects the write.
    /// - `StorageError`
    ///   when the connection is lost.
    async fn append_audit_event(&self, event: &AuditEvent) -> StorageResult<()>;

    /// Return audit events matching `filter`, ordered by timestamp descending.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   when the filter is invalid for the backend or the query fails.
    async fn query_audit_events(&self, filter: AuditFilter) -> StorageResult<Vec<AuditEvent>>;

    /// Return the number of audit events matching `filter`.
    ///
    /// # Errors
    ///
    /// Same conditions as [`query_audit_events`](Self::query_audit_events).
    async fn count_audit_events(&self, filter: AuditFilter) -> StorageResult<u64>;

    /// Insert or update an agent record.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   when an optimistic-concurrency check fails.
    /// - `StorageError`
    ///   on backend failure.
    async fn upsert_agent(&self, record: AgentRecord) -> StorageResult<()>;

    /// Return the agent record for `id`, if registered.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` for unknown ids; only backend failure surfaces
    /// as `StorageError` /
    /// `StorageError`.
    async fn get_agent(&self, id: &AgentId) -> StorageResult<Option<AgentRecord>>;

    /// Return all agent records matching `filter`, paged per the filter limits.
    ///
    /// # Errors
    ///
    /// As [`query_audit_events`](Self::query_audit_events).
    async fn list_agents(&self, filter: AgentFilter) -> StorageResult<Vec<AgentRecord>>;

    /// Remove the agent record for `id`.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   when no record matches.
    async fn delete_agent(&self, id: &AgentId) -> StorageResult<()>;

    /// Save a new policy version. Returns the assigned [`PolicyVersion`].
    ///
    /// The freshly-saved version is not automatically marked active;
    /// callers must use [`rollback_policy`](Self::rollback_policy) to
    /// activate a specific version.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   if a same-name, same-content version already exists and the
    ///   backend rejects the duplicate.
    async fn save_policy(&self, doc: PolicyDocument) -> StorageResult<PolicyVersion>;

    /// Return the currently-active version of `name`, if any.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` for unknown names; only backend failure surfaces
    /// as a `StorageError`.
    async fn get_active_policy(&self, name: &str) -> StorageResult<Option<PolicyDocument>>;

    /// List all stored versions of `name` (metadata only).
    ///
    /// # Errors
    ///
    /// As [`query_audit_events`](Self::query_audit_events). An unknown name
    /// returns `Ok(vec![])`.
    async fn list_policy_versions(&self, name: &str) -> StorageResult<Vec<PolicyMeta>>;

    /// Mark `version` of `name` as the active version.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   if `(name, version)` does not exist.
    async fn rollback_policy(&self, name: &str, version: u32) -> StorageResult<()>;

    /// Record a single metric sample.
    ///
    /// # Errors
    ///
    /// As [`append_audit_event`](Self::append_audit_event).
    async fn record_metric(&self, m: Metric) -> StorageResult<()>;

    /// Return metric points matching `q`.
    ///
    /// # Errors
    ///
    /// As [`query_audit_events`](Self::query_audit_events).
    async fn query_metrics(&self, q: MetricQuery) -> StorageResult<Vec<MetricPoint>>;

    /// Run any pending schema migrations.
    ///
    /// Must be idempotent — calling on an already-migrated database is a
    /// no-op.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   when a migration fails to apply or verify.
    async fn migrate(&self) -> StorageResult<()>;

    /// Apply `policy` to existing data: compress warm-tier rows, archive or
    /// drop cold-tier rows.
    ///
    /// When `policy.dry_run == true`, return statistics for the actions
    /// that *would* be taken without performing them.
    ///
    /// # Errors
    ///
    /// - `StorageError`
    ///   on a non-fatal retention failure.
    /// - `StorageError`
    ///   on backend failure during the run.
    async fn apply_retention(&self, policy: &RetentionPolicy) -> StorageResult<RetentionStats>;

    /// Probe backend liveness, latency, and current row counts.
    ///
    /// A degraded but reachable backend returns `Ok` with
    /// `StorageHealth.status = HealthStatus::Degraded` rather than an
    /// error. Errors only when the probe itself fails.
    async fn healthcheck(&self) -> StorageResult<StorageHealth>;
}
