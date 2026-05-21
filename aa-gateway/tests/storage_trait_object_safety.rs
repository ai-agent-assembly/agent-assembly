//! Verification probe for Epic 18 S-A ([AAASM-1583]).
//!
//! Confirms that:
//! 1. `aa_gateway::storage::StorageBackend` is publicly exported.
//! 2. The trait is dyn-safe — `Box<dyn StorageBackend>` compiles.
//! 3. All supporting value types named in the parent Story's AC
//!    (`StorageError`, `StorageHealth`, `RowCounts`, `RetentionStats`,
//!    `AuditFilter`) are publicly constructible.
//!
//! No behavioural assertions: this test exists solely to keep the trait
//! surface from regressing as concrete backends land in subsequent stories.
//!
//! [AAASM-1583]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1583

use std::collections::BTreeMap;

use aa_core::identity::AgentId;
use async_trait::async_trait;
use chrono::Utc;

use aa_gateway::storage::{
    AgentFilter, AgentRecord, AuditEvent, AuditFilter, HealthStatus, Metric, MetricPoint, MetricQuery, PolicyDocument,
    PolicyMeta, PolicyVersion, RetentionPolicy, RetentionStats, RowCounts, StorageBackend, StorageError, StorageHealth,
    StorageResult,
};

/// No-op `StorageBackend` implementation used only to prove dyn-safety.
struct NoopStorage;

#[async_trait]
impl StorageBackend for NoopStorage {
    async fn append_audit_event(&self, _: &AuditEvent) -> StorageResult<()> {
        Ok(())
    }
    async fn query_audit_events(&self, _: AuditFilter) -> StorageResult<Vec<AuditEvent>> {
        Ok(vec![])
    }
    async fn count_audit_events(&self, _: AuditFilter) -> StorageResult<u64> {
        Ok(0)
    }
    async fn upsert_agent(&self, _: AgentRecord) -> StorageResult<()> {
        Ok(())
    }
    async fn get_agent(&self, _: &AgentId) -> StorageResult<Option<AgentRecord>> {
        Ok(None)
    }
    async fn list_agents(&self, _: AgentFilter) -> StorageResult<Vec<AgentRecord>> {
        Ok(vec![])
    }
    async fn delete_agent(&self, _: &AgentId) -> StorageResult<()> {
        Ok(())
    }
    async fn save_policy(&self, doc: PolicyDocument) -> StorageResult<PolicyVersion> {
        Ok(PolicyVersion {
            meta: PolicyMeta {
                name: doc.name.clone(),
                version: 1,
                created_at: Utc::now(),
                is_active: false,
            },
            document: doc,
        })
    }
    async fn get_active_policy(&self, _: &str) -> StorageResult<Option<PolicyDocument>> {
        Ok(None)
    }
    async fn list_policy_versions(&self, _: &str) -> StorageResult<Vec<PolicyMeta>> {
        Ok(vec![])
    }
    async fn rollback_policy(&self, _: &str, _: u32) -> StorageResult<()> {
        Ok(())
    }
    async fn record_metric(&self, _: Metric) -> StorageResult<()> {
        Ok(())
    }
    async fn query_metrics(&self, _: MetricQuery) -> StorageResult<Vec<MetricPoint>> {
        Ok(vec![])
    }
    async fn migrate(&self) -> StorageResult<()> {
        Ok(())
    }
    async fn apply_retention(&self, _: &RetentionPolicy) -> StorageResult<RetentionStats> {
        Ok(RetentionStats {
            hot_rows: 0,
            compressed_rows: 0,
            archived_rows: 0,
            dropped_rows: 0,
            freed_bytes: 0,
            ran_at: Utc::now(),
        })
    }
    async fn healthcheck(&self) -> StorageResult<StorageHealth> {
        Ok(StorageHealth {
            status: HealthStatus::Ok,
            backend: "noop",
            latency_ms: 0,
            row_counts: RowCounts::default(),
        })
    }
}

#[test]
fn storage_backend_trait_is_dyn_safe() {
    let backend: Box<dyn StorageBackend> = Box::new(NoopStorage);
    let _send_sync: &(dyn Send + Sync) = &*backend;
}

#[test]
fn storage_error_covers_six_failure_modes() {
    // Exhaustive match — compilation fails if a variant is removed without
    // updating the verification matrix.
    let variants = [
        StorageError::ConnectionFailed("c".into()),
        StorageError::QueryFailed("q".into()),
        StorageError::MigrationFailed("m".into()),
        StorageError::NotFound("n".into()),
        StorageError::Conflict("o".into()),
        StorageError::RetentionError("r".into()),
    ];
    for v in &variants {
        match v {
            StorageError::ConnectionFailed(_)
            | StorageError::QueryFailed(_)
            | StorageError::MigrationFailed(_)
            | StorageError::NotFound(_)
            | StorageError::Conflict(_)
            | StorageError::RetentionError(_) => {}
        }
    }
    assert_eq!(variants.len(), 6);
}

#[test]
fn supporting_types_are_publicly_constructible() {
    let _ = AuditFilter::default();
    let _ = AgentFilter::default();
    let _ = MetricQuery::default();
    let _ = RowCounts::default();
    let _: BTreeMap<String, String> = BTreeMap::new();
    let _ = StorageHealth {
        status: HealthStatus::Ok,
        backend: "noop",
        latency_ms: 0,
        row_counts: RowCounts::default(),
    };
}
