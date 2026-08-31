//! `impl aa_core::storage::ApprovalStore for SqliteBackend` — AAASM-5657.
//!
//! Deliberately a direct `impl` against the concrete backend, not a
//! gateway-local trait with a Postgres/no-op default the way
//! [`super::sensitive_data`] is: `ApprovalStore` already lives in
//! `aa_core::storage` as a pure interface (see that module), so there is
//! nothing gateway-specific to abstract over here. `PostgresBackend` gets no
//! implementation in this ticket.
//!
//! Every query here is a plain `sqlx::query`/`query_as` call, not a
//! `sqlx::query!` macro — this module adds no `.sqlx` offline-query files and
//! needs none.

use async_trait::async_trait;
use sqlx::Row;

use aa_core::storage::{ApprovalDecisionRow, ApprovalRecord, ApprovalRoutingRow, ApprovalStore};

use super::sqlite::SqliteBackend;

/// Map a `sqlx` error onto `aa_core`'s backend-agnostic
/// [`aa_core::storage::StorageError`] — `ApprovalStore` returns
/// `aa_core::storage::Result`, distinct from this crate's own
/// [`super::error::StorageError`] (this storage layer predates
/// `aa_core::storage`; every other method in this file talks to the pool
/// directly, so there is no gateway-error value to convert from here).
fn sqlx_err(e: sqlx::Error) -> aa_core::storage::StorageError {
    aa_core::storage::StorageError::Backend(e.to_string())
}

fn row_to_record(row: &sqlx::sqlite::SqliteRow) -> Result<ApprovalRecord, aa_core::storage::StorageError> {
    Ok(ApprovalRecord {
        request_id: row.try_get("request_id").map_err(sqlx_err)?,
        agent_id: row.try_get("agent_id").map_err(sqlx_err)?,
        action: row.try_get("action").map_err(sqlx_err)?,
        condition_triggered: row.try_get("condition_triggered").map_err(sqlx_err)?,
        submitted_at: row.try_get::<i64, _>("submitted_at").map_err(sqlx_err)? as u64,
        timeout_secs: row.try_get::<i64, _>("timeout_secs").map_err(sqlx_err)? as u64,
        team_id: row.try_get("team_id").map_err(sqlx_err)?,
        fallback_json: row.try_get("fallback_json").map_err(sqlx_err)?,
    })
}

fn row_to_decision(row: &sqlx::sqlite::SqliteRow) -> Result<ApprovalDecisionRow, aa_core::storage::StorageError> {
    let decision_conditions_json: String = row.try_get("decision_conditions").map_err(sqlx_err)?;
    let decision_conditions: Vec<String> = serde_json::from_str(&decision_conditions_json).unwrap_or_default();
    Ok(ApprovalDecisionRow {
        request_id: row.try_get("request_id").map_err(sqlx_err)?,
        status: row.try_get("status").map_err(sqlx_err)?,
        decided_at: row
            .try_get::<Option<i64>, _>("decided_at")
            .map_err(sqlx_err)?
            .unwrap_or(0) as u64,
        decided_by: row
            .try_get::<Option<String>, _>("decided_by")
            .map_err(sqlx_err)?
            .unwrap_or_default(),
        decision_reason: row.try_get("decision_reason").map_err(sqlx_err)?,
        decision_conditions,
    })
}

#[async_trait]
impl ApprovalStore for SqliteBackend {
    async fn insert_pending(&self, record: &ApprovalRecord) -> aa_core::storage::Result<()> {
        sqlx::query(
            "INSERT OR REPLACE INTO approval_requests
                (request_id, agent_id, action, condition_triggered, submitted_at,
                 timeout_secs, team_id, fallback_json, status,
                 decision_conditions, routing_history_json)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending', '[]', '[]')",
        )
        .bind(&record.request_id)
        .bind(&record.agent_id)
        .bind(&record.action)
        .bind(&record.condition_triggered)
        .bind(record.submitted_at as i64)
        .bind(record.timeout_secs as i64)
        .bind(&record.team_id)
        .bind(&record.fallback_json)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }

    async fn record_decision(
        &self,
        request_id: &str,
        decision: &ApprovalDecisionRow,
    ) -> aa_core::storage::Result<bool> {
        let decision_conditions_json =
            serde_json::to_string(&decision.decision_conditions).unwrap_or_else(|_| "[]".to_string());
        let result = sqlx::query(
            "UPDATE approval_requests
             SET status = ?, decided_at = ?, decided_by = ?, decision_reason = ?, decision_conditions = ?
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&decision.status)
        .bind(decision.decided_at as i64)
        .bind(&decision.decided_by)
        .bind(&decision.decision_reason)
        .bind(decision_conditions_json)
        .bind(request_id)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(result.rows_affected() > 0)
    }

    async fn list_pending(&self) -> aa_core::storage::Result<Vec<ApprovalRecord>> {
        let rows = sqlx::query("SELECT * FROM approval_requests WHERE status = 'pending'")
            .fetch_all(self.pool())
            .await
            .map_err(sqlx_err)?;
        rows.iter().map(row_to_record).collect()
    }

    async fn list_resolved_for(&self, request_ids: &[String]) -> aa_core::storage::Result<Vec<ApprovalDecisionRow>> {
        if request_ids.is_empty() {
            return Ok(Vec::new());
        }
        // A per-id query rather than a dynamic `IN (...)` placeholder list:
        // this is a periodic poll over the caller's own locally-pending set
        // (typically a handful of entries), not a hot path, and it keeps the
        // query static instead of building SQL by hand.
        let mut out = Vec::new();
        for id in request_ids {
            let row = sqlx::query("SELECT * FROM approval_requests WHERE request_id = ? AND status != 'pending'")
                .bind(id)
                .fetch_optional(self.pool())
                .await
                .map_err(sqlx_err)?;
            if let Some(row) = row {
                out.push(row_to_decision(&row)?);
            }
        }
        Ok(out)
    }

    async fn update_routing(&self, request_id: &str, routing: &ApprovalRoutingRow) -> aa_core::storage::Result<()> {
        sqlx::query(
            "UPDATE approval_requests
             SET routing_status = ?, target_role = ?, routed_at = ?, escalate_at = ?, routing_history_json = ?
             WHERE request_id = ? AND status = 'pending'",
        )
        .bind(&routing.routing_status)
        .bind(&routing.target_role)
        .bind(routing.routed_at.map(|v| v as i64))
        .bind(routing.escalate_at.map(|v| v as i64))
        .bind(&routing.routing_history_json)
        .bind(request_id)
        .execute(self.pool())
        .await
        .map_err(sqlx_err)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use aa_runtime::approval::{ApprovalDecision, ApprovalQueue, ApprovalRequest};
    use tempfile::TempDir;
    use uuid::Uuid;

    use super::*;
    use crate::storage::backend::StorageBackend;
    use crate::storage::{SqliteBackend, SqliteConfig};

    async fn backend_on(path: &std::path::Path) -> Arc<SqliteBackend> {
        let backend = SqliteBackend::open(&SqliteConfig {
            path: path.to_path_buf(),
        })
        .await
        .expect("open should succeed");
        backend.migrate().await.expect("migrate should succeed");
        Arc::new(backend)
    }

    fn fresh_request(timeout_secs: u64) -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "read_file /etc/passwd".to_string(),
            condition_triggered: "sensitive-file-access".to_string(),
            submitted_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
            timeout_secs,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        }
    }

    /// AAASM-5657 headline test: two `SqliteBackend`s on one file (standing
    /// in for two OS processes), two `ApprovalQueue`s. Both the discovery
    /// direction (B sees A's submission) and the resolution direction (A's
    /// held future unblocks from B's decision) are asserted — discovery is
    /// what actually proves the queues are bridged, not just that a write
    /// round-trips through one connection.
    #[tokio::test]
    async fn two_queues_on_one_file_discover_and_resolve_across_each_other() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("shared.db");

        let backend_a = backend_on(&path).await;
        let queue_a = ApprovalQueue::new();
        queue_a.set_storage(backend_a.clone() as Arc<dyn ApprovalStore>);

        let backend_b = backend_on(&path).await;
        let queue_b = ApprovalQueue::new();
        queue_b.set_storage(backend_b.clone() as Arc<dyn ApprovalStore>);

        let req = fresh_request(60);
        let id = req.request_id;
        let (_rid, fut) = queue_a.submit_persisted(req).await;

        // Discovery direction: B never saw the submission in-process — it
        // must ingest it from the shared file.
        assert!(
            queue_b.list().is_empty(),
            "queue B must start with nothing until it syncs"
        );
        let stats = queue_b.sync_with_storage().await.expect("sync should succeed");
        assert_eq!(stats.ingested, 1);
        assert!(queue_b.list().iter().any(|p| p.request_id == id));

        // Resolution direction: B decides, A's held future (from its own,
        // separate submit call) unblocks via a sync tick.
        queue_b
            .decide_persisted(
                id,
                ApprovalDecision::Approved {
                    by: "operator".to_string(),
                    reason: None,
                    conditions: vec![],
                },
            )
            .await
            .expect("decide should succeed");

        let stats = queue_a.sync_with_storage().await.expect("sync should succeed");
        assert_eq!(stats.applied, 1);
        let decision = fut.await.expect("queue A's future must resolve");
        assert!(matches!(decision, ApprovalDecision::Approved { by, .. } if by == "operator"));
    }

    /// A row whose holder no longer runs (crashed / was never resolved by
    /// anyone) must still expire — another process's poll sweeps it.
    #[tokio::test]
    async fn another_process_sweeps_an_expired_orphaned_row() {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("shared.db");
        let backend = backend_on(&path).await;

        // A row already past its deadline, inserted directly — as if the
        // submitting process crashed before its own timer or a sync tick
        // could ever fire.
        let id = Uuid::new_v4();
        backend
            .insert_pending(&ApprovalRecord {
                request_id: id.to_string(),
                agent_id: "agent-1".to_string(),
                action: "action".to_string(),
                condition_triggered: "cond".to_string(),
                submitted_at: 1,
                timeout_secs: 1,
                team_id: None,
                fallback_json: serde_json::to_string(&aa_core::PolicyResult::Deny {
                    reason: "timed out".to_string(),
                })
                .unwrap(),
            })
            .await
            .unwrap();

        let queue = ApprovalQueue::new();
        queue.set_storage(backend.clone() as Arc<dyn ApprovalStore>);

        let stats = queue.sync_with_storage().await.expect("sync should succeed");
        assert_eq!(stats.ingested, 1);
        assert_eq!(stats.swept, 1);

        let rows = backend.list_resolved_for(&[id.to_string()]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].status, "timed_out");
    }

    #[tokio::test]
    async fn record_decision_is_conditional_on_pending() {
        let tmp = TempDir::new().expect("tempdir");
        let backend = backend_on(&tmp.path().join("db.sqlite")).await;

        let id = Uuid::new_v4();
        backend
            .insert_pending(&ApprovalRecord {
                request_id: id.to_string(),
                agent_id: "a".to_string(),
                action: "a".to_string(),
                condition_triggered: "c".to_string(),
                submitted_at: 0,
                timeout_secs: 60,
                team_id: None,
                fallback_json: "{}".to_string(),
            })
            .await
            .unwrap();

        let first = ApprovalDecisionRow {
            request_id: id.to_string(),
            status: "approved".to_string(),
            decided_at: 1,
            decided_by: "alice".to_string(),
            decision_reason: None,
            decision_conditions: vec![],
        };
        assert!(backend.record_decision(&id.to_string(), &first).await.unwrap());

        let second = ApprovalDecisionRow {
            request_id: id.to_string(),
            status: "rejected".to_string(),
            decided_at: 2,
            decided_by: "bob".to_string(),
            decision_reason: Some("no".to_string()),
            decision_conditions: vec![],
        };
        assert!(
            !backend.record_decision(&id.to_string(), &second).await.unwrap(),
            "a second decision on an already-decided row must not apply"
        );

        let rows = backend.list_resolved_for(&[id.to_string()]).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decided_by, "alice", "the first decision must win");
    }

    #[tokio::test]
    async fn list_resolved_for_omits_still_pending_and_unknown_ids() {
        let tmp = TempDir::new().expect("tempdir");
        let backend = backend_on(&tmp.path().join("db.sqlite")).await;

        let pending_id = Uuid::new_v4();
        backend
            .insert_pending(&ApprovalRecord {
                request_id: pending_id.to_string(),
                agent_id: "a".to_string(),
                action: "a".to_string(),
                condition_triggered: "c".to_string(),
                submitted_at: 0,
                timeout_secs: 60,
                team_id: None,
                fallback_json: "{}".to_string(),
            })
            .await
            .unwrap();

        let unknown_id = Uuid::new_v4();
        let rows = backend
            .list_resolved_for(&[pending_id.to_string(), unknown_id.to_string()])
            .await
            .unwrap();
        assert!(rows.is_empty());
    }

    #[tokio::test]
    async fn update_routing_persists_and_is_a_noop_once_resolved() {
        let tmp = TempDir::new().expect("tempdir");
        let backend = backend_on(&tmp.path().join("db.sqlite")).await;

        let id = Uuid::new_v4();
        backend
            .insert_pending(&ApprovalRecord {
                request_id: id.to_string(),
                agent_id: "a".to_string(),
                action: "a".to_string(),
                condition_triggered: "c".to_string(),
                submitted_at: 0,
                timeout_secs: 60,
                team_id: None,
                fallback_json: "{}".to_string(),
            })
            .await
            .unwrap();

        backend
            .update_routing(
                &id.to_string(),
                &ApprovalRoutingRow {
                    request_id: id.to_string(),
                    routing_status: Some("routed_to_team_admin".to_string()),
                    target_role: Some("TeamAdmin".to_string()),
                    routed_at: Some(5),
                    escalate_at: None,
                    routing_history_json: "[]".to_string(),
                },
            )
            .await
            .unwrap();

        let pending = backend.list_pending().await.unwrap();
        assert_eq!(pending.len(), 1);

        // Resolve, then confirm a routing update on the now-resolved row is
        // a no-op (does not resurrect it as pending or error).
        let decision = ApprovalDecisionRow {
            request_id: id.to_string(),
            status: "approved".to_string(),
            decided_at: 1,
            decided_by: "alice".to_string(),
            decision_reason: None,
            decision_conditions: vec![],
        };
        assert!(backend.record_decision(&id.to_string(), &decision).await.unwrap());

        backend
            .update_routing(
                &id.to_string(),
                &ApprovalRoutingRow {
                    request_id: id.to_string(),
                    routing_status: Some("escalated_to_org_admin".to_string()),
                    target_role: Some("OrgAdmin".to_string()),
                    routed_at: Some(10),
                    escalate_at: None,
                    routing_history_json: "[]".to_string(),
                },
            )
            .await
            .unwrap();

        assert!(
            backend.list_pending().await.unwrap().is_empty(),
            "a routing update must not resurrect a resolved row as pending"
        );
    }
}
