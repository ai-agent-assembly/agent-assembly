//! SQLite-backed escalation scheduler — restart-safe and concurrent-safe.
//!
//! `DbEscalationScheduler::tick` opens a `BEGIN IMMEDIATE` transaction before
//! selecting due rows, which serialises writer access in SQLite and guarantees
//! each due row fires exactly once even when multiple gateway instances share
//! the same SQLite file.

use std::sync::Arc;
use std::time::Duration;

use sqlx::SqlitePool;
use tokio::sync::broadcast;
use tokio_util::sync::CancellationToken;

use aa_core::AuditEventType;
use aa_runtime::approval::{ApprovalQueue, ApprovalRequestId};

use super::audit_sink::AuditEventSink;
use super::clock::Clock;
use super::escalation::EscalationEvent;

// ---------------------------------------------------------------------------
// DbEscalationScheduler
// ---------------------------------------------------------------------------

/// SQLite-backed escalation scheduler.
///
/// Replaces the file-based [`super::escalation::EscalationScheduler`] for
/// deployments that want:
///
/// * **Restart safety** — state lives in the DB, not in an in-memory HashMap.
/// * **Concurrent-replica safety** — `BEGIN IMMEDIATE` serialises the
///   fire-and-delete step so each row fires exactly once across multiple
///   gateway instances sharing the same SQLite file.
pub struct DbEscalationScheduler {
    pool: SqlitePool,
    clock: Arc<dyn Clock>,
    queue: Arc<ApprovalQueue>,
    audit_sink: Arc<dyn AuditEventSink>,
    event_tx: broadcast::Sender<EscalationEvent>,
    poll_interval: Duration,
}

impl DbEscalationScheduler {
    /// Create a new scheduler and run pending DB migrations against `pool`.
    pub async fn new(
        pool: SqlitePool,
        clock: Arc<dyn Clock>,
        queue: Arc<ApprovalQueue>,
        audit_sink: Arc<dyn AuditEventSink>,
        event_tx: broadcast::Sender<EscalationEvent>,
        poll_interval: Duration,
    ) -> Result<Self, DbEscalationError> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self {
            pool,
            clock,
            queue,
            audit_sink,
            event_tx,
            poll_interval,
        })
    }

    /// Subscribe to escalation-fired events.
    pub fn subscribe(&self) -> broadcast::Receiver<EscalationEvent> {
        self.event_tx.subscribe()
    }

    /// Record an escalation timer for `request_id`.
    ///
    /// `escalate_at` is an absolute Unix epoch (seconds). `INSERT OR IGNORE`
    /// makes duplicate calls for the same `request_id` safe no-ops, preserving
    /// the original deadline.
    pub async fn register(
        &self,
        request_id: ApprovalRequestId,
        team_id: String,
        escalation_role: String,
        from_role: String,
        escalate_at: u64,
    ) -> Result<(), DbEscalationError> {
        let id_str = request_id.to_string();
        let escalate_at_i = escalate_at as i64;
        sqlx::query!(
            r#"
            INSERT OR IGNORE INTO pending_escalations
                (approval_id, team_id, escalation_role, from_role, escalate_at)
            VALUES (?, ?, ?, ?, ?)
            "#,
            id_str,
            team_id,
            escalation_role,
            from_role,
            escalate_at_i,
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Remove the escalation row for `request_id`.
    ///
    /// Returns `true` when a row existed and was deleted; `false` when absent.
    /// Call this when an approval is resolved before its timer fires.
    pub async fn cancel(&self, request_id: ApprovalRequestId) -> Result<bool, DbEscalationError> {
        let id_str = request_id.to_string();
        let result = sqlx::query!("DELETE FROM pending_escalations WHERE approval_id = ?", id_str,)
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Fire all due escalations in a single `BEGIN IMMEDIATE` transaction.
    ///
    /// `BEGIN IMMEDIATE` acquires a write lock before reading, so concurrent
    /// scheduler instances queue up rather than racing to process the same rows.
    /// Rows are deleted inside the transaction; events are emitted after commit
    /// so the DB lock is released as quickly as possible.
    ///
    /// At most 50 rows are processed per call; callers that have a backlog will
    /// catch up over subsequent polling intervals.
    pub async fn tick(&self) -> Result<(), DbEscalationError> {
        let now = self.clock.now_secs().min(i64::MAX as u64) as i64;

        let mut conn = self.pool.acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

        let rows = sqlx::query!(
            r#"
            SELECT approval_id, team_id, escalation_role, from_role
            FROM pending_escalations
            WHERE escalate_at <= ?
            ORDER BY escalate_at
            LIMIT 50
            "#,
            now,
        )
        .fetch_all(&mut *conn)
        .await?;

        if rows.is_empty() {
            sqlx::query("ROLLBACK").execute(&mut *conn).await?;
            return Ok(());
        }

        for row in &rows {
            sqlx::query!("DELETE FROM pending_escalations WHERE approval_id = ?", row.approval_id,)
                .execute(&mut *conn)
                .await?;
        }
        sqlx::query("COMMIT").execute(&mut *conn).await?;
        drop(conn);

        for row in rows {
            let approval_id = match row.approval_id.parse::<ApprovalRequestId>() {
                Ok(id) => id,
                Err(_) => {
                    tracing::warn!(
                        approval_id = %row.approval_id,
                        "pending_escalations row has invalid UUID — skipping"
                    );
                    continue;
                }
            };

            let still_pending = self
                .queue
                .update_routing_status(approval_id, format!("escalated_to_{}", row.escalation_role));
            if !still_pending {
                tracing::debug!(
                    %approval_id,
                    "escalation fired but approval already resolved — no event emitted"
                );
                continue;
            }

            tracing::info!(
                %approval_id,
                team_id = %row.team_id,
                from_role = %row.from_role,
                escalation_role = %row.escalation_role,
                "approval escalation fired"
            );

            self.audit_sink.emit(
                AuditEventType::ApprovalEscalated,
                serde_json::json!({
                    "approval_id": approval_id.to_string(),
                    "from_role":   row.from_role,
                    "to_role":     row.escalation_role,
                    "team_id":     row.team_id,
                })
                .to_string(),
            );

            let _ = self.event_tx.send(EscalationEvent {
                request_id: approval_id,
                team_id: row.team_id,
                escalation_approvers: vec![row.escalation_role],
            });
        }

        Ok(())
    }

    /// Run the polling loop until `token` is cancelled.
    ///
    /// `tokio::select!` wakes on either the poll interval or the cancellation
    /// signal, so shutdown latency is bounded by `poll_interval`. A final
    /// `tick` is executed on shutdown to flush any due rows before exit.
    pub async fn run(self: Arc<Self>, token: CancellationToken) {
        let mut interval = tokio::time::interval(self.poll_interval);
        loop {
            tokio::select! {
                _ = token.cancelled() => {
                    if let Err(e) = self.tick().await {
                        tracing::error!(error = %e, "escalation tick failed during shutdown flush");
                    }
                    break;
                }
                _ = interval.tick() => {
                    if let Err(e) = self.tick().await {
                        tracing::error!(error = %e, "escalation tick failed");
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum DbEscalationError {
    #[error("db escalation database error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("db escalation migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    use crate::approval::audit_sink::NoopAuditSink;
    use crate::approval::clock::FakeClock;

    async fn in_memory_scheduler(
        clock: Arc<dyn Clock>,
    ) -> (DbEscalationScheduler, broadcast::Receiver<EscalationEvent>) {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let queue = ApprovalQueue::new();
        let (tx, rx) = broadcast::channel(256);
        let scheduler =
            DbEscalationScheduler::new(pool, clock, queue, Arc::new(NoopAuditSink), tx, Duration::from_secs(30))
                .await
                .unwrap();
        (scheduler, rx)
    }

    fn clock(secs: u64) -> Arc<dyn Clock> {
        Arc::new(FakeClock::new(secs))
    }

    #[tokio::test]
    async fn register_then_cancel_returns_true() {
        let (s, _rx) = in_memory_scheduler(clock(1000)).await;
        let id = Uuid::new_v4();
        s.register(id, "team-a".into(), "OrgAdmin".into(), "TeamAdmin".into(), 2000)
            .await
            .unwrap();
        assert!(s.cancel(id).await.unwrap());
        assert!(!s.cancel(id).await.unwrap());
    }

    #[tokio::test]
    async fn cancel_nonexistent_returns_false() {
        let (s, _rx) = in_memory_scheduler(clock(1000)).await;
        assert!(!s.cancel(Uuid::new_v4()).await.unwrap());
    }

    #[tokio::test]
    async fn register_idempotent_insert_or_ignore() {
        let (s, _rx) = in_memory_scheduler(clock(1000)).await;
        let id = Uuid::new_v4();
        // First insert wins; second is silently ignored.
        s.register(id, "team-a".into(), "OrgAdmin".into(), "TeamAdmin".into(), 2000)
            .await
            .unwrap();
        s.register(id, "team-a".into(), "OrgAdmin".into(), "TeamAdmin".into(), 9999)
            .await
            .unwrap();
        // Cancel should still succeed once (confirming the row exists).
        assert!(s.cancel(id).await.unwrap());
        assert!(!s.cancel(id).await.unwrap());
    }

    #[tokio::test]
    async fn tick_fires_overdue_entry_and_emits_event() {
        let fake = Arc::new(FakeClock::new(1000));
        let (s, mut rx) = in_memory_scheduler(fake.clone() as Arc<dyn Clock>).await;

        // Submit an approval request so update_routing_status returns true.
        let req = aa_runtime::approval::ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".into(),
            action: "test".into(),
            condition_triggered: "test-policy".into(),
            submitted_at: 0,
            timeout_secs: 3600,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timeout".into(),
            },
            team_id: Some("team-a".into()),
            timeout_override_secs: None,
            escalation_role_override: None,
        };
        let id = req.request_id;
        let _fut = s.queue.submit(req);

        // escalate_at = 999 < now = 1000 → immediately due.
        s.register(id, "team-a".into(), "OrgAdmin".into(), "TeamAdmin".into(), 999)
            .await
            .unwrap();
        s.tick().await.unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.request_id, id);
        assert_eq!(event.team_id, "team-a");
        assert_eq!(event.escalation_approvers, vec!["OrgAdmin"]);
    }

    #[tokio::test]
    async fn tick_does_not_fire_future_entry() {
        let fake = Arc::new(FakeClock::new(1000));
        let (s, mut rx) = in_memory_scheduler(fake.clone() as Arc<dyn Clock>).await;

        let id = Uuid::new_v4();
        // escalate_at = 9999 > now = 1000 → not yet due.
        s.register(id, "team-a".into(), "OrgAdmin".into(), "TeamAdmin".into(), 9999)
            .await
            .unwrap();
        s.tick().await.unwrap();

        assert!(rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn tick_skips_already_resolved_approval() {
        let fake = Arc::new(FakeClock::new(1000));
        let (s, mut rx) = in_memory_scheduler(fake.clone() as Arc<dyn Clock>).await;

        // Register but do NOT submit to the queue → approval is not pending.
        let id = Uuid::new_v4();
        s.register(id, "team-b".into(), "OrgAdmin".into(), "TeamAdmin".into(), 0)
            .await
            .unwrap();
        s.tick().await.unwrap();

        // Row was deleted from DB but no event emitted.
        assert!(rx.try_recv().is_err());
        // Confirm row is gone.
        assert!(!s.cancel(id).await.unwrap());
    }

    #[tokio::test]
    async fn run_stops_on_cancellation_and_flushes_due_rows() {
        let fake = Arc::new(FakeClock::new(1000));
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let queue = ApprovalQueue::new();

        // Submit a pending approval so the escalation fires the event.
        let req = aa_runtime::approval::ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-2".into(),
            action: "test".into(),
            condition_triggered: "test-policy".into(),
            submitted_at: 0,
            timeout_secs: 3600,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timeout".into(),
            },
            team_id: Some("team-b".into()),
            timeout_override_secs: None,
            escalation_role_override: None,
        };
        let id = req.request_id;
        let _fut = queue.submit(req);

        let (tx, mut rx) = broadcast::channel(16);
        let scheduler = Arc::new(
            DbEscalationScheduler::new(
                pool,
                fake.clone() as Arc<dyn Clock>,
                queue,
                Arc::new(NoopAuditSink),
                tx,
                Duration::from_secs(3600),
            )
            .await
            .unwrap(),
        );
        scheduler
            .register(id, "team-b".into(), "OrgAdmin".into(), "TeamAdmin".into(), 0)
            .await
            .unwrap();

        let token = CancellationToken::new();
        let token_clone = token.clone();
        let sched_clone = Arc::clone(&scheduler);
        let handle = tokio::spawn(async move { sched_clone.run(token_clone).await });

        token.cancel();
        handle.await.unwrap();

        let event = rx.try_recv().unwrap();
        assert_eq!(event.request_id, id);
    }

    // -----------------------------------------------------------------------
    // Concurrency test: 3 instances, 100 escalations, each deleted exactly once
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn concurrent_instances_fire_each_row_exactly_once() {
        use sqlx::sqlite::SqliteConnectOptions;
        use tempfile::NamedTempFile;

        // Shared SQLite file on disk so multiple pools can connect to it.
        let tmp = NamedTempFile::new().unwrap();
        let opts = SqliteConnectOptions::new()
            .filename(tmp.path())
            .create_if_missing(true)
            .busy_timeout(Duration::from_secs(5));

        // Migrate once via a bootstrap pool.
        let bootstrap = SqlitePool::connect_with(opts.clone()).await.unwrap();
        sqlx::migrate!("./migrations").run(&bootstrap).await.unwrap();

        // Insert 100 immediately-due rows (escalate_at = 0).
        for _ in 0..100_usize {
            let id = Uuid::new_v4().to_string();
            let at = 0_i64;
            sqlx::query!(
                "INSERT OR IGNORE INTO pending_escalations (approval_id, team_id, escalation_role, from_role, escalate_at) VALUES (?, 'team-x', 'OrgAdmin', 'TeamAdmin', ?)",
                id,
                at,
            )
            .execute(&bootstrap)
            .await
            .unwrap();
        }
        bootstrap.close().await;

        // Build 3 scheduler instances sharing the same DB file.
        let shared_queue = ApprovalQueue::new();
        let mut schedulers = vec![];
        for _ in 0..3_usize {
            let pool = SqlitePool::connect_with(opts.clone()).await.unwrap();
            let (tx, _rx) = broadcast::channel::<EscalationEvent>(256);
            let clock: Arc<dyn Clock> = Arc::new(FakeClock::new(u64::MAX));
            let s = Arc::new(
                DbEscalationScheduler::new(
                    pool,
                    clock,
                    Arc::clone(&shared_queue),
                    Arc::new(NoopAuditSink),
                    tx,
                    Duration::from_secs(30),
                )
                .await
                .unwrap(),
            );
            schedulers.push(s);
        }

        // Run one tick() on all 3 instances concurrently.
        let mut tick_handles = vec![];
        for s in &schedulers {
            let s = Arc::clone(s);
            tick_handles.push(tokio::spawn(async move { s.tick().await.unwrap() }));
        }
        for h in tick_handles {
            h.await.unwrap();
        }

        // Every row must be deleted exactly once regardless of which instance
        // claimed it. BEGIN IMMEDIATE ensures no row is processed by two instances.
        let check_pool = SqlitePool::connect_with(opts.clone()).await.unwrap();
        let remaining: i64 = sqlx::query_scalar!("SELECT COUNT(*) FROM pending_escalations")
            .fetch_one(&check_pool)
            .await
            .unwrap();
        check_pool.close().await;

        assert_eq!(remaining, 0, "all 100 rows must be deleted exactly once");
        // Keep tmp alive until here so the file is not removed while pools are open.
        drop(tmp);
    }
}
