//! PostgreSQL-backed implementation of [`StorageBackend`](super::backend::StorageBackend).
//!
//! Sub-task progress: `connect()` (E18 S-C #1) and `migrate()` (E18 S-C #2)
//! are implemented as inherent methods. The full
//! [`StorageBackend`](super::backend::StorageBackend) trait impl is built up
//! incrementally across sub-tasks #3 – #7 and consolidated into an
//! `impl StorageBackend for PostgresBackend` block at the end.

use std::time::Duration;

use aa_core::identity::AgentId;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

use super::audit::{AuditEvent, AuditFilter};
use super::error::{StorageError, StorageResult};
use super::postgres_config::PostgresConfig;

/// Encode an [`AgentId`] for the `agent_id` TEXT column (canonical UUID
/// hyphenated form). Mirrors the SQLite backend's storage shape so the
/// same TEXT serialisation round-trips across both backends.
fn agent_id_to_text(id: &AgentId) -> String {
    uuid::Uuid::from_bytes(*id.as_bytes()).to_string()
}

/// Decode an `agent_id` TEXT column value back into an [`AgentId`].
fn agent_id_from_text(s: &str) -> StorageResult<AgentId> {
    let uuid = uuid::Uuid::parse_str(s).map_err(|e| StorageError::QueryFailed(format!("invalid agent_id {s}: {e}")))?;
    Ok(AgentId::from_bytes(*uuid.as_bytes()))
}

/// Decode a single `audit_events` row into an [`AuditEvent`].
///
/// Native PostgreSQL types map directly to the value-type fields —
/// `TIMESTAMPTZ` → `DateTime<Utc>`, `UUID` → `Uuid`, `JSONB` →
/// `serde_json::Value`, `BOOLEAN` → `bool`. `agent_id` is the only
/// column that takes a manual TEXT round-trip via [`agent_id_from_text`].
fn row_to_audit_event(row: &sqlx::postgres::PgRow) -> StorageResult<AuditEvent> {
    use sqlx::Row;

    let agent_id_text: String = row
        .try_get("agent_id")
        .map_err(|e| StorageError::QueryFailed(format!("agent_id column: {e}")))?;
    let agent_id = agent_id_from_text(&agent_id_text)?;

    Ok(AuditEvent {
        ts: row
            .try_get("ts")
            .map_err(|e| StorageError::QueryFailed(format!("ts column: {e}")))?,
        event_id: row
            .try_get("event_id")
            .map_err(|e| StorageError::QueryFailed(format!("event_id column: {e}")))?,
        agent_id,
        team_id: row
            .try_get("team_id")
            .map_err(|e| StorageError::QueryFailed(format!("team_id column: {e}")))?,
        action: row
            .try_get("action")
            .map_err(|e| StorageError::QueryFailed(format!("action column: {e}")))?,
        decision: row
            .try_get("decision")
            .map_err(|e| StorageError::QueryFailed(format!("decision column: {e}")))?,
        dry_run: row
            .try_get("dry_run")
            .map_err(|e| StorageError::QueryFailed(format!("dry_run column: {e}")))?,
        shadow_decision: row
            .try_get("shadow_decision")
            .map_err(|e| StorageError::QueryFailed(format!("shadow_decision column: {e}")))?,
        matched_rule_id: row
            .try_get("matched_rule_id")
            .map_err(|e| StorageError::QueryFailed(format!("matched_rule_id column: {e}")))?,
        payload: row
            .try_get("payload")
            .map_err(|e| StorageError::QueryFailed(format!("payload column: {e}")))?,
    })
}

/// Push the audit-event WHERE clause derived from `filter` into `qb`.
///
/// Adds clauses for `agent_id`, `team_id`, `from` / `to` (`ts >=` / `ts <`),
/// and `dry_run_only`. Pushes nothing when `filter` is empty, leaving the
/// caller's base `SELECT … FROM audit_events` intact.
fn push_audit_where<'q>(qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>, filter: &'q AuditFilter) {
    let mut started = false;
    let mut connective = move |qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>| {
        qb.push(if started { " AND " } else { " WHERE " });
        started = true;
    };
    if let Some(agent_id) = filter.agent_id.as_ref() {
        connective(qb);
        qb.push("agent_id = ").push_bind(agent_id_to_text(agent_id));
    }
    if let Some(team_id) = filter.team_id.as_ref() {
        connective(qb);
        qb.push("team_id = ").push_bind(team_id.clone());
    }
    if let Some(from) = filter.from {
        connective(qb);
        qb.push("ts >= ").push_bind(from);
    }
    if let Some(to) = filter.to {
        connective(qb);
        qb.push("ts < ").push_bind(to);
    }
    if filter.dry_run_only {
        connective(qb);
        qb.push("dry_run = TRUE");
    }
}

/// PostgreSQL-backed control-plane storage.
///
/// Created via [`PostgresBackend::connect`]. The trait surface (audit /
/// registry / policy / metrics / lifecycle methods) is filled in by the
/// later Epic-18 S-C sub-tasks.
pub struct PostgresBackend {
    pool: PgPool,
}

impl PostgresBackend {
    /// Open a connection pool against `config`.
    ///
    /// Returns [`StorageError::ConnectionFailed`] when `database_url` is
    /// unset or the pool cannot be opened. The error message explicitly
    /// names `AAASM_DATABASE_URL` so operators see the missing-env path
    /// without having to dig through stack traces.
    pub async fn connect(config: &PostgresConfig) -> StorageResult<Self> {
        let database_url = config.database_url.as_deref().ok_or_else(|| {
            StorageError::ConnectionFailed(
                "AAASM_DATABASE_URL is not set and storage.postgres.database_url is not configured".into(),
            )
        })?;

        let pool = PgPoolOptions::new()
            .max_connections(config.max_connections)
            .min_connections(config.min_connections)
            .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
            .connect(database_url)
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;

        Ok(Self { pool })
    }

    /// Apply the embedded `migrations/postgres/*.sql` migrations.
    ///
    /// Idempotent — sqlx records applied versions in `_sqlx_migrations`,
    /// so calling this against an already-migrated database is a no-op.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::MigrationFailed`] when any migration fails
    /// to apply or sqlx cannot verify previously-applied versions.
    pub async fn migrate(&self) -> StorageResult<()> {
        sqlx::migrate!("./migrations/postgres")
            .run(&self.pool)
            .await
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))
    }

    /// Persist a single audit event.
    ///
    /// Binds native PostgreSQL types: `TIMESTAMPTZ` for `ts`, `UUID` for
    /// `event_id`, `BOOLEAN` for `dry_run`, and `JSONB` for `payload`.
    /// `agent_id` is serialised via [`agent_id_to_text`] so the column
    /// shape matches the SQLite backend.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::QueryFailed`] when the INSERT is rejected
    /// (duplicate `(ts, event_id)` PK, transport failure, etc.).
    pub async fn append_audit_event(&self, event: &AuditEvent) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO audit_events \
             (ts, event_id, agent_id, team_id, action, decision, \
              dry_run, shadow_decision, matched_rule_id, payload) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(event.ts)
        .bind(event.event_id)
        .bind(agent_id_to_text(&event.agent_id))
        .bind(event.team_id.as_deref())
        .bind(&event.action)
        .bind(&event.decision)
        .bind(event.dry_run)
        .bind(event.shadow_decision.as_deref())
        .bind(event.matched_rule_id.as_deref())
        .bind(event.payload.as_ref())
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| StorageError::QueryFailed(e.to_string()))
    }

    /// Return audit events matching `filter`, ordered by timestamp descending.
    ///
    /// `filter.limit` and `filter.offset` translate to PostgreSQL `LIMIT` /
    /// `OFFSET` clauses with `i64` bindings.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::QueryFailed`] on driver errors and when a
    /// column cannot be decoded into its expected runtime type.
    pub async fn query_audit_events(&self, filter: AuditFilter) -> StorageResult<Vec<AuditEvent>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT ts, event_id, agent_id, team_id, action, decision, \
             dry_run, shadow_decision, matched_rule_id, payload FROM audit_events",
        );
        push_audit_where(&mut qb, &filter);
        qb.push(" ORDER BY ts DESC");
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
        }
        if let Some(offset) = filter.offset {
            qb.push(" OFFSET ").push_bind(i64::from(offset));
        }

        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        rows.iter().map(row_to_audit_event).collect()
    }

    /// Count audit events matching `filter`.
    ///
    /// Uses the same WHERE-builder as [`Self::query_audit_events`] so both
    /// methods always agree on filter semantics. The PostgreSQL
    /// `count(*)` returns `BIGINT`, which is bound as `i64` and cast to
    /// `u64`; rows above `i64::MAX` are impossible in practice.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::QueryFailed`] on driver errors.
    pub async fn count_audit_events(&self, filter: AuditFilter) -> StorageResult<u64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT count(*) FROM audit_events");
        push_audit_where(&mut qb, &filter);

        let count: i64 = qb
            .build_query_scalar()
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(count as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a connected backend when `AAASM_DATABASE_URL` is set, or `None`
    /// after printing a skip notice when the env var is absent. This lets the
    /// suite stay green on developer machines without a local PostgreSQL while
    /// still exercising the real driver in CI.
    async fn pg_backend_or_skip() -> Option<PostgresBackend> {
        let url = match std::env::var("AAASM_DATABASE_URL") {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "skipping postgres test: AAASM_DATABASE_URL not set (CI provides this via services: postgres)"
                );
                return None;
            }
        };
        let config = PostgresConfig {
            database_url: Some(url),
            ..PostgresConfig::default()
        };
        Some(
            PostgresBackend::connect(&config)
                .await
                .expect("connect to AAASM_DATABASE_URL"),
        )
    }

    #[tokio::test]
    async fn connect_rejects_missing_database_url() {
        let config = PostgresConfig::default();
        let result = PostgresBackend::connect(&config).await;
        match result {
            Err(StorageError::ConnectionFailed(msg)) => {
                assert!(
                    msg.contains("AAASM_DATABASE_URL"),
                    "missing-URL error must mention AAASM_DATABASE_URL, got: {msg}"
                );
            }
            Err(other) => panic!("expected ConnectionFailed, got {other:?}"),
            Ok(_) => panic!("expected error when database_url is None"),
        }
    }

    #[tokio::test]
    async fn migrate_creates_expected_tables() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        for table in ["agent_registry", "policy_versions", "audit_events", "metrics"] {
            let exists: bool =
                sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_tables WHERE tablename = $1)")
                    .bind(table)
                    .fetch_one(&backend.pool)
                    .await
                    .expect("query pg_tables");
            assert!(exists, "table {table} should exist after migrate()");
        }
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("first migrate");
        backend.migrate().await.expect("second migrate should be a no-op");
    }

    /// Mint a fresh, unique [`AgentId`] so every test can scope its
    /// inserts and assertions against an isolated key — necessary because
    /// the audit_events table is shared across all postgres tests when
    /// they run against the CI's single-database service.
    fn fresh_agent_id() -> AgentId {
        AgentId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
    }

    /// PostgreSQL `TIMESTAMPTZ` stores microsecond precision; chrono's
    /// `DateTime<Utc>::now()` is nanosecond-resolution. Round-trip
    /// assertions need a pre-truncated timestamp or they flake.
    fn now_micros() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::from_timestamp_micros(chrono::Utc::now().timestamp_micros())
            .expect("now fits in micros range")
    }

    fn sample_event(agent_id: AgentId, ts: chrono::DateTime<chrono::Utc>) -> AuditEvent {
        AuditEvent {
            ts,
            event_id: uuid::Uuid::new_v4(),
            agent_id,
            team_id: Some("test-team".to_string()),
            action: "tool_call".to_string(),
            decision: "allow".to_string(),
            dry_run: false,
            shadow_decision: None,
            matched_rule_id: Some("rule-42".to_string()),
            payload: Some(serde_json::json!({"tool": "shell", "args": ["ls", "-la"]})),
        }
    }

    #[tokio::test]
    async fn append_then_query_round_trip() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let event = sample_event(agent_id, now_micros());
        backend.append_audit_event(&event).await.expect("append");

        let rows = backend
            .query_audit_events(AuditFilter {
                agent_id: Some(agent_id),
                ..AuditFilter::default()
            })
            .await
            .expect("query");

        assert_eq!(rows.len(), 1, "expected exactly one row for fresh agent");
        assert_eq!(rows[0], event, "round-trip event must match insert exactly");
    }

    #[tokio::test]
    async fn query_filters_by_time_range() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let base = now_micros();
        // Three events spaced 10 minutes apart so we can pick a cutoff between them.
        let t0 = base - chrono::Duration::minutes(20);
        let t1 = base - chrono::Duration::minutes(10);
        let t2 = base;
        for ts in [t0, t1, t2] {
            backend
                .append_audit_event(&sample_event(agent_id, ts))
                .await
                .expect("append");
        }

        let recent = backend
            .query_audit_events(AuditFilter {
                agent_id: Some(agent_id),
                from: Some(base - chrono::Duration::minutes(15)),
                ..AuditFilter::default()
            })
            .await
            .expect("query");

        assert_eq!(recent.len(), 2, "from-filter should drop the oldest event");
        // ORDER BY ts DESC — t2 first, then t1.
        assert_eq!(recent[0].ts, t2);
        assert_eq!(recent[1].ts, t1);
    }

    #[tokio::test]
    async fn count_matches_query_length() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let base = now_micros();
        for offset in 0..5 {
            backend
                .append_audit_event(&sample_event(agent_id, base - chrono::Duration::seconds(offset)))
                .await
                .expect("append");
        }

        let filter = AuditFilter {
            agent_id: Some(agent_id),
            ..AuditFilter::default()
        };
        let rows = backend.query_audit_events(filter.clone()).await.expect("query");
        let count = backend.count_audit_events(filter).await.expect("count");

        assert_eq!(rows.len(), 5);
        assert_eq!(count, 5);
        assert_eq!(count as usize, rows.len(), "count must equal query length");
    }
}
