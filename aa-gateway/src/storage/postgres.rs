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

use super::agent::{AgentFilter, AgentRecord};
use super::audit::{AuditEvent, AuditFilter};
use super::error::{StorageError, StorageResult};
use super::metric::{Metric, MetricPoint, MetricQuery};
use super::policy::{PolicyDocument, PolicyMeta, PolicyVersion};
use super::postgres_config::PostgresConfig;
use super::retention::{ColdAction, RetentionPolicy, RetentionStats};

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

/// Decode a single `agent_registry` row into an [`AgentRecord`].
///
/// Native PostgreSQL types map directly to the value-type fields —
/// `TIMESTAMPTZ` → `DateTime<Utc>`, `JSONB` → `serde_json::Value` →
/// `BTreeMap<String, String>`. `agent_id` is the only column that takes
/// a manual TEXT round-trip via [`agent_id_from_text`].
fn row_to_agent_record(row: &sqlx::postgres::PgRow) -> StorageResult<AgentRecord> {
    use sqlx::Row;

    let agent_id_text: String = row
        .try_get("agent_id")
        .map_err(|e| StorageError::QueryFailed(format!("agent_id column: {e}")))?;
    let agent_id = agent_id_from_text(&agent_id_text)?;

    let metadata_json: serde_json::Value = row
        .try_get("metadata")
        .map_err(|e| StorageError::QueryFailed(format!("metadata column: {e}")))?;
    let metadata: std::collections::BTreeMap<String, String> =
        serde_json::from_value(metadata_json).map_err(|e| StorageError::QueryFailed(format!("metadata parse: {e}")))?;

    Ok(AgentRecord {
        agent_id,
        team_id: row
            .try_get("team_id")
            .map_err(|e| StorageError::QueryFailed(format!("team_id column: {e}")))?,
        org_id: row
            .try_get("org_id")
            .map_err(|e| StorageError::QueryFailed(format!("org_id column: {e}")))?,
        metadata,
        registered_at: row
            .try_get("registered_at")
            .map_err(|e| StorageError::QueryFailed(format!("registered_at column: {e}")))?,
        last_seen_at: row
            .try_get("last_seen_at")
            .map_err(|e| StorageError::QueryFailed(format!("last_seen_at column: {e}")))?,
        enforcement_mode: row
            .try_get("enforcement_mode")
            .map_err(|e| StorageError::QueryFailed(format!("enforcement_mode column: {e}")))?,
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

/// Decode a `policy_versions.document` JSONB value back into the byte
/// representation expected by [`PolicyDocument::bytes`].
///
/// Inverse of the `save_policy` encoding: a `{"raw_yaml": "<utf8>"}`
/// wrapper is unwrapped back to its inner string bytes; any other JSON
/// value is re-serialised to compact canonical JSON.
fn policy_document_bytes(value: serde_json::Value) -> Vec<u8> {
    if let serde_json::Value::Object(ref obj) = value {
        if obj.len() == 1 {
            if let Some(serde_json::Value::String(raw)) = obj.get("raw_yaml") {
                return raw.clone().into_bytes();
            }
        }
    }
    serde_json::to_vec(&value).expect("serialising a parsed JSON value never fails")
}

/// Map a [`MetricQuery::bucket`] string into the corresponding
/// PostgreSQL `date_trunc` unit. Returns
/// [`StorageError::QueryFailed`] for any unsupported value so the
/// query never gets near the database with a typo.
fn metric_bucket_unit(raw: &str) -> StorageResult<&'static str> {
    match raw.trim() {
        "1 second" => Ok("second"),
        "1 minute" => Ok("minute"),
        "1 hour" => Ok("hour"),
        "1 day" => Ok("day"),
        other => Err(StorageError::QueryFailed(format!(
            "unsupported metric bucket interval: {other:?} (supported: \"1 second\", \"1 minute\", \"1 hour\", \"1 day\")"
        ))),
    }
}

/// Push the metric WHERE clause derived from `query` into `qb`.
///
/// Adds clauses for `agent_id`, `metric`, `from` / `to` (`ts >=` / `ts <`).
/// Pushes nothing when no field is set.
fn push_metric_where<'q>(qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>, query: &'q MetricQuery) {
    let mut started = false;
    let mut connective = move |qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>| {
        qb.push(if started { " AND " } else { " WHERE " });
        started = true;
    };
    if let Some(agent_id) = query.agent_id.as_ref() {
        connective(qb);
        qb.push("agent_id = ").push_bind(agent_id_to_text(agent_id));
    }
    if let Some(metric) = query.metric.as_ref() {
        connective(qb);
        qb.push("metric = ").push_bind(metric.clone());
    }
    if let Some(from) = query.from {
        connective(qb);
        qb.push("ts >= ").push_bind(from);
    }
    if let Some(to) = query.to {
        connective(qb);
        qb.push("ts < ").push_bind(to);
    }
}

/// Push the agent-registry WHERE clause derived from `filter` into `qb`.
///
/// PostgreSQL JSONB exposes object lookups via `metadata->>'name'`, so the
/// `name_contains` filter does a parameterised LIKE against that key. SQLite
/// uses `json_extract(metadata, '$.name')` for the same effect.
fn push_agent_where<'q>(qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>, filter: &'q AgentFilter) {
    let mut started = false;
    let mut connective = move |qb: &mut sqlx::QueryBuilder<'q, sqlx::Postgres>| {
        qb.push(if started { " AND " } else { " WHERE " });
        started = true;
    };
    if let Some(team_id) = filter.team_id.as_ref() {
        connective(qb);
        qb.push("team_id = ").push_bind(team_id.clone());
    }
    if let Some(org_id) = filter.org_id.as_ref() {
        connective(qb);
        qb.push("org_id = ").push_bind(org_id.clone());
    }
    if let Some(name_contains) = filter.name_contains.as_ref() {
        connective(qb);
        qb.push("metadata->>'name' LIKE ")
            .push_bind(format!("%{name_contains}%"));
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

    /// Insert or update an agent record.
    ///
    /// Uses PostgreSQL `ON CONFLICT (agent_id) DO UPDATE` so a re-registration
    /// preserves the original `registered_at` while refreshing every other
    /// field — including `last_seen_at`, which is the column the gateway
    /// uses to detect liveness.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::QueryFailed`] when metadata fails to encode as
    /// JSON or the INSERT/UPDATE is rejected by the driver.
    pub async fn upsert_agent(&self, record: AgentRecord) -> StorageResult<()> {
        let metadata = serde_json::to_value(&record.metadata)
            .map_err(|e| StorageError::QueryFailed(format!("metadata serialize: {e}")))?;
        sqlx::query(
            "INSERT INTO agent_registry \
             (agent_id, team_id, org_id, metadata, registered_at, last_seen_at, enforcement_mode) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) \
             ON CONFLICT (agent_id) DO UPDATE SET \
               team_id          = EXCLUDED.team_id, \
               org_id           = EXCLUDED.org_id, \
               metadata         = EXCLUDED.metadata, \
               last_seen_at     = EXCLUDED.last_seen_at, \
               enforcement_mode = EXCLUDED.enforcement_mode",
        )
        .bind(agent_id_to_text(&record.agent_id))
        .bind(record.team_id.as_deref())
        .bind(record.org_id.as_deref())
        .bind(metadata)
        .bind(record.registered_at)
        .bind(record.last_seen_at)
        .bind(&record.enforcement_mode)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| StorageError::QueryFailed(e.to_string()))
    }

    /// Return the agent record for `id`, if registered.
    ///
    /// Returns `Ok(None)` for unknown ids; only backend failure surfaces
    /// as a [`StorageError`].
    pub async fn get_agent(&self, id: &AgentId) -> StorageResult<Option<AgentRecord>> {
        let row = sqlx::query(
            "SELECT agent_id, team_id, org_id, metadata, registered_at, last_seen_at, \
             enforcement_mode FROM agent_registry WHERE agent_id = $1",
        )
        .bind(agent_id_to_text(id))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        row.as_ref().map(row_to_agent_record).transpose()
    }

    /// Return all agent records matching `filter`, ordered by `agent_id`.
    ///
    /// `filter.limit` and `filter.offset` translate to PostgreSQL
    /// `LIMIT`/`OFFSET` bound as `i64`. `name_contains` performs a
    /// substring search against the `metadata.name` JSONB key.
    pub async fn list_agents(&self, filter: AgentFilter) -> StorageResult<Vec<AgentRecord>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT agent_id, team_id, org_id, metadata, registered_at, last_seen_at, \
             enforcement_mode FROM agent_registry",
        );
        push_agent_where(&mut qb, &filter);
        qb.push(" ORDER BY agent_id");
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
            if let Some(offset) = filter.offset {
                qb.push(" OFFSET ").push_bind(i64::from(offset));
            }
        }
        let rows = qb
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        rows.iter().map(row_to_agent_record).collect()
    }

    /// Remove the agent record for `id`.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] when no row matches; the error
    /// payload carries the offending agent id (TEXT form) so callers can
    /// log it without re-encoding.
    pub async fn delete_agent(&self, id: &AgentId) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM agent_registry WHERE agent_id = $1")
            .bind(agent_id_to_text(id))
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(agent_id_to_text(id)));
        }
        Ok(())
    }

    /// Save a new policy version.
    ///
    /// Document bytes are first parsed as JSON so JSON policies round-trip
    /// natively through the JSONB column. Anything that fails JSON parsing
    /// (typically YAML) is wrapped as `{"raw_yaml": "<utf8 string>"}` so
    /// the column always stores a valid JSON value.
    ///
    /// Runs inside a transaction: the next version is computed via
    /// `SELECT COALESCE(MAX(version), 0) + 1`, then INSERT-RETURNING brings
    /// the assigned `id`, `created_at`, and `is_active` back in a single
    /// round-trip. Fresh saves land with `is_active = FALSE`.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Conflict`] when the `(name, version)` UNIQUE
    ///   constraint trips (race against a concurrent save for the same name).
    /// - [`StorageError::QueryFailed`] on any other driver / transaction failure.
    pub async fn save_policy(&self, doc: PolicyDocument) -> StorageResult<PolicyVersion> {
        let document_json = match serde_json::from_slice::<serde_json::Value>(&doc.bytes) {
            Ok(value) => value,
            Err(_) => {
                let text = std::str::from_utf8(&doc.bytes)
                    .map_err(|e| StorageError::QueryFailed(format!("document bytes not UTF-8: {e}")))?;
                serde_json::json!({ "raw_yaml": text })
            }
        };

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("begin tx: {e}")))?;

        let next_version: i32 =
            sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM policy_versions WHERE name = $1")
                .bind(&doc.name)
                .fetch_one(&mut *tx)
                .await
                .map_err(|e| StorageError::QueryFailed(format!("compute next version: {e}")))?;

        let (_id, returned_version, created_at, is_active): (i64, i32, chrono::DateTime<chrono::Utc>, bool) =
            sqlx::query_as(
                "INSERT INTO policy_versions (name, version, document, is_active) \
             VALUES ($1, $2, $3, FALSE) \
             RETURNING id, version, created_at, is_active",
            )
            .bind(&doc.name)
            .bind(next_version)
            .bind(&document_json)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| match e {
                sqlx::Error::Database(db) if db.is_unique_violation() => {
                    StorageError::Conflict(format!("{}@{next_version}", doc.name))
                }
                other => StorageError::QueryFailed(other.to_string()),
            })?;

        tx.commit()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("commit tx: {e}")))?;

        let version =
            u32::try_from(returned_version).map_err(|e| StorageError::QueryFailed(format!("version overflow: {e}")))?;
        Ok(PolicyVersion {
            meta: PolicyMeta {
                name: doc.name.clone(),
                version,
                created_at,
                is_active,
            },
            document: doc,
        })
    }

    /// Return the currently-active policy version for `name`, if one is
    /// flagged.
    ///
    /// # Errors
    ///
    /// Returns `Ok(None)` when no version is active. Driver failures surface
    /// as [`StorageError::QueryFailed`].
    pub async fn get_active_policy(&self, name: &str) -> StorageResult<Option<PolicyDocument>> {
        let row: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT document FROM policy_versions \
             WHERE name = $1 AND is_active = TRUE LIMIT 1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(row.map(|(document,)| PolicyDocument {
            name: name.to_owned(),
            bytes: policy_document_bytes(document),
        }))
    }

    /// List every stored version of `name`, newest first.
    ///
    /// Returns an empty Vec when the name has no saved versions — only
    /// driver failures surface as [`StorageError`].
    pub async fn list_policy_versions(&self, name: &str) -> StorageResult<Vec<PolicyMeta>> {
        let rows: Vec<(i32, chrono::DateTime<chrono::Utc>, bool)> = sqlx::query_as(
            "SELECT version, created_at, is_active FROM policy_versions \
             WHERE name = $1 ORDER BY version DESC",
        )
        .bind(name)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        rows.into_iter()
            .map(|(version, created_at, is_active)| {
                let version =
                    u32::try_from(version).map_err(|e| StorageError::QueryFailed(format!("version overflow: {e}")))?;
                Ok(PolicyMeta {
                    name: name.to_owned(),
                    version,
                    created_at,
                    is_active,
                })
            })
            .collect()
    }

    /// Mark `version` of `name` as the active version.
    ///
    /// Runs the existence check and both UPDATEs inside one transaction so
    /// no caller can ever observe two active versions for the same name.
    ///
    /// # Errors
    ///
    /// - [`StorageError::NotFound`] when `(name, version)` does not exist.
    ///   Payload is formatted `"<name>@<version>"` to mirror the SQLite
    ///   backend.
    /// - [`StorageError::QueryFailed`] on driver / transaction failure.
    pub async fn rollback_policy(&self, name: &str, version: u32) -> StorageResult<()> {
        let version_i =
            i32::try_from(version).map_err(|e| StorageError::QueryFailed(format!("version overflow: {e}")))?;

        let mut tx = self
            .pool
            .begin()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("begin tx: {e}")))?;

        let exists: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM policy_versions WHERE name = $1 AND version = $2")
            .bind(name)
            .bind(version_i)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        if exists.is_none() {
            return Err(StorageError::NotFound(format!("{name}@{version}")));
        }

        sqlx::query(
            "UPDATE policy_versions SET is_active = FALSE \
             WHERE name = $1 AND is_active = TRUE",
        )
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        sqlx::query(
            "UPDATE policy_versions SET is_active = TRUE \
             WHERE name = $1 AND version = $2",
        )
        .bind(name)
        .bind(version_i)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("commit tx: {e}")))?;
        Ok(())
    }

    /// Persist a single metric sample.
    ///
    /// Native PostgreSQL bindings: `TIMESTAMPTZ` for `ts`, `DOUBLE PRECISION`
    /// for `value`, JSONB for `labels`. `agent_id` is serialised via
    /// [`agent_id_to_text`] so the column matches the shape used elsewhere.
    ///
    /// # Errors
    ///
    /// - [`StorageError::QueryFailed`] when `labels` cannot be encoded as
    ///   JSON or the INSERT is rejected.
    pub async fn record_metric(&self, m: Metric) -> StorageResult<()> {
        let labels =
            serde_json::to_value(&m.labels).map_err(|e| StorageError::QueryFailed(format!("labels serialize: {e}")))?;
        sqlx::query(
            "INSERT INTO metrics (ts, agent_id, metric, value, labels) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(m.ts)
        .bind(agent_id_to_text(&m.agent_id))
        .bind(&m.metric)
        .bind(m.value)
        .bind(labels)
        .execute(&self.pool)
        .await
        .map(|_| ())
        .map_err(|e| StorageError::QueryFailed(e.to_string()))
    }

    /// Return metric points matching `query`, ordered by timestamp ascending.
    ///
    /// When `query.bucket` is set, rows are aggregated via
    /// `date_trunc(<unit>, ts)` + `AVG(value)` grouped by the truncated
    /// timestamp. Supported bucket strings are validated by
    /// [`metric_bucket_unit`] before any SQL hits the wire, so a typo
    /// surfaces as [`StorageError::QueryFailed`] rather than a confusing
    /// driver error.
    ///
    /// When `query.bucket` is `None`, raw `(ts, value)` rows are returned.
    /// `query.limit` translates to `LIMIT $N` (bound as `i64`).
    ///
    /// # Errors
    ///
    /// - [`StorageError::QueryFailed`] for an unsupported bucket string or
    ///   any driver failure.
    pub async fn query_metrics(&self, query: MetricQuery) -> StorageResult<Vec<MetricPoint>> {
        let bucket_unit = query.bucket.as_deref().map(metric_bucket_unit).transpose()?;

        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT ");
        if let Some(unit) = bucket_unit {
            // `unit` came from a validated allow-list, never user input
            qb.push("date_trunc('");
            qb.push(unit);
            qb.push("', ts) AS bucket_ts, AVG(value) AS value FROM metrics");
        } else {
            qb.push("ts, value FROM metrics");
        }

        push_metric_where(&mut qb, &query);

        if let Some(unit) = bucket_unit {
            // Reference the full expression instead of the column alias
            // `bucket_ts` — and avoid the raw `metrics.ts` column — so the
            // aggregation actually collapses rows sharing the same truncated
            // timestamp.
            qb.push(" GROUP BY date_trunc('");
            qb.push(unit);
            qb.push("', ts) ORDER BY date_trunc('");
            qb.push(unit);
            qb.push("', ts) ASC");
        } else {
            qb.push(" ORDER BY ts ASC");
        }
        if let Some(limit) = query.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
        }

        let rows: Vec<(chrono::DateTime<chrono::Utc>, f64)> = qb
            .build_query_as()
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(rows.into_iter().map(|(ts, value)| MetricPoint { ts, value }).collect())
    }

    /// Apply `policy` to the `audit_events` table.
    ///
    /// The cold-tier cutoff is `now() - (hot_days + warm_days)` — any row
    /// with `ts` older than this is past the warm tier and a candidate
    /// for cold-action processing.
    ///
    /// * `dry_run = true` projects `dropped_rows` via `SELECT count(*)`
    ///   without modifying any rows. `freed_bytes` is left at `0` since
    ///   no chunks are compressed (E18 S-D will replace this path with
    ///   TimescaleDB `drop_chunks` + byte accounting).
    /// * `dry_run = false`, `cold_action = Drop` → `DELETE FROM
    ///   audit_events WHERE ts < $1`; the affected row count populates
    ///   `dropped_rows`.
    /// * `cold_action = Archive` → returns
    ///   [`StorageError::RetentionError`] until E18 S-D lands the
    ///   TimescaleDB `drop_chunks()` path. The error surfaces the
    ///   archive URL so operators see what they configured.
    ///
    /// `hot_rows` is always populated via a second `count(*)` filtered
    /// at the hot cutoff so the caller can report how much data is
    /// indexed-and-queryable after the run.
    pub async fn apply_retention(&self, policy: &RetentionPolicy) -> StorageResult<RetentionStats> {
        if matches!(policy.cold_action, ColdAction::Archive) {
            return Err(StorageError::RetentionError(format!(
                "archive cold_action not supported by PostgresBackend yet (S-D will add drop_chunks); \
                 archive_url = {:?}",
                policy.archive_url
            )));
        }

        let now = chrono::Utc::now();
        let cold_threshold = now - chrono::Duration::days(i64::from(policy.hot_days + policy.warm_days));
        let hot_threshold = now - chrono::Duration::days(i64::from(policy.hot_days));

        let dropped_rows: u64 = if policy.dry_run {
            let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE ts < $1")
                .bind(cold_threshold)
                .fetch_one(&self.pool)
                .await
                .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
            count as u64
        } else {
            let result = sqlx::query("DELETE FROM audit_events WHERE ts < $1")
                .bind(cold_threshold)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::RetentionError(e.to_string()))?;
            result.rows_affected()
        };

        let hot_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE ts >= $1")
            .bind(hot_threshold)
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        Ok(RetentionStats {
            hot_rows: hot_count as u64,
            compressed_rows: 0,
            archived_rows: 0,
            dropped_rows,
            freed_bytes: 0,
            ran_at: chrono::Utc::now(),
        })
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

    #[tokio::test]
    async fn dry_run_only_filter_excludes_non_dry_events() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let base = now_micros();

        let dry = AuditEvent {
            dry_run: true,
            ..sample_event(agent_id, base)
        };
        let live = AuditEvent {
            dry_run: false,
            ..sample_event(agent_id, base - chrono::Duration::seconds(1))
        };
        backend.append_audit_event(&dry).await.expect("append dry");
        backend.append_audit_event(&live).await.expect("append live");

        let dry_only = backend
            .query_audit_events(AuditFilter {
                agent_id: Some(agent_id),
                dry_run_only: true,
                ..AuditFilter::default()
            })
            .await
            .expect("query dry-only");

        assert_eq!(dry_only.len(), 1, "expected only the dry-run event");
        assert!(dry_only[0].dry_run, "returned event must be dry_run = true");
        assert_eq!(dry_only[0].event_id, dry.event_id);
    }

    fn sample_agent_record(
        agent_id: AgentId,
        registered_at: chrono::DateTime<chrono::Utc>,
        last_seen_at: chrono::DateTime<chrono::Utc>,
    ) -> AgentRecord {
        let mut metadata = std::collections::BTreeMap::new();
        metadata.insert("name".to_string(), "alpha-agent".to_string());
        metadata.insert("env".to_string(), "test".to_string());
        AgentRecord {
            agent_id,
            team_id: Some("team-rust".to_string()),
            org_id: Some("acme".to_string()),
            metadata,
            registered_at,
            last_seen_at,
            enforcement_mode: "enforce".to_string(),
        }
    }

    #[tokio::test]
    async fn upsert_then_get_round_trip() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let ts = now_micros();
        let record = sample_agent_record(agent_id, ts, ts);
        backend.upsert_agent(record.clone()).await.expect("upsert");

        let fetched = backend
            .get_agent(&agent_id)
            .await
            .expect("get_agent")
            .expect("agent should exist");

        assert_eq!(fetched, record, "round-trip record must match insert exactly");
    }

    #[tokio::test]
    async fn upsert_updates_last_seen_at() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let t1 = now_micros();
        let t2 = t1 + chrono::Duration::seconds(60);

        backend
            .upsert_agent(sample_agent_record(agent_id, t1, t1))
            .await
            .expect("first upsert");
        backend
            .upsert_agent(sample_agent_record(agent_id, t1, t2))
            .await
            .expect("second upsert");

        let fetched = backend
            .get_agent(&agent_id)
            .await
            .expect("get_agent")
            .expect("agent should exist");

        assert_eq!(fetched.last_seen_at, t2, "second upsert must move last_seen_at forward");
        assert_eq!(
            fetched.registered_at, t1,
            "registered_at must be preserved across re-registration"
        );
    }

    #[tokio::test]
    async fn list_filters_by_team() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        // Use a fresh team_id per test to isolate from rows left by other tests.
        let team = format!("team-{}", uuid::Uuid::new_v4());
        let other_team = format!("team-{}", uuid::Uuid::new_v4());
        let ts = now_micros();

        let mut in_team_a = sample_agent_record(fresh_agent_id(), ts, ts);
        in_team_a.team_id = Some(team.clone());
        let mut in_team_a_2 = sample_agent_record(fresh_agent_id(), ts, ts);
        in_team_a_2.team_id = Some(team.clone());
        let mut in_other = sample_agent_record(fresh_agent_id(), ts, ts);
        in_other.team_id = Some(other_team.clone());

        backend.upsert_agent(in_team_a.clone()).await.expect("upsert a1");
        backend.upsert_agent(in_team_a_2.clone()).await.expect("upsert a2");
        backend.upsert_agent(in_other.clone()).await.expect("upsert other");

        let listed = backend
            .list_agents(AgentFilter {
                team_id: Some(team.clone()),
                ..AgentFilter::default()
            })
            .await
            .expect("list");

        assert_eq!(listed.len(), 2, "filter should return both team-a agents");
        assert!(
            listed.iter().all(|r| r.team_id.as_deref() == Some(team.as_str())),
            "every returned row must belong to {team}",
        );
    }

    #[tokio::test]
    async fn delete_unknown_returns_not_found() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let missing = fresh_agent_id();
        let err = backend
            .delete_agent(&missing)
            .await
            .expect_err("delete of unknown id must error");

        match err {
            StorageError::NotFound(payload) => {
                assert_eq!(
                    payload,
                    agent_id_to_text(&missing),
                    "NotFound payload should carry the offending TEXT id",
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Mint a fresh, unique policy name so each test's saves and rollbacks
    /// stay isolated against the shared CI database.
    fn fresh_policy_name() -> String {
        format!("policy-{}", uuid::Uuid::new_v4())
    }

    /// JSON policy doc with alphabetical keys so serde_json's canonical
    /// re-serialisation round-trips byte-equal back to this slice.
    fn json_policy(name: &str, version_marker: u32) -> PolicyDocument {
        PolicyDocument {
            name: name.to_owned(),
            bytes: format!(r#"{{"marker":{version_marker},"rule":"allow"}}"#).into_bytes(),
        }
    }

    #[tokio::test]
    async fn save_policy_assigns_monotonic_versions() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let name = fresh_policy_name();
        let v1 = backend.save_policy(json_policy(&name, 1)).await.expect("save 1");
        let v2 = backend.save_policy(json_policy(&name, 2)).await.expect("save 2");
        let v3 = backend.save_policy(json_policy(&name, 3)).await.expect("save 3");

        assert_eq!(v1.meta.version, 1);
        assert_eq!(v2.meta.version, 2);
        assert_eq!(v3.meta.version, 3);
    }

    #[tokio::test]
    async fn save_policy_does_not_activate_by_default() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let name = fresh_policy_name();
        let saved = backend.save_policy(json_policy(&name, 1)).await.expect("save");

        assert!(
            !saved.meta.is_active,
            "freshly saved policy must land with is_active = false"
        );
        let active = backend.get_active_policy(&name).await.expect("get_active");
        assert!(
            active.is_none(),
            "no version should be active until rollback_policy is called"
        );
    }

    #[tokio::test]
    async fn rollback_then_get_active_returns_chosen_version() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let name = fresh_policy_name();
        let v1 = json_policy(&name, 1);
        let v2 = json_policy(&name, 2);
        let v3 = json_policy(&name, 3);
        backend.save_policy(v1).await.expect("save v1");
        backend.save_policy(v2.clone()).await.expect("save v2");
        backend.save_policy(v3).await.expect("save v3");

        backend.rollback_policy(&name, 2).await.expect("rollback to v2");

        let active = backend
            .get_active_policy(&name)
            .await
            .expect("get_active")
            .expect("a version must be active after rollback");

        assert_eq!(active.bytes, v2.bytes, "active document must be the v2 we wrote");

        // Cross-check via list: exactly one row should be flagged active and
        // it must be the one we rolled back to.
        let metas = backend.list_policy_versions(&name).await.expect("list_policy_versions");
        let active_metas: Vec<&PolicyMeta> = metas.iter().filter(|m| m.is_active).collect();
        assert_eq!(active_metas.len(), 1, "exactly one version must be active");
        assert_eq!(active_metas[0].version, 2);
    }

    #[tokio::test]
    async fn rollback_unknown_version_returns_not_found() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let name = fresh_policy_name();
        backend.save_policy(json_policy(&name, 1)).await.expect("save v1");

        let err = backend
            .rollback_policy(&name, 999)
            .await
            .expect_err("rollback of missing version must error");

        match err {
            StorageError::NotFound(payload) => {
                assert_eq!(
                    payload,
                    format!("{name}@999"),
                    "NotFound payload should carry <name>@<version>",
                );
            }
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    /// Mint a fresh metric name so each test scopes its inserts and
    /// assertions to its own slice of the shared `metrics` table.
    fn fresh_metric_name() -> String {
        format!("metric-{}", uuid::Uuid::new_v4())
    }

    fn sample_metric(agent_id: AgentId, metric: &str, ts: chrono::DateTime<chrono::Utc>, value: f64) -> Metric {
        let mut labels = std::collections::BTreeMap::new();
        labels.insert("region".to_string(), "us-west".to_string());
        Metric {
            ts,
            agent_id,
            metric: metric.to_owned(),
            value,
            labels,
        }
    }

    #[tokio::test]
    async fn record_metric_then_query_round_trip() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let metric_name = fresh_metric_name();
        let ts = now_micros();
        backend
            .record_metric(sample_metric(agent_id, &metric_name, ts, 42.5))
            .await
            .expect("record_metric");

        let points = backend
            .query_metrics(MetricQuery {
                agent_id: Some(agent_id),
                metric: Some(metric_name.clone()),
                ..MetricQuery::default()
            })
            .await
            .expect("query_metrics");

        assert_eq!(points.len(), 1, "expected the single sample we just inserted");
        assert_eq!(points[0].ts, ts);
        assert_eq!(points[0].value, 42.5);
    }

    #[tokio::test]
    async fn query_metrics_with_bucket_aggregates() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let agent_id = fresh_agent_id();
        let metric_name = fresh_metric_name();
        // Three samples within the same minute — date_trunc('minute') collapses
        // them into a single bucketed point with the averaged value. Aligning
        // to a minute boundary makes the test timing-deterministic regardless
        // of when in the wall-clock minute it runs.
        let now = chrono::Utc::now();
        let base = chrono::DateTime::from_timestamp(now.timestamp() / 60 * 60, 0)
            .expect("minute-aligned timestamp fits in chrono range");
        for (offset_secs, value) in [(0i64, 10.0_f64), (10, 20.0), (20, 30.0)] {
            let ts = base + chrono::Duration::seconds(offset_secs);
            backend
                .record_metric(sample_metric(agent_id, &metric_name, ts, value))
                .await
                .expect("record");
        }

        let points = backend
            .query_metrics(MetricQuery {
                agent_id: Some(agent_id),
                metric: Some(metric_name.clone()),
                bucket: Some("1 minute".to_string()),
                ..MetricQuery::default()
            })
            .await
            .expect("query_metrics");

        assert_eq!(
            points.len(),
            1,
            "three samples in the same minute must collapse to one bucket"
        );
        assert!(
            (points[0].value - 20.0).abs() < 1e-9,
            "averaged value should be (10 + 20 + 30) / 3 = 20.0, got {}",
            points[0].value,
        );
    }

    #[tokio::test]
    async fn query_metrics_unsupported_bucket_unit_returns_query_failed() {
        let Some(backend) = pg_backend_or_skip().await else {
            return;
        };
        backend.migrate().await.expect("migrate");

        let err = backend
            .query_metrics(MetricQuery {
                bucket: Some("5 microseconds".to_string()),
                ..MetricQuery::default()
            })
            .await
            .expect_err("unsupported bucket must error");

        match err {
            StorageError::QueryFailed(msg) => {
                assert!(
                    msg.contains("unsupported metric bucket"),
                    "error must explain the rejection, got: {msg}",
                );
            }
            other => panic!("expected QueryFailed, got {other:?}"),
        }
    }
}
