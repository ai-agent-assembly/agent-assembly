//! SQLite implementation of the [`StorageBackend`](super::backend::StorageBackend) trait.
//!
//! Targets local development mode: zero external infrastructure, single-file
//! durability at the configured path (default `~/.aasm/local.db`). Data
//! survives gateway restarts.
//!
//! Concrete trait methods land in subsequent Epic-18 S-B sub-tasks; this
//! sub-module currently exposes only the configuration value type and the
//! [`SqliteBackend`] constructor / connection-pool plumbing.
//!
//! Spec reference: lines 7140–7155 (local dev mode storage stack).

use std::path::{Path, PathBuf};

use aa_core::identity::AgentId;
use async_trait::async_trait;
use sqlx::SqlitePool;

use super::agent::{AgentFilter, AgentRecord};
use super::audit::{AuditEvent, AuditFilter};
use super::backend::StorageBackend;
use super::error::{StorageError, StorageResult};
use super::health::StorageHealth;
use super::metric::{Metric, MetricPoint, MetricQuery};
use super::policy::{PolicyDocument, PolicyMeta, PolicyVersion};
use super::retention::{RetentionPolicy, RetentionStats};

/// SQL DDL applied by [`SqliteBackend::migrate`] on every gateway start.
///
/// Each statement is `CREATE TABLE IF NOT EXISTS` / `CREATE INDEX IF NOT
/// EXISTS`, so the slice is safe to apply against either a fresh file or
/// an already-migrated one. Statements run in declaration order; indexes
/// follow their owning table.
///
/// Mirrors the SQLite schema documented under Story AAASM-1584 (Epic 18 S-B).
const SCHEMA: &[&str] = &[
    // audit_events — composite (ts, event_id) primary key with agent + ts indexes.
    "CREATE TABLE IF NOT EXISTS audit_events (
        ts              TEXT NOT NULL,
        event_id        TEXT NOT NULL,
        agent_id        TEXT NOT NULL,
        team_id         TEXT,
        action          TEXT NOT NULL,
        decision        TEXT NOT NULL,
        dry_run         INTEGER NOT NULL DEFAULT 0,
        shadow_decision TEXT,
        matched_rule_id TEXT,
        payload         TEXT,
        PRIMARY KEY (ts, event_id)
    )",
    "CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_events(agent_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts)",
    // agent_registry — durable identity / config slice of the registry.
    "CREATE TABLE IF NOT EXISTS agent_registry (
        agent_id          TEXT PRIMARY KEY,
        team_id           TEXT,
        org_id            TEXT,
        metadata          TEXT NOT NULL DEFAULT '{}',
        registered_at     TEXT NOT NULL,
        last_seen_at      TEXT NOT NULL,
        enforcement_mode  TEXT NOT NULL DEFAULT 'enforce'
    )",
    // policy_versions — versioned policy documents with at most one active
    // version per name (enforced at the application layer).
    "CREATE TABLE IF NOT EXISTS policy_versions (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        name        TEXT NOT NULL,
        version     INTEGER NOT NULL,
        document    TEXT NOT NULL,
        created_at  TEXT NOT NULL,
        is_active   INTEGER NOT NULL DEFAULT 0,
        UNIQUE(name, version)
    )",
    // metrics — time-series sample stream; no index in SQLite mode.
    "CREATE TABLE IF NOT EXISTS metrics (
        ts        TEXT NOT NULL,
        agent_id  TEXT NOT NULL,
        metric    TEXT NOT NULL,
        value     REAL NOT NULL,
        labels    TEXT NOT NULL DEFAULT '{}'
    )",
];

/// Local SQLite backend configuration.
///
/// Defined here as a minimal type so this Story (E18 S-B) can land
/// independently of E18 S-H (AAASM-1582), which will introduce the full
/// gateway storage-config parser. S-H may later move or extend this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqliteConfig {
    /// Filesystem path to the SQLite database file. A leading `~` is
    /// expanded to the current user's home directory. Parent directories
    /// are created on first open.
    pub path: PathBuf,
}

/// SQLite-backed implementation of [`StorageBackend`](super::backend::StorageBackend).
///
/// Concrete trait methods land in subsequent Epic-18 S-B sub-tasks; this
/// struct currently exposes only the [`SqliteBackend::open`] constructor
/// and an internal connection-pool handle.
pub struct SqliteBackend {
    pool: SqlitePool,
}

impl SqliteBackend {
    /// Open (or create) the SQLite database at the configured path.
    ///
    /// On first open this:
    ///
    /// 1. Expands a leading `~` in `config.path` to the user's home directory.
    /// 2. Creates the parent directory if absent.
    /// 3. Opens a connection pool with `mode=rwc` (read-write, create-if-missing).
    /// 4. Enables WAL journal mode for better concurrent reads.
    ///
    /// # Errors
    ///
    /// - [`StorageError::ConnectionFailed`] if the parent directory cannot
    ///   be created, the pool cannot be opened, or the WAL pragma is rejected.
    pub async fn open(config: &SqliteConfig) -> StorageResult<Self> {
        let path = expand_tilde(&config.path);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    StorageError::ConnectionFailed(format!(
                        "failed to create parent directory {}: {e}",
                        parent.display()
                    ))
                })?;
            }
        }
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let pool = SqlitePool::connect(&url)
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await
            .map_err(|e| StorageError::ConnectionFailed(format!("WAL pragma: {e}")))?;
        Ok(Self { pool })
    }

    /// Borrow the connection pool. Crate-internal helper for trait-impl
    /// sub-modules that land in subsequent S-B sub-tasks.
    #[allow(dead_code)] // first non-test consumer arrives with the trait impl methods
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

/// Encode an [`AgentId`] for storage as a TEXT column (canonical UUID
/// hyphenated string).
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
/// Maps TEXT timestamps back to `DateTime<Utc>` and TEXT JSON payloads
/// back to `serde_json::Value`. Any malformed column produces
/// [`StorageError::QueryFailed`] with the column name.
fn row_to_audit_event(row: &sqlx::sqlite::SqliteRow) -> StorageResult<AuditEvent> {
    use sqlx::Row;

    let ts_text: String = row
        .try_get("ts")
        .map_err(|e| StorageError::QueryFailed(format!("ts column: {e}")))?;
    let ts = chrono::DateTime::parse_from_rfc3339(&ts_text)
        .map_err(|e| StorageError::QueryFailed(format!("ts parse: {e}")))?
        .with_timezone(&chrono::Utc);

    let event_id_text: String = row
        .try_get("event_id")
        .map_err(|e| StorageError::QueryFailed(format!("event_id column: {e}")))?;
    let event_id =
        uuid::Uuid::parse_str(&event_id_text).map_err(|e| StorageError::QueryFailed(format!("event_id parse: {e}")))?;

    let agent_id_text: String = row
        .try_get("agent_id")
        .map_err(|e| StorageError::QueryFailed(format!("agent_id column: {e}")))?;
    let agent_id = agent_id_from_text(&agent_id_text)?;

    let dry_run: i64 = row
        .try_get("dry_run")
        .map_err(|e| StorageError::QueryFailed(format!("dry_run column: {e}")))?;

    let payload_text: Option<String> = row
        .try_get("payload")
        .map_err(|e| StorageError::QueryFailed(format!("payload column: {e}")))?;
    let payload = payload_text
        .map(|t| {
            serde_json::from_str::<serde_json::Value>(&t)
                .map_err(|e| StorageError::QueryFailed(format!("payload parse: {e}")))
        })
        .transpose()?;

    Ok(AuditEvent {
        ts,
        event_id,
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
        dry_run: dry_run != 0,
        shadow_decision: row
            .try_get("shadow_decision")
            .map_err(|e| StorageError::QueryFailed(format!("shadow_decision column: {e}")))?,
        matched_rule_id: row
            .try_get("matched_rule_id")
            .map_err(|e| StorageError::QueryFailed(format!("matched_rule_id column: {e}")))?,
        payload,
    })
}

/// Push the audit-event WHERE clause derived from `filter` into `qb`.
///
/// Adds clauses for `agent_id`, `team_id`, `from`/`to` (`ts >=` / `ts <`),
/// and `dry_run_only`. Pushes nothing when `filter` is empty, leaving the
/// caller's `SELECT … FROM audit_events` unchanged.
fn push_audit_where<'q>(qb: &mut sqlx::QueryBuilder<'q, sqlx::Sqlite>, filter: &'q AuditFilter) {
    let mut started = false;
    let mut connective = move |qb: &mut sqlx::QueryBuilder<'q, sqlx::Sqlite>| {
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
        qb.push("ts >= ").push_bind(from.to_rfc3339());
    }
    if let Some(to) = filter.to {
        connective(qb);
        qb.push("ts < ").push_bind(to.to_rfc3339());
    }
    if filter.dry_run_only {
        connective(qb);
        qb.push("dry_run = 1");
    }
}

/// Decode a single `agent_registry` row into an [`AgentRecord`].
///
/// Maps TEXT timestamps back to `DateTime<Utc>` and TEXT JSON metadata
/// back to a `BTreeMap<String, String>`.
fn row_to_agent_record(row: &sqlx::sqlite::SqliteRow) -> StorageResult<AgentRecord> {
    use sqlx::Row;

    let agent_id_text: String = row
        .try_get("agent_id")
        .map_err(|e| StorageError::QueryFailed(format!("agent_id column: {e}")))?;
    let agent_id = agent_id_from_text(&agent_id_text)?;

    let metadata_text: String = row
        .try_get("metadata")
        .map_err(|e| StorageError::QueryFailed(format!("metadata column: {e}")))?;
    let metadata: std::collections::BTreeMap<String, String> =
        serde_json::from_str(&metadata_text).map_err(|e| StorageError::QueryFailed(format!("metadata parse: {e}")))?;

    let registered_at: String = row
        .try_get("registered_at")
        .map_err(|e| StorageError::QueryFailed(format!("registered_at column: {e}")))?;
    let registered_at = chrono::DateTime::parse_from_rfc3339(&registered_at)
        .map_err(|e| StorageError::QueryFailed(format!("registered_at parse: {e}")))?
        .with_timezone(&chrono::Utc);

    let last_seen_at: String = row
        .try_get("last_seen_at")
        .map_err(|e| StorageError::QueryFailed(format!("last_seen_at column: {e}")))?;
    let last_seen_at = chrono::DateTime::parse_from_rfc3339(&last_seen_at)
        .map_err(|e| StorageError::QueryFailed(format!("last_seen_at parse: {e}")))?
        .with_timezone(&chrono::Utc);

    Ok(AgentRecord {
        agent_id,
        team_id: row
            .try_get("team_id")
            .map_err(|e| StorageError::QueryFailed(format!("team_id column: {e}")))?,
        org_id: row
            .try_get("org_id")
            .map_err(|e| StorageError::QueryFailed(format!("org_id column: {e}")))?,
        metadata,
        registered_at,
        last_seen_at,
        enforcement_mode: row
            .try_get("enforcement_mode")
            .map_err(|e| StorageError::QueryFailed(format!("enforcement_mode column: {e}")))?,
    })
}

/// Push the agent-registry WHERE clause derived from `filter` into `qb`.
///
/// Uses SQLite's JSON1 `json_extract` to perform the substring match on
/// the metadata `name` key. Pushes nothing for an empty filter.
fn push_agent_where<'q>(qb: &mut sqlx::QueryBuilder<'q, sqlx::Sqlite>, filter: &'q AgentFilter) {
    let mut started = false;
    let mut connective = move |qb: &mut sqlx::QueryBuilder<'q, sqlx::Sqlite>| {
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
        qb.push("json_extract(metadata, '$.name') LIKE ")
            .push_bind(format!("%{name_contains}%"));
    }
}

/// Trait wiring. Concrete method bodies for each slice land in their own
/// Epic-18 S-B sub-task; until then the unimplemented slices return
/// `todo!("AAASM-…")` so the workspace compiles.
#[async_trait]
impl StorageBackend for SqliteBackend {
    async fn append_audit_event(&self, event: &AuditEvent) -> StorageResult<()> {
        let payload_text = match event.payload.as_ref() {
            Some(value) => Some(
                serde_json::to_string(value)
                    .map_err(|e| StorageError::QueryFailed(format!("payload serialize: {e}")))?,
            ),
            None => None,
        };
        sqlx::query(
            "INSERT INTO audit_events \
             (ts, event_id, agent_id, team_id, action, decision, dry_run, shadow_decision, matched_rule_id, payload) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(event.ts.to_rfc3339())
        .bind(event.event_id.to_string())
        .bind(agent_id_to_text(&event.agent_id))
        .bind(event.team_id.clone())
        .bind(&event.action)
        .bind(&event.decision)
        .bind(i64::from(event.dry_run))
        .bind(event.shadow_decision.clone())
        .bind(event.matched_rule_id.clone())
        .bind(payload_text)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(())
    }

    async fn query_audit_events(&self, filter: AuditFilter) -> StorageResult<Vec<AuditEvent>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT ts, event_id, agent_id, team_id, action, decision, dry_run, \
             shadow_decision, matched_rule_id, payload FROM audit_events",
        );
        push_audit_where(&mut qb, &filter);
        qb.push(" ORDER BY ts DESC");
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
        rows.iter().map(row_to_audit_event).collect()
    }

    async fn count_audit_events(&self, filter: AuditFilter) -> StorageResult<u64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT COUNT(*) FROM audit_events");
        push_audit_where(&mut qb, &filter);
        let (count,): (i64,) = qb
            .build_query_as()
            .fetch_one(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        u64::try_from(count).map_err(|e| StorageError::QueryFailed(format!("count overflow: {e}")))
    }

    async fn upsert_agent(&self, record: AgentRecord) -> StorageResult<()> {
        let metadata_text = serde_json::to_string(&record.metadata)
            .map_err(|e| StorageError::QueryFailed(format!("metadata serialize: {e}")))?;
        sqlx::query(
            "INSERT OR REPLACE INTO agent_registry \
             (agent_id, team_id, org_id, metadata, registered_at, last_seen_at, enforcement_mode) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(agent_id_to_text(&record.agent_id))
        .bind(record.team_id)
        .bind(record.org_id)
        .bind(metadata_text)
        .bind(record.registered_at.to_rfc3339())
        .bind(record.last_seen_at.to_rfc3339())
        .bind(record.enforcement_mode)
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(())
    }

    async fn get_agent(&self, id: &AgentId) -> StorageResult<Option<AgentRecord>> {
        let row = sqlx::query(
            "SELECT agent_id, team_id, org_id, metadata, registered_at, last_seen_at, enforcement_mode \
             FROM agent_registry WHERE agent_id = ?",
        )
        .bind(agent_id_to_text(id))
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        row.as_ref().map(row_to_agent_record).transpose()
    }

    async fn list_agents(&self, filter: AgentFilter) -> StorageResult<Vec<AgentRecord>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
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

    async fn delete_agent(&self, id: &AgentId) -> StorageResult<()> {
        let result = sqlx::query("DELETE FROM agent_registry WHERE agent_id = ?")
            .bind(agent_id_to_text(id))
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(StorageError::NotFound(agent_id_to_text(id)));
        }
        Ok(())
    }

    async fn save_policy(&self, _doc: PolicyDocument) -> StorageResult<PolicyVersion> {
        todo!("AAASM-1712: save_policy")
    }

    async fn get_active_policy(&self, _name: &str) -> StorageResult<Option<PolicyDocument>> {
        todo!("AAASM-1712: get_active_policy")
    }

    async fn list_policy_versions(&self, _name: &str) -> StorageResult<Vec<PolicyMeta>> {
        todo!("AAASM-1712: list_policy_versions")
    }

    async fn rollback_policy(&self, _name: &str, _version: u32) -> StorageResult<()> {
        todo!("AAASM-1712: rollback_policy")
    }

    async fn record_metric(&self, _m: Metric) -> StorageResult<()> {
        todo!("AAASM-1714: record_metric")
    }

    async fn query_metrics(&self, _q: MetricQuery) -> StorageResult<Vec<MetricPoint>> {
        todo!("AAASM-1714: query_metrics")
    }

    async fn migrate(&self) -> StorageResult<()> {
        for stmt in SCHEMA {
            sqlx::query(stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
        }
        Ok(())
    }

    async fn apply_retention(&self, _policy: &RetentionPolicy) -> StorageResult<RetentionStats> {
        todo!("AAASM-1721: apply_retention")
    }

    async fn healthcheck(&self) -> StorageResult<StorageHealth> {
        todo!("AAASM-1721: healthcheck")
    }
}

/// Expand a leading `~` in `path` to the current user's home directory.
///
/// When `path` does not start with `~`, it is returned unchanged. When the
/// home directory cannot be determined, the original path is returned
/// (mirroring most CLI tools' behaviour rather than failing).
fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn expand_tilde_leaves_non_tilde_path_unchanged() {
        let absolute = Path::new("/tmp/sqlite-skeleton/db.sqlite");
        assert_eq!(expand_tilde(absolute), PathBuf::from(absolute));

        let relative = Path::new("data/db.sqlite");
        assert_eq!(expand_tilde(relative), PathBuf::from("data/db.sqlite"));
    }

    /// Open a SqliteBackend against a fresh tempdir.
    async fn open_temp_backend() -> (TempDir, SqliteBackend) {
        let tmp = TempDir::new().expect("tempdir");
        let path = tmp.path().join("test.db");
        let backend = SqliteBackend::open(&SqliteConfig { path })
            .await
            .expect("open should succeed");
        (tmp, backend)
    }

    #[tokio::test]
    async fn open_creates_parent_dir_and_enables_wal() {
        let tmp = TempDir::new().expect("tempdir");
        // Intentionally nest two levels under the temp root so create_dir_all
        // has actual work to do — covers the parent-creation AC.
        let path = tmp.path().join("nested").join("dir").join("test.db");
        let backend = SqliteBackend::open(&SqliteConfig { path: path.clone() })
            .await
            .expect("open should succeed");

        assert!(path.exists(), "database file should be created");
        assert!(path.parent().expect("parent").exists(), "parent dir should be created");

        let (mode,): (String,) = sqlx::query_as("PRAGMA journal_mode")
            .fetch_one(backend.pool())
            .await
            .expect("journal_mode probe");
        assert_eq!(mode.to_lowercase(), "wal", "WAL pragma should stick");
    }

    #[tokio::test]
    async fn migrate_creates_all_expected_tables_and_indexes() {
        let (_tmp, backend) = open_temp_backend().await;
        backend.migrate().await.expect("migrate should succeed");

        let names: Vec<(String, String)> = sqlx::query_as(
            "SELECT type, name FROM sqlite_master \
             WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(backend.pool())
        .await
        .expect("sqlite_master probe");

        let actual: std::collections::BTreeSet<(String, String)> = names.into_iter().collect();
        let expected: std::collections::BTreeSet<(String, String)> = [
            ("table", "audit_events"),
            ("table", "agent_registry"),
            ("table", "policy_versions"),
            ("table", "metrics"),
            ("index", "idx_audit_agent"),
            ("index", "idx_audit_ts"),
        ]
        .into_iter()
        .map(|(t, n)| (t.to_owned(), n.to_owned()))
        .collect();
        for entry in &expected {
            assert!(actual.contains(entry), "missing schema entry: {entry:?}");
        }
    }

    #[tokio::test]
    async fn migrate_is_idempotent_across_repeated_calls() {
        let (_tmp, backend) = open_temp_backend().await;
        backend.migrate().await.expect("first migrate");
        backend.migrate().await.expect("second migrate should be a no-op");
        backend.migrate().await.expect("third migrate should still be a no-op");

        // Schema row count should be unchanged across re-runs.
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM sqlite_master \
             WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_one(backend.pool())
        .await
        .expect("count probe");
        assert_eq!(count, 6, "exactly 4 tables + 2 indexes expected");
    }

    /// Three audit events with distinct agent_ids, timestamps and flags.
    /// Shared helper for the AuditFilter / paging / count tests.
    fn sample_events() -> Vec<AuditEvent> {
        let agent_a = AgentId::from_bytes([1; 16]);
        let agent_b = AgentId::from_bytes([2; 16]);
        vec![
            AuditEvent {
                ts: chrono::DateTime::parse_from_rfc3339("2026-05-21T10:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                event_id: uuid::Uuid::from_u128(1),
                agent_id: agent_a,
                team_id: Some("team-x".into()),
                action: "tool_call".into(),
                decision: "allow".into(),
                dry_run: false,
                shadow_decision: None,
                matched_rule_id: Some("rule-1".into()),
                payload: Some(serde_json::json!({"tool": "fetch"})),
            },
            AuditEvent {
                ts: chrono::DateTime::parse_from_rfc3339("2026-05-21T11:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                event_id: uuid::Uuid::from_u128(2),
                agent_id: agent_a,
                team_id: Some("team-x".into()),
                action: "policy_decision".into(),
                decision: "deny".into(),
                dry_run: true,
                shadow_decision: Some("allow".into()),
                matched_rule_id: None,
                payload: None,
            },
            AuditEvent {
                ts: chrono::DateTime::parse_from_rfc3339("2026-05-21T12:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
                event_id: uuid::Uuid::from_u128(3),
                agent_id: agent_b,
                team_id: Some("team-y".into()),
                action: "tool_call".into(),
                decision: "allow".into(),
                dry_run: false,
                shadow_decision: None,
                matched_rule_id: Some("rule-2".into()),
                payload: Some(serde_json::json!({"k": [1, 2, 3]})),
            },
        ]
    }

    async fn migrated_backend_with_samples() -> (TempDir, SqliteBackend, Vec<AuditEvent>) {
        let (tmp, backend) = open_temp_backend().await;
        backend.migrate().await.expect("migrate");
        let events = sample_events();
        for ev in &events {
            backend.append_audit_event(ev).await.expect("append");
        }
        (tmp, backend, events)
    }

    #[tokio::test]
    async fn audit_round_trip_preserves_all_columns_including_payload() {
        let (_tmp, backend, events) = migrated_backend_with_samples().await;
        let mut out = backend.query_audit_events(AuditFilter::default()).await.expect("query");
        // ORDER BY ts DESC — newest first.
        out.reverse();
        assert_eq!(out, events, "all columns + payload must round-trip");
    }

    #[tokio::test]
    async fn audit_filter_dimensions_independently_narrow_results() {
        let (_tmp, backend, _events) = migrated_backend_with_samples().await;
        let agent_a = AgentId::from_bytes([1; 16]);
        let agent_b = AgentId::from_bytes([2; 16]);

        let by_a = backend
            .query_audit_events(AuditFilter {
                agent_id: Some(agent_a),
                ..AuditFilter::default()
            })
            .await
            .expect("agent filter");
        assert_eq!(by_a.len(), 2);
        assert!(by_a.iter().all(|e| e.agent_id == agent_a));

        let by_team_y = backend
            .query_audit_events(AuditFilter {
                team_id: Some("team-y".into()),
                ..AuditFilter::default()
            })
            .await
            .expect("team filter");
        assert_eq!(by_team_y.len(), 1);
        assert_eq!(by_team_y[0].agent_id, agent_b);

        let only_dry = backend
            .query_audit_events(AuditFilter {
                dry_run_only: true,
                ..AuditFilter::default()
            })
            .await
            .expect("dry_run filter");
        assert_eq!(only_dry.len(), 1);
        assert!(only_dry[0].dry_run);

        let in_window = backend
            .query_audit_events(AuditFilter {
                from: Some(
                    chrono::DateTime::parse_from_rfc3339("2026-05-21T10:30:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                to: Some(
                    chrono::DateTime::parse_from_rfc3339("2026-05-21T11:30:00Z")
                        .unwrap()
                        .with_timezone(&chrono::Utc),
                ),
                ..AuditFilter::default()
            })
            .await
            .expect("time-range filter");
        assert_eq!(in_window.len(), 1);
        assert_eq!(in_window[0].event_id, uuid::Uuid::from_u128(2));
    }

    #[tokio::test]
    async fn audit_query_limit_and_offset_produce_disjoint_pages() {
        let (_tmp, backend, _events) = migrated_backend_with_samples().await;
        let first = backend
            .query_audit_events(AuditFilter {
                limit: Some(2),
                offset: Some(0),
                ..AuditFilter::default()
            })
            .await
            .expect("page 1");
        let second = backend
            .query_audit_events(AuditFilter {
                limit: Some(2),
                offset: Some(2),
                ..AuditFilter::default()
            })
            .await
            .expect("page 2");
        assert_eq!(first.len(), 2);
        assert_eq!(second.len(), 1);
        let ids_first: std::collections::HashSet<_> = first.iter().map(|e| e.event_id).collect();
        let ids_second: std::collections::HashSet<_> = second.iter().map(|e| e.event_id).collect();
        assert!(ids_first.is_disjoint(&ids_second));
    }

    #[tokio::test]
    async fn audit_count_matches_query_result_size() {
        let (_tmp, backend, _events) = migrated_backend_with_samples().await;

        let total = backend
            .count_audit_events(AuditFilter::default())
            .await
            .expect("count all");
        assert_eq!(total, 3);

        let agent_a = AgentId::from_bytes([1; 16]);
        let scoped = backend
            .count_audit_events(AuditFilter {
                agent_id: Some(agent_a),
                ..AuditFilter::default()
            })
            .await
            .expect("count scoped");
        let scoped_rows = backend
            .query_audit_events(AuditFilter {
                agent_id: Some(agent_a),
                ..AuditFilter::default()
            })
            .await
            .expect("query scoped");
        assert_eq!(scoped, scoped_rows.len() as u64);
    }
}
