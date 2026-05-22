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

use sqlx::SqlitePool;

use super::error::{StorageError, StorageResult};

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

    /// Apply the [`SCHEMA`] DDL to the open database.
    ///
    /// Idempotent: each statement uses `IF NOT EXISTS`, so re-running on
    /// an already-migrated database is a no-op. Intended to be invoked
    /// once at gateway startup before the runtime issues any trait-level
    /// reads or writes.
    ///
    /// # Errors
    ///
    /// - [`StorageError::MigrationFailed`] if any DDL statement is
    ///   rejected by the backend.
    pub async fn migrate(&self) -> StorageResult<()> {
        for stmt in SCHEMA {
            sqlx::query(stmt)
                .execute(&self.pool)
                .await
                .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
        }
        Ok(())
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
}
