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
    #[allow(dead_code)] // first writers land in S-B.2 (migrate)
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
    #[allow(dead_code)] // first consumer arrives in S-B.2
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
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
}
