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

/// Local SQLite backend configuration.
///
/// Defined here as a minimal type so this Story (E18 S-B) can land
/// independently of E18 S-H (AAASM-1582), which will introduce the full
/// gateway storage-config parser. S-H may later move or extend this type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)] // wired into `SqliteBackend::open` in a follow-up commit
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
#[allow(dead_code)] // `pool` is read by trait-impl sub-tasks that follow
pub struct SqliteBackend {
    pool: SqlitePool,
}

/// Expand a leading `~` in `path` to the current user's home directory.
///
/// When `path` does not start with `~`, it is returned unchanged. When the
/// home directory cannot be determined, the original path is returned
/// (mirroring most CLI tools' behaviour rather than failing).
#[allow(dead_code)] // consumed by `SqliteBackend::open` in a follow-up commit
fn expand_tilde(path: &Path) -> PathBuf {
    if let Ok(stripped) = path.strip_prefix("~") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped);
        }
    }
    path.to_path_buf()
}
