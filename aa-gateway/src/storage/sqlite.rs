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

use std::path::PathBuf;

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
