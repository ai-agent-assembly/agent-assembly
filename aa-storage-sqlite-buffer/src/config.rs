//! Configuration for the SQLite event buffer.

use std::path::PathBuf;

use serde::Deserialize;

/// Default maximum number of events retained before the oldest are evicted.
///
/// Bounds disk use while still tolerating a multi-minute upstream outage at
/// typical audit-event rates.
pub const DEFAULT_CAP: usize = 10_000;

/// Resolve the default buffer database path.
///
/// Returns the platform data directory joined with `agent-assembly/buffer.db` —
/// `~/.local/share/agent-assembly/buffer.db` on Linux (per the XDG
/// base-directory spec). Falls back to a relative `buffer.db` when no data
/// directory can be determined.
#[must_use]
pub fn default_path() -> PathBuf {
    dirs::data_dir()
        .map(|dir| dir.join("agent-assembly").join("buffer.db"))
        .unwrap_or_else(|| PathBuf::from("buffer.db"))
}

/// Operator configuration for the SQLite event buffer.
///
/// Deserialized from the `[storage.sqlite_buffer]` table of
/// `agent-assembly.toml`. Both fields are optional; omitted fields fall back to
/// [`default_path`] and [`DEFAULT_CAP`].
///
/// ```
/// use aa_storage_sqlite_buffer::{SqliteBufferConfig, DEFAULT_CAP};
///
/// let cfg = SqliteBufferConfig::default();
/// assert_eq!(cfg.cap, DEFAULT_CAP);
/// ```
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct SqliteBufferConfig {
    /// Filesystem path to the single-file SQLite buffer database.
    pub path: PathBuf,
    /// Maximum number of events retained before the oldest are evicted.
    pub cap: usize,
}

impl Default for SqliteBufferConfig {
    fn default() -> Self {
        Self {
            path: default_path(),
            cap: DEFAULT_CAP,
        }
    }
}
