//! The on-disk SQLite event buffer.

use std::path::Path;
use std::sync::Mutex;

use aa_core::storage::{Result, StorageError};
use rusqlite::Connection;

/// Map a `rusqlite` error onto the storage contract's backend variant.
fn backend_err(err: rusqlite::Error) -> StorageError {
    StorageError::Backend(err.to_string())
}

/// A restart-safe, FIFO event buffer backed by a single SQLite file.
///
/// Events are appended with [`enqueue`](EventBuffer::enqueue) while the upstream
/// sink is unreachable and replayed in insertion order with
/// [`drain_and_send`](EventBuffer::drain_and_send) once it recovers. The file is
/// opened in WAL mode so buffered events survive a process restart.
pub struct EventBuffer {
    conn: Mutex<Connection>,
    cap: usize,
}

impl EventBuffer {
    /// Open (creating if absent) a buffer at `path` retaining at most `cap`
    /// events.
    ///
    /// Enables WAL journaling and `synchronous = NORMAL` for a durability/perf
    /// balance, and creates the `events` table if it does not yet exist. Parent
    /// directories are created as needed.
    pub fn new(path: impl AsRef<Path>, cap: usize) -> Result<Self> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| StorageError::Backend(format!("create buffer directory {}: {e}", parent.display())))?;
            }
        }
        let conn = Connection::open(path).map_err(backend_err)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS events (
                 id          INTEGER PRIMARY KEY AUTOINCREMENT,
                 payload     BLOB    NOT NULL,
                 enqueued_at INTEGER NOT NULL
             );",
        )
        .map_err(backend_err)?;
        Ok(Self {
            conn: Mutex::new(conn),
            cap,
        })
    }

    /// Open a buffer from operator [`SqliteBufferConfig`](crate::SqliteBufferConfig).
    pub fn from_config(config: &crate::SqliteBufferConfig) -> Result<Self> {
        Self::new(&config.path, config.cap)
    }

    /// The maximum number of events this buffer retains before eviction.
    #[must_use]
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Number of events currently buffered.
    pub fn len(&self) -> Result<usize> {
        let conn = self.conn.lock().expect("event buffer mutex poisoned");
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
            .map_err(backend_err)?;
        Ok(count as usize)
    }

    /// Whether the buffer currently holds no events.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }
}
