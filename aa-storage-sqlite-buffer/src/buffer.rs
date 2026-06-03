//! The on-disk SQLite event buffer.

use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use aa_core::storage::{AuditEntry, AuditSink, Result, StorageError};
use rusqlite::{params, Connection, OptionalExtension};

/// Map a `rusqlite` error onto the storage contract's backend variant.
fn backend_err(err: rusqlite::Error) -> StorageError {
    StorageError::Backend(err.to_string())
}

/// Nanoseconds since the Unix epoch, saturating to `0` if the clock predates it.
fn now_unix_nanos() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// Delete the oldest events until at most `cap` remain, returning the count
/// removed.
fn prune_to_cap(conn: &Connection, cap: usize) -> Result<usize> {
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .map_err(backend_err)?;
    let cap = cap as i64;
    if count <= cap {
        return Ok(0);
    }
    let excess = count - cap;
    let deleted = conn
        .execute(
            "DELETE FROM events WHERE id IN \
             (SELECT id FROM events ORDER BY id ASC LIMIT ?1)",
            params![excess],
        )
        .map_err(backend_err)?;
    Ok(deleted)
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

    /// Append `event` to the buffer.
    ///
    /// The entry is serialized to JSON and stored as a BLOB. When the buffer
    /// would exceed its cap, the oldest events are evicted to make room and the
    /// [`METRIC_EVENTS_DROPPED`](crate::METRIC_EVENTS_DROPPED) counter is bumped
    /// by the number dropped — the loss is metered, never silent. Each accepted
    /// event bumps [`METRIC_EVENTS_BUFFERED`](crate::METRIC_EVENTS_BUFFERED).
    pub fn enqueue(&self, event: &AuditEntry) -> Result<()> {
        let payload = serde_json::to_vec(event).map_err(|e| StorageError::Serialization(e.to_string()))?;
        let enqueued_at = now_unix_nanos();
        let conn = self.conn.lock().expect("event buffer mutex poisoned");
        conn.execute(
            "INSERT INTO events (payload, enqueued_at) VALUES (?1, ?2)",
            params![payload, enqueued_at],
        )
        .map_err(backend_err)?;
        metrics::counter!(crate::METRIC_EVENTS_BUFFERED).increment(1);

        let dropped = prune_to_cap(&conn, self.cap)?;
        if dropped > 0 {
            metrics::counter!(crate::METRIC_EVENTS_DROPPED).increment(dropped as u64);
        }
        Ok(())
    }

    /// Replay buffered events to `sink` in insertion (FIFO) order.
    ///
    /// Each event is sent and, only after the sink acknowledges it, deleted from
    /// the buffer — so a crash mid-flush replays at-least-once rather than
    /// losing data. Draining stops at the first sink failure (the upstream is
    /// treated as still-unreachable), leaving the remaining events buffered for
    /// a later retry. Returns the number of events flushed; each one bumps
    /// [`METRIC_EVENTS_FLUSHED`](crate::METRIC_EVENTS_FLUSHED).
    pub async fn drain_and_send(&self, sink: &dyn AuditSink) -> Result<usize> {
        let mut flushed = 0usize;
        while let Some((id, payload)) = self.peek_oldest()? {
            let entry: AuditEntry =
                serde_json::from_slice(&payload).map_err(|e| StorageError::Serialization(e.to_string()))?;
            if sink.emit(entry).await.is_err() {
                break;
            }
            self.delete(id)?;
            flushed += 1;
            metrics::counter!(crate::METRIC_EVENTS_FLUSHED).increment(1);
        }
        Ok(flushed)
    }

    /// Fetch the oldest buffered event as `(id, payload)`, if any.
    fn peek_oldest(&self) -> Result<Option<(i64, Vec<u8>)>> {
        let conn = self.conn.lock().expect("event buffer mutex poisoned");
        conn.query_row("SELECT id, payload FROM events ORDER BY id ASC LIMIT 1", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .optional()
        .map_err(backend_err)
    }

    /// Delete the buffered event with the given row id.
    fn delete(&self, id: i64) -> Result<()> {
        let conn = self.conn.lock().expect("event buffer mutex poisoned");
        conn.execute("DELETE FROM events WHERE id = ?1", params![id])
            .map_err(backend_err)?;
        Ok(())
    }
}
