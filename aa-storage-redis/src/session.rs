//! [`SessionStore`] backed by a Redis hash per session.

use aa_storage::{AgentId, Result, SessionId, SessionRecord, SessionStore, StorageError};
use async_trait::async_trait;
use deadpool_redis::Pool;

use crate::error::backend;
use crate::util::hex16;

/// Time-to-live applied to a session record on every
/// [`save`](SessionStore::save), via Redis `EXPIRE`.
///
/// One hour. An actively re-saved session never lapses; an abandoned one is
/// reclaimed automatically.
pub const SESSION_TTL_SECS: u64 = 3600;

/// Redis-backed [`SessionStore`].
///
/// Each record is a hash at `aa:session:<session_id>` holding the raw
/// `agent_id` bytes and `started_at_ns`. See the [crate](crate) docs for the
/// full key layout and TTL semantics. Cheap to [`Clone`] — clones share the
/// underlying [`Pool`].
#[derive(Clone)]
pub struct RedisSessionStore {
    pool: Pool,
}

impl RedisSessionStore {
    /// Create a store over an existing connection pool.
    pub fn new(pool: Pool) -> Self {
        Self { pool }
    }
}

// TODO(AAASM-3919): namespace this key by the verified tenant/org id
// (e.g. `aa:session:<org_id>:<session_id>`) once org context is threaded into
// the SessionStore path. The shared L2 cache currently has no tenant boundary;
// session ids are globally unique so there is no collision today, but also no
// isolation. Deferred here because SessionStore::save/load/delete carry only a
// session id — adding a prefix without the org id would break lookups.
fn session_key(id: &SessionId) -> String {
    format!("aa:session:{}", hex16(id.as_bytes()))
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    async fn save(&self, session: SessionRecord) -> Result<()> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let key = session_key(&session.session_id);
        let _: () = redis::cmd("HSET")
            .arg(&key)
            .arg("agent_id")
            .arg(&session.agent_id.as_bytes()[..])
            .arg("started_at_ns")
            .arg(session.started_at_ns)
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        let _: () = redis::cmd("EXPIRE")
            .arg(&key)
            .arg(SESSION_TTL_SECS)
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(())
    }

    async fn load(&self, session_id: &SessionId) -> Result<SessionRecord> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let key = session_key(session_id);
        let (agent_bytes, started_at_ns): (Option<Vec<u8>>, Option<u64>) = redis::cmd("HMGET")
            .arg(&key)
            .arg("agent_id")
            .arg("started_at_ns")
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        let agent_bytes = agent_bytes.ok_or_else(|| StorageError::NotFound(format!("session {key}")))?;
        let started_at_ns = started_at_ns.ok_or_else(|| StorageError::NotFound(format!("session {key}")))?;
        let agent_id: [u8; 16] = agent_bytes
            .try_into()
            .map_err(|_| StorageError::Serialization("session agent_id is not 16 bytes".to_owned()))?;
        Ok(SessionRecord {
            session_id: *session_id,
            agent_id: AgentId::from_bytes(agent_id),
            started_at_ns,
        })
    }

    async fn delete(&self, session_id: &SessionId) -> Result<()> {
        let mut conn = self.pool.get().await.map_err(backend)?;
        let _: () = redis::cmd("DEL")
            .arg(session_key(session_id))
            .query_async(&mut conn)
            .await
            .map_err(backend)?;
        Ok(())
    }
}
