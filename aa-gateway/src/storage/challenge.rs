//! Replica-shared, Redis-backed registration challenge store (AAASM-3882).
//!
//! AAASM-3866 backed agent-registration challenge nonces with a process-local
//! map ([`InMemoryChallengeStore`](crate::service::lifecycle_service::InMemoryChallengeStore)),
//! which is correct only for a single gateway replica: behind a multi-replica
//! load balancer a nonce issued by `RequestChallenge` on one replica is unknown
//! to `Register` on another, so registration fails closed.
//!
//! [`RedisChallengeStore`] is a drop-in shared backend — inject it via
//! [`AgentLifecycleServiceImpl::with_challenge_store`](crate::service::AgentLifecycleServiceImpl::with_challenge_store)
//! so any replica can issue and any replica can consume. It reuses the gateway's
//! existing optional `redis` dependency (the same one behind
//! [`RedisPolicyCache`](super::cache::RedisPolicyCache)); no new dependency is
//! added, and like the policy cache it is gated behind the `redis-cache` Cargo
//! feature. The `redis` driver is confined to the `storage` module per the
//! driver-isolation rule (see [`super`]).
//!
//! # Cross-replica guarantees
//!
//! The three security properties of the AAASM-3866 possession proof are
//! preserved across replicas by leaning on Redis primitives:
//!
//! * **single-use** — `consume` uses `GETDEL`, which atomically returns *and*
//!   deletes the key, so exactly one caller (on any replica) can ever consume a
//!   given nonce; a replay or an identity-redirect attempt still burns it.
//! * **time-bound** — `issue` writes the key with `SET … EX 30` (the shared
//!   `CHALLENGE_TTL`); once it lapses Redis drops the key, so `GETDEL` returns
//!   nil and consume fails.
//! * **identity-binding** — the stored value is the issuing `agent_id` +
//!   `public_key`; `consume` re-checks it so a nonce cannot be redirected to a
//!   different identity.
//!
//! `GETDEL` requires Redis (or Valkey) 6.2 or newer.

#[cfg(feature = "redis-cache")]
use redis::aio::ConnectionManager;
#[cfg(feature = "redis-cache")]
use tonic::Status;

#[cfg(feature = "redis-cache")]
use super::cache::RedisConfig;
#[cfg(feature = "redis-cache")]
use super::error::{StorageError, StorageResult};
#[cfg(feature = "redis-cache")]
use crate::service::lifecycle_service::{
    challenge_expiry_unix_ms, fresh_nonce, ChallengeStoreLike, CHALLENGE_TTL,
};

/// Lower-case hex encoding of the nonce bytes, namespaced under `aa:challenge:`.
#[cfg(feature = "redis-cache")]
fn challenge_key(nonce: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut hex = String::with_capacity(4 + nonce.len() * 2);
    hex.push_str("aa:challenge:");
    for byte in nonce {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Value stored against a nonce: the issuing identity, so `consume` can re-check
/// the binding. `agent_id` (a `did:key`) and `public_key` (hex) are joined by an
/// ASCII unit separator (`0x1F`), which cannot appear in either, so the split is
/// unambiguous and no field can be smuggled across the boundary.
#[cfg(feature = "redis-cache")]
fn binding_value(agent_id: &str, public_key: &str) -> String {
    format!("{agent_id}\u{1f}{public_key}")
}

/// Redis-backed, replica-shared [`ChallengeStoreLike`] (AAASM-3882).
///
/// Holds a cloneable [`ConnectionManager`] (the redis-rs multiplexed handle).
/// Only available with the `redis-cache` Cargo feature.
#[cfg(feature = "redis-cache")]
pub struct RedisChallengeStore {
    conn: ConnectionManager,
}

#[cfg(feature = "redis-cache")]
impl RedisChallengeStore {
    /// Establish a Redis connection from `config` and wrap it in a
    /// [`ConnectionManager`].
    ///
    /// Returns [`StorageError::ConnectionFailed`] when `config.url` is `None`,
    /// the URL cannot be parsed, or the manager cannot complete its initial
    /// handshake. Mirrors [`RedisPolicyCache::connect`](super::cache::RedisPolicyCache::connect)
    /// so both shared stores share one connection convention.
    pub async fn connect(config: &RedisConfig) -> StorageResult<Self> {
        let url = config.url.as_deref().ok_or_else(|| {
            StorageError::ConnectionFailed("storage.redis.url is required when redis.enabled = true".into())
        })?;
        let client = redis::Client::open(url).map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
        let conn = client
            .get_connection_manager()
            .await
            .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
        Ok(Self { conn })
    }
}

#[cfg(feature = "redis-cache")]
#[async_trait::async_trait]
impl ChallengeStoreLike for RedisChallengeStore {
    async fn issue(&self, agent_id: &str, public_key: &str) -> Result<(Vec<u8>, i64), Status> {
        use redis::AsyncCommands;
        let nonce = fresh_nonce();
        let key = challenge_key(&nonce);
        let value = binding_value(agent_id, public_key);
        let mut conn = self.conn.clone();
        // SET key value EX 30 — TTL enforced by Redis and visible to every
        // replica. Fail closed: never hand out a nonce we could not persist, or
        // Register would later reject a legitimate agent.
        let result: redis::RedisResult<()> = conn.set_ex(&key, value, CHALLENGE_TTL.as_secs()).await;
        result.map_err(|err| {
            tracing::warn!(error = %err, "redis registration challenge issue failed");
            Status::internal("could not issue registration challenge")
        })?;
        Ok((nonce, challenge_expiry_unix_ms()))
    }

    async fn consume(&self, nonce: &[u8], agent_id: &str, public_key: &str) -> Result<(), Status> {
        if nonce.is_empty() {
            return Err(Status::unauthenticated(
                "missing registration_nonce — call RequestChallenge before Register (AAASM-3866)",
            ));
        }
        let key = challenge_key(nonce);
        let mut conn = self.conn.clone();
        // GETDEL atomically reads and removes the key — single-use across
        // replicas. A driver error fails closed (Unauthenticated) so a Redis
        // outage cannot let an unverified registration through.
        let stored: redis::RedisResult<Option<String>> =
            redis::cmd("GETDEL").arg(&key).query_async(&mut conn).await;
        let stored = stored
            .map_err(|err| {
                tracing::warn!(error = %err, "redis registration challenge consume failed");
                Status::unauthenticated("registration challenge store unavailable")
            })?
            .ok_or_else(|| Status::unauthenticated("unknown or already-used registration nonce"))?;

        // The key is already gone (GETDEL), so any mismatch still burns the
        // nonce — matching the in-memory store's "any attempt burns it".
        if stored != binding_value(agent_id, public_key) {
            return Err(Status::unauthenticated(
                "registration nonce was not issued for this agent_id + public_key",
            ));
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "redis-cache"))]
mod tests {
    use super::*;

    const DID: &str = "did:key:z6MkExampleAgent";
    const PK: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn challenge_key_is_namespaced_lowercase_hex() {
        let key = challenge_key(&[0x0a, 0xff, 0x01]);
        assert_eq!(key, "aa:challenge:0aff01");
    }

    #[test]
    fn binding_value_round_trips_via_unit_separator() {
        let value = binding_value(DID, PK);
        let mut parts = value.split('\u{1f}');
        assert_eq!(parts.next(), Some(DID));
        assert_eq!(parts.next(), Some(PK));
        assert_eq!(parts.next(), None);
    }

    #[tokio::test]
    async fn connect_with_none_url_returns_connection_failed() {
        let config = RedisConfig {
            enabled: true,
            url: None,
            ..RedisConfig::default()
        };
        match RedisChallengeStore::connect(&config).await {
            Ok(_) => panic!("None URL must surface as ConnectionFailed"),
            Err(err) => assert!(matches!(err, StorageError::ConnectionFailed(_))),
        }
    }

    #[tokio::test]
    async fn connect_with_malformed_url_returns_connection_failed() {
        let config = RedisConfig {
            enabled: true,
            url: Some("not-a-redis-url".into()),
            ..RedisConfig::default()
        };
        match RedisChallengeStore::connect(&config).await {
            Ok(_) => panic!("malformed URL must surface as ConnectionFailed"),
            Err(err) => assert!(matches!(err, StorageError::ConnectionFailed(_))),
        }
    }
}
