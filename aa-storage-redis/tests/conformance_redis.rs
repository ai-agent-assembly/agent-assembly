//! Trait-conformance suite for `aa-storage-redis`.
//!
//! Each test provisions a throwaway Redis with `testcontainers-modules`, so a
//! running Docker daemon is required (the same expectation as the Postgres
//! conformance tests elsewhere in the workspace).

use aa_storage::conformance::assert_policy_store_conformance;
use aa_storage::{AgentId, PolicyDocument, RateLimitCounter, SessionId, SessionRecord, SessionStore, StorageError};
use aa_storage_redis::{RedisBackend, RedisStorageConfig, DEFAULT_POLICY_CACHE_TTL_SECS};
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ContainerAsync;

/// Start a Redis container and connect a backend to it. The returned container
/// guard must be kept alive for the duration of the test — dropping it stops
/// the container.
async fn start_redis() -> (ContainerAsync<Redis>, RedisBackend) {
    let container = Redis::default().start().await.expect("start redis container");
    let host = container.get_host().await.expect("redis host");
    let port = container.get_host_port_ipv4(6379).await.expect("redis mapped port");
    let config = RedisStorageConfig {
        url: format!("redis://{host}:{port}"),
        pool_size: 8,
        tls: false,
    };
    let backend = RedisBackend::connect(&config).expect("connect redis backend");
    (container, backend)
}

#[tokio::test]
async fn redis_session_store_roundtrip() {
    let (_container, backend) = start_redis().await;
    let store = backend.sessions();

    let session_id = SessionId::from_bytes([7; 16]);
    let record = SessionRecord {
        session_id,
        agent_id: AgentId::from_bytes([3; 16]),
        started_at_ns: 1_700_000_000_000_000_000,
    };

    store.save(record.clone()).await.unwrap();
    assert_eq!(store.load(&session_id).await.unwrap(), record);

    store.delete(&session_id).await.unwrap();
    match store.load(&session_id).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("expected NotFound after delete, got {other:?}"),
    }
    // Deleting an absent session is idempotent.
    store.delete(&session_id).await.unwrap();
}

#[tokio::test]
async fn redis_rate_limit_counter_increments_and_resets() {
    let (_container, backend) = start_redis().await;
    let counter = backend.rate_limiter();

    assert_eq!(counter.current("alpha").await.unwrap(), 0);
    assert_eq!(counter.increment("alpha", 1, 60).await.unwrap(), 1);
    assert_eq!(counter.increment("alpha", 2, 60).await.unwrap(), 3);
    assert_eq!(counter.current("alpha").await.unwrap(), 3);

    counter.reset("alpha").await.unwrap();
    assert_eq!(counter.current("alpha").await.unwrap(), 0);
    // Resetting an absent key is idempotent.
    counter.reset("alpha").await.unwrap();
}

#[tokio::test]
async fn redis_policy_store_satisfies_conformance() {
    let (_container, backend) = start_redis().await;
    let store = backend.policies();

    let present = AgentId::from_bytes([1; 16]);
    let absent = AgentId::from_bytes([2; 16]);
    let policy = PolicyDocument {
        version: 1,
        name: "conformance".to_owned(),
        rules: Vec::new(),
        enforcement_mode: Default::default(),
    };
    store
        .cache_policy(&present, &policy, DEFAULT_POLICY_CACHE_TTL_SECS)
        .await
        .unwrap();

    // Coerces to `&dyn PolicyStore`, exercising object-safety.
    assert_policy_store_conformance(&store, &present, &absent).await;
}
