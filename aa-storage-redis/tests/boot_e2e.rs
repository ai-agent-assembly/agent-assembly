//! End-to-end verification (AAASM-2541): a `[storage]` config that selects
//! `redis` for the L2 kinds resolves through `aa_storage::Registry` to a real
//! `RedisBackend` that talks to a live Redis (testcontainers) — proving the
//! boot wiring works rather than returning the `NotImplemented` placeholder.
//!
//! Requires a running Docker daemon (same expectation as the conformance suite).

use aa_storage::{AgentId, Registry, SessionId, SessionRecord, StorageConfig, StorageError};
use testcontainers_modules::redis::Redis;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ContainerAsync;

fn registry() -> Registry {
    let mut reg = Registry::new();
    aa_storage::builtin::register_builtin_drivers(&mut reg);
    aa_storage_memory::register(&mut reg);
    aa_storage_redis::register(&mut reg);
    reg
}

async fn start_redis() -> (ContainerAsync<Redis>, String) {
    let container = Redis::default().start().await.expect("start redis container");
    let host = container.get_host().await.expect("redis host");
    let port = container.get_host_port_ipv4(6379).await.expect("redis mapped port");
    (container, format!("redis://{host}:{port}"))
}

/// Mixed config: redis for the L2 kinds, memory for the durable kinds.
fn mixed_config(redis_url: &str) -> StorageConfig {
    let src = format!(
        r#"
policy_store       = "redis"
audit_sink         = "memory"
session_store      = "redis"
credential_store   = "memory"
rate_limit_counter = "redis"
lifecycle_store    = "memory"

[redis]
url = "{redis_url}"
pool_size = 4

[memory]
"#
    );
    toml::from_str(&src).expect("mixed config parses")
}

#[tokio::test]
async fn redis_backed_config_boots_and_serves_real_ops() {
    let (_container, url) = start_redis().await;
    let reg = registry();
    let config = mixed_config(&url);

    reg.validate(&config).expect("mixed config validates");

    // Rate-limit counter (redis): real INCR against the live container.
    let counter = reg.build_rate_limit_counter(&config).expect("redis rate-limit builds");
    assert_eq!(counter.increment("verify", 1, 60).await.unwrap(), 1);
    assert_eq!(counter.increment("verify", 2, 60).await.unwrap(), 3);
    assert_eq!(counter.current("verify").await.unwrap(), 3);

    // Session store (redis): real save/load round-trip.
    let sessions = reg.build_session_store(&config).expect("redis session builds");
    let session_id = SessionId::from_bytes([9; 16]);
    let record = SessionRecord {
        session_id,
        agent_id: AgentId::from_bytes([4; 16]),
        started_at_ns: 1_700_000_000_000_000_000,
    };
    sessions.save(record.clone()).await.unwrap();
    assert_eq!(sessions.load(&session_id).await.unwrap(), record);

    // Policy store (redis): a miss proves it queried the live cache (not the
    // NotImplemented placeholder, which would error instead of returning NotFound).
    let policies = reg.build_policy_store(&config).expect("redis policy builds");
    match policies.get_policy(&AgentId::from_bytes([7; 16])).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("expected NotFound from the empty redis cache, got {other:?}"),
    }

    // Durable kinds resolve to the memory driver under the same mixed config.
    reg.build_audit_sink(&config).expect("memory audit builds");
    reg.build_credential_store(&config).expect("memory credential builds");
    reg.build_lifecycle_store(&config).expect("memory lifecycle builds");
}
