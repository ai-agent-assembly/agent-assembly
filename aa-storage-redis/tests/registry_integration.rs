//! Proves the Redis driver registers into `aa_storage::Registry` for the three
//! kinds it backs, and that a mixed `[storage]` config (redis for the L2 kinds,
//! memory for the durable kinds) validates and builds every backend.
//!
//! No live Redis is needed: the Redis factories build over a lazily-connected
//! pool, so `build_*` succeeds without contacting a server. The live end-to-end
//! boot is the verification subtask (AAASM-2541).

use aa_storage::{Registry, StorageConfig};

const MIXED: &str = r#"
policy_store       = "redis"
audit_sink         = "memory"
session_store      = "redis"
credential_store   = "memory"
rate_limit_counter = "redis"
lifecycle_store    = "memory"

[redis]
url = "redis://127.0.0.1:6379"
pool_size = 4

[memory]
"#;

fn build_registry() -> Registry {
    let mut reg = Registry::new();
    aa_storage::builtin::register_builtin_drivers(&mut reg);
    aa_storage_memory::register(&mut reg);
    aa_storage_redis::register(&mut reg);
    reg
}

#[test]
fn redis_registers_for_the_kinds_it_backs() {
    let reg = build_registry();
    assert!(reg.policy_store_names().contains(&"redis"));
    assert!(reg.session_store_names().contains(&"redis"));
    assert!(reg.rate_limit_counter_names().contains(&"redis"));
}

#[test]
fn mixed_redis_memory_config_validates_and_builds_every_backend() {
    let reg = build_registry();
    let config: StorageConfig = toml::from_str(MIXED).expect("fixture parses");

    reg.validate(&config).expect("mixed config validates");
    reg.build_policy_store(&config).expect("policy (redis) builds");
    reg.build_audit_sink(&config).expect("audit (memory) builds");
    reg.build_session_store(&config).expect("session (redis) builds");
    reg.build_credential_store(&config).expect("credential (memory) builds");
    reg.build_rate_limit_counter(&config)
        .expect("rate limit (redis) builds");
    reg.build_lifecycle_store(&config).expect("lifecycle (memory) builds");
}
