//! Proves the memory driver registers into `aa_storage::Registry` and that an
//! all-`"memory"` `[storage]` config validates and builds every backend.

use aa_storage::{Registry, StorageConfig};

const ALL_MEMORY: &str = r#"
policy_store       = "memory"
audit_sink         = "memory"
session_store      = "memory"
credential_store   = "memory"
rate_limit_counter = "memory"
lifecycle_store    = "memory"

[memory]
"#;

fn all_memory_config() -> StorageConfig {
    toml::from_str(ALL_MEMORY).expect("fixture parses")
}

#[test]
fn register_makes_memory_resolvable_for_all_kinds() {
    let mut reg = Registry::new();
    aa_storage_memory::register(&mut reg);

    for names in [
        reg.policy_store_names(),
        reg.audit_sink_names(),
        reg.session_store_names(),
        reg.credential_store_names(),
        reg.rate_limit_counter_names(),
        reg.lifecycle_store_names(),
    ] {
        assert!(names.contains(&"memory"), "memory should be registered for every kind");
    }
}

#[test]
fn all_memory_config_validates_and_builds_every_backend() {
    let mut reg = Registry::new();
    aa_storage_memory::register(&mut reg);
    let config = all_memory_config();

    reg.validate(&config).expect("all-memory config validates");
    reg.build_policy_store(&config).expect("policy store builds");
    reg.build_audit_sink(&config).expect("audit sink builds");
    reg.build_session_store(&config).expect("session store builds");
    reg.build_credential_store(&config).expect("credential store builds");
    reg.build_rate_limit_counter(&config)
        .expect("rate limit counter builds");
    reg.build_lifecycle_store(&config).expect("lifecycle store builds");
}
