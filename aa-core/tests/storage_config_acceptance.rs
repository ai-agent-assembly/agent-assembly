//! Story-level acceptance spec for E18 S-H (AAASM-1582).
//!
//! Each `#[test]` ticks one of the seven AC bullets from the Story
//! description. Tests use the public `aa_core::config` surface only —
//! no `pub(crate)` shortcuts — so a future refactor that keeps the
//! external behaviour intact stays green.
//!
//! Gated behind `feature = "serde"` because every AC exercises the
//! YAML loader; `cargo nextest run -p aa-core --all-features` enables it.

#![cfg(feature = "serde")]
// Imports below are consumed incrementally by the AC tests; the
// allow is dropped in the final test commit on this Subtask.
#![allow(unused_imports)]

use std::path::PathBuf;

use aa_core::config::{ColdAction, ConfigError, DeploymentMode, GatewayConfig, StorageBackendType};

/// AC #1 — `storage.backend: sqlite` and `postgres` parse correctly.
#[test]
fn parses_explicit_sqlite_and_postgres_backends() {
    let sqlite_yaml = r#"
storage:
  backend: sqlite
"#;
    let cfg = GatewayConfig::from_yaml_str(sqlite_yaml).expect("sqlite backend YAML must parse");
    assert_eq!(cfg.storage.backend, StorageBackendType::Sqlite);

    let postgres_yaml = r#"
storage:
  backend: postgres
"#;
    let cfg = GatewayConfig::from_yaml_str(postgres_yaml).expect("postgres backend YAML must parse");
    assert_eq!(cfg.storage.backend, StorageBackendType::Postgres);
}

/// AC #2 — backend defaults to `sqlite` in local mode when not set.
#[test]
fn defaults_to_sqlite_in_local_mode_when_unset() {
    let yaml = r#"
mode: local
"#;
    let mut cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    cfg.resolve_storage_backend();
    assert_eq!(cfg.mode, DeploymentMode::Local);
    assert_eq!(cfg.storage.backend, StorageBackendType::Sqlite);
}

/// AC #2 (continued) — backend defaults to `postgres` in remote mode when not set.
#[test]
fn defaults_to_postgres_in_remote_mode_when_unset() {
    let yaml = r#"
mode: remote
"#;
    let mut cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    cfg.resolve_storage_backend();
    assert_eq!(cfg.mode, DeploymentMode::Remote);
    assert_eq!(cfg.storage.backend, StorageBackendType::Postgres);
}

/// Tiny RAII guard for env-var manipulation in the AC tests.
///
/// `apply_env_overrides()` reads from `std::env::var`, which is
/// process-global. Restoring the prior value when the guard drops
/// keeps tests independent.
struct ScopedEnv {
    key: &'static str,
    prior: Option<String>,
}

impl ScopedEnv {
    #[allow(dead_code)] // wired up incrementally — used by AC #4 once added.
    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var(key).ok();
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prior }
    }
}

impl Drop for ScopedEnv {
    fn drop(&mut self) {
        unsafe {
            match &self.prior {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
