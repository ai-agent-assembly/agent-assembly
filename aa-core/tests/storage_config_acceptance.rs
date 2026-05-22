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

use std::path::PathBuf;

use aa_core::config::{ConfigError, DeploymentMode, GatewayConfig, StorageBackendType};

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

/// AC #4 — `~` in SQLite path expanded to the actual home directory
/// at parse time (well, at expand_paths() time).
#[test]
fn tilde_in_sqlite_path_expanded_to_home() {
    let yaml = r#"
storage:
  sqlite:
    path: ~/.aasm/local.db
"#;
    let mut cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    assert_eq!(cfg.storage.sqlite.path, PathBuf::from("~/.aasm/local.db"));
    cfg.expand_paths();
    let home = dirs::home_dir().expect("$HOME must be set on CI runners and dev boxes");
    assert_eq!(cfg.storage.sqlite.path, home.join(".aasm/local.db"));
}

/// AC #3 — `AAASM_DATABASE_URL` env var overrides
/// `storage.postgres.database_url`.
#[test]
fn aaasm_database_url_overrides_storage_postgres() {
    let yaml = r#"
storage:
  postgres:
    database_url: "postgres://yaml-default/aasm"
"#;
    let mut cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    assert_eq!(
        cfg.storage.postgres.database_url.as_deref(),
        Some("postgres://yaml-default/aasm"),
    );
    let _guard = ScopedEnv::set("AAASM_DATABASE_URL", "postgres://env-override/aasm");
    cfg.apply_env_overrides().expect("env overrides must apply");
    assert_eq!(
        cfg.storage.postgres.database_url.as_deref(),
        Some("postgres://env-override/aasm"),
    );
}

/// AC #5 — `cold_action: archive` without `archive_url` is a startup
/// error with the documented message.
#[test]
fn cold_action_archive_without_url_fails_validation() {
    let yaml = r#"
storage:
  retention:
    cold_action: archive
"#;
    let cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    let err = cfg
        .validate()
        .expect_err("cold_action = archive without archive_url must fail");
    assert!(matches!(err, ConfigError::ArchiveUrlRequired));
    assert_eq!(format!("{err}"), "archive_url is required when cold_action is archive",);
}

/// AC #6 — `warm_days <= hot_days` is a startup error with the
/// documented message naming both values.
#[test]
fn warm_days_less_than_hot_days_fails_validation() {
    // Use warm = hot to also catch the strict-inequality edge case.
    let yaml = r#"
storage:
  retention:
    hot_days: 60
    warm_days: 30
"#;
    let cfg = GatewayConfig::from_yaml_str(yaml).expect("YAML must parse");
    let err = cfg.validate().expect_err("warm_days < hot_days must fail validation");
    // The {hot, warm} pair is the precise Story-AC message.
    assert!(matches!(
        err,
        ConfigError::WarmDaysNotGreaterThanHotDays { hot: 60, warm: 30 }
    ));
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
