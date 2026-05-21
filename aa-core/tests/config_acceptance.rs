//! Story-level acceptance spec for E17 S-A (AAASM-1575).
//!
//! Exercises the full GatewayConfig precedence chain through the
//! public crate surface — no `pub(crate)` shortcuts — once all four
//! implementation sub-tickets (AAASM-1689..1692) have landed. Each
//! `#[test]` ticks one of the eight AC bullets from the Story.
//!
//! Gated behind `feature = "serde"` because every meaningful AC
//! exercises the YAML loader; running `cargo nextest run -p aa-core
//! --all-features` enables it.

#![cfg(feature = "serde")]

use std::path::PathBuf;

use aa_core::config::{ConfigError, DeploymentMode, GatewayConfig};

/// AC #1 — `DeploymentMode` reachable via `aa_core::config::DeploymentMode`.
#[test]
fn ac_1_deployment_mode_exported_from_config_module() {
    let _: DeploymentMode = DeploymentMode::Local;
    let _: DeploymentMode = DeploymentMode::Remote;
}

/// AC #2 — full Epic-17 sample YAML round-trips through `from_yaml_str`.
#[test]
fn ac_2_full_epic_example_yaml_round_trips() {
    let yaml = r#"
mode: remote
local:
  port: 7391
  dashboard: true
  storage_path: ~/.aasm/local.db
remote:
  listen_addr: "0.0.0.0:7391"
  tls:
    cert_file: /etc/aasm/tls.crt
    key_file: /etc/aasm/tls.key
  database_url: "postgres://aasm@db.internal/aasm"
  redis_url: "redis://redis.internal:6379"
agent:
  gateway_url: "http://localhost:7391"
  api_key: "secret"
"#;
    let cfg = GatewayConfig::from_yaml_str(yaml).expect("Epic example YAML must parse");
    assert_eq!(cfg.mode, DeploymentMode::Remote);
    assert!(cfg.remote.tls.is_some());
    assert!(cfg.remote.database_url.is_some());
}

/// AC #3 — missing YAML file at `load_from_path` returns defaults, no error.
#[test]
fn ac_3_missing_yaml_file_returns_default() {
    let missing = std::env::temp_dir().join("aasm-config-AAASM-1693-missing.yaml");
    let _ = std::fs::remove_file(&missing);
    let cfg = GatewayConfig::load_from_path(&missing).expect("NotFound must not error");
    assert_eq!(cfg, GatewayConfig::default());
}

/// AC #4 — `AA_MODE=remote` env var overrides `mode: local` in the YAML.
#[test]
fn ac_4_aa_mode_env_overrides_yaml_mode() {
    let mut cfg = GatewayConfig::from_yaml_str("mode: local").unwrap();
    assert_eq!(cfg.mode, DeploymentMode::Local, "precondition: YAML wins to start");
    // Use the public method through a scoped temp env-var set / unset to
    // exercise the exact code path the gateway will run at boot.
    let restore = ScopedEnv::set("AA_MODE", "remote");
    cfg.apply_env_overrides().expect("env override should succeed");
    drop(restore);
    assert_eq!(cfg.mode, DeploymentMode::Remote);
}

/// AC #5 — `AAASM_DATABASE_URL` env var overrides the Postgres URL.
///
/// As of E18 S-H (AAASM-1735) the env var targets
/// `storage.postgres.database_url`; `remote.database_url` is left
/// untouched and will be removed by the E18 S-I wiring story.
#[test]
fn ac_5_aasm_database_url_env_overrides_yaml_value() {
    let yaml = r#"
storage:
  postgres:
    database_url: "postgres://yaml-default/aasm"
"#;
    let mut cfg = GatewayConfig::from_yaml_str(yaml).unwrap();
    assert_eq!(
        cfg.storage.postgres.database_url.as_deref(),
        Some("postgres://yaml-default/aasm"),
    );
    let restore = ScopedEnv::set("AAASM_DATABASE_URL", "postgres://env-override/aasm");
    cfg.apply_env_overrides().unwrap();
    drop(restore);
    assert_eq!(
        cfg.storage.postgres.database_url.as_deref(),
        Some("postgres://env-override/aasm"),
    );
}

/// AC #6 — `~` in `storage_path` expanded to the real home directory.
#[test]
fn ac_6_tilde_in_storage_path_expanded_to_real_home() {
    let mut cfg = GatewayConfig::default();
    assert_eq!(cfg.local.storage_path, PathBuf::from("~/.aasm/local.db"));
    cfg.expand_paths();
    // dirs::home_dir() must be set on every supported CI runner; if it isn't,
    // expand_paths is a no-op and the assertion below still holds (the path
    // simply stays raw). We assert non-emptiness either way to prove the
    // call did not error and the field is still a valid PathBuf.
    let expanded = cfg.local.storage_path.to_string_lossy();
    if let Some(home) = dirs::home_dir() {
        let expected = home.join(".aasm").join("local.db");
        assert_eq!(cfg.local.storage_path, expected, "expanded path should match real home");
    }
    assert!(!expanded.is_empty(), "storage_path must remain a valid PathBuf");
}

/// AC #7 — Invalid `AA_MODE` returns a clear error containing both
/// `AA_MODE` and the bad value.
#[test]
fn ac_7_invalid_aa_mode_returns_clear_error() {
    let mut cfg = GatewayConfig::default();
    let restore = ScopedEnv::set("AA_MODE", "foobar");
    let err = cfg.apply_env_overrides().expect_err("AA_MODE=foobar must Err");
    drop(restore);
    let msg = format!("{err}");
    assert!(matches!(err, ConfigError::InvalidMode { ref raw } if raw == "foobar"));
    assert!(msg.contains("AA_MODE"), "message must name the var: {msg}");
    assert!(msg.contains("foobar"), "message must include the value: {msg}");
}

/// AC #8 (partial) — the whole crate test surface stays green.
///
/// The full assertion is `cargo nextest run -p aa-core --all-features` in CI;
/// this placeholder makes the AC visible in the integration spec and ensures
/// the spec file itself contributes a passing test even when run alone.
#[test]
fn ac_8_crate_suite_smoke() {
    // Sanity-check: defaults survive a no-op load attempt against a fake path.
    let cfg = GatewayConfig::load_from_path("/tmp/aasm-config-does-not-exist-AAASM-1693.yaml").unwrap();
    assert_eq!(cfg, GatewayConfig::default());
}

/// Tiny RAII guard for env-var manipulation in the AC tests.
///
/// `apply_env_overrides()` reads from `std::env::var`, which is process-global.
/// Restoring the prior value when the guard drops keeps tests independent
/// (nextest may still serialise them — that's fine; correctness here doesn't
/// depend on parallelism).
struct ScopedEnv {
    key: &'static str,
    prior: Option<String>,
}

impl ScopedEnv {
    fn set(key: &'static str, value: &str) -> Self {
        let prior = std::env::var(key).ok();
        // SAFETY: tests run in this process; we restore on drop. Other parallel
        // tests in this binary do not read these specific env vars.
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
