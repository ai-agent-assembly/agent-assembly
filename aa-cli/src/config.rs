//! Configuration file management for the `aasm` CLI.
//!
//! Config is stored at `~/.aa/config.yaml` and contains named contexts,
//! each with an API URL and optional API key.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::CliError;

/// A named API context (e.g. "production", "staging").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextConfig {
    /// Base URL of the Agent Assembly API (e.g. `http://localhost:8080`).
    pub api_url: String,
    /// Optional API key for authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
}

/// Dashboard server configuration, stored under `dashboard:` in `~/.aa/config.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardConfig {
    /// TCP port the embedded SPA server listens on (default: 3000).
    #[serde(default = "DashboardConfig::default_port")]
    pub port: u16,
    /// Open the system browser automatically after `aasm dashboard start` is ready.
    #[serde(default)]
    pub auto_open: bool,
}

impl DashboardConfig {
    fn default_port() -> u16 {
        3000
    }
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            auto_open: false,
        }
    }
}

/// Top-level CLI configuration file schema (`~/.aa/config.yaml`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CliConfig {
    /// Name of the default context to use when `--context` is not specified.
    #[serde(default)]
    pub default_context: Option<String>,
    /// Named contexts mapping (e.g. `{ "production": { api_url: "..." } }`).
    #[serde(default)]
    pub contexts: BTreeMap<String, ContextConfig>,
    /// Dashboard server settings (`aasm dashboard start`).
    #[serde(default)]
    pub dashboard: DashboardConfig,
}

/// Resolve the dashboard port from (highest to lowest priority):
/// 1. `AASM_DASHBOARD_PORT` environment variable
/// 2. `port_flag` — the `--port` CLI argument
/// 3. `config.dashboard.port`
pub fn resolve_dashboard_port(config: &CliConfig, port_flag: Option<u16>) -> u16 {
    if let Ok(val) = std::env::var("AASM_DASHBOARD_PORT") {
        if let Ok(p) = val.parse::<u16>() {
            return p;
        }
    }
    port_flag.unwrap_or(config.dashboard.port)
}

/// Return the config directory path (`~/.aa/`).
pub fn config_dir() -> PathBuf {
    dirs::home_dir().expect("cannot determine home directory").join(".aa")
}

/// Return the config file path (`~/.aa/config.yaml`).
pub fn config_path() -> PathBuf {
    config_dir().join("config.yaml")
}

/// Load the CLI configuration from `~/.aa/config.yaml`.
///
/// Returns a default (empty) config if the file does not exist.
pub fn load() -> Result<CliConfig, CliError> {
    let path = config_path();
    if !path.exists() {
        return Ok(CliConfig::default());
    }
    let contents = std::fs::read_to_string(&path).map_err(|e| CliError::Config {
        path: path.clone(),
        source: e,
    })?;
    let config: CliConfig = serde_yaml::from_str(&contents)?;
    Ok(config)
}

/// Save the CLI configuration to `~/.aa/config.yaml`.
///
/// Creates the `~/.aa/` directory if it does not exist. The file holds the
/// operator bearer token (`api_key`), so on Unix the directory is locked to
/// `0700` and the file to `0600` — otherwise any local user on a shared host
/// could read the token from a world-readable `~/.aa/config.yaml`.
pub fn save(config: &CliConfig) -> Result<(), CliError> {
    let dir = config_dir();
    ensure_config_dir(&dir)?;
    let path = config_path();
    let yaml = serde_yaml::to_string(config)?;
    write_config_file(&path, &yaml)?;
    Ok(())
}

/// Create the config directory if missing, restricting it to `0700` on Unix.
///
/// `DirBuilder::mode` only applies when the directory is newly created, so an
/// existing directory (e.g. one left at `0755` by an older version) is tightened
/// explicitly.
#[cfg(unix)]
fn ensure_config_dir(dir: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if dir.exists() {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| CliError::Config {
            path: dir.to_path_buf(),
            source: e,
        })?;
        return Ok(());
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CliError::Config {
            path: dir.to_path_buf(),
            source: e,
        })
}

/// Create the config directory if missing (non-Unix: no permission control).
#[cfg(not(unix))]
fn ensure_config_dir(dir: &std::path::Path) -> Result<(), CliError> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(|e| CliError::Config {
        path: dir.to_path_buf(),
        source: e,
    })
}

/// Write the config file, restricting it to `0600` on Unix.
///
/// The file is created with `0600` via `OpenOptions::mode` (no world-readable
/// window), and `set_permissions` then tightens any pre-existing file that an
/// older, vulnerable version may have left at `0644`.
#[cfg(unix)]
fn write_config_file(path: &std::path::Path, yaml: &str) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Config {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Config {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(yaml.as_bytes()).map_err(|e| CliError::Config {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Write the config file (non-Unix: no permission control).
#[cfg(not(unix))]
fn write_config_file(path: &std::path::Path, yaml: &str) -> Result<(), CliError> {
    std::fs::write(path, yaml).map_err(|e| CliError::Config {
        path: path.to_path_buf(),
        source: e,
    })
}

/// Resolved connection parameters after merging CLI flags and config file.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ResolvedContext {
    /// The context name that was resolved (if any).
    pub name: Option<String>,
    /// Base URL of the API gateway.
    pub api_url: String,
    /// API key for authentication (if any).
    pub api_key: Option<String>,
}

/// Resolve the active API context by merging CLI flags with the config file.
///
/// Precedence (highest to lowest):
/// 1. Explicit CLI flags (`--api-url`, `--api-key`)
/// 2. Named context from config (`--context <name>` or `default_context`)
/// 3. Built-in default (`http://localhost:8080`)
pub fn resolve_context(
    config: &CliConfig,
    context_flag: Option<&str>,
    api_url_flag: Option<&str>,
    api_key_flag: Option<&str>,
) -> Result<ResolvedContext, CliError> {
    let default_url = "http://localhost:8080";

    // If explicit --api-url is provided, use it directly (no context lookup).
    if let Some(url) = api_url_flag {
        return Ok(ResolvedContext {
            name: None,
            api_url: url.to_string(),
            api_key: api_key_flag.map(String::from),
        });
    }

    // Determine which context name to look up.
    let context_name = context_flag
        .map(String::from)
        .or_else(|| config.default_context.clone());

    if let Some(ref name) = context_name {
        let ctx = config
            .contexts
            .get(name)
            .ok_or_else(|| CliError::ContextNotFound(name.clone()))?;
        return Ok(ResolvedContext {
            name: Some(name.clone()),
            api_url: ctx.api_url.clone(),
            api_key: api_key_flag.map(String::from).or_else(|| ctx.api_key.clone()),
        });
    }

    // No context specified, no default — use built-in default.
    Ok(ResolvedContext {
        name: None,
        api_url: default_url.to_string(),
        api_key: api_key_flag.map(String::from),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> CliConfig {
        let mut contexts = BTreeMap::new();
        contexts.insert(
            "production".to_string(),
            ContextConfig {
                api_url: "https://api.example.com".to_string(),
                api_key: Some("prod-key".to_string()),
            },
        );
        contexts.insert(
            "staging".to_string(),
            ContextConfig {
                api_url: "https://staging.example.com".to_string(),
                api_key: None,
            },
        );
        CliConfig {
            default_context: Some("production".to_string()),
            contexts,
            dashboard: DashboardConfig::default(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn save_restricts_config_file_and_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let result = save(&sample_config());
        let dir = config_dir();
        let path = config_path();
        let dir_mode = std::fs::metadata(&dir).map(|m| m.permissions().mode() & 0o777);
        let file_mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777);

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        result.unwrap();
        assert_eq!(dir_mode.unwrap(), 0o700, "config dir must be owner-only (0700)");
        assert_eq!(file_mode.unwrap(), 0o600, "config file must be owner-only (0600)");
    }

    #[cfg(unix)]
    #[test]
    fn save_tightens_preexisting_loose_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        // Simulate a config left world-readable by an older, vulnerable version.
        let dir = config_dir();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = config_path();
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let result = save(&sample_config());
        let dir_mode = std::fs::metadata(&dir).map(|m| m.permissions().mode() & 0o777);
        let file_mode = std::fs::metadata(&path).map(|m| m.permissions().mode() & 0o777);

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        result.unwrap();
        assert_eq!(dir_mode.unwrap(), 0o700, "save must tighten an existing dir to 0700");
        assert_eq!(file_mode.unwrap(), 0o600, "save must tighten an existing file to 0600");
    }

    #[test]
    fn config_round_trip_yaml() {
        let cfg = sample_config();
        let yaml = serde_yaml::to_string(&cfg).unwrap();
        let parsed: CliConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.default_context, cfg.default_context);
        assert_eq!(parsed.contexts.len(), 2);
    }

    #[test]
    fn empty_config_deserializes() {
        let yaml = "{}";
        let cfg: CliConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(cfg.default_context.is_none());
        assert!(cfg.contexts.is_empty());
    }

    #[test]
    fn resolve_uses_default_context() {
        let cfg = sample_config();
        let resolved = resolve_context(&cfg, None, None, None).unwrap();
        assert_eq!(resolved.name.as_deref(), Some("production"));
        assert_eq!(resolved.api_url, "https://api.example.com");
        assert_eq!(resolved.api_key.as_deref(), Some("prod-key"));
    }

    #[test]
    fn resolve_explicit_context_overrides_default() {
        let cfg = sample_config();
        let resolved = resolve_context(&cfg, Some("staging"), None, None).unwrap();
        assert_eq!(resolved.name.as_deref(), Some("staging"));
        assert_eq!(resolved.api_url, "https://staging.example.com");
        assert!(resolved.api_key.is_none());
    }

    #[test]
    fn resolve_api_url_flag_overrides_everything() {
        let cfg = sample_config();
        let resolved = resolve_context(&cfg, Some("production"), Some("http://custom:9090"), None).unwrap();
        assert!(resolved.name.is_none());
        assert_eq!(resolved.api_url, "http://custom:9090");
    }

    #[test]
    fn resolve_api_key_flag_overrides_config_key() {
        let cfg = sample_config();
        let resolved = resolve_context(&cfg, Some("production"), None, Some("override-key")).unwrap();
        assert_eq!(resolved.api_key.as_deref(), Some("override-key"));
    }

    #[test]
    fn resolve_unknown_context_returns_error() {
        let cfg = sample_config();
        let result = resolve_context(&cfg, Some("nonexistent"), None, None);
        assert!(result.is_err());
    }

    #[test]
    fn resolve_no_config_uses_default_url() {
        let cfg = CliConfig {
            default_context: None,
            contexts: BTreeMap::new(),
            dashboard: DashboardConfig::default(),
        };
        let resolved = resolve_context(&cfg, None, None, None).unwrap();
        assert_eq!(resolved.api_url, "http://localhost:8080");
        assert!(resolved.name.is_none());
    }

    #[test]
    fn dashboard_config_defaults() {
        let cfg: DashboardConfig = serde_yaml::from_str("{}").unwrap();
        assert_eq!(cfg.port, 3000);
        assert!(!cfg.auto_open);
    }

    #[test]
    fn dashboard_config_round_trip_yaml() {
        let yaml = "port: 4000\nauto_open: true\n";
        let cfg: DashboardConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.port, 4000);
        assert!(cfg.auto_open);
        let roundtripped = serde_yaml::to_string(&cfg).unwrap();
        let cfg2: DashboardConfig = serde_yaml::from_str(&roundtripped).unwrap();
        assert_eq!(cfg2.port, 4000);
        assert!(cfg2.auto_open);
    }

    #[test]
    fn resolve_dashboard_port_env_overrides_all() {
        let _guard = crate::test_support::env_guard();
        std::env::set_var("AASM_DASHBOARD_PORT", "9999");
        let port = resolve_dashboard_port(&CliConfig::default(), Some(5000));
        std::env::remove_var("AASM_DASHBOARD_PORT");
        assert_eq!(port, 9999);
    }

    #[test]
    fn resolve_dashboard_port_flag_beats_config() {
        let _guard = crate::test_support::env_guard();
        std::env::remove_var("AASM_DASHBOARD_PORT");
        assert_eq!(resolve_dashboard_port(&CliConfig::default(), Some(4321)), 4321);
    }

    #[test]
    fn resolve_dashboard_port_uses_config_default() {
        let _guard = crate::test_support::env_guard();
        std::env::remove_var("AASM_DASHBOARD_PORT");
        assert_eq!(resolve_dashboard_port(&CliConfig::default(), None), 3000);
    }
}
