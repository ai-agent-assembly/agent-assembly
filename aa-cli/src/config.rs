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
        Self { port: 3000, auto_open: false }
    }
}

/// Top-level CLI configuration file schema (`~/.aa/config.yaml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        return Ok(CliConfig {
            default_context: None,
            contexts: BTreeMap::new(),
            dashboard: DashboardConfig::default(),
        });
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
/// Creates the `~/.aa/` directory if it does not exist.
pub fn save(config: &CliConfig) -> Result<(), CliError> {
    let dir = config_dir();
    if !dir.exists() {
        std::fs::create_dir_all(&dir).map_err(|e| CliError::Config {
            path: dir.clone(),
            source: e,
        })?;
    }
    let path = config_path();
    let yaml = serde_yaml::to_string(config)?;
    std::fs::write(&path, yaml).map_err(|e| CliError::Config { path, source: e })?;
    Ok(())
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
}
