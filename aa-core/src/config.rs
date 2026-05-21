//! Gateway deployment-mode configuration types (Epic 17, AAASM-1568).
//!
//! Configuration is loaded once at startup and threaded through the
//! application. This module is the **foundation** of Epic 17 — every
//! other story in the Epic depends on these types to decide whether
//! the gateway should boot in local-dev or remote-control-plane mode.

use std::net::SocketAddr;
use std::path::PathBuf;

/// Errors that can occur while loading or parsing a `GatewayConfig`.
///
/// All variants carry enough context to be surfaced verbatim to an
/// operator running `aasm start`; `Display` implementations come
/// from `thiserror` so they format cleanly into log lines and CLI
/// stderr.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// Failed to read the YAML config file (permission denied, or
    /// other filesystem error other than "file not found").
    #[error("failed to read config file: {0}")]
    Io(#[from] std::io::Error),
    /// The YAML payload could not be deserialised into a `GatewayConfig`.
    #[error("failed to parse config YAML: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Which deployment topology the gateway should boot into.
///
/// Selected at startup from a combination of YAML config, environment
/// variables, and CLI flags. See [Epic 17 spec][epic] for the full
/// precedence rules.
///
/// [epic]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1568
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "lowercase"))]
pub enum DeploymentMode {
    /// Lightweight in-process control plane on `localhost:7391`.
    ///
    /// Zero-config developer experience: SQLite storage, embedded
    /// dashboard, no network connectivity required.
    #[default]
    Local,
    /// Independently-deployed control plane reached over the network.
    ///
    /// Agents on multiple machines all register against one gateway.
    /// PostgreSQL storage, TLS required for production.
    Remote,
}

/// Configuration for the in-process **local-dev** control plane.
///
/// All fields default to the zero-config developer values documented
/// in the Epic 17 spec. `storage_path` is stored raw; `~` is expanded
/// later by `GatewayConfig::expand_paths()` (added in AAASM-1691).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct LocalModeConfig {
    /// TCP port the local gateway listens on. Default: `7391`.
    pub port: u16,
    /// Whether to serve the dashboard SPA at the same address. Default: `true`.
    pub dashboard: bool,
    /// SQLite database path. Default: `~/.aasm/local.db` (un-expanded).
    pub storage_path: PathBuf,
}

impl Default for LocalModeConfig {
    fn default() -> Self {
        Self {
            port: 7391,
            dashboard: true,
            storage_path: PathBuf::from("~/.aasm/local.db"),
        }
    }
}

/// TLS material for the remote control plane listener.
///
/// `None` on `RemoteModeConfig::tls` disables TLS (development only).
/// Production deployments must supply both files; paths are stored raw
/// and expanded by `GatewayConfig::expand_paths()` (AAASM-1691).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct TlsConfig {
    /// PEM-encoded certificate chain.
    pub cert_file: PathBuf,
    /// PEM-encoded private key matching `cert_file`.
    pub key_file: PathBuf,
}

/// Configuration for the network-reachable **remote** control plane.
///
/// Defaults bind to `0.0.0.0:7391` with no TLS and no database —
/// production callers must explicitly configure `tls` and
/// `database_url` before serving real traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct RemoteModeConfig {
    /// Address the gateway binds to. Default: `0.0.0.0:7391`.
    pub listen_addr: SocketAddr,
    /// TLS cert / key paths. `None` disables TLS (development only).
    pub tls: Option<TlsConfig>,
    /// PostgreSQL connection URL. `None` falls back to in-memory storage.
    pub database_url: Option<String>,
    /// Optional Redis URL used by the rate-limit and pub/sub subsystems.
    pub redis_url: Option<String>,
}

impl Default for RemoteModeConfig {
    fn default() -> Self {
        Self {
            listen_addr: SocketAddr::from(([0, 0, 0, 0], 7391)),
            tls: None,
            database_url: None,
            redis_url: None,
        }
    }
}

/// Agent-side connection settings (used by the SDK FFI shims, not the gateway).
///
/// `gateway_url` is the address the SDK calls into. `api_key` is the
/// optional bearer token surface for authenticated SaaS deployments;
/// in local mode it is typically `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct AgentConnectConfig {
    /// Where the SDK connects. Default: `http://localhost:7391`.
    pub gateway_url: String,
    /// Optional API key for authenticated control planes.
    pub api_key: Option<String>,
}

impl Default for AgentConnectConfig {
    fn default() -> Self {
        Self {
            gateway_url: String::from("http://localhost:7391"),
            api_key: None,
        }
    }
}

/// Top-level gateway configuration loaded at startup.
///
/// Composes the four sub-configs and a [`DeploymentMode`] flag. All
/// fields use `#[serde(default)]` so a minimal YAML — even an empty
/// document — deserialises into the documented defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
#[cfg_attr(feature = "serde", serde(default))]
pub struct GatewayConfig {
    /// Which topology to boot — local-dev or remote control-plane.
    pub mode: DeploymentMode,
    /// Settings for `mode = Local`.
    pub local: LocalModeConfig,
    /// Settings for `mode = Remote`.
    pub remote: RemoteModeConfig,
    /// Settings the SDK FFI shim reads to dial the gateway.
    pub agent: AgentConnectConfig,
}

#[cfg(feature = "serde")]
impl GatewayConfig {
    /// Parse a `GatewayConfig` from a YAML string.
    ///
    /// Missing fields fall back to their documented defaults thanks to
    /// the type-level `#[serde(default)]` attribute, so an empty
    /// document (`""` or `"{}"`) deserialises to `Self::default()`.
    pub fn from_yaml_str(yaml: &str) -> Result<Self, ConfigError> {
        Ok(serde_yaml::from_str(yaml)?)
    }

    /// Load a `GatewayConfig` from a YAML file on disk.
    ///
    /// A `NotFound` error returns `Self::default()` so missing
    /// `~/.aasm/config.yaml` does not break startup. Any other I/O
    /// error (permission denied, malformed YAML, etc.) propagates
    /// as `ConfigError`.
    pub fn load_from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(yaml) => Self::from_yaml_str(&yaml),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(ConfigError::Io(err)),
        }
    }

    /// Load `GatewayConfig` from the user's `~/.aasm/config.yaml`.
    ///
    /// Equivalent to `load_from_path(dirs::home_dir() / ".aasm/config.yaml")`.
    /// Falls back to `Self::default()` when the file is absent or the
    /// home directory cannot be resolved (e.g. `$HOME` unset in a
    /// systemd unit without `User=`).
    pub fn load_default_path() -> Result<Self, ConfigError> {
        let Some(home) = dirs::home_dir() else {
            return Ok(Self::default());
        };
        Self::load_from_path(home.join(".aasm").join("config.yaml"))
    }
}

impl GatewayConfig {
    /// Expand a leading `~` in every path field to the user's home directory.
    ///
    /// Touches `local.storage_path` and both `remote.tls` paths.
    /// A no-op when the home directory cannot be resolved or when
    /// no field starts with `~`. Idempotent — calling twice produces
    /// the same result as calling once.
    pub fn expand_paths(&mut self) {
        if let Some(home) = dirs::home_dir() {
            self.expand_paths_in(&home);
        }
    }

    /// Same as [`expand_paths`](Self::expand_paths) but takes an explicit home
    /// directory — used by tests so the assertion is independent of `$HOME`.
    pub(crate) fn expand_paths_in(&mut self, home: &std::path::Path) {
        self.local.storage_path = expand_tilde(&self.local.storage_path, home);
        if let Some(tls) = &mut self.remote.tls {
            tls.cert_file = expand_tilde(&tls.cert_file, home);
            tls.key_file = expand_tilde(&tls.key_file, home);
        }
    }
}

fn expand_tilde(path: &std::path::Path, home: &std::path::Path) -> PathBuf {
    match path.strip_prefix("~") {
        Ok(stripped) => home.join(stripped),
        Err(_) => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_mode_default_is_local() {
        assert_eq!(DeploymentMode::default(), DeploymentMode::Local);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_round_trip_local() {
        let mode: DeploymentMode = serde_yaml::from_str("local").unwrap();
        assert_eq!(mode, DeploymentMode::Local);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_round_trip_remote() {
        let mode: DeploymentMode = serde_yaml::from_str("remote").unwrap();
        assert_eq!(mode, DeploymentMode::Remote);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn deployment_mode_yaml_rejects_unknown_variant() {
        let result: Result<DeploymentMode, _> = serde_yaml::from_str("foobar");
        assert!(result.is_err(), "unknown variant should fail to deserialize");
    }

    #[test]
    fn local_mode_config_default_matches_spec() {
        let cfg = LocalModeConfig::default();
        assert_eq!(cfg.port, 7391);
        assert!(cfg.dashboard);
        assert_eq!(cfg.storage_path, PathBuf::from("~/.aasm/local.db"));
    }

    #[cfg(feature = "serde")]
    #[test]
    fn local_mode_config_yaml_overrides_port_keeps_other_defaults() {
        let cfg: LocalModeConfig = serde_yaml::from_str("port: 8080").unwrap();
        assert_eq!(cfg.port, 8080);
        assert!(cfg.dashboard, "dashboard should fall back to default");
        assert_eq!(
            cfg.storage_path,
            PathBuf::from("~/.aasm/local.db"),
            "storage_path should fall back to default"
        );
    }

    #[test]
    fn remote_mode_config_default_binds_all_interfaces() {
        let cfg = RemoteModeConfig::default();
        assert_eq!(cfg.listen_addr, SocketAddr::from(([0, 0, 0, 0], 7391)));
        assert!(cfg.tls.is_none(), "tls should be opt-in, never on by default");
        assert!(cfg.database_url.is_none());
        assert!(cfg.redis_url.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn remote_mode_config_yaml_overrides_database_keeps_other_defaults() {
        let yaml = r#"database_url: "postgres://aasm@db.internal/aasm""#;
        let cfg: RemoteModeConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.database_url.as_deref(), Some("postgres://aasm@db.internal/aasm"));
        assert_eq!(cfg.listen_addr, SocketAddr::from(([0, 0, 0, 0], 7391)));
        assert!(cfg.tls.is_none());
        assert!(cfg.redis_url.is_none());
    }

    #[test]
    fn agent_connect_config_default_points_at_localhost() {
        let cfg = AgentConnectConfig::default();
        assert_eq!(cfg.gateway_url, "http://localhost:7391");
        assert!(cfg.api_key.is_none());
    }

    #[cfg(feature = "serde")]
    #[test]
    fn agent_connect_config_yaml_round_trip() {
        let yaml = r#"
gateway_url: "https://cp.company.internal:7391"
api_key: "secret"
"#;
        let cfg: AgentConnectConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(cfg.gateway_url, "https://cp.company.internal:7391");
        assert_eq!(cfg.api_key.as_deref(), Some("secret"));
    }
}
