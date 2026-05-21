//! Gateway deployment-mode configuration types (Epic 17, AAASM-1568).
//!
//! Configuration is loaded once at startup and threaded through the
//! application. This module is the **foundation** of Epic 17 — every
//! other story in the Epic depends on these types to decide whether
//! the gateway should boot in local-dev or remote-control-plane mode.

use std::path::PathBuf;

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
}
