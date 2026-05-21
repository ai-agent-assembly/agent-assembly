//! Gateway deployment-mode configuration types (Epic 17, AAASM-1568).
//!
//! Configuration is loaded once at startup and threaded through the
//! application. This module is the **foundation** of Epic 17 — every
//! other story in the Epic depends on these types to decide whether
//! the gateway should boot in local-dev or remote-control-plane mode.

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
}
