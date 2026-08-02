//! Configuration for the policy history store.

use std::path::PathBuf;

/// Default maximum number of retained policy versions.
const DEFAULT_MAX_VERSIONS: usize = 50;

/// Default history subdirectory name under the data root.
const HISTORY_DIR_NAME: &str = "policy-history";

/// Configuration for the policy version history store.
#[derive(Debug, Clone, PartialEq)]
pub struct HistoryConfig {
    /// Directory where versioned policy snapshots are stored.
    pub history_dir: PathBuf,
    /// Maximum number of versions to retain before pruning.
    pub max_versions: usize,
}

impl HistoryConfig {
    /// Build a default configuration.
    ///
    /// The history directory resolves in this order:
    /// 1. `$AA_DATA_DIR/policy-history/` if `AA_DATA_DIR` is set
    /// 2. `~/.aa/policy-history/` otherwise
    pub fn default_config() -> Self {
        let base = std::env::var("AA_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| dirs::home_dir().unwrap_or_else(|| PathBuf::from(".")).join(".aa"));

        Self {
            history_dir: base.join(HISTORY_DIR_NAME),
            max_versions: DEFAULT_MAX_VERSIONS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_max_versions_is_50() {
        let cfg = HistoryConfig {
            history_dir: PathBuf::from("/tmp/test"),
            max_versions: DEFAULT_MAX_VERSIONS,
        };
        assert_eq!(cfg.max_versions, 50);
    }

    #[test]
    fn custom_construction() {
        let cfg = HistoryConfig {
            history_dir: PathBuf::from("/custom/path"),
            max_versions: 100,
        };
        assert_eq!(cfg.history_dir, PathBuf::from("/custom/path"));
        assert_eq!(cfg.max_versions, 100);
    }

    #[test]
    fn default_config_ends_with_policy_history() {
        let cfg = HistoryConfig::default_config();
        assert!(cfg.history_dir.ends_with("policy-history"));
        assert_eq!(cfg.max_versions, 50);
    }
}
