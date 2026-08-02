//! Error types for the policy version history store.

use std::fmt;

/// Errors produced by [`super::store::PolicyHistoryStore`] operations.
#[derive(Debug)]
pub enum PolicyHistoryError {
    /// Filesystem I/O failure.
    Io(std::io::Error),
    /// JSON serialization or deserialization failure for metadata sidecars.
    SerdeJson(serde_json::Error),
    /// YAML serialization or deserialization failure for policy snapshots.
    SerdeYaml(serde_yaml::Error),
    /// The requested version identifier was not found in the history.
    VersionNotFound(String),
    /// A metadata sidecar file exists but contains invalid or inconsistent data.
    CorruptedMetadata(String),
}

impl fmt::Display for PolicyHistoryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "history I/O error: {e}"),
            Self::SerdeJson(e) => write!(f, "metadata JSON error: {e}"),
            Self::SerdeYaml(e) => write!(f, "policy YAML error: {e}"),
            Self::VersionNotFound(id) => write!(f, "version not found: {id}"),
            Self::CorruptedMetadata(msg) => write!(f, "corrupted metadata: {msg}"),
        }
    }
}

impl std::error::Error for PolicyHistoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::SerdeJson(e) => Some(e),
            Self::SerdeYaml(e) => Some(e),
            Self::VersionNotFound(_) | Self::CorruptedMetadata(_) => None,
        }
    }
}

impl From<std::io::Error> for PolicyHistoryError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for PolicyHistoryError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e)
    }
}

impl From<serde_yaml::Error> for PolicyHistoryError {
    fn from(e: serde_yaml::Error) -> Self {
        Self::SerdeYaml(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_version_not_found() {
        let e = PolicyHistoryError::VersionNotFound("abc123".to_string());
        assert_eq!(e.to_string(), "version not found: abc123");
    }

    #[test]
    fn display_corrupted_metadata() {
        let e = PolicyHistoryError::CorruptedMetadata("missing sha256 field".to_string());
        assert!(e.to_string().contains("corrupted metadata"));
    }

    #[test]
    fn display_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let e = PolicyHistoryError::Io(io_err);
        assert!(e.to_string().contains("I/O error"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let e: PolicyHistoryError = io_err.into();
        assert!(matches!(e, PolicyHistoryError::Io(_)));
    }

    #[test]
    fn source_returns_inner_for_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let e = PolicyHistoryError::Io(io_err);
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn source_returns_none_for_version_not_found() {
        let e = PolicyHistoryError::VersionNotFound("v1".to_string());
        assert!(std::error::Error::source(&e).is_none());
    }

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let e: PolicyHistoryError = json_err.into();
        assert!(matches!(e, PolicyHistoryError::SerdeJson(_)));
        assert!(e.to_string().contains("metadata JSON error"));
    }

    #[test]
    fn from_serde_yaml_error() {
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(":\n  [[[bad").unwrap_err();
        let e: PolicyHistoryError = yaml_err.into();
        assert!(matches!(e, PolicyHistoryError::SerdeYaml(_)));
        assert!(e.to_string().contains("policy YAML error"));
    }

    #[test]
    fn source_returns_inner_for_serde_json() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let e = PolicyHistoryError::SerdeJson(json_err);
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn source_returns_inner_for_serde_yaml() {
        let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(":\n  [[[bad").unwrap_err();
        let e = PolicyHistoryError::SerdeYaml(yaml_err);
        assert!(std::error::Error::source(&e).is_some());
    }

    #[test]
    fn source_returns_none_for_corrupted_metadata() {
        let e = PolicyHistoryError::CorruptedMetadata("bad data".to_string());
        assert!(std::error::Error::source(&e).is_none());
    }
}
