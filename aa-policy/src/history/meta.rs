//! Version metadata for a stored policy snapshot.

use serde::{Deserialize, Serialize};

/// Metadata sidecar for a versioned policy snapshot.
///
/// Persisted as `<timestamp>-<sha256-prefix>.meta.json` alongside
/// the YAML snapshot in the history directory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyVersionMeta {
    /// ISO 8601 UTC timestamp when the policy was applied.
    pub timestamp: String,
    /// Hex-encoded SHA-256 digest of the YAML content.
    pub sha256: String,
    /// Identity of the user or system that applied this version.
    pub applied_by: Option<String>,
    /// Original file path from which the policy was loaded.
    pub source_path: Option<String>,
    /// ISO 8601 UTC timestamp of the first event evaluated under this policy version.
    pub first_event_covered: Option<String>,
    /// Whether this version was created by a rollback operation.
    pub is_rollback: bool,
    /// Version identifier of the rollback target (set when `is_rollback` is true).
    pub rollback_target: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_construction_with_required_fields() {
        let meta = PolicyVersionMeta {
            timestamp: "2026-04-28T12:00:00Z".to_string(),
            sha256: "abcdef1234567890".to_string(),
            applied_by: None,
            source_path: None,
            first_event_covered: None,
            is_rollback: false,
            rollback_target: None,
        };
        assert_eq!(meta.timestamp, "2026-04-28T12:00:00Z");
        assert!(!meta.is_rollback);
    }

    #[test]
    fn meta_json_round_trip() {
        let meta = PolicyVersionMeta {
            timestamp: "2026-04-28T12:00:00Z".to_string(),
            sha256: "abcdef1234567890".to_string(),
            applied_by: Some("alice".to_string()),
            source_path: Some("/etc/aa/policy.yaml".to_string()),
            first_event_covered: None,
            is_rollback: false,
            rollback_target: None,
        };
        let json = serde_json::to_string(&meta).unwrap();
        let deserialized: PolicyVersionMeta = serde_json::from_str(&json).unwrap();
        assert_eq!(meta, deserialized);
    }

    #[test]
    fn meta_rollback_fields() {
        let meta = PolicyVersionMeta {
            timestamp: "2026-04-28T13:00:00Z".to_string(),
            sha256: "fedcba0987654321".to_string(),
            applied_by: Some("ops-bot".to_string()),
            source_path: None,
            first_event_covered: Some("2026-04-28T13:01:00Z".to_string()),
            is_rollback: true,
            rollback_target: Some("abcdef1234567890".to_string()),
        };
        assert!(meta.is_rollback);
        assert_eq!(meta.rollback_target.as_deref(), Some("abcdef1234567890"));
    }
}
