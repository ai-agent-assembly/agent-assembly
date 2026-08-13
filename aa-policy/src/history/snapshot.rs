//! Complete policy snapshot combining metadata and YAML content.

use super::meta::PolicyVersionMeta;

/// A stored policy version: metadata plus the full YAML body.
///
/// Returned by [`super::store::PolicyHistoryStore::get`] when the caller
/// needs both the index entry and the policy content.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicySnapshot {
    /// Version metadata (timestamps, hash, attribution).
    pub meta: PolicyVersionMeta,
    /// Raw YAML content of this policy version.
    pub yaml_content: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_holds_meta_and_content() {
        let snapshot = PolicySnapshot {
            meta: PolicyVersionMeta {
                timestamp: "2026-04-28T12:00:00Z".to_string(),
                sha256: "abc123".to_string(),
                applied_by: None,
                source_path: None,
                first_event_covered: None,
                is_rollback: false,
                rollback_target: None,
            },
            yaml_content: "network:\n  allowlist:\n    - api.openai.com\n".to_string(),
        };
        assert_eq!(snapshot.meta.sha256, "abc123");
        assert!(snapshot.yaml_content.contains("allowlist"));
    }
}
