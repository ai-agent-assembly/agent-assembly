//! Trait interface for policy version history storage.

use async_trait::async_trait;

use super::error::PolicyHistoryError;
use super::meta::PolicyVersionMeta;
use super::snapshot::PolicySnapshot;

/// Async trait for storing and retrieving versioned policy snapshots.
///
/// Implementations may back this with the local filesystem
/// (`~/.aa/policy-history/`), a database, or an in-memory store for testing.
#[async_trait]
pub trait PolicyHistoryStore: Send + Sync {
    /// Persist a new policy version and return its metadata.
    ///
    /// The store computes the SHA-256 hash of `yaml`, writes the YAML
    /// snapshot and its `.meta.json` sidecar, then prunes old versions
    /// if the configured maximum is exceeded.
    async fn save(&self, yaml: &str, applied_by: Option<&str>) -> Result<PolicyVersionMeta, PolicyHistoryError>;

    /// List the most recent policy versions, newest first.
    ///
    /// Returns at most `limit` entries. Pass `usize::MAX` for all.
    async fn list(&self, limit: usize) -> Result<Vec<PolicyVersionMeta>, PolicyHistoryError>;

    /// Retrieve a full snapshot (metadata + YAML body) by version identifier.
    ///
    /// The `version_id` is the SHA-256 prefix stored in the metadata.
    async fn get(&self, version_id: &str) -> Result<PolicySnapshot, PolicyHistoryError>;

    /// Roll back to a previous version, creating a new history entry.
    ///
    /// The returned metadata describes the newly-created rollback entry,
    /// not the original version being restored.
    async fn rollback(&self, version_id: &str) -> Result<PolicyVersionMeta, PolicyHistoryError>;

    /// Compute a unified diff between two policy versions.
    ///
    /// Returns the diff as a string in unified diff format.
    async fn diff(&self, version_a: &str, version_b: &str) -> Result<String, PolicyHistoryError>;

    /// Remove versions beyond the configured maximum, oldest first.
    ///
    /// Returns the number of versions pruned.
    async fn prune(&self) -> Result<usize, PolicyHistoryError>;
}
