//! Filesystem-backed implementation of [`PolicyHistoryStore`].

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use super::config::HistoryConfig;
use super::error::PolicyHistoryError;
use super::meta::PolicyVersionMeta;
use super::snapshot::PolicySnapshot;
use super::store::PolicyHistoryStore;

/// Filesystem-backed policy version history store.
///
/// Stores versioned YAML snapshots and JSON metadata sidecars in a configurable
/// directory (default `~/.aa/policy-history/`).
pub struct FsHistoryStore {
    config: HistoryConfig,
}

impl FsHistoryStore {
    /// Create a new store with the given configuration.
    pub fn new(config: HistoryConfig) -> Self {
        Self { config }
    }

    /// Create a store using the default configuration.
    pub fn with_defaults() -> Self {
        Self::new(HistoryConfig::default_config())
    }

    /// Ensure the history directory exists.
    fn ensure_dir(&self) -> Result<(), PolicyHistoryError> {
        std::fs::create_dir_all(&self.config.history_dir)?;
        Ok(())
    }

    /// Compute the SHA-256 hex digest of content.
    fn sha256_hex(content: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(content.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Build the filename stem: `<timestamp>-<sha256_prefix>`.
    fn version_stem(timestamp: &str, sha256: &str) -> String {
        // Use first 12 hex chars of sha256 as the prefix
        let prefix = &sha256[..sha256.len().min(12)];
        // Replace colons and dots in timestamp for filesystem compatibility
        let safe_ts = timestamp.replace([':', '.'], "");
        format!("{}-{}", safe_ts, prefix)
    }

    /// Path to the YAML snapshot file.
    fn yaml_path(&self, stem: &str) -> PathBuf {
        self.config.history_dir.join(format!("{}.yaml", stem))
    }

    /// Path to the JSON metadata sidecar file.
    fn meta_path(&self, stem: &str) -> PathBuf {
        self.config.history_dir.join(format!("{}.meta.json", stem))
    }

    /// Write a snapshot (YAML + metadata sidecar) to disk.
    fn write_snapshot(&self, yaml: &str, meta: &PolicyVersionMeta) -> Result<(), PolicyHistoryError> {
        let stem = Self::version_stem(&meta.timestamp, &meta.sha256);
        let yaml_path = self.yaml_path(&stem);
        let meta_path = self.meta_path(&stem);

        std::fs::write(&yaml_path, yaml)?;
        let meta_json = serde_json::to_string_pretty(meta)?;
        std::fs::write(&meta_path, meta_json)?;

        Ok(())
    }

    /// List all `.meta.json` files in the history directory, sorted newest first.
    fn list_meta_files(&self) -> Result<Vec<PathBuf>, PolicyHistoryError> {
        if !self.config.history_dir.exists() {
            return Ok(Vec::new());
        }

        let mut entries: Vec<PathBuf> = std::fs::read_dir(&self.config.history_dir)?
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "json") && p.to_string_lossy().ends_with(".meta.json"))
            .collect();

        // Sort by filename descending (newest first since filenames start with timestamp)
        entries.sort_by(|a, b| b.file_name().cmp(&a.file_name()));
        Ok(entries)
    }

    /// Read a `PolicyVersionMeta` from a `.meta.json` file.
    fn read_meta(path: &Path) -> Result<PolicyVersionMeta, PolicyHistoryError> {
        let content = std::fs::read_to_string(path)?;
        let meta: PolicyVersionMeta = serde_json::from_str(&content)?;
        Ok(meta)
    }

    /// Find the meta file path for a given version id (sha256 prefix match).
    fn find_version_path(&self, version_id: &str) -> Result<PathBuf, PolicyHistoryError> {
        let meta_files = self.list_meta_files()?;
        for path in meta_files {
            let meta = Self::read_meta(&path)?;
            if meta.sha256.starts_with(version_id) || version_id.starts_with(&meta.sha256[..meta.sha256.len().min(12)])
            {
                return Ok(path);
            }
        }
        Err(PolicyHistoryError::VersionNotFound(version_id.to_string()))
    }

    /// Derive the YAML path from a `.meta.json` path.
    fn yaml_path_from_meta(meta_path: &Path) -> PathBuf {
        let stem = meta_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .replace(".meta.json", "");
        meta_path.with_file_name(format!("{}.yaml", stem))
    }

    /// Generate an ISO 8601 UTC timestamp string with millisecond precision.
    fn now_timestamp() -> String {
        chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
    }
}

#[async_trait]
impl PolicyHistoryStore for FsHistoryStore {
    async fn save(&self, yaml: &str, applied_by: Option<&str>) -> Result<PolicyVersionMeta, PolicyHistoryError> {
        self.ensure_dir()?;

        let sha256 = Self::sha256_hex(yaml);
        let timestamp = Self::now_timestamp();

        let meta = PolicyVersionMeta {
            timestamp,
            sha256,
            applied_by: applied_by.map(|s| s.to_string()),
            source_path: None,
            first_event_covered: None,
            is_rollback: false,
            rollback_target: None,
        };

        self.write_snapshot(yaml, &meta)?;

        // Auto-prune after save
        self.prune().await?;

        Ok(meta)
    }

    async fn list(&self, limit: usize) -> Result<Vec<PolicyVersionMeta>, PolicyHistoryError> {
        let meta_files = self.list_meta_files()?;
        let mut metas = Vec::new();

        for path in meta_files.into_iter().take(limit) {
            metas.push(Self::read_meta(&path)?);
        }

        Ok(metas)
    }

    async fn get(&self, version_id: &str) -> Result<PolicySnapshot, PolicyHistoryError> {
        let meta_path = self.find_version_path(version_id)?;
        let meta = Self::read_meta(&meta_path)?;
        let yaml_path = Self::yaml_path_from_meta(&meta_path);

        if !yaml_path.exists() {
            return Err(PolicyHistoryError::CorruptedMetadata(format!(
                "YAML file missing for version {}",
                version_id
            )));
        }

        let yaml_content = std::fs::read_to_string(&yaml_path)?;
        Ok(PolicySnapshot { meta, yaml_content })
    }

    async fn rollback(&self, version_id: &str) -> Result<PolicyVersionMeta, PolicyHistoryError> {
        // Read the target version
        let snapshot = self.get(version_id).await?;

        // Create a new history entry marked as a rollback
        self.ensure_dir()?;

        let sha256 = Self::sha256_hex(&snapshot.yaml_content);
        let timestamp = Self::now_timestamp();

        let meta = PolicyVersionMeta {
            timestamp,
            sha256,
            applied_by: None,
            source_path: None,
            first_event_covered: None,
            is_rollback: true,
            rollback_target: Some(snapshot.meta.sha256.clone()),
        };

        self.write_snapshot(&snapshot.yaml_content, &meta)?;

        Ok(meta)
    }

    async fn diff(&self, version_a: &str, version_b: &str) -> Result<String, PolicyHistoryError> {
        let snap_a = self.get(version_a).await?;
        let snap_b = self.get(version_b).await?;

        let diff = similar::TextDiff::from_lines(&snap_a.yaml_content, &snap_b.yaml_content);

        let mut output = String::new();
        output.push_str(&format!("--- {}\n", snap_a.meta.sha256));
        output.push_str(&format!("+++ {}\n", snap_b.meta.sha256));

        for hunk in diff.unified_diff().context_radius(3).iter_hunks() {
            output.push_str(&hunk.to_string());
        }

        Ok(output)
    }

    async fn prune(&self) -> Result<usize, PolicyHistoryError> {
        let meta_files = self.list_meta_files()?;

        if meta_files.len() <= self.config.max_versions {
            return Ok(0);
        }

        let to_remove = &meta_files[self.config.max_versions..];
        let mut removed = 0;

        for meta_path in to_remove {
            let yaml_path = Self::yaml_path_from_meta(meta_path);
            if yaml_path.exists() {
                std::fs::remove_file(&yaml_path)?;
            }
            std::fs::remove_file(meta_path)?;
            removed += 1;
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &Path) -> HistoryConfig {
        HistoryConfig {
            history_dir: dir.to_path_buf(),
            max_versions: 50,
        }
    }

    const POLICY_A: &str = "version: \"1\"\nnetwork:\n  allowlist:\n    - api.openai.com\n";
    const POLICY_B: &str = "version: \"2\"\nnetwork:\n  allowlist:\n    - api.openai.com\n    - slack.com\n";

    #[test]
    fn sha256_hex_is_deterministic() {
        let a = FsHistoryStore::sha256_hex("hello");
        let b = FsHistoryStore::sha256_hex("hello");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn sha256_hex_differs_for_different_input() {
        let a = FsHistoryStore::sha256_hex("hello");
        let b = FsHistoryStore::sha256_hex("world");
        assert_ne!(a, b);
    }

    #[test]
    fn version_stem_format() {
        let stem = FsHistoryStore::version_stem("2026-04-28T12:00:00Z", "abcdef1234567890abcdef");
        assert!(stem.contains("abcdef123456"));
        assert!(!stem.contains(':'));
    }

    #[tokio::test]
    async fn save_creates_yaml_and_meta_files() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let meta = store.save(POLICY_A, Some("alice")).await.unwrap();

        assert!(!meta.sha256.is_empty());
        assert!(meta.applied_by.as_deref() == Some("alice"));
        assert!(!meta.is_rollback);

        // Verify files were created
        let files: Vec<_> = std::fs::read_dir(tmp.path()).unwrap().collect();
        assert_eq!(files.len(), 2); // .yaml + .meta.json
    }

    #[tokio::test]
    async fn list_returns_versions_newest_first() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        store.save(POLICY_A, Some("alice")).await.unwrap();
        // Small delay to ensure different timestamps
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save(POLICY_B, Some("bob")).await.unwrap();

        let list = store.list(10).await.unwrap();
        assert_eq!(list.len(), 2);
        // Newest first
        assert!(list[0].timestamp >= list[1].timestamp);
    }

    #[tokio::test]
    async fn list_respects_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        store.save(POLICY_A, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save(POLICY_B, None).await.unwrap();

        let list = store.list(1).await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn get_returns_snapshot_with_content() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let meta = store.save(POLICY_A, None).await.unwrap();
        let snapshot = store.get(&meta.sha256).await.unwrap();

        assert_eq!(snapshot.yaml_content, POLICY_A);
        assert_eq!(snapshot.meta.sha256, meta.sha256);
    }

    #[tokio::test]
    async fn get_returns_version_not_found_for_unknown_id() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let result = store.get("nonexistent").await;
        assert!(matches!(result, Err(PolicyHistoryError::VersionNotFound(_))));
    }

    #[tokio::test]
    async fn rollback_creates_new_entry_marked_as_rollback() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let original = store.save(POLICY_A, Some("alice")).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save(POLICY_B, Some("bob")).await.unwrap();

        // Rollback to original
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let rollback_meta = store.rollback(&original.sha256).await.unwrap();

        assert!(rollback_meta.is_rollback);
        assert_eq!(rollback_meta.rollback_target.as_deref(), Some(original.sha256.as_str()));

        // Should now have 3 entries
        let list = store.list(10).await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn diff_produces_unified_diff_format() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let meta_a = store.save(POLICY_A, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let meta_b = store.save(POLICY_B, None).await.unwrap();

        let diff_output = store.diff(&meta_a.sha256, &meta_b.sha256).await.unwrap();

        assert!(diff_output.contains("---"));
        assert!(diff_output.contains("+++"));
        assert!(diff_output.contains("@@"));
        assert!(diff_output.contains("slack.com"));
    }

    #[tokio::test]
    async fn prune_removes_oldest_beyond_max() {
        let tmp = tempfile::tempdir().unwrap();
        let config = HistoryConfig {
            history_dir: tmp.path().to_path_buf(),
            max_versions: 2,
        };
        let store = FsHistoryStore::new(config);

        // Create 4 versions
        store.save("v1: true\n", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save("v2: true\n", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save("v3: true\n", None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        store.save("v4: true\n", None).await.unwrap();

        // After save (which auto-prunes), should have max_versions entries
        let list = store.list(10).await.unwrap();
        assert_eq!(list.len(), 2);
    }

    #[tokio::test]
    async fn list_on_empty_dir_returns_empty_vec() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let list = store.list(10).await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn list_on_nonexistent_dir_returns_empty_vec() {
        let config = HistoryConfig {
            history_dir: PathBuf::from("/tmp/nonexistent-aa-test-dir-xyz"),
            max_versions: 50,
        };
        let store = FsHistoryStore::new(config);

        let list = store.list(10).await.unwrap();
        assert!(list.is_empty());
    }

    #[tokio::test]
    async fn save_with_same_content_produces_same_sha256() {
        let tmp = tempfile::tempdir().unwrap();
        let store = FsHistoryStore::new(test_config(tmp.path()));

        let meta1 = store.save(POLICY_A, None).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let meta2 = store.save(POLICY_A, None).await.unwrap();

        assert_eq!(meta1.sha256, meta2.sha256);
        // But timestamps differ
        assert_ne!(meta1.timestamp, meta2.timestamp);
    }
}
