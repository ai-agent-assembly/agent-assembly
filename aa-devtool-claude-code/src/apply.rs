use std::path::{Path, PathBuf};

use aa_core::AdapterError;

/// Injectable path resolver for the settings file location.
///
/// The production implementation prefers `<cwd>/.claude/settings.json` when
/// a `.claude/` directory exists in the current working directory, and falls
/// back to `~/.claude/settings.json`. Tests inject a stub that returns a
/// fixed path inside a [`tempfile::TempDir`] so no real home directory or
/// working directory is touched.
pub(crate) trait SettingsPathResolver: Send + Sync {
    fn resolve(&self) -> Result<PathBuf, AdapterError>;
}

/// Production [`SettingsPathResolver`].
pub(crate) struct DefaultSettingsPathResolver {
    pub home_dir: Option<PathBuf>,
}

impl SettingsPathResolver for DefaultSettingsPathResolver {
    fn resolve(&self) -> Result<PathBuf, AdapterError> {
        // Prefer project-scoped settings when invoked from inside a project.
        if let Ok(cwd) = std::env::current_dir() {
            let dot_claude = cwd.join(".claude");
            if dot_claude.is_dir() {
                return Ok(dot_claude.join("settings.json"));
            }
        }
        // Fall back to the global ~/.claude/settings.json.
        let home = self
            .home_dir
            .clone()
            .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
            .ok_or_else(|| {
                AdapterError::SettingsApplyFailed(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "cannot determine home directory",
                ))
            })?;
        Ok(home.join(".claude").join("settings.json"))
    }
}

/// The four keys in `settings.json` that are owned by Agent Assembly.
/// All other keys found in an existing file are preserved unchanged.
const MANAGED_KEYS: &[&str] = &[
    "permissions",
    "permissionMode",
    "enabledMcpjsonServers",
    "disabledMcpjsonServers",
];

/// Write `settings_json` to `path`, merging AA-managed keys on top of any
/// existing content and preserving all other keys.
///
/// The write is atomic: content is written to a sibling `.tmp` file then
/// renamed into place so a mid-write failure never corrupts the original.
pub(crate) fn apply_settings_at(path: &Path, settings_json: &str) -> Result<(), AdapterError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(AdapterError::SettingsApplyFailed)?;
    }

    // Load existing content (if any) as a JSON object to preserve unmanaged keys.
    let mut base: serde_json::Value = if path.exists() {
        let raw = std::fs::read_to_string(path).map_err(AdapterError::SettingsApplyFailed)?;
        serde_json::from_str(&raw).unwrap_or(serde_json::Value::Object(Default::default()))
    } else {
        serde_json::Value::Object(Default::default())
    };

    // Parse the incoming AA-managed settings.
    let incoming: serde_json::Value =
        serde_json::from_str(settings_json).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))?;

    // Splice only the managed keys from incoming into the base object.
    if let (Some(base_obj), Some(inc_obj)) = (base.as_object_mut(), incoming.as_object()) {
        for &key in MANAGED_KEYS {
            if let Some(val) = inc_obj.get(key) {
                base_obj.insert(key.to_string(), val.clone());
            }
        }
    }

    let serialized =
        serde_json::to_string_pretty(&base).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))?;

    // Atomic write: write to sibling .tmp then rename.
    let tmp_path = path.with_file_name(format!(
        "{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    std::fs::write(&tmp_path, &serialized).map_err(AdapterError::SettingsApplyFailed)?;
    std::fs::rename(&tmp_path, path).map_err(AdapterError::SettingsApplyFailed)?;

    Ok(())
}

/// Update only the MCP server allow/deny lists in `settings.json` at `path`.
///
/// Replaces `enabledMcpjsonServers` and `disabledMcpjsonServers` with the
/// supplied slices. All other keys in the existing file are preserved.
/// Idempotent: running twice with the same arguments produces the same file.
pub(crate) fn apply_mcp_governance_at(path: &Path, allowed: &[String], denied: &[String]) -> Result<(), AdapterError> {
    let mcp_json = serde_json::json!({
        "enabledMcpjsonServers": allowed,
        "disabledMcpjsonServers": denied,
    });
    let json_str =
        serde_json::to_string_pretty(&mcp_json).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))?;
    apply_settings_at(path, &json_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_settings_creates_file_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let settings = r#"{
            "permissions": {"allow": ["Bash"], "deny": []},
            "permissionMode": "acceptEdits",
            "enabledMcpjsonServers": [],
            "disabledMcpjsonServers": []
        }"#;
        apply_settings_at(&path, settings).unwrap();
        assert!(path.exists());
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["permissionMode"], "acceptEdits");
        assert_eq!(v["permissions"]["allow"][0], "Bash");
    }

    #[test]
    fn apply_settings_preserves_unmanaged_keys() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme": "dark", "version": "1.0"}"#).unwrap();
        let settings = r#"{
            "permissions": {"allow": [], "deny": []},
            "permissionMode": "default",
            "enabledMcpjsonServers": [],
            "disabledMcpjsonServers": []
        }"#;
        apply_settings_at(&path, settings).unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["theme"], "dark");
        assert_eq!(v["version"], "1.0");
        assert_eq!(v["permissionMode"], "default");
    }

    #[cfg(unix)]
    #[test]
    fn apply_settings_atomic_on_failure() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(&path, r#"{"theme": "dark"}"#).unwrap();
        // Make the directory read-only so the .tmp file cannot be created.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();
        let settings = r#"{"permissionMode": "default", "permissions": {"allow": [], "deny": []}, "enabledMcpjsonServers": [], "disabledMcpjsonServers": []}"#;
        let result = apply_settings_at(&path, settings);
        // Restore permissions so TempDir cleanup succeeds.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(result.is_err());
        // Original file must be unchanged.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("dark"));
    }

    #[test]
    fn apply_mcp_governance_replaces_lists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        std::fs::write(
            &path,
            r#"{"theme": "dark", "enabledMcpjsonServers": ["old"], "disabledMcpjsonServers": ["gone"]}"#,
        )
        .unwrap();
        apply_mcp_governance_at(&path, &["filesystem".to_string()], &["search".to_string()]).unwrap();
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(v["enabledMcpjsonServers"], serde_json::json!(["filesystem"]));
        assert_eq!(v["disabledMcpjsonServers"], serde_json::json!(["search"]));
        assert_eq!(v["theme"], "dark");
    }
}
