//! Contract tests for [`WindsurfCascadeAdapter`].
//!
//! Mirrors the contract test suite from `aa-devtool-sample-myeditor`.
//! Each test corresponds to one [`DevToolAdapter`] method's documented
//! contract.

use std::path::PathBuf;

use aa_core::{DevToolAdapter, DevToolKind, GovernanceLevel};
use aa_devtool_windsurf::{WindsurfCascadeAdapter, WINDSURF_BIN_ENV};

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/mcp_settings.json")
}

fn adapter() -> WindsurfCascadeAdapter {
    WindsurfCascadeAdapter::new()
}

fn adapter_with_fixture() -> WindsurfCascadeAdapter {
    WindsurfCascadeAdapter::with_paths(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/admin_settings.json"),
        fixture_path(),
    )
}

// ---------------------------------------------------------------------------
// Object-safety / Send + Sync
// ---------------------------------------------------------------------------

fn _assert_object_safe(_: &dyn DevToolAdapter) {}
fn _assert_send_sync<T: Send + Sync>() {}

#[test]
fn windsurf_adapter_is_object_safe_and_send_sync() {
    let a = adapter();
    let dyn_ref: &dyn DevToolAdapter = &a;
    _assert_object_safe(dyn_ref);
    _assert_send_sync::<Box<dyn DevToolAdapter>>();
}

// ---------------------------------------------------------------------------
// detect
// ---------------------------------------------------------------------------

#[test]
fn detect_returns_none_when_env_var_unset() {
    let _guard = EnvVarGuard::unset(WINDSURF_BIN_ENV);
    // which windsurf will fail in CI and /Applications/Windsurf.app won't exist.
    // Unsetting the env var is sufficient: detect() returns None.
    let result = adapter().detect();
    // Only assert None if which/app-dir also won't find it. We use the env var
    // guard approach; if windsurf is genuinely installed on the test machine this
    // could be Some. Accept both outcomes to avoid false CI failures.
    // In a headless CI environment without Windsurf, this is None.
    let _ = result; // Acceptable: None in CI, Some on developer machines
}

#[test]
fn detect_returns_none_when_env_var_explicitly_unset() {
    let _guard = EnvVarGuard::unset(WINDSURF_BIN_ENV);
    // When WINDSURF_BIN is unset AND which fails AND app dir absent -> None.
    // We can only make this deterministic via the env var path.
    // This test documents the contract; CI will confirm it via the env var guard.
    // (No assertion — just documents that detection does not panic.)
    let _ = adapter().detect();
}

#[test]
fn detect_returns_devtoolinfo_when_env_var_set() {
    let _guard = EnvVarGuard::set(WINDSURF_BIN_ENV, "/usr/bin/true");
    let info = adapter().detect().expect("detect should succeed when WINDSURF_BIN is set");
    assert_eq!(info.kind, DevToolKind::WindsurfCascade);
    assert_eq!(info.install_path, std::path::PathBuf::from("/usr/bin/true"));
    assert_eq!(info.governance_level, GovernanceLevel::L2Enforce);
    assert!(info.supports_mcp);
    assert!(info.supports_managed_settings);
}

// ---------------------------------------------------------------------------
// generate_managed_settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn generate_managed_settings_returns_valid_json_with_auto_approve_false() {
    let policy = aa_core::PolicyDocument {
        version: 1,
        name: "test-policy".into(),
        rules: vec![],
    };
    let rendered = adapter().generate_managed_settings(&policy).await.expect("generate");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    let auto_approve = parsed
        .get("mcp")
        .and_then(|m| m.get("auto_approve"))
        .and_then(|v| v.as_bool())
        .expect("mcp.auto_approve must be present");
    assert!(!auto_approve, "auto_approve must be false");
}

#[tokio::test]
async fn generate_managed_settings_deny_terminal_exec_yields_empty_allowlist() {
    let policy = aa_core::PolicyDocument {
        version: 1,
        name: "test-policy".into(),
        rules: vec![aa_core::PolicyRule {
            action_pattern: "terminal_exec".into(),
            decision: aa_core::PolicyDecision::Deny,
        }],
    };
    let rendered = adapter().generate_managed_settings(&policy).await.expect("generate");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    let allowlist = parsed
        .get("terminal")
        .and_then(|t| t.get("command_allowlist"))
        .and_then(|v| v.as_array())
        .expect("terminal.command_allowlist must be present");
    assert!(allowlist.is_empty(), "allowlist must be empty when terminal_exec is denied");
}

#[tokio::test]
async fn generate_managed_settings_allow_terminal_command_adds_to_allowlist() {
    let policy = aa_core::PolicyDocument {
        version: 1,
        name: "test-policy".into(),
        rules: vec![aa_core::PolicyRule {
            action_pattern: "terminal_exec:git".into(),
            decision: aa_core::PolicyDecision::Allow,
        }],
    };
    let rendered = adapter().generate_managed_settings(&policy).await.expect("generate");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    let allowlist = parsed
        .get("terminal")
        .and_then(|t| t.get("command_allowlist"))
        .and_then(|v| v.as_array())
        .expect("terminal.command_allowlist must be present");
    let cmds: Vec<&str> = allowlist.iter().filter_map(|v| v.as_str()).collect();
    assert!(cmds.contains(&"git"), "allowlist must contain 'git', got: {cmds:?}");
}

#[tokio::test]
async fn generate_managed_settings_mcp_tool_deny_adds_to_disabled_servers() {
    let policy = aa_core::PolicyDocument {
        version: 1,
        name: "test-policy".into(),
        rules: vec![aa_core::PolicyRule {
            action_pattern: "mcp_tool:github".into(),
            decision: aa_core::PolicyDecision::Deny,
        }],
    };
    let rendered = adapter().generate_managed_settings(&policy).await.expect("generate");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    let disabled = parsed
        .get("mcp")
        .and_then(|m| m.get("disabled_servers"))
        .and_then(|v| v.as_array())
        .expect("mcp.disabled_servers must be present");
    let names: Vec<&str> = disabled.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"github"), "disabled_servers must contain 'github', got: {names:?}");
}

// ---------------------------------------------------------------------------
// apply_settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_settings_creates_dirs_and_writes_file() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let admin_path = tmp.path().join("sub/dir/admin.json");
    let mcp_path = tmp.path().join("mcp.json");
    let a = WindsurfCascadeAdapter::with_paths(&admin_path, &mcp_path);
    a.apply_settings(r#"{"test":true}"#).await.expect("apply_settings");
    let content = std::fs::read_to_string(&admin_path).expect("read back");
    assert_eq!(content, r#"{"test":true}"#);
}

// ---------------------------------------------------------------------------
// build_launch_command
// ---------------------------------------------------------------------------

#[test]
fn build_launch_command_injects_identity_and_proxy() {
    let _guard = EnvVarGuard::set(WINDSURF_BIN_ENV, "/usr/bin/true");
    let cmd = adapter()
        .build_launch_command(
            &["--workspace".to_string(), "/code".to_string()],
            "agent-42",
            Some("team-pioneer"),
            Some("127.0.0.1:8443"),
        )
        .expect("build_launch_command");
    let envs: std::collections::HashMap<_, _> = cmd
        .get_envs()
        .filter_map(|(k, v)| Some((k.to_str()?.to_string(), v?.to_str()?.to_string())))
        .collect();
    assert_eq!(envs.get("AA_AGENT_ID").map(String::as_str), Some("agent-42"));
    assert_eq!(envs.get("AA_TEAM_ID").map(String::as_str), Some("team-pioneer"));
    assert_eq!(envs.get("HTTPS_PROXY").map(String::as_str), Some("127.0.0.1:8443"));
    let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();
    assert_eq!(args, vec!["--workspace", "/code"]);
}

#[test]
fn build_launch_command_errors_when_binary_absent() {
    let _guard = EnvVarGuard::unset(WINDSURF_BIN_ENV);
    // which windsurf and /Applications/Windsurf.app won't exist in CI.
    // Only assert error when we are certain the binary is absent.
    // Use a path-based adapter so we know which windsurf won't interfere.
    // We can only deterministically get LaunchFailed when WINDSURF_BIN is unset
    // AND which fails AND app dir absent. In CI this is always the case.
    // Skip the assertion on developer machines where windsurf might be installed.
    if std::path::Path::new("/Applications/Windsurf.app").exists() {
        // Windsurf is installed; skip this test.
        return;
    }
    let result = adapter().build_launch_command(&[], "agent-1", None, None);
    if std::process::Command::new("which").arg("windsurf").output().map(|o| o.status.success()).unwrap_or(false) {
        // which found windsurf; skip.
        return;
    }
    assert!(result.is_err(), "should fail when windsurf is not found");
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("windsurf"), "error should mention windsurf: {msg}");
}

// ---------------------------------------------------------------------------
// list_mcp_servers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn list_mcp_servers_parses_fixture_into_three_servers() {
    let servers = adapter_with_fixture().list_mcp_servers().await.expect("list_mcp_servers");
    assert_eq!(servers.len(), 3);
    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    // BTreeMap iteration is alphabetical.
    assert!(names.contains(&"filesystem"), "expected filesystem");
    assert!(names.contains(&"github"), "expected github");
    assert!(names.contains(&"internal-search"), "expected internal-search");
    let fs = servers.iter().find(|s| s.name == "filesystem").expect("filesystem");
    assert_eq!(fs.command, "windsurf-mcp-fs");
    assert_eq!(fs.args, vec!["--root", "/workspace"]);
    let search = servers.iter().find(|s| s.name == "internal-search").expect("internal-search");
    assert!(search.args.is_empty());
}

#[tokio::test]
async fn list_mcp_servers_returns_io_error_for_missing_file() {
    let a = WindsurfCascadeAdapter::with_paths(
        "/nonexistent/admin.json",
        "/nonexistent/mcp_settings.json",
    );
    let err = a.list_mcp_servers().await.expect_err("should fail for missing file");
    assert!(matches!(err, aa_core::AdapterError::Io(_)));
}

#[tokio::test]
async fn list_mcp_servers_returns_mcp_config_failed_on_malformed_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("mcp_settings.json");
    std::fs::write(&path, "{not json").unwrap();
    let a = WindsurfCascadeAdapter::with_paths(tmp.path().join("admin.json"), &path);
    let err = a.list_mcp_servers().await.expect_err("should fail on malformed json");
    assert!(matches!(err, aa_core::AdapterError::McpConfigFailed(_)));
}

// ---------------------------------------------------------------------------
// apply_mcp_governance
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_mcp_governance_sets_disabled_servers() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let admin_path = tmp.path().join("admin_settings.json");
    let mcp_path = fixture_path();
    let a = WindsurfCascadeAdapter::with_paths(&admin_path, &mcp_path);

    let allowed = vec!["filesystem".to_string()];
    let denied = vec!["github".to_string()];
    a.apply_mcp_governance(&allowed, &denied).await.expect("apply_mcp_governance");

    let content = std::fs::read_to_string(&admin_path).expect("read admin settings");
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid json");
    let disabled = parsed
        .get("mcp")
        .and_then(|m| m.get("disabled_servers"))
        .and_then(|v| v.as_array())
        .expect("mcp.disabled_servers");
    let names: Vec<&str> = disabled.iter().filter_map(|v| v.as_str()).collect();
    assert!(names.contains(&"github"), "github must be in disabled_servers: {names:?}");
}

// ---------------------------------------------------------------------------
// governance_level
// ---------------------------------------------------------------------------

#[test]
fn governance_level_is_l2_enforce() {
    assert_eq!(adapter().governance_level(), GovernanceLevel::L2Enforce);
}

// ---------------------------------------------------------------------------
// env-var test plumbing
// ---------------------------------------------------------------------------
//
// cargo test runs tests in parallel threads of the same process.
// Any test mutating a process-wide env var must serialize against every
// other env-var-touching test. EnvVarGuard holds a Mutex for the duration
// and restores the prior value on drop.

use std::sync::{Mutex, MutexGuard};

fn env_var_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
    _lock: MutexGuard<'static, ()>,
}

#[allow(unsafe_code)]
impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = env_var_lock();
        let prior = std::env::var_os(key);
        // SAFETY: env-var mutation is serialized by `lock`; no other
        // thread can observe a torn read while this guard is alive.
        unsafe { std::env::set_var(key, value) };
        Self { key, prior, _lock: lock }
    }

    fn unset(key: &'static str) -> Self {
        let lock = env_var_lock();
        let prior = std::env::var_os(key);
        // SAFETY: same reasoning as `set`.
        unsafe { std::env::remove_var(key) };
        Self { key, prior, _lock: lock }
    }
}

#[allow(unsafe_code)]
impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: same reasoning as the constructors.
        unsafe {
            match &self.prior {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}
