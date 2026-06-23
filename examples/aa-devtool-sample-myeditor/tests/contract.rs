//! Contract tests for the [`MyEditorAdapter`] sample.
//!
//! These tests double as the **reference contract suite** plugin
//! authors should mirror in their own out-of-tree adapter crates: each
//! test corresponds to one [`DevToolAdapter`] method's documented
//! contract from the [`DevToolAdapter`] rustdoc (re-exported via the
//! `aa-devtool-contract` capability facade). When the
//! workspace later grows a shared `aa-devtool-contract-tests` crate
//! (currently out of scope; see `docs/devtools/plugins.md` "What's not
//! yet in scope"), this file moves there and gets imported by every
//! adapter crate.
//!
//! [`DevToolAdapter`]: aa_devtool_contract::DevToolAdapter
//! [`MyEditorAdapter`]: aa_devtool_sample_myeditor::MyEditorAdapter

use std::path::PathBuf;

use aa_devtool_contract::{DevToolAdapter, DevToolKind, GovernanceLevel};
use aa_devtool_sample_myeditor::{MyEditorAdapter, MYEDITOR_BIN_ENV, MYEDITOR_KIND_ID};

/// Path to the in-repo MCP fixture, computed at compile time so tests
/// don't depend on the working directory cargo invokes them from.
fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fixtures/mcp_servers.json")
}

fn adapter() -> MyEditorAdapter {
    MyEditorAdapter::new(fixture_path())
}

// --- Object-safety / Send + Sync (mirrors the contract's trait_is_object_safe) --

fn _assert_object_safe(_: &dyn DevToolAdapter) {}
fn _assert_send_sync<T: Send + Sync>() {}

#[test]
fn myeditor_adapter_is_object_safe_and_send_sync() {
    // Compile-time check: if `MyEditorAdapter` were not object-safe via
    // the trait, the cast below would fail. If the trait were not
    // `Send + Sync`, the boxed assertion would fail.
    let a = adapter();
    let dyn_ref: &dyn DevToolAdapter = &a;
    _assert_object_safe(dyn_ref);
    _assert_send_sync::<Box<dyn DevToolAdapter>>();
}

// --- detect ----------------------------------------------------------------

#[test]
fn detect_returns_none_when_env_var_unset() {
    // Use a scoped lock to avoid clobbering parallel tests that read the
    // env var. cargo test runs tests in threads of the same process by
    // default, so we mutate env carefully.
    let _guard = EnvVarGuard::unset(MYEDITOR_BIN_ENV);
    assert!(adapter().detect().is_none());
}

#[test]
fn detect_returns_devtoolinfo_when_env_var_set() {
    let _guard = EnvVarGuard::set(MYEDITOR_BIN_ENV, "/usr/local/bin/myeditor");
    let info = adapter().detect().expect("detect");
    assert_eq!(info.kind, DevToolKind::Custom(MYEDITOR_KIND_ID.to_string()));
    assert_eq!(info.install_path.to_str(), Some("/usr/local/bin/myeditor"));
    assert_eq!(info.governance_level, GovernanceLevel::L1Observe);
    assert!(info.supports_mcp);
    assert!(info.supports_managed_settings);
    assert_eq!(info.version.as_deref(), Some("0.0.0-sample"));
}

// --- generate_managed_settings + apply_settings ---------------------------

#[tokio::test]
async fn generate_managed_settings_returns_valid_json() {
    let policy = aa_devtool_contract::PolicyDocument {
        version: 1,
        name: "sample-test-policy".into(),
        rules: vec![],
        enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
    };
    let rendered = adapter().generate_managed_settings(&policy).await.expect("generate");
    let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid json");
    assert!(parsed.get("generated_by").is_some());
    assert!(parsed.get("mcp_allow").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn apply_settings_writes_managed_json_next_to_fixture() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let mcp_path = tmp.path().join("mcp_servers.json");
    std::fs::write(&mcp_path, "{\"mcpServers\":{}}").unwrap();
    let a = MyEditorAdapter::new(&mcp_path);
    a.apply_settings("hello").await.expect("apply");
    let written = std::fs::read_to_string(tmp.path().join("managed.json")).expect("read");
    assert_eq!(written, "hello");
}

// --- build_launch_command -------------------------------------------------

#[test]
fn build_launch_command_injects_identity_and_proxy() {
    let _guard = EnvVarGuard::set(MYEDITOR_BIN_ENV, "/usr/local/bin/myeditor");
    let cmd = adapter()
        .build_launch_command(
            &["--workspace".to_string(), "/code".to_string()],
            "agent-42",
            Some("team-pioneer"),
            Some("127.0.0.1:8443"),
        )
        .expect("build");
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
fn build_launch_command_errors_when_binary_unset() {
    let _guard = EnvVarGuard::unset(MYEDITOR_BIN_ENV);
    let err = adapter()
        .build_launch_command(&[], "agent-1", None, None)
        .expect_err("should fail");
    let msg = err.to_string();
    assert!(msg.contains("MYEDITOR_BIN"), "unexpected error: {msg}");
}

// --- list_mcp_servers -----------------------------------------------------

#[tokio::test]
async fn list_mcp_servers_parses_fixture_into_three_servers() {
    let servers = adapter().list_mcp_servers().await.expect("list");
    let names: Vec<&str> = servers.iter().map(|s| s.name.as_str()).collect();
    assert_eq!(names, vec!["filesystem", "github", "internal-search"]);
    let filesystem = &servers[0];
    assert_eq!(filesystem.command, "myeditor-mcp-fs");
    assert_eq!(filesystem.args, vec!["--root", "/workspace"]);
    let internal_search = &servers[2];
    assert!(internal_search.args.is_empty());
}

#[tokio::test]
async fn list_mcp_servers_returns_io_error_for_missing_fixture() {
    let a = MyEditorAdapter::new("/nonexistent/path/mcp_servers.json");
    let err = a.list_mcp_servers().await.expect_err("should fail");
    // The Io variant carries the underlying NotFound — its Display
    // message is the OS-level "No such file or directory" string.
    assert!(matches!(err, aa_devtool_contract::AdapterError::Io(_)));
}

#[tokio::test]
async fn list_mcp_servers_returns_mcp_config_failed_on_malformed_json() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("mcp_servers.json");
    std::fs::write(&path, "{not json").unwrap();
    let err = MyEditorAdapter::new(&path)
        .list_mcp_servers()
        .await
        .expect_err("should fail");
    assert!(matches!(err, aa_devtool_contract::AdapterError::McpConfigFailed(_)));
}

// --- apply_mcp_governance + governance_level ------------------------------

#[tokio::test]
async fn apply_mcp_governance_is_a_noop_in_sample() {
    let allow: Vec<String> = vec!["filesystem".into()];
    let deny: Vec<String> = vec!["github".into()];
    adapter().apply_mcp_governance(&allow, &deny).await.expect("noop ok");
}

#[test]
fn governance_level_is_l1_observe() {
    assert_eq!(adapter().governance_level(), GovernanceLevel::L1Observe);
}

// --- env-var test plumbing -------------------------------------------------
//
// `cargo test` runs tests in parallel threads of the same process, so
// any test that mutates a process-wide env var must serialize against
// every other env-var-touching test. `EnvVarGuard` does two things:
//
// 1. Holds a process-wide `Mutex` for the duration of the test, so
//    parallel env-var-touching tests can never interleave.
// 2. Saves the prior value on construction and restores on drop, so
//    a single test's mutation does not leak into the next test that
//    happens to grab the lock.

use std::sync::{Mutex, MutexGuard};

fn env_var_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    // PoisonError carries the inner guard; tests that panic while
    // holding the lock should still let later tests proceed rather
    // than cascade-failing on poison.
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

struct EnvVarGuard {
    key: &'static str,
    prior: Option<std::ffi::OsString>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = env_var_lock();
        let prior = std::env::var_os(key);
        // SAFETY: env-var mutation is serialized by `lock`; no other
        // thread can observe a torn read while this guard is alive.
        unsafe { std::env::set_var(key, value) };
        Self {
            key,
            prior,
            _lock: lock,
        }
    }

    fn unset(key: &'static str) -> Self {
        let lock = env_var_lock();
        let prior = std::env::var_os(key);
        // SAFETY: same reasoning as `set`.
        unsafe { std::env::remove_var(key) };
        Self {
            key,
            prior,
            _lock: lock,
        }
    }
}

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
