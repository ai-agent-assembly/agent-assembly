//! Integration tests for the two-level settings merge precedence rules.
//!
//! Each test uses `tempfile::TempDir` to construct an isolated `$HOME` and
//! project directory, and `std::env::set_current_dir` to drive which scope
//! the `DefaultSettingsPathResolver` selects.
//!
//! **Process-isolation requirement:** `set_current_dir` is process-global
//! state. These tests are safe when run with `cargo nextest`, which runs each
//! test in its own process. Running with plain `cargo test --test
//! settings_merge` is also safe because each integration-test binary gets its
//! own process, but the five tests within that binary share a process and must
//! not run concurrently — pass `-- --test-threads=1` if not using nextest.

use aa_core::DevToolAdapter;
use aa_devtool_claude_code::ClaudeCodeAdapter;

fn full_settings(permission_mode: &str) -> String {
    serde_json::json!({
        "permissions": { "allow": [], "deny": [] },
        "permissionMode": permission_mode,
        "enabledMcpjsonServers": [],
        "disabledMcpjsonServers": [],
    })
    .to_string()
}

fn read_json(path: &std::path::Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

// ── Test 1 ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn global_only_writes_to_global_path() {
    let home = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap(); // no .claude/ subdir — triggers global scope
    std::env::set_current_dir(other.path()).unwrap();

    let adapter = ClaudeCodeAdapter::with_overrides(None, Some(home.path().to_path_buf()));
    adapter.apply_settings(&full_settings("default")).await.unwrap();

    assert!(home.path().join(".claude").join("settings.json").exists());
    assert!(!other.path().join(".claude").join("settings.json").exists());
}

// ── Test 2 ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn project_present_writes_to_project_path() {
    let home = tempfile::tempdir().unwrap();
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".claude")).unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let adapter = ClaudeCodeAdapter::with_overrides(None, Some(home.path().to_path_buf()));
    adapter.apply_settings(&full_settings("default")).await.unwrap();

    assert!(project.path().join(".claude").join("settings.json").exists());
    // Global directory must not have been created at all.
    assert!(!home.path().join(".claude").exists());
}

// ── Test 3 ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn project_settings_override_global_at_runtime() {
    let home = tempfile::tempdir().unwrap();
    let global_dir = home.path().join(".claude");
    std::fs::create_dir_all(&global_dir).unwrap();
    std::fs::write(
        global_dir.join("settings.json"),
        r#"{"permissionMode":"plan","theme":"dark"}"#,
    )
    .unwrap();

    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".claude")).unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let adapter = ClaudeCodeAdapter::with_overrides(None, Some(home.path().to_path_buf()));
    adapter.apply_settings(&full_settings("default")).await.unwrap();

    // Project file receives the applied permissionMode.
    let project_v = read_json(&project.path().join(".claude").join("settings.json"));
    assert_eq!(project_v["permissionMode"], "default");

    // Global file is completely untouched.
    let global_v = read_json(&global_dir.join("settings.json"));
    assert_eq!(global_v["permissionMode"], "plan");
    assert_eq!(global_v["theme"], "dark");
}

// ── Test 4 ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn merge_preserves_user_keys_at_both_levels() {
    let home = tempfile::tempdir().unwrap();
    let global_dir = home.path().join(".claude");
    std::fs::create_dir_all(&global_dir).unwrap();
    std::fs::write(
        global_dir.join("settings.json"),
        r#"{"theme":"dark","permissionMode":"plan"}"#,
    )
    .unwrap();

    let project = tempfile::tempdir().unwrap();
    let project_dot_claude = project.path().join(".claude");
    std::fs::create_dir(&project_dot_claude).unwrap();
    std::fs::write(
        project_dot_claude.join("settings.json"),
        r#"{"language":"rust","permissionMode":"plan"}"#,
    )
    .unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let adapter = ClaudeCodeAdapter::with_overrides(None, Some(home.path().to_path_buf()));
    adapter.apply_settings(&full_settings("default")).await.unwrap();

    // Project user key survives the merge.
    let project_v = read_json(&project_dot_claude.join("settings.json"));
    assert_eq!(project_v["language"], "rust");
    assert_eq!(project_v["permissionMode"], "default");

    // Global file is untouched — its user key is also preserved.
    let global_v = read_json(&global_dir.join("settings.json"));
    assert_eq!(global_v["theme"], "dark");
    assert_eq!(global_v["permissionMode"], "plan");
}

// ── Test 5 ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn mcp_governance_only_touches_active_scope() {
    let home = tempfile::tempdir().unwrap();
    let global_dir = home.path().join(".claude");
    std::fs::create_dir_all(&global_dir).unwrap();
    std::fs::write(global_dir.join("settings.json"), r#"{"theme":"dark"}"#).unwrap();

    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir(project.path().join(".claude")).unwrap();
    std::env::set_current_dir(project.path()).unwrap();

    let adapter = ClaudeCodeAdapter::with_overrides(None, Some(home.path().to_path_buf()));
    adapter
        .apply_mcp_governance(&["filesystem".to_string()], &["search".to_string()])
        .await
        .unwrap();

    // Project file has the MCP governance lists.
    let project_v = read_json(&project.path().join(".claude").join("settings.json"));
    assert_eq!(project_v["enabledMcpjsonServers"], serde_json::json!(["filesystem"]));
    assert_eq!(project_v["disabledMcpjsonServers"], serde_json::json!(["search"]));

    // Global file is unchanged — no MCP keys added.
    let global_v = read_json(&global_dir.join("settings.json"));
    assert_eq!(global_v["theme"], "dark");
    assert!(global_v.get("enabledMcpjsonServers").is_none());
}
