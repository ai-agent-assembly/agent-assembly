//! Integration tests for `CodexAdapter::apply_settings` and
//! `CodexAdapter::build_launch_command` (AAASM-988).
//!
//! These tests use `tempfile::TempDir` for `$HOME` so they never touch
//! the real filesystem. The Codex binary is never spawned — only the
//! prepared `Command` value is inspected.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use aa_core::policy::{PolicyDecision, PolicyDocument, PolicyRule};
use aa_core::{AdapterError, DevToolAdapter};
use aa_devtool_codex::{BinaryLocator, CodexAdapter, VersionProbe};

// ---------------------------------------------------------------------------
// Shared stubs
// ---------------------------------------------------------------------------

struct FixedLocator(PathBuf);

impl BinaryLocator for FixedLocator {
    fn locate_via_path(&self) -> Option<PathBuf> {
        Some(self.0.clone())
    }
    fn locate_via_npm_global(&self) -> Option<PathBuf> {
        None
    }
}

struct FixedProbe;

impl VersionProbe for FixedProbe {
    fn probe_version(&self, _bin: &Path) -> Option<String> {
        Some("0.125.0".into())
    }
}

struct NullLocator;

impl BinaryLocator for NullLocator {
    fn locate_via_path(&self) -> Option<PathBuf> {
        None
    }
    fn locate_via_npm_global(&self) -> Option<PathBuf> {
        None
    }
}

fn fixture_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "test".into(),
        rules: vec![
            PolicyRule {
                action_pattern: "shell:exec".into(),
                decision: PolicyDecision::Deny,
            },
            PolicyRule {
                action_pattern: "network:api.openai.com".into(),
                decision: PolicyDecision::Allow,
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// apply_settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_settings_creates_config_json_with_correct_content() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());

    let settings = adapter.generate_managed_settings(&fixture_policy()).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();

    let config_path = tmp.path().join(".codex").join("config.json");
    assert!(config_path.exists(), "config.json must be created");

    let parsed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();

    assert_eq!(parsed["sandbox_mode"], "ask", "Deny rule → ask sandbox mode");
    let allowed = parsed["allowed_domains"].as_array().unwrap();
    assert!(
        allowed.contains(&serde_json::json!("api.openai.com")),
        "allowed_domains must include api.openai.com"
    );
}

#[tokio::test]
async fn apply_settings_merges_preserving_user_managed_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    // Pre-seed the config with a user-managed key.
    let codex_dir = tmp.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::write(
        codex_dir.join("config.json"),
        r#"{"user_theme": "dark", "sandbox_mode": "stale"}"#,
    )
    .unwrap();

    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());

    // Apply an all-Allow policy — sandbox_mode becomes full-auto.
    let allow_policy = PolicyDocument {
        version: 1,
        name: "allow-all".into(),
        rules: vec![PolicyRule {
            action_pattern: "*".into(),
            decision: PolicyDecision::Allow,
        }],
    };
    let settings = adapter.generate_managed_settings(&allow_policy).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();

    let config_path = codex_dir.join("config.json");
    let parsed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();

    assert_eq!(parsed["user_theme"], "dark", "user-managed key must be preserved");
    assert_eq!(parsed["sandbox_mode"], "full-auto", "AA-managed key must be updated");
}

#[tokio::test]
async fn apply_settings_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());

    let settings = adapter.generate_managed_settings(&fixture_policy()).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap(); // second write must not fail

    let config_path = tmp.path().join(".codex").join("config.json");
    let parsed: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(parsed["sandbox_mode"], "ask");
}

// ---------------------------------------------------------------------------
// build_launch_command
// ---------------------------------------------------------------------------

#[test]
fn build_launch_command_sets_program_args_and_env() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let adapter = CodexAdapter::new(Box::new(FixedLocator(bin.clone())), Box::new(FixedProbe));

    let cmd = adapter
        .build_launch_command(
            &["chat".to_string()],
            "agent-1",
            Some("team-1"),
            Some("http://127.0.0.1:8080"),
        )
        .unwrap();

    assert_eq!(cmd.get_program(), bin.as_os_str(), "program must be the codex binary");

    let args: Vec<&OsStr> = cmd.get_args().collect();
    assert!(args.contains(&OsStr::new("chat")), "tool_args must be forwarded");

    let env: std::collections::HashMap<&OsStr, Option<&OsStr>> = cmd.get_envs().collect();
    assert_eq!(env[OsStr::new("AA_AGENT_ID")], Some(OsStr::new("agent-1")));
    assert_eq!(env[OsStr::new("AA_TEAM_ID")], Some(OsStr::new("team-1")));
    assert_eq!(
        env[OsStr::new("HTTPS_PROXY")],
        Some(OsStr::new("http://127.0.0.1:8080"))
    );
}

#[test]
fn build_launch_command_omits_optional_env_when_none() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let adapter = CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe));

    let cmd = adapter.build_launch_command(&[], "agent-2", None, None).unwrap();

    let env_keys: Vec<&OsStr> = cmd.get_envs().map(|(k, _)| k).collect();
    assert!(
        !env_keys.contains(&OsStr::new("AA_TEAM_ID")),
        "AA_TEAM_ID must not be set when team_id is None"
    );
    assert!(
        !env_keys.contains(&OsStr::new("HTTPS_PROXY")),
        "HTTPS_PROXY must not be set when proxy_addr is None"
    );
}

#[test]
fn build_launch_command_fails_when_binary_not_found() {
    let adapter = CodexAdapter::new(Box::new(NullLocator), Box::new(FixedProbe));

    let result = adapter.build_launch_command(&[], "a", None, None);
    assert!(
        matches!(result, Err(AdapterError::LaunchFailed(_))),
        "must return LaunchFailed when binary is not on PATH or npm global"
    );
}
