//! Integration tests for `CodexAdapter::apply_settings` and
//! `CodexAdapter::build_launch_command` (AAASM-988).
//!
//! These tests use `tempfile::TempDir` for `$HOME` so they never touch
//! the real filesystem. The Codex binary is never spawned — only the
//! prepared `Command` value is inspected.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use aa_devtool_codex::{BinaryLocator, CodexAdapter, VersionProbe};
use aa_devtool_contract::{AdapterError, DevToolAdapter};
use aa_devtool_contract::{PolicyDecision, PolicyDocument, PolicyRule};

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
        enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
    }
}

// ---------------------------------------------------------------------------
// apply_settings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn apply_settings_creates_config_toml_with_correct_content() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());

    let settings = adapter.generate_managed_settings(&fixture_policy()).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();

    // AAASM-5336: the real `codex` CLI reads `config.toml`, not `config.json`.
    let config_path = tmp.path().join(".codex").join("config.toml");
    assert!(config_path.exists(), "config.toml must be created");

    let parsed: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();

    assert_eq!(
        parsed["sandbox_mode"].as_str(),
        Some("read-only"),
        "Deny rule → the strictest sandbox Codex accepts (AA level `ask`)"
    );
    // Codex's approval_policy is ONE string (a table fails to load, AAASM-6319).
    assert_eq!(parsed["approval_policy"].as_str(), Some("on-request"));
    // AAASM-6330: codex 0.160 does not honor these keys and rejects them under
    // `--strict-config`, so they must not be written.
    assert!(parsed.get("allowed_domains").is_none());
    assert!(parsed.get("blocked_domains").is_none());
}

/// Seeds `~/.codex/config.toml`, applies a one-rule policy through the real
/// generate+apply path, and returns the parsed result.
async fn apply_one_rule(seed: &str, pattern: &str, decision: PolicyDecision) -> toml::Value {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();
    let codex_dir = tmp.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::write(codex_dir.join("config.toml"), seed).unwrap();
    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());
    let policy = PolicyDocument {
        version: 1,
        name: "one-rule".into(),
        enforcement_mode: aa_devtool_contract::EnforcementMode::default(),
        rules: vec![PolicyRule {
            action_pattern: pattern.into(),
            decision,
        }],
    };
    let settings = adapter.generate_managed_settings(&policy).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();
    toml::from_str(&std::fs::read_to_string(codex_dir.join("config.toml")).unwrap()).unwrap()
}

/// AAASM-6327: a permissive all-Allow policy must not lower the user's own
/// security settings, and must not disturb their other keys.
#[tokio::test]
async fn apply_settings_never_relaxes_the_users_security_settings() {
    let parsed = apply_one_rule(
        "user_theme = \"dark\"\nsandbox_mode = \"read-only\"\napproval_policy = \"on-request\"\n",
        "*",
        PolicyDecision::Allow,
    )
    .await;
    assert_eq!(parsed["user_theme"].as_str(), Some("dark"));
    assert_eq!(parsed["sandbox_mode"].as_str(), Some("read-only"));
    assert_eq!(parsed["approval_policy"].as_str(), Some("on-request"));
}

/// Positive control for the test above: the rule still lets AA tighten.
#[tokio::test]
async fn apply_settings_tightens_a_looser_user_setting() {
    let parsed = apply_one_rule(
        "sandbox_mode = \"workspace-write\"\napproval_policy = \"on-failure\"\n",
        "fs:write",
        PolicyDecision::Deny,
    )
    .await;
    assert_eq!(parsed["sandbox_mode"].as_str(), Some("read-only"));
    assert_eq!(parsed["approval_policy"].as_str(), Some("on-request"));
}

/// `never` can only auto-reject prompts, so replacing it could only relax.
#[tokio::test]
async fn apply_settings_leaves_a_value_it_cannot_rank_alone() {
    let parsed = apply_one_rule("approval_policy = \"never\"\n", "fs:write", PolicyDecision::Deny).await;
    assert_eq!(parsed["approval_policy"].as_str(), Some("never"));
    assert_eq!(parsed["sandbox_mode"].as_str(), Some("read-only"));
}

/// An empty config ranks strictest: a permissive value must not land on it.
#[tokio::test]
async fn apply_settings_writes_no_permissive_value_onto_an_empty_config() {
    let parsed = apply_one_rule("", "*", PolicyDecision::Allow).await;
    assert!(parsed.get("sandbox_mode").is_none());
    assert!(parsed.get("approval_policy").is_none());
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

    let config_path = tmp.path().join(".codex").join("config.toml");
    let parsed: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    assert_eq!(parsed["sandbox_mode"].as_str(), Some("read-only"));
}

/// A real `config.toml` is not flat: `codex mcp add` writes sub-tables like
/// `[mcp_servers.foo]`. `apply_settings`'s merge must preserve one across an
/// AA-managed write, not just scalar top-level keys — the shape every other
/// test in this file happens to exercise.
#[tokio::test]
async fn apply_settings_preserves_a_user_written_sub_table() {
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();

    let codex_dir = tmp.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).unwrap();
    std::fs::write(codex_dir.join("config.toml"), "[mcp_servers.foo]\ncommand = \"bar\"\n").unwrap();

    let adapter =
        CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe)).with_home_dir(tmp.path().to_path_buf());

    let settings = adapter.generate_managed_settings(&fixture_policy()).await.unwrap();
    adapter.apply_settings(&settings).await.unwrap();

    let config_path = codex_dir.join("config.toml");
    let parsed: toml::Value = toml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();

    assert_eq!(
        parsed["mcp_servers"]["foo"]["command"].as_str(),
        Some("bar"),
        "a user-written MCP server sub-table must survive an AA-managed settings write"
    );
    assert_eq!(
        parsed["sandbox_mode"].as_str(),
        Some("read-only"),
        "AA-managed key must still be applied"
    );
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

#[test]
fn build_launch_command_normalizes_a_bare_proxy_authority_and_sets_both_vars() {
    // AAASM-5324/AAASM-5916: `aasm run` passes a bare `host:port`, and both
    // HTTPS_PROXY and HTTP_PROXY must be set — the adapter used to set only
    // HTTPS_PROXY with the bare (unusable) authority.
    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();
    let adapter = CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe));

    let cmd = adapter
        .build_launch_command(&[], "agent-1", None, Some("127.0.0.1:8080"))
        .unwrap();
    let env: std::collections::HashMap<&OsStr, Option<&OsStr>> = cmd.get_envs().collect();
    assert_eq!(
        env[OsStr::new("HTTPS_PROXY")],
        Some(OsStr::new("http://127.0.0.1:8080")),
        "a bare authority must be normalized to a URL"
    );
    assert_eq!(
        env[OsStr::new("HTTP_PROXY")],
        Some(OsStr::new("http://127.0.0.1:8080")),
        "HTTP_PROXY must be set alongside HTTPS_PROXY"
    );
}

#[test]
fn build_launch_command_carries_the_installed_launch_environment() {
    use aa_devtool_contract::{LaunchEnvStore, SettingsScope};

    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();
    let state = tmp.path().join("state");
    let paths = aa_devtool_codex::CodexPaths::default().with_state(&state);
    LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
        .set("CODEX_CA_CERTIFICATE", "/aasm/proxy-ca.pem")
        .unwrap();

    let adapter = CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe))
        .with_home_dir(tmp.path().join("home"))
        .with_state_dir(state);

    let cmd = adapter.build_launch_command(&[], "agent-1", None, None).unwrap();
    let env: std::collections::HashMap<&OsStr, Option<&OsStr>> = cmd.get_envs().collect();
    assert_eq!(
        env[OsStr::new("CODEX_CA_CERTIFICATE")],
        Some(OsStr::new("/aasm/proxy-ca.pem")),
        "the store's value must reach the child command"
    );
}

#[test]
fn build_launch_command_lets_a_caller_pinned_proxy_win_over_the_installed_one() {
    use aa_devtool_contract::{LaunchEnvStore, SettingsScope};

    let tmp = tempfile::tempdir().unwrap();
    let bin = tmp.path().join("codex");
    std::fs::write(&bin, "").unwrap();
    let state = tmp.path().join("state");
    let paths = aa_devtool_codex::CodexPaths::default().with_state(&state);
    LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
        .set("HTTPS_PROXY", "http://installed:9000")
        .unwrap();
    LaunchEnvStore::at(paths.launch_env_dir(SettingsScope::User).unwrap())
        .set("HTTP_PROXY", "http://installed:9000")
        .unwrap();

    let adapter = CodexAdapter::new(Box::new(FixedLocator(bin)), Box::new(FixedProbe))
        .with_home_dir(tmp.path().join("home"))
        .with_state_dir(state);

    let cmd = adapter
        .build_launch_command(&[], "agent-1", None, Some("http://pinned:1234"))
        .unwrap();
    let env: std::collections::HashMap<&OsStr, Option<&OsStr>> = cmd.get_envs().collect();
    assert_eq!(
        env[OsStr::new("HTTPS_PROXY")],
        Some(OsStr::new("http://pinned:1234")),
        "a caller-pinned proxy for this run must win over the installed one"
    );
    assert_eq!(env[OsStr::new("HTTP_PROXY")], Some(OsStr::new("http://pinned:1234")));
}
