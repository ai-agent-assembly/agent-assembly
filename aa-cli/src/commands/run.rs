//! `aasm run` — launch an AI dev tool with governance wiring.

use std::collections::HashMap;
use std::process::ExitCode;

use anyhow::Result;
use async_trait::async_trait;
use clap::Args;
use serde::Deserialize;
use uuid::Uuid;

use aa_core::{
    AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument, PolicyRule,
};

use crate::config::ResolvedContext;
use crate::output::OutputFormat;

/// Arguments for the `aasm run <tool> [args...]` subcommand.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// The AI development tool to launch (claude, codex, copilot, windsurf).
    pub tool: String,

    /// Arguments forwarded verbatim to the launched tool.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub tool_args: Vec<String>,

    /// Override the agent identity for this session.
    #[arg(long)]
    pub agent_id: Option<String>,

    /// Team identifier for this session.
    #[arg(long)]
    pub team_id: Option<String>,

    /// Root agent identifier for lineage tracking.
    #[arg(long)]
    pub root_agent: Option<String>,

    /// Override the governance level for this session.
    #[arg(long)]
    pub governance_level: Option<GovernanceLevel>,

    /// Skip proxy injection (not recommended for governed environments).
    #[arg(long)]
    pub no_proxy: bool,

    /// Show the launch command and settings without executing.
    #[arg(long)]
    pub dry_run: bool,
}

// Placeholder until per-tool adapter crates (AAASM-201..205) are ready.
// Each of the four known tools maps to this struct; replace individual arms
// in resolve_adapter() when the real crate lands.
struct PlaceholderAdapter;

#[async_trait]
impl DevToolAdapter for PlaceholderAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        None
    }

    async fn generate_managed_settings(&self, _policy: &PolicyDocument) -> Result<String, AdapterError> {
        Err(AdapterError::SettingsGenerationFailed(
            "adapter not yet implemented".into(),
        ))
    }

    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Err(AdapterError::SettingsApplyFailed(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "adapter not yet implemented",
        )))
    }

    fn build_launch_command(
        &self,
        _tool_args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        Err(AdapterError::LaunchFailed("adapter not yet implemented".into()))
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _allowed: &[String], _denied: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L0Discover
    }
}

/// Convert a [`DevToolKind`] to the snake_case string sent in the registration request body.
fn dev_tool_kind_str(kind: &DevToolKind) -> String {
    match kind {
        DevToolKind::ClaudeCode => "claude_code".into(),
        DevToolKind::Codex => "codex".into(),
        DevToolKind::GitHubCopilot => "github_copilot".into(),
        DevToolKind::WindsurfCascade => "windsurf_cascade".into(),
        DevToolKind::Custom(s) => s.clone(),
    }
}

/// Gateway registration result for a single `aasm run` session.
struct RegistrationHandle {
    agent_id: String,
    registration_id: String,
    trace_id: String,
    session_id: String,
    proxy_addr: Option<String>,
    /// Carried from [`RunArgs::team_id`] (or echoed by the gateway) for `AA_TEAM_ID` injection.
    team_id: Option<String>,
}

/// Register the detected tool with the Agent Assembly gateway.
///
/// POSTs `{kind, version, agent_id, team_id, root_agent, governance_level}` to
/// `POST {ctx.api_url}/api/v1/agents`. UUIDs are generated locally for any
/// identity fields the gateway omits from its response.
async fn register_with_gateway(
    info: &DevToolInfo,
    args: &RunArgs,
    ctx: &ResolvedContext,
) -> Result<RegistrationHandle> {
    let agent_id = args.agent_id.clone().unwrap_or_else(|| Uuid::new_v4().to_string());

    let body = serde_json::json!({
        "kind": dev_tool_kind_str(&info.kind),
        "version": info.version.as_deref().unwrap_or("unknown"),
        "agent_id": &agent_id,
        "team_id": args.team_id,
        "root_agent": args.root_agent,
        "governance_level": info.governance_level.to_string(),
    });

    let url = format!("{}/api/v1/agents", ctx.api_url.trim_end_matches('/'));
    let client = reqwest::Client::new();
    let mut req = client.post(&url).json(&body);
    if let Some(ref key) = ctx.api_key {
        req = req.header("Authorization", format!("Bearer {key}"));
    }

    let resp = req.send().await?;
    if !resp.status().is_success() {
        return Err(anyhow::anyhow!("gateway registration failed: HTTP {}", resp.status()));
    }

    #[derive(Deserialize)]
    struct RegisterResponse {
        agent_id: Option<String>,
        registration_id: Option<String>,
        trace_id: Option<String>,
        session_id: Option<String>,
        proxy_addr: Option<String>,
        team_id: Option<String>,
    }

    let reg: RegisterResponse = resp.json().await?;

    Ok(RegistrationHandle {
        agent_id: reg.agent_id.unwrap_or(agent_id),
        registration_id: reg.registration_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        trace_id: reg.trace_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        session_id: reg.session_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
        proxy_addr: reg.proxy_addr,
        team_id: reg.team_id.or_else(|| args.team_id.clone()),
    })
}

/// Build the environment map to be inherited by the child process.
///
/// Starts from the current process environment, then overlays governance
/// identity variables. `HTTPS_PROXY` / `HTTP_PROXY` are only injected when
/// `handle.proxy_addr` is set and `no_proxy` is `false`.
fn build_child_env(handle: &RegistrationHandle, no_proxy: bool) -> HashMap<String, String> {
    let mut env: HashMap<String, String> = std::env::vars().collect();
    env.insert("AA_AGENT_ID".into(), handle.agent_id.clone());
    env.insert("AA_TRACE_ID".into(), handle.trace_id.clone());
    env.insert("AA_SESSION_ID".into(), handle.session_id.clone());
    env.insert("AA_REGISTRATION_ID".into(), handle.registration_id.clone());
    if let Some(ref team_id) = handle.team_id {
        env.insert("AA_TEAM_ID".into(), team_id.clone());
    }
    if let Some(ref proxy) = handle.proxy_addr {
        if !no_proxy {
            env.insert("HTTPS_PROXY".into(), proxy.clone());
            env.insert("HTTP_PROXY".into(), proxy.clone());
        }
    }
    env
}

/// Construct a default policy document used until a real loader is wired in.
fn load_policy() -> PolicyDocument {
    PolicyDocument {
        version: 1,
        name: "default".into(),
        rules: Vec::<PolicyRule>::new(),
    }
}

/// Mask a value when its key contains "TOKEN" or "KEY" (case-insensitive).
fn mask_value(key: &str, value: &str) -> String {
    let upper = key.to_uppercase();
    if upper.contains("TOKEN") || upper.contains("KEY") {
        "***MASKED***".into()
    } else {
        value.to_string()
    }
}

/// Build the structured dry-run output string.
fn format_dry_run_output(
    handle: &RegistrationHandle,
    settings: &str,
    cmd: &std::process::Command,
    env: &HashMap<String, String>,
) -> String {
    const SETTINGS_LIMIT: usize = 1024;

    let truncated_settings = if settings.len() > SETTINGS_LIMIT {
        format!("{}... [truncated]", &settings[..SETTINGS_LIMIT])
    } else {
        settings.to_string()
    };

    let program = cmd.get_program().to_string_lossy().into_owned();
    let args_strs: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().into_owned()).collect();
    let cmd_line = if args_strs.is_empty() {
        program
    } else {
        format!("{} {}", program, args_strs.join(" "))
    };

    let mut sorted_env: Vec<(&String, &String)> = env.iter().collect();
    sorted_env.sort_by_key(|(k, _)| k.as_str());
    let env_lines: String = sorted_env
        .iter()
        .map(|(k, v)| format!("{}={}\n", k, mask_value(k, v)))
        .collect();

    format!(
        "--- aasm run dry-run ---\nagent_id:    {}\ntrace_id:    {}\nsession_id:  {}\n\n--- managed settings ---\n{}\n\n--- launch command ---\n{}\n\n--- environment ---\n{}",
        handle.agent_id,
        handle.trace_id,
        handle.session_id,
        truncated_settings,
        cmd_line,
        env_lines,
    )
}

/// Return the adapter for `tool`, or an error for unrecognised tool names.
fn resolve_adapter(tool: &str) -> Result<Box<dyn DevToolAdapter>> {
    match tool {
        // Real adapters replace PlaceholderAdapter here once their crates land.
        "claude" => Ok(Box::new(PlaceholderAdapter)),
        "codex" => Ok(Box::new(PlaceholderAdapter)),
        "copilot" => Ok(Box::new(PlaceholderAdapter)),
        "windsurf" => Ok(Box::new(PlaceholderAdapter)),
        _ => Err(anyhow::anyhow!(
            "unknown tool: {tool}, supported: claude, codex, copilot, windsurf"
        )),
    }
}

/// Testable core of `execute`: detect, register, apply settings, optionally dry-run.
async fn execute_with_adapters(
    args: &RunArgs,
    ctx: &ResolvedContext,
    adapters: &HashMap<&str, Box<dyn DevToolAdapter>>,
) -> Result<()> {
    let adapter = adapters.get(args.tool.as_str()).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown tool: {}, supported: claude, codex, copilot, windsurf",
            args.tool
        )
    })?;

    let info = adapter
        .detect()
        .ok_or_else(|| anyhow::anyhow!("{} is not installed", args.tool))?;

    eprintln!(
        "tool={} version={} path={} governance_level={}",
        args.tool,
        info.version.as_deref().unwrap_or("unknown"),
        info.install_path.display(),
        info.governance_level,
    );

    let handle = register_with_gateway(&info, args, ctx).await?;
    let child_env = build_child_env(&handle, args.no_proxy);

    let policy = load_policy();
    let settings = adapter
        .generate_managed_settings(&policy)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate managed settings: {e}"))?;

    if !args.dry_run {
        adapter
            .apply_settings(&settings)
            .await
            .map_err(|e| anyhow::anyhow!("failed to apply settings: {e}"))?;
    }

    let mut cmd = adapter
        .build_launch_command(
            &args.tool_args,
            &handle.agent_id,
            handle.team_id.as_deref(),
            handle.proxy_addr.as_deref(),
        )
        .map_err(|e| anyhow::anyhow!("failed to build launch command: {e}"))?;
    cmd.envs(&child_env);

    if args.dry_run {
        print!("{}", format_dry_run_output(&handle, &settings, &cmd, &child_env));
        return Ok(());
    }

    // AAASM-942: exec the child process here.
    Ok(())
}

/// Launch the specified AI dev tool with governance wiring.
pub async fn execute(args: RunArgs, ctx: &ResolvedContext) -> Result<()> {
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    for tool in ["claude", "codex", "copilot", "windsurf"] {
        adapters.insert(tool, resolve_adapter(tool)?);
    }
    execute_with_adapters(&args, ctx, &adapters).await
}

/// Entry point for `aasm run`.
pub fn dispatch(args: RunArgs, ctx: &ResolvedContext, _output: OutputFormat) -> ExitCode {
    let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
    match rt.block_on(execute(args, ctx)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    use aa_core::{DevToolInfo, DevToolKind};
    use clap::Parser;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::*;

    /// Minimal CLI wrapper for testing `run` subcommand parsing.
    #[derive(Parser)]
    #[command(name = "aasm")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand)]
    enum TestCommands {
        Run(RunArgs),
    }

    // --- parse tests (carried forward from AAASM-927) ---

    #[test]
    fn parse_basic_run_command() {
        let cli = TestCli::try_parse_from(["aasm", "run", "claude", "foo", "bar"]).unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert_eq!(args.tool, "claude");
                assert_eq!(args.tool_args, vec!["foo", "bar"]);
                assert!(!args.dry_run);
                assert!(!args.no_proxy);
            }
        }
    }

    #[test]
    fn parse_with_flags() {
        let cli = TestCli::try_parse_from([
            "aasm",
            "run",
            "claude",
            "--agent-id",
            "a1",
            "--dry-run",
            "--",
            "--some-flag",
        ])
        .unwrap();
        match cli.command {
            TestCommands::Run(args) => {
                assert_eq!(args.tool, "claude");
                assert_eq!(args.agent_id.as_deref(), Some("a1"));
                assert!(args.dry_run);
                assert_eq!(args.tool_args, vec!["--some-flag"]);
            }
        }
    }

    #[test]
    fn parse_governance_level_short_forms() {
        for (input, expected) in [
            ("L0", GovernanceLevel::L0Discover),
            ("L1", GovernanceLevel::L1Observe),
            ("L2", GovernanceLevel::L2Enforce),
            ("L3", GovernanceLevel::L3Native),
        ] {
            let cli = TestCli::try_parse_from(["aasm", "run", "codex", "--governance-level", input]).unwrap();
            match cli.command {
                TestCommands::Run(args) => {
                    assert_eq!(args.governance_level, Some(expected), "input={input}");
                }
            }
        }
    }

    // --- adapter resolution tests ---

    #[test]
    fn unknown_tool_errors() {
        let err = match resolve_adapter("notathing") {
            Ok(_) => panic!("expected Err for unknown tool"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("unknown tool"),
            "expected 'unknown tool' in error, got: {err}"
        );
        assert!(
            err.to_string().contains("notathing"),
            "expected tool name in error, got: {err}"
        );
    }

    #[test]
    fn known_tools_resolve_without_error() {
        for tool in ["claude", "codex", "copilot", "windsurf"] {
            assert!(resolve_adapter(tool).is_ok(), "resolve_adapter({tool}) should succeed");
        }
    }

    // --- build_child_env tests ---

    fn stub_handle(proxy_addr: Option<&str>, team_id: Option<&str>) -> RegistrationHandle {
        RegistrationHandle {
            agent_id: "test-agent".into(),
            registration_id: "test-reg".into(),
            trace_id: "test-trace".into(),
            session_id: "test-session".into(),
            proxy_addr: proxy_addr.map(String::from),
            team_id: team_id.map(String::from),
        }
    }

    #[test]
    fn build_child_env_sets_proxy() {
        let handle = stub_handle(Some("http://proxy:8080"), None);
        let env = build_child_env(&handle, false);
        assert_eq!(
            env.get("HTTPS_PROXY").map(String::as_str),
            Some("http://proxy:8080"),
            "HTTPS_PROXY should be set"
        );
        assert_eq!(
            env.get("HTTP_PROXY").map(String::as_str),
            Some("http://proxy:8080"),
            "HTTP_PROXY should be set"
        );
        assert_eq!(env.get("AA_AGENT_ID").map(String::as_str), Some("test-agent"));
        assert_eq!(env.get("AA_TRACE_ID").map(String::as_str), Some("test-trace"));
        assert_eq!(env.get("AA_SESSION_ID").map(String::as_str), Some("test-session"));
        assert_eq!(env.get("AA_REGISTRATION_ID").map(String::as_str), Some("test-reg"));
    }

    #[test]
    fn build_child_env_skips_proxy_when_no_proxy() {
        let handle = stub_handle(Some("http://proxy:8080"), None);
        let env = build_child_env(&handle, true);
        assert!(
            !env.contains_key("HTTPS_PROXY"),
            "HTTPS_PROXY must not be set when no_proxy=true"
        );
        assert!(
            !env.contains_key("HTTP_PROXY"),
            "HTTP_PROXY must not be set when no_proxy=true"
        );
    }

    #[test]
    fn build_child_env_sets_team_id_when_present() {
        let handle = stub_handle(None, Some("my-team"));
        let env = build_child_env(&handle, false);
        assert_eq!(env.get("AA_TEAM_ID").map(String::as_str), Some("my-team"));
    }

    #[test]
    fn build_child_env_omits_team_id_when_absent() {
        let handle = stub_handle(None, None);
        let env = build_child_env(&handle, false);
        assert!(
            !env.contains_key("AA_TEAM_ID"),
            "AA_TEAM_ID must not be set when team_id is None"
        );
    }

    // --- register_with_gateway tests ---

    #[tokio::test]
    async fn register_with_gateway_posts_correct_body() {
        let mock_server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "agent_id": "gw-agent-id",
                "registration_id": "gw-reg-id",
                "trace_id": "gw-trace-id",
                "session_id": "gw-session-id",
                "proxy_addr": "http://gw-proxy:9090"
            })))
            .mount(&mock_server)
            .await;

        let info = DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.2.3".into()),
            install_path: PathBuf::from("/usr/local/bin/claude"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: true,
            supports_managed_settings: true,
        };
        let args = RunArgs {
            tool: "claude".into(),
            tool_args: vec![],
            agent_id: Some("my-agent".into()),
            team_id: Some("my-team".into()),
            root_agent: None,
            governance_level: None,
            no_proxy: false,
            dry_run: false,
        };
        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };

        let handle = register_with_gateway(&info, &args, &ctx).await.unwrap();

        assert_eq!(handle.agent_id, "gw-agent-id");
        assert_eq!(handle.registration_id, "gw-reg-id");
        assert_eq!(handle.trace_id, "gw-trace-id");
        assert_eq!(handle.session_id, "gw-session-id");
        assert_eq!(handle.proxy_addr.as_deref(), Some("http://gw-proxy:9090"));
        assert_eq!(handle.team_id.as_deref(), Some("my-team"));

        // Verify the request body shape
        let reqs = mock_server.received_requests().await.unwrap();
        assert_eq!(reqs.len(), 1, "expected exactly one POST request");
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["kind"], "claude_code");
        assert_eq!(body["version"], "1.2.3");
        assert_eq!(body["agent_id"], "my-agent");
        assert_eq!(body["team_id"], "my-team");
        assert_eq!(body["governance_level"], "L2Enforce");
    }

    // --- execute_with_adapters tests ---

    struct StubNotInstalled;

    #[async_trait]
    impl DevToolAdapter for StubNotInstalled {
        fn detect(&self) -> Option<DevToolInfo> {
            None
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            unimplemented!()
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            unimplemented!()
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            unimplemented!()
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L0Discover
        }
    }

    struct StubDetected {
        version: Option<String>,
    }

    #[async_trait]
    impl DevToolAdapter for StubDetected {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: self.version.clone(),
                install_path: PathBuf::from("/usr/local/bin/claude"),
                governance_level: GovernanceLevel::L2Enforce,
                supports_mcp: true,
                supports_managed_settings: true,
            })
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Ok("{}".into())
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            Ok(())
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Ok(std::process::Command::new("echo"))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L2Enforce
        }
    }

    /// Adapter that records whether `apply_settings` was called.
    struct MockAdapter {
        apply_called: Arc<AtomicBool>,
    }

    #[async_trait]
    impl DevToolAdapter for MockAdapter {
        fn detect(&self) -> Option<DevToolInfo> {
            Some(DevToolInfo {
                kind: DevToolKind::ClaudeCode,
                version: Some("9.9.9".into()),
                install_path: PathBuf::from("/usr/local/bin/mock-tool"),
                governance_level: GovernanceLevel::L2Enforce,
                supports_mcp: false,
                supports_managed_settings: true,
            })
        }
        async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
            Ok(r#"{"key":"val"}"#.into())
        }
        async fn apply_settings(&self, _s: &str) -> Result<(), AdapterError> {
            self.apply_called.store(true, Ordering::SeqCst);
            Ok(())
        }
        fn build_launch_command(
            &self,
            _a: &[String],
            _b: &str,
            _c: Option<&str>,
            _d: Option<&str>,
        ) -> Result<std::process::Command, AdapterError> {
            Ok(std::process::Command::new("mock-tool"))
        }
        async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
            Ok(vec![])
        }
        async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
            Ok(())
        }
        fn governance_level(&self) -> GovernanceLevel {
            GovernanceLevel::L2Enforce
        }
    }

    fn run_args(tool: &str) -> RunArgs {
        RunArgs {
            tool: tool.to_string(),
            tool_args: vec![],
            agent_id: None,
            team_id: None,
            root_agent: None,
            governance_level: None,
            no_proxy: false,
            dry_run: false,
        }
    }

    fn dummy_ctx() -> ResolvedContext {
        ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".into(),
            api_key: None,
        }
    }

    #[tokio::test]
    async fn tool_not_found_errors() {
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert("claude", Box::new(StubNotInstalled));

        let err = execute_with_adapters(&run_args("claude"), &dummy_ctx(), &adapters)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("is not installed"),
            "expected 'is not installed' in error, got: {err}"
        );
        assert!(
            err.to_string().contains("claude"),
            "expected tool name in error, got: {err}"
        );
    }

    #[tokio::test]
    async fn detected_tool_succeeds() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "agent_id": "a1",
                "registration_id": "r1",
                "trace_id": "t1",
                "session_id": "s1",
                "proxy_addr": null
            })))
            .mount(&mock_server)
            .await;

        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert(
            "claude",
            Box::new(StubDetected {
                version: Some("1.2.3".into()),
            }),
        );
        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };

        assert!(
            execute_with_adapters(&run_args("claude"), &ctx, &adapters)
                .await
                .is_ok(),
            "execute_with_adapters should succeed when detect() returns Some and gateway responds 201"
        );
    }

    #[tokio::test]
    async fn unknown_tool_in_adapters_errors() {
        let adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();

        let err = execute_with_adapters(&run_args("notathing"), &dummy_ctx(), &adapters)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("unknown tool"), "got: {err}");
    }

    // --- dry-run tests ---

    #[tokio::test]
    async fn dry_run_does_not_apply_settings() {
        let mock_server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/api/v1/agents"))
            .respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({
                "agent_id": "dr-agent",
                "registration_id": "dr-reg",
                "trace_id": "dr-trace",
                "session_id": "dr-session",
                "proxy_addr": null
            })))
            .mount(&mock_server)
            .await;

        let apply_called = Arc::new(AtomicBool::new(false));
        let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
        adapters.insert(
            "claude",
            Box::new(MockAdapter {
                apply_called: Arc::clone(&apply_called),
            }),
        );

        let mut args = run_args("claude");
        args.dry_run = true;
        let ctx = ResolvedContext {
            name: None,
            api_url: mock_server.uri(),
            api_key: None,
        };

        let result = execute_with_adapters(&args, &ctx, &adapters).await;
        assert!(result.is_ok(), "dry-run should succeed: {result:?}");
        assert!(
            !apply_called.load(Ordering::SeqCst),
            "apply_settings must NOT be called when --dry-run is set"
        );
    }

    #[test]
    fn dry_run_prints_command_line() {
        let handle = RegistrationHandle {
            agent_id: "agent-xyz".into(),
            registration_id: "reg-xyz".into(),
            trace_id: "trace-xyz".into(),
            session_id: "session-xyz".into(),
            proxy_addr: None,
            team_id: None,
        };
        let settings = r#"{"mode":"strict"}"#;
        let mut cmd = std::process::Command::new("mock-tool");
        cmd.args(["--flag", "value"]);
        let mut env = HashMap::new();
        env.insert("AA_AGENT_ID".into(), "agent-xyz".into());
        env.insert("MY_API_KEY".into(), "secret123".into());
        env.insert("NORMAL_VAR".into(), "hello".into());

        let output = format_dry_run_output(&handle, settings, &cmd, &env);

        assert!(output.contains("agent_id:"), "missing identity section: {output}");
        assert!(output.contains("agent-xyz"), "missing agent_id value: {output}");
        assert!(output.contains("trace-xyz"), "missing trace_id value: {output}");
        assert!(output.contains("session-xyz"), "missing session_id value: {output}");
        assert!(
            output.contains("--- managed settings ---"),
            "missing settings header: {output}"
        );
        assert!(
            output.contains(r#"{"mode":"strict"}"#),
            "missing settings content: {output}"
        );
        assert!(
            output.contains("--- launch command ---"),
            "missing command header: {output}"
        );
        assert!(
            output.contains("mock-tool"),
            "missing tool name in command line: {output}"
        );
        assert!(
            output.contains("--- environment ---"),
            "missing environment header: {output}"
        );
        assert!(
            output.contains("***MASKED***"),
            "MY_API_KEY value should be masked: {output}"
        );
        assert!(
            output.contains("NORMAL_VAR=hello"),
            "NORMAL_VAR should be unmasked: {output}"
        );
    }
}
