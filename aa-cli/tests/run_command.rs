//! Integration tests for `aasm run`: child-process spawn + deregister on exit.

use std::collections::HashMap;
use std::path::PathBuf;

use aa_cli::commands::run::{execute_with_adapters, RunArgs};
use aa_cli::config::ResolvedContext;
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn registration_response(registration_id: &str) -> serde_json::Value {
    serde_json::json!({
        "agent_id": "test-agent",
        "registration_id": registration_id,
        "trace_id": "trace-1",
        "session_id": "session-1",
        "proxy_addr": null,
    })
}

/// Adapter whose child process is `echo hello` (exits 0).
struct EchoAdapter;

#[async_trait]
impl DevToolAdapter for EchoAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/usr/bin/echo"),
            governance_level: GovernanceLevel::L0Discover,
            supports_mcp: false,
            supports_managed_settings: false,
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
        _args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        let mut cmd = std::process::Command::new("echo");
        cmd.arg("hello");
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L0Discover
    }
}

/// Adapter whose child process is `sh -c 'exit 7'` (exits 7).
struct ExitSevenAdapter;

#[async_trait]
impl DevToolAdapter for ExitSevenAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/usr/bin/sh"),
            governance_level: GovernanceLevel::L0Discover,
            supports_mcp: false,
            supports_managed_settings: false,
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
        _args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        let mut cmd = std::process::Command::new("sh");
        cmd.args(["-c", "exit 7"]);
        Ok(cmd)
    }

    async fn list_mcp_servers(&self) -> Result<Vec<McpServerInfo>, AdapterError> {
        Ok(vec![])
    }

    async fn apply_mcp_governance(&self, _a: &[String], _d: &[String]) -> Result<(), AdapterError> {
        Ok(())
    }

    fn governance_level(&self) -> GovernanceLevel {
        GovernanceLevel::L0Discover
    }
}

#[tokio::test]
async fn run_command_exits_zero_and_deregisters() {
    let server = MockServer::start().await;
    let reg_id = "integ-reg-001";

    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(201).set_body_json(registration_response(reg_id)))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/api/v1/agents/{reg_id}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("echo", Box::new(EchoAdapter));

    let ctx = ResolvedContext {
        name: None,
        api_url: server.uri(),
        api_key: None,
    };

    let args = RunArgs {
        tool: "echo".into(),
        tool_args: vec![],
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: false,
        dry_run: false,
    };

    let code = execute_with_adapters(&args, &ctx, &adapters).await.unwrap();
    assert_eq!(code, 0, "echo exits 0");
    // server drops here — wiremock verifies expect(1) on both POST and DELETE
}

#[tokio::test]
async fn run_command_propagates_nonzero_exit_and_deregisters() {
    let server = MockServer::start().await;
    let reg_id = "integ-reg-007";

    Mock::given(method("POST"))
        .and(path("/api/v1/agents"))
        .respond_with(ResponseTemplate::new(201).set_body_json(registration_response(reg_id)))
        .expect(1)
        .mount(&server)
        .await;

    Mock::given(method("DELETE"))
        .and(path(format!("/api/v1/agents/{reg_id}")))
        .respond_with(ResponseTemplate::new(204))
        .expect(1)
        .mount(&server)
        .await;

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("sh", Box::new(ExitSevenAdapter));

    let ctx = ResolvedContext {
        name: None,
        api_url: server.uri(),
        api_key: None,
    };

    let args = RunArgs {
        tool: "sh".into(),
        tool_args: vec![],
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: false,
        dry_run: false,
    };

    let code = execute_with_adapters(&args, &ctx, &adapters).await.unwrap();
    assert_eq!(code, 7, "sh -c 'exit 7' propagates exit code 7");
    // server drops here — wiremock verifies DELETE was called despite nonzero exit
}
