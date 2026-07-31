//! Integration tests for `aasm run`: child-process spawn + deregister on exit.
//!
//! Since AAASM-5323 a session must be registered with the gateway's gRPC
//! `AgentLifecycleService` before anything is launched, so these run against a
//! real one ([`gateway_support::TestGateway`]) rather than a mock of a REST
//! route no gateway serves. That also makes the deregistration assertion a real
//! one: the registry either still holds the agent or it does not.

use std::collections::HashMap;
use std::path::PathBuf;

use aa_cli::commands::run::{execute_with_adapters, RunArgs};
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

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

/// Adapter that records whether a launch command was ever built for it.
///
/// `detect()` succeeds, so a refusal measured with this adapter is attributable
/// to registration rather than to the tool being absent — and the flag makes
/// "never launched" an observation instead of an inference from an exit code.
struct RecordingAdapter {
    launched: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[async_trait]
impl DevToolAdapter for RecordingAdapter {
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
        self.launched.store(true, std::sync::atomic::Ordering::SeqCst);
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

#[tokio::test(flavor = "multi_thread")]
async fn run_command_exits_zero_and_deregisters() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("echo", Box::new(EchoAdapter));

    let code = execute_with_adapters(&run_args("echo"), &adapters).await.unwrap();

    assert_eq!(code, 0, "echo exits 0");
    assert!(
        gateway.registry().list().is_empty(),
        "the session must be released on a clean exit; the registry still holds {:?}",
        gateway.registry().list().len(),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn run_command_propagates_nonzero_exit_and_deregisters() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("sh", Box::new(ExitSevenAdapter));

    let code = execute_with_adapters(&run_args("sh"), &adapters).await.unwrap();

    assert_eq!(code, 7, "sh -c 'exit 7' propagates exit code 7");
    assert!(
        gateway.registry().list().is_empty(),
        "a non-zero child exit is still a clean session end; the registration must be released",
    );
}

/// A launch the gateway never accepted must not happen at all.
///
/// The gateway here is one that is not running: the endpoint points at a port
/// nothing holds. That is the everyday shape of "no identity" — and the tool
/// must not start, because a tool started without a governed identity is an
/// ungoverned process wearing a governed launch's name.
#[tokio::test(flavor = "multi_thread")]
async fn run_command_refuses_to_launch_when_registration_is_impossible() {
    // Bind-and-release, so the port is one nothing is listening on.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr")
    };
    let _env = GatewayEnv::point_at(&format!("http://{dead}"));

    let launched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert(
        "echo",
        Box::new(RecordingAdapter {
            launched: launched.clone(),
        }),
    );

    let err = execute_with_adapters(&run_args("echo"), &adapters)
        .await
        .expect_err("an unregistered session must not launch");

    assert!(
        err.to_string().contains("refusing to launch unregistered"),
        "the operator must be told the launch was refused and why; got: {err}"
    );
    assert!(
        !launched.load(std::sync::atomic::Ordering::SeqCst),
        "the launch command was built for a session the gateway never accepted"
    );
}

/// An identity the gateway *refuses* — as distinct from a gateway it cannot
/// reach — must also stop the launch.
///
/// `--root-agent` declares a parent, and `RegisterRequest` has no other field
/// for a declared lineage, so the gateway resolves it: a parent it has never
/// registered is `InvalidArgument`. A lineage claim nobody can verify must not
/// be quietly dropped into a successful launch, because the resulting session
/// would be attributed to a delegation chain that does not exist.
#[tokio::test(flavor = "multi_thread")]
async fn run_command_refuses_a_lineage_the_gateway_will_not_accept() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let launched = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert(
        "echo",
        Box::new(RecordingAdapter {
            launched: launched.clone(),
        }),
    );

    let mut args = run_args("echo");
    args.root_agent = Some("a-parent-that-was-never-registered".into());

    let err = execute_with_adapters(&args, &adapters)
        .await
        .expect_err("a refused registration must not produce a launch");

    assert!(
        err.to_string().contains("refusing to launch unregistered"),
        "the refusal must name what was refused; got: {err}"
    );
    assert!(
        !launched.load(std::sync::atomic::Ordering::SeqCst),
        "the tool was launched despite the gateway refusing the session's identity"
    );
    assert!(
        gateway.registry().list().is_empty(),
        "a refused registration must leave no record behind"
    );
}

/// Args shared by every test here.
///
/// `--no-proxy`: these tests measure child-process spawn and deregistration, not
/// proxy trust. Since AAASM-5323 a launch without it refuses unless a verified
/// proxy is running on this host, which is not something an exit-code test
/// should have to stand up — and refusing is exactly what `aa-cli`'s own
/// `launch_refuses_when_no_trusted_proxy_can_be_established` asserts.
fn run_args(tool: &str) -> RunArgs {
    RunArgs {
        tool: tool.into(),
        tool_args: vec![],
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: true,
        dry_run: false,
        enforcement_mode: None,
        observe: false,
    }
}
