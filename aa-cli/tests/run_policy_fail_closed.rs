//! Falsification tests for AAASM-5349: an empty effective policy is
//! unconfigured, and a governed launch refuses on it.
//!
//! These drive the whole `aasm run` path — detect, resolve policy, register,
//! launch — rather than the resolver in isolation, because the defect being
//! fixed was not in a resolver. It was that the launch path never asked: it
//! synthesized an empty `PolicyDocument` inline and carried on. An assertion
//! that only exercises the resolver would still pass against that bug.
//!
//! Every launch here is measured with a [`RecordingAdapter`], so "did not
//! launch" is an observation rather than an inference from an exit code: a
//! refusal that happened *after* the tool started would be indistinguishable
//! from a real refusal if all we checked was the returned `Err`.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use aa_cli::commands::run::{execute_with_adapters, RunArgs};
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use async_trait::async_trait;

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

/// Adapter that records whether a launch command was ever built, and what
/// policy the managed settings were generated from.
struct RecordingAdapter {
    launched: Arc<AtomicBool>,
    rules_seen: Arc<std::sync::Mutex<Option<usize>>>,
}

impl RecordingAdapter {
    fn new() -> (Self, Arc<AtomicBool>, Arc<std::sync::Mutex<Option<usize>>>) {
        let launched = Arc::new(AtomicBool::new(false));
        let rules_seen = Arc::new(std::sync::Mutex::new(None));
        (
            Self {
                launched: launched.clone(),
                rules_seen: rules_seen.clone(),
            },
            launched,
            rules_seen,
        )
    }
}

#[async_trait]
impl DevToolAdapter for RecordingAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/usr/bin/echo"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, p: &PolicyDocument) -> Result<String, AdapterError> {
        *self.rules_seen.lock().unwrap() = Some(p.rules.len());
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
        self.launched.store(true, Ordering::SeqCst);
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
        GovernanceLevel::L2Enforce
    }
}

/// `--policy` is always pinned at a path under this test's own temp dir, so a
/// developer machine with a real `~/.aasm/policy.yaml` measures the same thing
/// as a bare CI runner.
fn args_with_policy(path: PathBuf) -> RunArgs {
    RunArgs {
        tool: "echo".into(),
        tool_args: vec![],
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: true,
        policy: Some(path),
        dry_run: false,
        enforcement_mode: None,
        observe: false,
    }
}

async fn run_with(policy: PathBuf) -> (anyhow::Result<i32>, bool, Option<usize>) {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let (adapter, launched, rules_seen) = RecordingAdapter::new();
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("echo", Box::new(adapter));

    let result = execute_with_adapters(&args_with_policy(policy), &adapters).await;
    let seen = *rules_seen.lock().unwrap();
    (result, launched.load(Ordering::SeqCst), seen)
}

/// The headline contract: no effective policy, no launch.
#[tokio::test(flavor = "multi_thread")]
async fn a_governed_launch_with_no_policy_refuses_and_never_starts_the_tool() {
    let dir = tempfile::tempdir().unwrap();
    let (result, launched, rules_seen) = run_with(dir.path().join("absent.yaml")).await;

    let err = result.expect_err("a launch with no effective policy must refuse");
    assert!(
        err.to_string().contains("refusing to launch ungoverned"),
        "the operator must be told the launch was refused; got: {err}"
    );
    assert!(
        !launched,
        "the tool was started for a session with no policy — the launch is ungoverned"
    );
    assert!(
        rules_seen.is_none(),
        "managed settings were generated from a policy that does not exist"
    );
}

/// An empty-but-valid policy is the exact shape the old `load_policy()`
/// produced. It must refuse for the same reason an absent one does.
#[tokio::test(flavor = "multi_thread")]
async fn a_policy_with_no_rules_refuses_rather_than_launching_permissively() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("empty.yaml");
    std::fs::write(&path, "budget:\n  daily_limit_usd: 5.0\n").unwrap();

    let (result, launched, rules_seen) = run_with(path).await;

    let err = result.expect_err("an empty effective policy must refuse");
    assert!(
        err.to_string()
            .contains("An empty policy is unconfigured, not allow-all"),
        "the refusal must say why an empty policy is not permission; got: {err}"
    );
    assert!(!launched, "a policy that governs nothing launched a governed session");
    assert!(rules_seen.is_none(), "an empty rule list reached the adapter");
}

/// Refusing is only half the contract — the operator has to be able to act on
/// it without going to read the source.
#[tokio::test(flavor = "multi_thread")]
async fn the_refusal_names_the_remedy() {
    let dir = tempfile::tempdir().unwrap();
    let (result, _, _) = run_with(dir.path().join("absent.yaml")).await;
    let err = result.expect_err("must refuse").to_string();

    assert!(err.contains("--policy"), "must name the flag that supplies one: {err}");
    assert!(err.contains("AA_POLICY"), "must name the env var: {err}");
    assert!(
        err.contains("~/.aasm/policy.yaml"),
        "must name where an installed policy lives: {err}"
    );
    assert!(
        err.contains("aasm policy validate"),
        "must name how to check a candidate before re-running: {err}"
    );
    assert!(
        err.contains("allow: true"),
        "must show the allow-all artifact, or the escape hatch is undiscoverable: {err}"
    );
}

/// Permissive execution stays reachable — but only for an operator who wrote
/// the artifact that says so.
#[tokio::test(flavor = "multi_thread")]
async fn an_explicit_allow_all_artifact_launches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("allow-all.yaml");
    std::fs::write(&path, aa_policy::resolve::ALLOW_ALL_TEMPLATE).unwrap();

    let (result, launched, rules_seen) = run_with(path).await;

    assert_eq!(
        result.expect("an explicit allow-all policy must launch"),
        0,
        "the child ran and exited cleanly"
    );
    assert!(launched, "an explicitly permissive session must still start the tool");
    assert_eq!(
        rules_seen,
        Some(1),
        "the wildcard rule must reach the adapter, not an empty list"
    );
}

/// A policy with real rules launches and carries those rules to the adapter —
/// the over-rejection guard for the fail-closed default.
#[tokio::test(flavor = "multi_thread")]
async fn an_enforced_policy_launches_and_its_rules_reach_the_adapter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("enforced.yaml");
    std::fs::write(
        &path,
        "tools:\n  bash:\n    allow: false\n  read_file:\n    allow: true\n",
    )
    .unwrap();

    let (result, launched, rules_seen) = run_with(path).await;

    assert_eq!(result.expect("a policy with rules must launch"), 0);
    assert!(launched);
    assert_eq!(
        rules_seen,
        Some(2),
        "both tool rules must reach the adapter that renders managed settings"
    );
}

/// A broken policy and an absent one are different operator problems. If the
/// launch path collapsed them, an operator whose file has a typo would be told
/// to configure a policy they already configured — and the audit trail would
/// record a corrupted policy as if none had ever been set.
#[tokio::test(flavor = "multi_thread")]
async fn a_malformed_policy_refuses_with_a_different_message_than_an_absent_one() {
    let dir = tempfile::tempdir().unwrap();
    let broken = dir.path().join("broken.yaml");
    std::fs::write(&broken, "capabilties:\n  deny:\n    - file_delete\n").unwrap();

    let (broken_result, launched, _) = run_with(broken.clone()).await;
    let broken_err = broken_result.expect_err("a broken policy must refuse").to_string();

    let (absent_result, _, _) = run_with(dir.path().join("absent.yaml")).await;
    let absent_err = absent_result.expect_err("an absent policy must refuse").to_string();

    assert!(!launched, "a session with an unloadable policy must not start the tool");
    assert!(
        broken_err.contains("could not be loaded"),
        "a broken policy must be reported as broken; got: {broken_err}"
    );
    assert!(
        broken_err.contains(&broken.display().to_string()),
        "the refusal must name the file to fix; got: {broken_err}"
    );
    assert_ne!(
        broken_err, absent_err,
        "a broken policy and an absent one produced the same refusal, so the operator cannot \
         tell which problem they have"
    );
    assert!(
        !broken_err.contains("An absent policy is not permission"),
        "a broken policy must not be described as an absent one; got: {broken_err}"
    );
}
