//! Integration tests for `aasm run exec` — the generic command target
//! (AAASM-5706).
//!
//! # What these measure, and why they are not unit tests
//!
//! The claim is that a program the operator owns enters the *same* governed
//! lifecycle as a managed developer tool: it registers with a real gateway before
//! it starts, it is refused when that registration cannot happen, its exit code
//! comes back unchanged, and it deregisters when it ends. None of that is
//! observable from the plan alone, so these drive `execute_with_adapters` against
//! `gateway_support::TestGateway` — the real `AgentLifecycleService` — exactly as
//! the dev-tool tests in `run_command.rs` do.
//!
//! The two negative controls are the point of the file:
//!
//! * [`generic_run_writes_no_dev_tool_settings`] — a generic command must not
//!   have any developer tool's managed settings generated or applied on its
//!   behalf. It carries its own positive control, so "nothing was written" is a
//!   measurement rather than an artifact of a spy that cannot see writes.
//! * [`a_registered_tool_id_wins_over_the_exec_target`] — the reserved word must
//!   not take an id away from a tool that already answers to it.
//!
//! Child argv is observed by having the child *write it down*, not by
//! re-rendering it in the test: a reconstruction is written by the same hand as
//! the code under test and can agree with itself while both have drifted.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use aa_cli::commands::run::{execute_with_adapters, RunArgs};
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use aa_proto::assembly::agent::v1::RegisterRequest;
use async_trait::async_trait;

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

// --- test doubles -----------------------------------------------------------

/// A dev-tool adapter that records every managed-settings write it is asked to
/// perform, and performs a real one so the write is observable on disk.
///
/// The on-disk file is what makes the negative control a measurement: an
/// in-memory flag proves only that this struct's method was not called, while a
/// missing file proves nothing landed in the place a real adapter would put it.
struct SettingsWritingAdapter {
    settings_path: PathBuf,
    generated: Arc<AtomicBool>,
    applied: Arc<AtomicBool>,
    launched: Arc<AtomicBool>,
}

impl SettingsWritingAdapter {
    fn new(settings_path: PathBuf) -> (Self, Arc<AtomicBool>, Arc<AtomicBool>, Arc<AtomicBool>) {
        let generated = Arc::new(AtomicBool::new(false));
        let applied = Arc::new(AtomicBool::new(false));
        let launched = Arc::new(AtomicBool::new(false));
        (
            Self {
                settings_path,
                generated: generated.clone(),
                applied: applied.clone(),
                launched: launched.clone(),
            },
            generated,
            applied,
            launched,
        )
    }
}

#[async_trait]
impl DevToolAdapter for SettingsWritingAdapter {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/usr/bin/true"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: true,
        })
    }

    async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
        self.generated.store(true, Ordering::SeqCst);
        Ok("{\"managed\":true}".into())
    }

    async fn apply_settings(&self, settings: &str) -> Result<(), AdapterError> {
        self.applied.store(true, Ordering::SeqCst);
        std::fs::write(&self.settings_path, settings).expect("write managed settings");
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
        Ok(std::process::Command::new("true"))
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

// --- shared fixtures --------------------------------------------------------

/// A real policy artifact on disk, shared by every test in this binary.
///
/// A governed launch refuses when no effective policy resolves (AAASM-5349), so
/// a spawn test has to supply one the same way it has to supply a gateway.
/// Pinning it with `--policy` keeps these hermetic on a developer machine that
/// happens to have `~/.aasm/policy.yaml` installed.
fn test_policy_path() -> &'static Path {
    static POLICY: std::sync::OnceLock<(tempfile::TempDir, PathBuf)> = std::sync::OnceLock::new();
    let (_dir, path) = POLICY.get_or_init(|| {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("policy.yaml");
        std::fs::write(
            &path,
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: run-exec-target-test\n\
             spec:\n\
             \x20 tools:\n\
             \x20   bash:\n\
             \x20     allow: false\n",
        )
        .expect("write policy");
        (dir, path)
    });
    path
}

/// `aasm run exec -- <argv...>` with the flags every test here shares.
///
/// `--no-proxy`: these tests measure the generic target's lifecycle, not proxy
/// trust. Without it a launch refuses unless a verified proxy is running on this
/// host, which is not something an exit-code test should have to stand up.
fn exec_args(argv: &[&str]) -> RunArgs {
    RunArgs {
        tool: "exec".into(),
        tool_args: argv.iter().map(|a| (*a).to_string()).collect(),
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        no_proxy: true,
        policy: Some(test_policy_path().to_path_buf()),
        workdir: None,
        dry_run: false,
        enforcement_mode: None,
        observe: false,
    }
}

/// No adapters at all — the everyday shape of a generic run, and proof that
/// `exec` needs none.
fn no_adapters() -> HashMap<&'static str, Box<dyn DevToolAdapter>> {
    HashMap::new()
}

/// A `sh -c` invocation whose script is `script`, wrapped so `$@` holds `args`.
///
/// `sh -c <script> <argv0> <args...>` is POSIX: the token after the script
/// becomes `$0` and the rest become `$1..`, so the child can print exactly the
/// argv it was handed.
#[cfg(unix)]
fn sh_argv<'a>(script: &'a str, args: &[&'a str]) -> Vec<&'a str> {
    let mut argv = vec!["/bin/sh", "-c", script, "aasm-test"];
    argv.extend_from_slice(args);
    argv
}

// --- the launch itself ------------------------------------------------------

/// AC 1: a Python invocation launches through the canonical run planner, and its
/// exit code comes back unchanged.
///
/// `python3` is required rather than skipped-if-absent: a test that quietly
/// vanishes on a host without an interpreter reports the same green as one that
/// ran, and Python is the archetypal self-owned agent this target exists for.
#[tokio::test(flavor = "multi_thread")]
async fn exec_launches_a_python_agent_and_propagates_its_exit_code() {
    let python = which_python().expect(
        "python3 must be on PATH for this test: it measures the archetypal self-owned agent, and \
         skipping it would report the same green as running it",
    );

    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let code = execute_with_adapters(
        &exec_args(&[python.as_str(), "-c", "import sys; sys.exit(42)"]),
        &no_adapters(),
    )
    .await
    .expect("a generic command with a reachable gateway must launch");

    assert_eq!(code, 42, "the child's exit code must reach the caller unchanged");
    assert!(
        gateway.registry().list().is_empty(),
        "a generic command must release its registration on exit, exactly as a dev-tool run does"
    );
}

/// AC 1 + AC 9: a non-Python executable is not a special case.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_launches_a_non_python_executable_and_propagates_its_exit_code() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let code = execute_with_adapters(&exec_args(&["/bin/sh", "-c", "exit 7"]), &no_adapters())
        .await
        .expect("a generic command with a reachable gateway must launch");

    assert_eq!(code, 7, "`sh -c 'exit 7'` propagates exit code 7");
    assert!(
        gateway.registry().list().is_empty(),
        "a non-zero child exit is still a clean session end; the registration must be released"
    );
}

/// AC 2: argv reaches the child element for element.
///
/// The cases that a shell round-trip would corrupt are all present in one argv:
/// an embedded space, a leading hyphen, a bare `--`, an empty string, and a glob
/// character that a re-parse would expand. The child writes down what it
/// received, so the assertion is against the real argv rather than against the
/// test's own idea of it.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_forwards_argv_element_for_element() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("argv.txt");
    let script = format!("printf '%s\\n' \"$@\" > '{}'", out.display());

    let awkward = ["--flag", "two words", "--", "", "*.py", "-x"];
    let code = execute_with_adapters(&exec_args(&sh_argv(&script, &awkward)), &no_adapters())
        .await
        .expect("launch");

    assert_eq!(code, 0, "the argv-recording child must exit cleanly");

    let recorded = std::fs::read_to_string(&out).expect("the child must have written its argv");
    // `printf '%s\n'` terminates every element, so the trailing empty split is
    // the terminator rather than a seventh argument.
    let mut lines: Vec<&str> = recorded.split('\n').collect();
    assert_eq!(lines.pop(), Some(""), "printf terminates the last element too");

    assert_eq!(
        lines, awkward,
        "argv must reach the child exactly as supplied; got {lines:?}"
    );
}

// --- working directory ------------------------------------------------------

/// AC 3: `--workdir` decides where the child starts.
///
/// Asserted by having the child create a *relative* file: if the working
/// directory were not applied, the file would land in this test process's own
/// cwd and the assertion inside the requested directory would fail.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_starts_the_child_in_the_requested_working_directory() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let mut args = exec_args(&sh_argv("echo started > marker", &[]));
    args.workdir = Some(dir.path().to_path_buf());

    let code = execute_with_adapters(&args, &no_adapters()).await.expect("launch");

    assert_eq!(code, 0, "the child must run");
    assert!(
        dir.path().join("marker").exists(),
        "the child's relative write must land in --workdir, not in the launcher's own directory"
    );
}

/// AC 3: a working directory that does not exist is a refusal, not a spawn
/// error after a registration has already been created.
#[tokio::test(flavor = "multi_thread")]
async fn exec_refuses_a_working_directory_that_does_not_exist() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("nope");
    let mut args = exec_args(&["/bin/sh", "-c", "exit 0"]);
    args.workdir = Some(missing);

    let err = execute_with_adapters(&args, &no_adapters())
        .await
        .expect_err("a launch that cannot start where it was told to must be refused");

    assert!(
        err.to_string().contains("--workdir"),
        "the refusal must name the flag that caused it; got: {err}"
    );
    assert!(
        gateway.registry().list().is_empty(),
        "a refused launch must not leave a governed identity with no process behind it"
    );
}

// --- identity, lineage and policy ------------------------------------------

/// AC 4: `--agent-id` decides the identity the child sees.
///
/// Read out of the child's own environment rather than out of the plan: the
/// claim is about what the launched process is told, and only the child can
/// report that.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_honours_agent_id_and_team_in_the_child_environment() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let out = dir.path().join("identity.txt");
    let script = format!(
        "printf '%s\\n%s\\n' \"$AA_AGENT_ID\" \"$AA_TEAM_ID\" > '{}'",
        out.display()
    );

    let mut args = exec_args(&sh_argv(&script, &[]));
    args.agent_id = Some("self-owned-agent-1".into());
    args.team_id = Some("team-pioneer".into());

    let code = execute_with_adapters(&args, &no_adapters()).await.expect("launch");
    assert_eq!(code, 0, "the child must run");

    let recorded = std::fs::read_to_string(&out).expect("the child must have written its identity");
    let lines: Vec<&str> = recorded.lines().collect();
    assert_eq!(
        lines,
        vec!["self-owned-agent-1", "team-pioneer"],
        "the governance identity must reach a generic child exactly as it reaches a dev-tool child"
    );
}

/// AC 4 + AC 5: a lineage the gateway will not accept stops a generic launch,
/// exactly as it stops a dev-tool launch.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_refuses_a_lineage_the_gateway_will_not_accept() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("started");
    let script = format!("touch '{}'", marker.display());

    let mut args = exec_args(&sh_argv(&script, &[]));
    args.root_agent = Some("a-parent-that-was-never-registered".into());

    let err = execute_with_adapters(&args, &no_adapters())
        .await
        .expect_err("a refused registration must not produce a launch");

    assert!(
        err.to_string().contains("refusing to launch unregistered"),
        "the refusal must name what was refused; got: {err}"
    );
    assert!(
        !marker.exists(),
        "the program was started despite the gateway refusing the session's identity"
    );
    assert!(
        gateway.registry().list().is_empty(),
        "a refused registration must leave no record behind"
    );
}

/// AC 5: a generic run registers through the same handshake, and says something
/// true about itself while doing it.
///
/// The request is read off the wire the CLI actually wrote — `start_recording`
/// taps the real service — rather than rebuilt in the test.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_registers_through_the_same_governed_handshake() {
    let seen: Arc<Mutex<Vec<RegisterRequest>>> = Arc::new(Mutex::new(Vec::new()));
    let gateway = TestGateway::start_recording(seen.clone()).await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let code = execute_with_adapters(&exec_args(&["/bin/sh", "-c", "exit 0"]), &no_adapters())
        .await
        .expect("launch");
    assert_eq!(code, 0);

    let requests = seen.lock().expect("lock");
    let request = requests
        .first()
        .expect("a generic command must register before it launches");

    assert!(
        !request.public_key.is_empty() && !request.possession_proof.is_empty(),
        "a generic command must present the same key and possession proof a dev-tool launch does"
    );
    assert_eq!(
        request.name, "command:/bin/sh",
        "a generic run must be named as a command so it cannot be mistaken for a managed dev tool"
    );
    assert_eq!(
        request.version, "unknown",
        "`aasm run` does not probe an arbitrary program for a version, and must not invent one"
    );
    assert_eq!(
        request.metadata.get("governance_level").map(String::as_str),
        Some("L0Discover"),
        "a launch with no adapter reaches no higher level than the proxy sees"
    );
}

/// AC 4: an unresolvable policy refuses a generic launch, before anything runs.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_refuses_when_the_policy_cannot_be_loaded() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("started");
    let script = format!("touch '{}'", marker.display());

    let mut args = exec_args(&sh_argv(&script, &[]));
    args.policy = Some(dir.path().join("no-such-policy.yaml"));

    let err = execute_with_adapters(&args, &no_adapters())
        .await
        .expect_err("an absent policy is not an implicit allow-all for a generic command either");

    assert!(
        !marker.exists(),
        "the program ran under a policy that never resolved: {err}"
    );
    assert!(
        gateway.registry().list().is_empty(),
        "the policy refusal must land before any registration exists"
    );
}

/// A generic launch the gateway never accepted must not happen at all.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn exec_refuses_to_launch_when_registration_is_impossible() {
    // Bind-and-release, so the port is one nothing is listening on.
    let dead = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.local_addr().expect("local_addr")
    };
    let _env = GatewayEnv::point_at(&format!("http://{dead}"));

    let dir = tempfile::tempdir().expect("tempdir");
    let marker = dir.path().join("started");
    let script = format!("touch '{}'", marker.display());

    let err = execute_with_adapters(&exec_args(&sh_argv(&script, &[])), &no_adapters())
        .await
        .expect_err("an unregistered session must not launch");

    assert!(
        err.to_string().contains("refusing to launch unregistered"),
        "the operator must be told the launch was refused and why; got: {err}"
    );
    assert!(
        !marker.exists(),
        "a program was started for a session the gateway never accepted"
    );
}

// --- negative control 1: no dev-tool settings for a generic command ---------

/// **Negative control.** A generic command must not have any developer tool's
/// managed settings generated or applied on its behalf.
///
/// The spy adapter is registered as a dev tool and writes a real file, so the
/// claim is measured on disk. The **positive control** in the same test runs the
/// dev tool through the same adapter and asserts the file *does* appear — without
/// it, an adapter that silently never wrote anything would make the negative half
/// pass for the wrong reason.
///
/// This is security-relevant rather than tidiness: writing a settings file for a
/// program the operator merely wanted to run would change a different tool's
/// behaviour on the host, persistently, and nothing would undo it.
#[tokio::test(flavor = "multi_thread")]
async fn generic_run_writes_no_dev_tool_settings() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");

    // --- the claim: a generic command writes nothing ---
    let generic_settings = dir.path().join("generic-settings.json");
    let (adapter, generated, applied, _launched) = SettingsWritingAdapter::new(generic_settings.clone());
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("spy-tool", Box::new(adapter));

    let code = execute_with_adapters(&exec_args(&["/bin/sh", "-c", "exit 0"]), &adapters)
        .await
        .expect(
            "the generic launch itself must succeed — an absence measured on a launch that \
                 never happened would prove nothing",
        );

    assert_eq!(code, 0, "the generic command must actually have run");
    assert!(
        !generated.load(Ordering::SeqCst),
        "managed settings were generated for a program that has no dev-tool adapter"
    );
    assert!(
        !applied.load(Ordering::SeqCst),
        "managed settings were applied for a program that has no dev-tool adapter"
    );
    assert!(
        !generic_settings.exists(),
        "a settings file was written to {} for a generic command",
        generic_settings.display()
    );

    // --- the positive control: the same adapter DOES write for a dev tool ---
    let devtool_settings = dir.path().join("devtool-settings.json");
    let (adapter, generated, applied, launched) = SettingsWritingAdapter::new(devtool_settings.clone());
    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("spy-tool", Box::new(adapter));

    let mut devtool_args = exec_args(&[]);
    devtool_args.tool = "spy-tool".into();
    let code = execute_with_adapters(&devtool_args, &adapters)
        .await
        .expect("the dev-tool control launch must succeed");

    assert_eq!(code, 0);
    assert!(
        launched.load(Ordering::SeqCst),
        "the control must exercise the dev-tool path"
    );
    assert!(
        generated.load(Ordering::SeqCst) && applied.load(Ordering::SeqCst),
        "the control must show this adapter is one that generates and applies settings"
    );
    assert!(
        devtool_settings.exists(),
        "the control must show a settings write is observable at all; without it the assertion \
         above measures a spy that cannot write rather than a launch that did not"
    );
}

// --- negative control 2: exec must not shadow a tool id --------------------

/// **Negative control.** A registered tool id wins over the generic target.
///
/// Registering an adapter under the literal token `exec` is the only way to
/// measure the precedence directly: if the reserved word were resolved first, the
/// adapter would never be asked to build anything and the `exec` argv would be
/// launched as a program instead. The adapter records that it *was* asked.
///
/// This pins the rule from the direction that matters. Whether any tool happens
/// to be called `exec` today is a separate, weaker fact, asserted as a unit test
/// in `run.rs`.
#[tokio::test(flavor = "multi_thread")]
async fn a_registered_tool_id_wins_over_the_exec_target() {
    let gateway = TestGateway::start().await.expect("start gateway");
    let _env = GatewayEnv::point_at(gateway.endpoint());

    let dir = tempfile::tempdir().expect("tempdir");
    let never = dir.path().join("generic-was-launched");
    let (adapter, _generated, _applied, launched) = SettingsWritingAdapter::new(dir.path().join("settings.json"));

    let mut adapters: HashMap<&str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert("exec", Box::new(adapter));

    // An argv that would be unmistakable if it were ever treated as a program.
    let args = exec_args(&["/bin/sh", "-c", &format!("touch '{}'", never.display())]);
    let code = execute_with_adapters(&args, &adapters).await.expect("launch");

    assert_eq!(code, 0);
    assert!(
        launched.load(Ordering::SeqCst),
        "an id a tool answers to must resolve to that tool, not to a generic command"
    );
    assert!(
        !never.exists(),
        "the trailing arguments were launched as a program even though a tool claimed the id"
    );
}

/// A generic target with nothing after `--` names no program, and must say so
/// rather than defaulting to a shell.
#[tokio::test(flavor = "multi_thread")]
async fn exec_with_no_program_is_refused() {
    let err = execute_with_adapters(&exec_args(&[]), &no_adapters())
        .await
        .expect_err("`aasm run exec` with no program must be refused");

    assert!(
        err.to_string().contains("needs a program to launch"),
        "the refusal must say what is missing; got: {err}"
    );
}

/// The first `python3` on `PATH`, or `None`.
fn which_python() -> Option<String> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join("python3"))
        .find(|candidate| candidate.is_file())
        .map(|candidate| candidate.to_string_lossy().into_owned())
}
