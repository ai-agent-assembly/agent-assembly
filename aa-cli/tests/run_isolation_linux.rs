//! `aasm run --isolation process` measured against a real boundary (AAASM-5711).
//!
//! # What makes a scenario here count
//!
//! The design is `aa-isolation-sandlock/tests/linux_confinement.rs`'s, deliberately:
//! every scenario asserts on an **effect** — a file that exists or does not —
//! never on an exit code or an error message, and every scenario carries a
//! **control** that differs from it by one grant. A denial counts only when the
//! control produced the effect and the test did not, so a scenario cannot pass
//! because the command was broken, the directory was unwritable or the boundary
//! never started, all of which would also produce "no effect".
//!
//! What this file adds over that one is the *product* path. There the spec is
//! hand-built by the test; here it is lowered from a policy artifact an operator
//! wrote, negotiated by the planner, and executed by `aasm run`'s own supervisor
//! against a real gateway registration. The chain that could silently break is
//! policy → canonical projection → lowering → negotiation → confined launch, and
//! only an end-to-end run exercises all of it.
//!
//! # Never `2>/dev/null` inside a confined command
//!
//! The null device is *opened for writing*, and a default-deny boundary denies
//! it. A confined command carrying that redirection fails for the redirection
//! rather than for the thing under test, which previously made every control run
//! read as a spurious decline.
//!
//! # Skips are recorded, never silent
//!
//! A host that cannot run a scenario prints `SKIP [scenario]: reason` **and**
//! writes to the shared evidence ledger, which `.ci/test-evidence-summary.sh`
//! nets against the runner's pass count. A lane that declined everything cannot
//! report as a lane that measured something.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use aa_cli::commands::run::{execute_with_adapters, IsolationIntent, RunArgs};
use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo, PolicyDocument};
use aa_isolation_native::NativeBackend;
use aa_isolation_sandlock::SandlockBackend;
use async_trait::async_trait;

mod gateway_support;
use gateway_support::{GatewayEnv, TestGateway};

/// The shared evidence ledger, included by path.
///
/// Included rather than copied, for the reason the sandlock suite gives: one CI
/// summary reads every suite's records, and two implementations of "what a
/// decline looks like" would drift until the summary quietly stopped seeing one
/// of them.
#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

use evidence::Measurement;

// ---------------------------------------------------------------------------
// Guards.
// ---------------------------------------------------------------------------

/// Print and record a decline, and return `None`.
fn decline<T>(scenario: &str, measurement: Measurement, reason: &str) -> Option<T> {
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, measurement, reason);
    None
}

/// Record that a scenario took its measurement.
fn measured(scenario: &str, detail: &str) {
    evidence::record(scenario, Measurement::Measured, detail);
}

/// `Some(())` when this host can actually confine something.
///
/// The four preconditions are folded into one guard because they are answered by
/// the same object, and because a scenario that checked three of them and forgot
/// the fourth would report a missing measurement as a product failure. The three
/// decline reasons are kept apart because they need different fixes.
fn require_confining_host(scenario: &str) -> Option<()> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the process-isolation backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let backend = SandlockBackend::discover();
    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            "no confinement executable was found on this host; a lane that installs it and still reports \
             this is broken",
        );
    };
    if host.below_default_protection_floor() {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            "the kernel's access-control interface is below the mechanism's protection floor, so it will \
             not confine at all here; a newer runner can",
        );
    }
    let probe = backend.probe_result();
    if !probe.filesystem_write.is_denied() || !probe.filesystem_read.is_denied() {
        // Every precondition held and the boundary still denied nothing. That is
        // a failed measurement, not an opt-out, and it is the one state that
        // must never read as a skip.
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition. read: {} | write: {}",
                probe.filesystem_read.describe(),
                probe.filesystem_write.describe()
            ),
        );
    }
    Some(())
}

/// `Some(())` when this host can actually confine syscalls via the AASM-native
/// backend.
///
/// Mirrors [`require_confining_host`] for the other backend `--isolation auto`
/// can select (AAASM-5808): the native backend is what a syscall-restricting
/// policy resolves to, so a scenario that measures syscall confinement must
/// decline on a host that cannot demonstrate it rather than pass by accident
/// of the process never being confined at all.
fn require_confining_native_host(scenario: &str) -> Option<()> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the AASM-native backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let backend = NativeBackend::discover();
    let Some(_host) = backend.host() else {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            "no usable native launcher was found on this host; a lane that installs it and still \
             reports this is broken",
        );
    };
    let probe = backend.probe_result();
    if !probe.syscall.is_denied() {
        // Every precondition held and the discovery probe still observed no
        // syscall denial. That is a failed measurement, not an opt-out, and it
        // must never read as a skip.
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no syscall denial on a host that meets every \
                 precondition: {}",
                probe.syscall.describe()
            ),
        );
    }
    Some(())
}

// ---------------------------------------------------------------------------
// Fixtures.
// ---------------------------------------------------------------------------

/// A scratch tree with a permitted and a forbidden half.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        // Digits and dashes only: these paths are interpolated into a shell
        // redirection, and a name carrying a space would break the command
        // rather than the boundary.
        let root = std::env::temp_dir().join(format!(
            "aa-run-isolation-linux-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(root.join("permitted")).expect("permitted directory");
        std::fs::create_dir_all(root.join("forbidden")).expect("forbidden directory");
        Self { root }
    }

    fn permitted(&self) -> PathBuf {
        self.root.join("permitted")
    }

    fn forbidden(&self) -> PathBuf {
        self.root.join("forbidden")
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// The read grants a shell and its loader need, so that the only thing differing
/// between the two runs of a pair is the write grant under test.
fn system_reads() -> Vec<String> {
    ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(|p| (*p).to_string())
        .collect()
}

/// A policy artifact whose write allow-list is exactly `writes`.
///
/// Authored the way an operator authors one — `filesystem.write.allow`, the node
/// AAASM-5751 added — rather than assembled as a `ControlRequirement`. That is
/// the point of this suite: the requirement has to survive resolution, the
/// canonical projection and the lowering to get here.
fn policy_permitting_writes(scratch: &Scratch, name: &str, writes: &[PathBuf]) -> PathBuf {
    let reads: String = system_reads()
        .into_iter()
        .chain(std::iter::once(scratch.root.display().to_string()))
        .map(|p| format!("        - \"{p}\"\n"))
        .collect();
    let writes: String = writes
        .iter()
        .map(|p| format!("        - \"{}\"\n", p.display()))
        .collect();
    let path = scratch.root.join(name);
    std::fs::write(
        &path,
        format!(
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: run-isolation-linux\n\
             spec:\n\
             \x20 tools:\n\
             \x20   bash:\n\
             \x20     allow: true\n\
             \x20 filesystem:\n\
             \x20   read:\n\
             \x20     allow:\n{reads}\
             \x20   write:\n\
             \x20     allow:\n{writes}"
        ),
    )
    .expect("write policy");
    path
}

/// A policy artifact whose write allow-list is exactly `writes` and whose
/// syscall allow-list is exactly `syscalls`.
///
/// Authored the way an operator authors one — `syscalls.allow`, per
/// `aa-isolation/src/lowering.rs`'s syscall lowering — rather than assembled
/// as a `ControlRequirement`, for the same reason
/// [`policy_permitting_writes`] is: the requirement has to survive
/// resolution, the canonical projection and the lowering to get here, and
/// `--isolation auto` has to select a backend that can actually enforce it.
fn policy_permitting_writes_and_syscalls(
    scratch: &Scratch,
    name: &str,
    writes: &[PathBuf],
    syscalls: &[&str],
) -> PathBuf {
    let reads: String = system_reads()
        .into_iter()
        .chain(std::iter::once(scratch.root.display().to_string()))
        .map(|p| format!("        - \"{p}\"\n"))
        .collect();
    let writes: String = writes
        .iter()
        .map(|p| format!("        - \"{}\"\n", p.display()))
        .collect();
    let syscalls: String = syscalls.iter().map(|s| format!("      - \"{s}\"\n")).collect();
    let path = scratch.root.join(name);
    std::fs::write(
        &path,
        format!(
            "apiVersion: agent-assembly/v1\n\
             kind: Policy\n\
             metadata:\n\
             \x20 name: run-isolation-linux-native\n\
             spec:\n\
             \x20 tools:\n\
             \x20   bash:\n\
             \x20     allow: true\n\
             \x20 filesystem:\n\
             \x20   read:\n\
             \x20     allow:\n{reads}\
             \x20   write:\n\
             \x20     allow:\n{writes}\
             \x20 syscalls:\n\
             \x20   allow:\n{syscalls}"
        ),
    )
    .expect("write policy");
    path
}

/// `aasm run exec --isolation process -- /bin/sh -c <script>`.
fn confined_exec_args(policy: &Path, script: &str) -> RunArgs {
    RunArgs {
        tool: "exec".into(),
        tool_args: vec!["/bin/sh".into(), "-c".into(), script.to_string()],
        agent_id: None,
        team_id: None,
        root_agent: None,
        governance_level: None,
        // These measure the execution boundary, not proxy trust. Without it a
        // launch refuses unless a verified proxy is running on this host.
        no_proxy: true,
        policy: Some(policy.to_path_buf()),
        workdir: None,
        dry_run: false,
        enforcement_mode: None,
        observe: false,
        isolation: IsolationIntent::Process,
        isolation_backend: None,
    }
}

/// A shell command whose whole observable effect is creating `target`.
fn creates(target: &Path) -> String {
    format!("printf x > {}", target.display())
}

/// A developer-tool adapter that launches `script` through a shell.
///
/// Stands in for a real dev tool so the dev-tool arm and the generic arm can be
/// measured against the *same* effect. What is under test is that both reach the
/// same execution-isolation planning path, not what any particular tool does.
struct ScriptedDevTool {
    script: String,
}

#[async_trait]
impl DevToolAdapter for ScriptedDevTool {
    fn detect(&self) -> Option<DevToolInfo> {
        Some(DevToolInfo {
            kind: DevToolKind::ClaudeCode,
            version: Some("1.0.0".into()),
            install_path: PathBuf::from("/bin/sh"),
            governance_level: GovernanceLevel::L2Enforce,
            supports_mcp: false,
            supports_managed_settings: false,
        })
    }

    async fn generate_managed_settings(&self, _p: &PolicyDocument) -> Result<String, AdapterError> {
        Ok("{}".into())
    }

    /// Deliberately writes nothing. A managed-settings write is a host mutation
    /// and these scenarios assert on host state; a real one would put a second
    /// writer in the measurement.
    async fn apply_settings(&self, _settings: &str) -> Result<(), AdapterError> {
        Ok(())
    }

    fn build_launch_command(
        &self,
        _args: &[String],
        _agent_id: &str,
        _team_id: Option<&str>,
        _proxy_addr: Option<&str>,
    ) -> Result<std::process::Command, AdapterError> {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg(&self.script);
        // The variable a dev-tool adapter contributes and whose absence makes a
        // session ungoverned. Asserted inside the boundary by
        // `the_adapter_environment_reaches_the_confined_program`.
        cmd.env("NODE_EXTRA_CA_CERTS", "/aa-5711/adapter-supplied-ca.pem");
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

/// Drive one governed launch against a real gateway.
fn launch(args: &RunArgs, adapters: HashMap<&str, Box<dyn DevToolAdapter>>) -> anyhow::Result<i32> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    runtime.block_on(async move {
        let gateway = TestGateway::start().await.expect("test gateway");
        let _env = GatewayEnv::point_at(gateway.endpoint());
        execute_with_adapters(args, &adapters).await
    })
}

fn no_adapters() -> HashMap<&'static str, Box<dyn DevToolAdapter>> {
    HashMap::new()
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

/// **The generic target, confined.** A write outside the operator's own
/// `filesystem.write.allow` list does not happen.
///
/// The controlled pair: both runs execute the identical command through the
/// identical launch path, and the artifacts differ by exactly one entry in
/// `filesystem.write.allow`. The control must produce the file; the test must
/// not. Either half alone proves nothing.
#[test]
fn a_confined_generic_target_cannot_write_outside_the_policys_write_scope() {
    const SCENARIO: &str = "aasm-run-exec-confined-write-denied";
    if require_confining_host(SCENARIO).is_none() {
        return;
    }
    let scratch = Scratch::new("exec-write");
    let target = scratch.forbidden().join("escaped");

    // Control: the same launch with the forbidden directory permitted.
    let control_policy =
        policy_permitting_writes(&scratch, "control.yaml", &[scratch.permitted(), scratch.forbidden()]);
    let _ = launch(&confined_exec_args(&control_policy, &creates(&target)), no_adapters())
        .expect("the control launch runs");
    assert!(
        target.exists(),
        "the control run produced no effect, so the test run's absence would mean nothing: {} is missing",
        target.display()
    );
    std::fs::remove_file(&target).expect("reset between the pair");

    // Test: the identical command, with only the permitted half granted.
    let test_policy = policy_permitting_writes(&scratch, "test.yaml", &[scratch.permitted()]);
    let _ = launch(&confined_exec_args(&test_policy, &creates(&target)), no_adapters());
    assert!(
        !target.exists(),
        "the confined program wrote outside the policy's write scope: {} exists",
        target.display()
    );

    measured(
        SCENARIO,
        "a generic exec target confined by an operator-authored filesystem.write.allow list did not \
         create a file outside it, and the same launch with the directory granted did",
    );
}

/// **The developer-tool target, confined**, through the same planning path.
///
/// AC 2 is that a dev tool and a generic command use *one* execution-isolation
/// planning path, so the assertion is the same effect under the same pair of
/// artifacts — reached through an adapter's `build_launch_command` instead of
/// through argv.
#[test]
fn a_confined_dev_tool_cannot_write_outside_the_policys_write_scope() {
    const SCENARIO: &str = "aasm-run-devtool-confined-write-denied";
    if require_confining_host(SCENARIO).is_none() {
        return;
    }
    let scratch = Scratch::new("devtool-write");
    let target = scratch.forbidden().join("escaped");

    let adapters = || -> HashMap<&'static str, Box<dyn DevToolAdapter>> {
        let mut map: HashMap<&'static str, Box<dyn DevToolAdapter>> = HashMap::new();
        map.insert(
            "claude",
            Box::new(ScriptedDevTool {
                script: creates(&target),
            }),
        );
        map
    };
    let args_for = |policy: &Path| {
        let mut args = confined_exec_args(policy, "unused");
        args.tool = "claude".into();
        args.tool_args = Vec::new();
        args
    };

    let control_policy =
        policy_permitting_writes(&scratch, "control.yaml", &[scratch.permitted(), scratch.forbidden()]);
    let _ = launch(&args_for(&control_policy), adapters()).expect("the control launch runs");
    assert!(
        target.exists(),
        "the control run produced no effect: {} is missing",
        target.display()
    );
    std::fs::remove_file(&target).expect("reset between the pair");

    let test_policy = policy_permitting_writes(&scratch, "test.yaml", &[scratch.permitted()]);
    let _ = launch(&args_for(&test_policy), adapters());
    assert!(
        !target.exists(),
        "the confined developer tool wrote outside the policy's write scope: {} exists",
        target.display()
    );

    measured(
        SCENARIO,
        "a developer-tool launch reached the same execution-isolation planning path as a generic target \
         and was denied the same write, with the granted control producing the effect",
    );
}

/// The confined program's exit code is the launcher's exit code.
///
/// Two values rather than one: a supervisor that returned a constant would pass
/// a single-value assertion, and `0` in particular is what a swallowed failure
/// looks like.
#[test]
fn a_confined_launch_propagates_the_programs_exit_code() {
    const SCENARIO: &str = "aasm-run-confined-exit-code";
    if require_confining_host(SCENARIO).is_none() {
        return;
    }
    let scratch = Scratch::new("exit-code");
    let artifact = policy_permitting_writes(&scratch, "p.yaml", &[scratch.permitted()]);

    let zero = launch(&confined_exec_args(&artifact, "exit 0"), no_adapters()).expect("a confined launch runs");
    assert_eq!(zero, 0, "a clean exit was not propagated");

    let seven = launch(&confined_exec_args(&artifact, "exit 7"), no_adapters()).expect("a confined launch runs");
    assert_eq!(seven, 7, "the program's exit code was replaced by the supervisor's");

    measured(
        SCENARIO,
        "a confined launch propagated both a zero and a non-zero exit code from the program through the \
         mechanism and the supervisor unchanged",
    );
}

/// The governance identity and the adapter's own variables reach the program
/// *inside* the boundary.
///
/// AC 7. The confined program is a different process from the supervisor, and a
/// launch that let it inherit the supervisor's environment instead of installing
/// the resolved one would lose exactly the variables whose absence makes a
/// session ungoverned. The program writes what it sees into a permitted path, so
/// the assertion is on what arrived rather than on what was sent.
#[test]
fn the_adapter_environment_reaches_the_confined_program() {
    const SCENARIO: &str = "aasm-run-confined-child-environment";
    if require_confining_host(SCENARIO).is_none() {
        return;
    }
    let scratch = Scratch::new("child-env");
    let artifact = policy_permitting_writes(&scratch, "p.yaml", &[scratch.permitted()]);
    let seen = scratch.permitted().join("environment");

    let mut args = confined_exec_args(&artifact, "unused");
    args.tool = "claude".into();
    args.tool_args = Vec::new();
    args.agent_id = Some("aa-5711-env-probe".into());
    let mut adapters: HashMap<&'static str, Box<dyn DevToolAdapter>> = HashMap::new();
    adapters.insert(
        "claude",
        Box::new(ScriptedDevTool {
            script: format!(
                "printf 'agent=%s ca=%s policy=%s' \"$AA_AGENT_ID\" \"$NODE_EXTRA_CA_CERTS\" \
                 \"$AA_POLICY_STATE\" > {}",
                seen.display()
            ),
        }),
    );

    let _ = launch(&args, adapters).expect("the confined launch runs");
    let observed = std::fs::read_to_string(&seen).unwrap_or_else(|e| {
        panic!(
            "the confined program wrote no environment record to {}: {e}",
            seen.display()
        )
    });

    assert!(
        observed.contains("agent=aa-5711-env-probe"),
        "the governance identity did not reach the confined program: {observed}"
    );
    assert!(
        observed.contains("ca=/aa-5711/adapter-supplied-ca.pem"),
        "the adapter's own contribution did not reach the confined program — this is the AAASM-5327 \
         failure inside the boundary: {observed}"
    );
    assert!(
        observed.contains("policy=enforced"),
        "the policy annotation did not reach the confined program: {observed}"
    );

    measured(
        SCENARIO,
        "the governance identity, the adapter's NODE_EXTRA_CA_CERTS and the policy annotation were all \
         observed by the program from inside the boundary",
    );
}

/// **End-to-end: `--isolation auto` selects the native backend for a
/// syscall-restricting policy, and the confined program is killed for a
/// syscall outside its allowlist.**
///
/// The scenario `run_isolation.rs` cannot measure on any host, because it
/// needs a backend that can actually confine syscalls: Sandlock reports no
/// mechanism for `CapabilityDomain::Syscall` at all, so a policy carrying
/// `syscalls.allow` and nothing else the sandlock domains can satisfy is a
/// launch only the native backend can plan — proving `--isolation auto`
/// (AAASM-5808) walks past Sandlock and selects it through the real CLI path,
/// not through a fixture. The assertion is on the observed effect — the
/// target file's content — never on exit code alone, per this file's own
/// rule; the control is the identical launch with `write` additionally
/// allowlisted.
#[test]
fn an_auto_selected_native_backend_kills_a_syscall_outside_its_allowlist() {
    const SCENARIO: &str = "aasm-run-auto-native-syscall-denied";
    if require_confining_native_host(SCENARIO).is_none() {
        return;
    }
    let scratch = Scratch::new("auto-native-syscall");
    let target = scratch.permitted().join("secret");

    // `openat(O_CREAT)` is inside the baseline the native backend always
    // grants a launcher, so the target file's mere *existence* is a false
    // positive: it exists whether or not `write` ran. What `write` decides is
    // whether the empty file `openat` created gets any bytes in it.
    let has_content = |p: &Path| p.exists() && std::fs::read(p).map(|b| !b.is_empty()).unwrap_or(false);
    let baseline: &[&str] = &[
        "read",
        "openat",
        "close",
        "fstat",
        "lseek",
        "mmap",
        "munmap",
        "brk",
        "exit_group",
        "rt_sigaction",
        "rt_sigprocmask",
        "clock_gettime",
        "getrandom",
    ];

    // Control: the identical launch with `write` additionally allowlisted.
    let mut allowlisted = baseline.to_vec();
    allowlisted.push("write");
    let control_policy =
        policy_permitting_writes_and_syscalls(&scratch, "control.yaml", &[scratch.permitted()], &allowlisted);
    let mut control_args = confined_exec_args(&control_policy, &creates(&target));
    control_args.isolation = IsolationIntent::Auto;
    let _ = launch(&control_args, no_adapters()).expect("the control launch runs");
    assert!(
        has_content(&target),
        "the control run, with `write` allowlisted, did not produce the effect, so the kill below \
         proves nothing"
    );
    std::fs::remove_file(&target).expect("reset between the pair");

    // Test: the identical launch, `write` omitted from the syscall allowlist.
    let test_policy = policy_permitting_writes_and_syscalls(&scratch, "test.yaml", &[scratch.permitted()], baseline);
    let mut test_args = confined_exec_args(&test_policy, &creates(&target));
    test_args.isolation = IsolationIntent::Auto;
    let _ = launch(&test_args, no_adapters());
    assert!(
        !has_content(&target),
        "the confined program wrote even though `write` was not in the syscall allowlist: {} has content",
        target.display()
    );

    measured(
        SCENARIO,
        "a syscalls.allow policy resolved `--isolation auto` to the native backend, its filter killed \
         the process for the write it did not permit, and the identical launch with `write` \
         allowlisted produced the effect instead",
    );
}
