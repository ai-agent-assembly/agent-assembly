//! End-to-end confinement measurements on a real Linux host (AAASM-5708).
//!
//! # What makes a scenario here count
//!
//! Every scenario asserts on an **effect**, never on an exit code or an error
//! message: a file that exists or does not, bytes that arrived or did not, a
//! connection that was accepted or was not. An exit code says what a program
//! reported; the effect says what happened.
//!
//! And every scenario carries a **control**. The control run and the test run
//! execute the same command with the same confinement, differing by one grant.
//! A denial counts only when the control produced the effect and the test did
//! not — so a scenario cannot pass because the command was broken, the
//! directory was unwritable or the sandbox never started, all of which would
//! also produce "no effect".
//!
//! # Skips are recorded, never silent
//!
//! A host that cannot run a scenario prints `SKIP [scenario]: reason` **and**
//! writes a record to the evidence ledger, which `.ci/test-evidence-summary.sh`
//! nets against the runner's pass count. A lane that declined everything cannot
//! report as a lane that measured something. The three decline reasons are kept
//! apart because they need different fixes:
//!
//! * [`Measurement::UnsupportedPlatform`] — this host can never run it. A
//!   different runner can. macOS, or a kernel below the mechanism's floor.
//! * [`Measurement::ToolAbsent`] — the platform is fine and the mechanism is not
//!   installed. Honest on a laptop; a broken lane in CI, which installs it.
//! * [`Measurement::NotMeasured`] — every precondition held, the scenario
//!   committed to measuring, and no measurement came out. A failure, not an
//!   opt-out.
//!
//! # Why this suite lives in this crate rather than `aa-integration-tests`
//!
//! It measures one backend's boundary against the host kernel and needs no
//! gateway, no database and no server. Putting it beside the code it measures
//! keeps `cargo nextest run -p aa-isolation-sandlock` a complete answer to "does
//! this backend still confine anything".

use std::collections::BTreeMap;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, DescendantRequirement, EnforcementEvidence,
    ExecutionHandle, ExecutionSpec, IdentityRef, IsolationBackend, RequirementScope, ResourceLimits,
};
use aa_isolation_sandlock::{host::DEFAULT_PROTECTION_FLOOR_ABI, CompletedRun, SandlockBackend};

/// The shared evidence ledger, included by path.
///
/// Included rather than copied: one CI summary reads every suite's records, and
/// two implementations of "what a decline looks like" would drift until the
/// summary quietly stopped seeing one of them. The module has no dependencies,
/// so including it costs this crate no dev-dependency.
#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

use evidence::Measurement;

/// The synthetic content a read scenario looks for. Unmistakably fabricated,
/// and distinctive enough that it cannot appear in a diagnostic by accident.
const SECRET: &str = "aa-sandlock-conformance-secret-4d71";

// ---------------------------------------------------------------------------
// Guards. Each prints a visible skip and records it, so no opt-out path can
// forget to declare itself — the reason `require_*` records inside the guard
// rather than at the call site.
// ---------------------------------------------------------------------------

/// A backend that measured a working boundary on this host, or a recorded skip.
///
/// Folds four preconditions into one guard because they are answered by the same
/// object, and because a scenario that checked three of them and forgot the
/// fourth would report a missing measurement as a product failure.
fn require_confining_backend(scenario: &str) -> Option<SandlockBackend> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the sandlock backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    let backend = SandlockBackend::discover().with_captured_output(true);

    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            "no sandlock executable was found; a lane that installs it and still reports this is broken",
        );
    };

    // The mechanism refuses to confine at all below its own protection floor,
    // so a host under it cannot be measured — by any configuration of this
    // runner. A newer runner can, which is what makes this an unsupported
    // platform rather than an absent tool.
    if host.below_default_protection_floor() {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the kernel's access-control interface is {} and the mechanism enforces every \
                 protection it knows about, requiring at least version {DEFAULT_PROTECTION_FLOOR_ABI}. \
                 Self-check said: {}",
                host.landlock_abi()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unreadable".to_string()),
                host.self_check()
                    .unwrap_or("<no self-check output>")
                    .replace('\n', " | ")
            ),
        );
    }

    let probe = backend.probe_result();
    if !probe.filesystem_write.is_denied() || !probe.filesystem_read.is_denied() {
        // Every precondition held and the boundary still did not deny anything.
        // That is a failed measurement, not an opt-out, and it is the one state
        // that must never read as a skip.
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
    Some(backend)
}

/// Print and record a decline, and return `None`.
fn decline<T>(scenario: &str, measurement: Measurement, reason: &str) -> Option<T> {
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, measurement, reason);
    None
}

/// Record that a scenario took its measurement.
///
/// The summary script computes substance by subtracting declines from the
/// runner's pass count, so this record changes no arithmetic. It is written
/// anyway: the per-scenario list in the job summary is the only place a reader
/// can see *which* scenarios measured, and a lane that reports only its failures
/// makes the successes unauditable.
fn measured(scenario: &str, detail: &str) {
    evidence::record(scenario, Measurement::Measured, detail);
}

// ---------------------------------------------------------------------------
// Fixture.
// ---------------------------------------------------------------------------

/// A scratch tree that removes itself, with a permitted and a forbidden half.
struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aa-sandlock-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        ));
        std::fs::create_dir_all(root.join("permitted")).expect("scratch permitted directory");
        std::fs::create_dir_all(root.join("forbidden")).expect("scratch forbidden directory");
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

/// The read grants every scenario needs so the loader and the shell work, and
/// the only thing under test is the grant that differs between the runs.
fn system_reads() -> Vec<String> {
    ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"]
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(|p| permit_only_selector(p))
        .collect()
}

/// A spec that runs `script` through a shell, with the given extra grants.
fn shell_spec(script: &str, reads: Vec<String>, writes: Vec<String>) -> ExecutionSpec {
    let mut all_reads = system_reads();
    all_reads.extend(reads);
    ExecutionSpec::new("/bin/sh", IdentityRef::root("agent-under-test"))
        .with_args(["-c", script])
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(all_reads)),
        )
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
                .with_scope(RequirementScope::Selectors(writes)),
        )
}

/// Plan, prepare, launch and wait — the whole contract in the order ADR 0035
/// fixes it.
fn run(backend: &SandlockBackend, spec: &ExecutionSpec) -> (CompletedRun, EnforcementEvidence) {
    let plan = backend
        .plan(spec)
        .unwrap_or_else(|refusal| panic!("the backend refused a spec this scenario needs: {refusal:?}"));
    let prepared = backend.prepare(plan).expect("the boundary could not be prepared");
    let handle: ExecutionHandle = backend
        .spawn(prepared)
        .expect("the confined program could not be launched");
    let completed = backend.wait(&handle).expect("waiting for the confined program failed");
    let evidence = backend.evidence(&handle);
    (completed, evidence)
}

/// A shell command that performs `inner` from a *grandchild* of the launched
/// process, so what is measured is descendant coverage and not the launched
/// process alone.
fn as_grandchild(inner: &str) -> String {
    // No `2>/dev/null`: the null device is opened for *writing*, which a
    // default-deny write policy denies, so the redirection would fail before
    // the command under test ever ran. Stderr is captured by the backend and
    // only surfaces in an assertion message.
    format!("/bin/sh -c {}; exit 0", quote(inner))
}

/// Single-quote a value for a shell script this test constructs.
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

/// AC: a trivial child can be launched and its exit status, stdout and stderr
/// behaviour is preserved.
///
/// The control is the pair of runs: the same program with a different exit
/// code. Asserting `7` alone would also pass against a backend that returned a
/// constant.
#[test]
fn a_trivial_child_keeps_its_exit_status_and_its_streams() {
    let scenario = "trivial child streams and exit status";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let spec = shell_spec("printf on-stdout; printf on-stderr >&2; exit 7", Vec::new(), Vec::new());
    let (completed, evidence) = run(&backend, &spec);

    assert_eq!(completed.stdout, "on-stdout", "stdout did not pass through unchanged");
    assert!(
        completed.stderr.contains("on-stderr"),
        "stderr did not pass through: {:?}",
        completed.stderr
    );
    assert_eq!(
        completed.status.code(),
        Some(7),
        "the child's exit status was not preserved"
    );

    let zero = shell_spec("exit 0", Vec::new(), Vec::new());
    let (control, _) = run(&backend, &zero);
    assert_eq!(
        control.status.code(),
        Some(0),
        "the exit status is a constant, not the child's"
    );

    // A successful launch is not evidence that any control decided anything,
    // and this backend must never say otherwise.
    for domain in CapabilityDomain::ALL {
        assert!(
            !evidence.supports_prevention_claim(*domain),
            "{domain} produced a prevention claim from a run with no decision record"
        );
    }
    measured(
        scenario,
        "exit status 7 and both streams preserved; control run exited 0",
    );
}

/// AC: argv survives to the child verbatim.
///
/// End-to-end rather than at the command-line builder: the question is whether
/// anything between this process and the child re-parses an argument, and only
/// the child can answer it.
#[test]
fn hostile_argv_reaches_the_child_verbatim() {
    let scenario = "argv passed as argv";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let hostile = "; id; --fs-write=/ $(id) `id` --no-supervisor";
    let mut reads = system_reads();
    reads.push(permit_only_selector("/tmp"));
    let spec = ExecutionSpec::new("/bin/sh", IdentityRef::root("agent-under-test"))
        .with_args(["-c", "printf %s \"$1\"", "sh", hostile])
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(reads)),
        );
    let (completed, _) = run(&backend, &spec);

    assert_eq!(
        completed.stdout, hostile,
        "an argument was re-parsed on the way to the child"
    );
    assert!(
        !completed.stdout.contains("uid="),
        "a substitution ran: {:?}",
        completed.stdout
    );
    measured(
        scenario,
        "shell metacharacters and backend flags arrived as one literal argument",
    );
}

/// AC: a filesystem-deny demonstrates **pre-effect** denial.
///
/// The forbidden file exists and has content before the run. A control that
/// stopped the write *after* it took effect would leave the file truncated or
/// changed; the assertion is that it is byte-for-byte what it was. That is what
/// makes this pre-effect rather than merely denied.
#[test]
fn a_forbidden_write_never_takes_effect() {
    let scenario = "filesystem write denied before the effect";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("fs-write");
    let victim = scratch.forbidden().join("existing");
    std::fs::write(&victim, "original").expect("fixture");
    let created = scratch.forbidden().join("created");

    let script = as_grandchild(&format!(
        "printf tampered > {}; printf x > {}",
        quote(&victim.to_string_lossy()),
        quote(&created.to_string_lossy())
    ));

    // Test run: only the permitted half is writable.
    let spec = shell_spec(
        &script,
        vec![permit_only_selector(&scratch.root.to_string_lossy())],
        vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
    );
    let (_, evidence) = run(&backend, &spec);

    assert_eq!(
        std::fs::read_to_string(&victim).expect("the victim file must still be readable"),
        "original",
        "the write took effect and was undone afterwards, or was never denied — either way it is not \
         pre-effect denial"
    );
    assert!(!created.exists(), "a forbidden file was created: {}", created.display());

    // Control: grant the forbidden half and the identical script lands.
    let control_spec = shell_spec(
        &script,
        vec![permit_only_selector(&scratch.root.to_string_lossy())],
        vec![permit_only_selector(&scratch.root.to_string_lossy())],
    );
    run(&backend, &control_spec);
    assert_eq!(
        std::fs::read_to_string(&victim).expect("readable"),
        "tampered",
        "the control run did not perform the write either, so the test run proves nothing"
    );
    assert!(created.exists(), "the control run did not create the file either");

    // The report must match what was just observed.
    let report = backend
        .capabilities()
        .report_for(CapabilityDomain::FilesystemWrite)
        .cloned()
        .expect("the domain is reported");
    assert!(
        report.can_prevent(),
        "the backend observed a pre-effect denial and still does not report the domain as preventing"
    );
    assert!(
        !evidence.supports_prevention_claim(CapabilityDomain::FilesystemWrite),
        "the kernel denied the write, but the mechanism reports no decision to the supervisor, so no \
         prevention claim may be derived from this run"
    );
    measured(
        scenario,
        "an existing file was unchanged and a new file was never created under confinement; the same \
         script with the grant changed both",
    );
}

/// AC: a forbidden read yields nothing, and the control shows the read works.
#[test]
fn a_forbidden_read_returns_no_bytes() {
    let scenario = "filesystem read denied";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("fs-read");
    let secret = scratch.forbidden().join("secret");
    std::fs::write(&secret, SECRET).expect("fixture");
    let script = as_grandchild(&format!("cat {}", quote(&secret.to_string_lossy())));

    let (denied, _) = run(&backend, &shell_spec(&script, Vec::new(), Vec::new()));
    assert!(
        !denied.stdout.contains(SECRET),
        "the confined process read a file the launch did not permit: {:?}",
        denied.stdout
    );

    let (control, _) = run(
        &backend,
        &shell_spec(
            &script,
            vec![permit_only_selector(&scratch.forbidden().to_string_lossy())],
            Vec::new(),
        ),
    );
    assert!(
        control.stdout.contains(SECRET),
        "the control run did not read the file either, so the denial above proves nothing: {:?}",
        control.stdout
    );
    measured(
        scenario,
        "a grandchild read nothing without the grant and the secret with it",
    );
}

/// AC: descendants cannot regain broader authority.
///
/// Two directions, because "a descendant is confined" and "a descendant cannot
/// widen its confinement" are different claims:
///
/// 1. the grandchild is subject to the same denial as the launched process; and
/// 2. a grandchild that re-invokes the mechanism asking for a *wider* grant
///    still does not get it.
///
/// The second is the one that matters: an agent that can re-enter the sandbox
/// with better terms has no boundary at all.
#[test]
fn a_descendant_cannot_regain_broader_authority() {
    let scenario = "descendants cannot widen authority";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let Some(mechanism) = backend.host().map(|h| h.executable().to_path_buf()) else {
        return;
    };
    let scratch = Scratch::new("descendant");
    let direct = scratch.forbidden().join("direct");
    let widened = scratch.forbidden().join("widened");

    // (1) the grandchild's own attempt.
    let script = as_grandchild(&format!("printf x > {}", quote(&direct.to_string_lossy())));
    run(&backend, &shell_spec(&script, Vec::new(), Vec::new()));
    assert!(
        !direct.exists(),
        "a grandchild wrote where the launch did not permit it"
    );

    // (2) the grandchild asks the mechanism for a wider grant than it has.
    let reinvoke = format!(
        "{} run --fs-read=/ --fs-write={} -- /bin/sh -c {}",
        mechanism.display(),
        quote(&scratch.root.to_string_lossy()),
        quote(&format!("printf x > {}", quote(&widened.to_string_lossy())))
    );
    run(&backend, &shell_spec(&as_grandchild(&reinvoke), Vec::new(), Vec::new()));
    // Whichever layer refuses — the kernel's monotonic restriction or the
    // mechanism's own refusal to nest a supervisor — the property under test is
    // the same and is stated in terms of the effect: the wider grant produced
    // nothing.
    assert!(
        !widened.exists(),
        "a descendant re-entered the mechanism with a wider grant and got it: {} exists",
        widened.display()
    );

    // The control for (2): the identical command outside the boundary does
    // create the file, so its absence above is the boundary and not the command.
    let control = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&reinvoke)
        .output()
        .expect("the control command runs");
    assert!(
        widened.exists(),
        "the same re-invocation outside the boundary also failed, so the assertion above proves \
         nothing. stderr: {}",
        String::from_utf8_lossy(&control.stderr)
    );

    let report = backend
        .capabilities()
        .report_for(CapabilityDomain::FilesystemWrite)
        .cloned()
        .expect("reported");
    assert_eq!(
        report.descendants(),
        aa_isolation::DescendantCoverage::ProcessTree,
        "descendant coverage was observed and is not reported"
    );
    measured(
        scenario,
        "a grandchild was denied directly, and a grandchild re-invoking the mechanism with a wider \
         grant was still denied, while the same re-invocation outside the boundary succeeded",
    );
}

/// AC: a network-deny demonstrates the backend's actual enforcement semantics
/// for a forbidden destination.
///
/// Loopback rather than a public host, so the measurement needs no DNS, no
/// route and no third party, and cannot pass because a remote endpoint was
/// down. The assertion is on the *listener*: whether a connection arrived, not
/// whether the client reported an error.
#[test]
fn a_forbidden_destination_is_never_connected() {
    let scenario = "network egress denied";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    if which("python3").is_none() {
        decline::<()>(
            scenario,
            Measurement::ToolAbsent,
            "python3 is not on PATH and no POSIX shell can open a TCP connection; a lane that \
             provisions it and still reports this is broken",
        );
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener");
    listener.set_nonblocking(true).expect("non-blocking listener");
    let port = listener.local_addr().expect("addr").port();
    let script = as_grandchild(&format!(
        "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',{port}),3);s.sendall(b'{SECRET}')\""
    ));

    // Test run: no destination is permitted.
    run(&backend, &shell_spec(&script, Vec::new(), Vec::new()));
    assert!(
        accepted_payload(&listener).is_none(),
        "a connection the launch did not permit reached the listener"
    );

    // Control: the identical spec with exactly one thing added — a permitted
    // destination. Nothing else about the two runs differs, so the connection
    // that arrives below is attributable to that grant and to nothing else.
    let control = shell_spec(&script, Vec::new(), Vec::new()).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::NetworkEgress).with_scope(RequirementScope::Selectors(vec![
            permit_only_selector(&format!("127.0.0.1:{port}")),
        ])),
    );
    run(&backend, &control);
    let payload = accepted_payload(&listener);
    assert_eq!(
        payload.as_deref(),
        Some(SECRET),
        "the control run did not reach the listener either, so the denial above proves nothing"
    );

    let report = backend
        .capabilities()
        .report_for(CapabilityDomain::NetworkEgress)
        .cloned()
        .expect("reported");
    assert!(
        report.can_prevent(),
        "an egress denial was observed and the domain is not reported as preventing"
    );
    measured(
        scenario,
        "a grandchild's connection to an unpermitted loopback destination never reached the listener; \
         the same connection with the destination permitted did",
    );
}

/// AC: at least one process/resource constraint is exercised end-to-end.
///
/// A ceiling of one process leaves room for the launched shell and nothing
/// below it, so the grandchild that would produce the effect never exists. The
/// control is the identical spec without the ceiling.
#[test]
fn a_process_ceiling_stops_the_descendant_from_existing() {
    let scenario = "process ceiling enforced";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("ceiling");
    let target = scratch.permitted().join("forked");
    let script = as_grandchild(&format!("printf x > {}", quote(&target.to_string_lossy())));
    let writes = vec![permit_only_selector(&scratch.permitted().to_string_lossy())];

    // Control first: without the ceiling, the grandchild lands its effect.
    run(&backend, &shell_spec(&script, Vec::new(), writes.clone()));
    assert!(
        target.exists(),
        "the control run produced no effect, so the ceiling below cannot be shown to have stopped one"
    );
    std::fs::remove_file(&target).expect("reset between runs");

    let ceilinged = shell_spec(&script, Vec::new(), writes).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Resource).with_scope(RequirementScope::Limits(ResourceLimits {
            max_pids: Some(1),
            ..ResourceLimits::default()
        })),
    );
    run(&backend, &ceilinged);
    assert!(
        !target.exists(),
        "the process ceiling did not stop the descendant: {} exists",
        target.display()
    );
    measured(
        scenario,
        "a grandchild produced its effect without a ceiling and did not exist with a ceiling of one",
    );
}

/// AC: an absent backend is reported before launch, not as a runtime surprise.
///
/// The assertion is that the program's effect never happened — a refusal that
/// still ran the program would be a refusal in name only.
#[test]
fn an_absent_backend_refuses_before_the_program_runs() {
    let scenario = "absent backend refuses before launch";
    // Deliberately ungated: this scenario needs no mechanism and no Linux, and
    // gating it would make the one property that holds everywhere the one
    // property nothing checks.
    let scratch = Scratch::new("absent");
    let target = scratch.permitted().join("should-never-exist");
    let backend = SandlockBackend::unavailable(&aa_isolation_sandlock::BackendLookupError::NotOnPath);
    let spec = shell_spec(
        &format!("printf x > {}", quote(&target.to_string_lossy())),
        Vec::new(),
        vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
    );

    let refusal = backend
        .plan(&spec)
        .expect_err("an absent mechanism must refuse rather than plan");
    assert!(
        refusal.backend_unavailable().is_some(),
        "the refusal must name the host-level reason: {refusal:?}"
    );
    assert!(
        !target.exists(),
        "the program ran despite the refusal: {} exists",
        target.display()
    );

    let evidence = EnforcementEvidence::from_refusal(&refusal);
    assert_eq!(evidence.posture(), aa_isolation::LaunchPosture::Refused);
    measured(scenario, "planning refused and the program's effect never happened");
}

/// AC: a required capability the backend cannot enforce refuses before the
/// child starts, with no silent unconfined fallback.
///
/// Name resolution is the case: the mechanism redirects it rather than deciding
/// about it, so the domain is unsupported by construction on every host. The
/// control is the same spec with the requirement made optional, which plans.
#[test]
fn a_required_unsupported_capability_refuses_and_its_optional_twin_does_not() {
    let scenario = "unsupported capability refuses before launch";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("unsupported");
    let target = scratch.permitted().join("should-never-exist");
    let script = format!("printf x > {}", quote(&target.to_string_lossy()));
    let writes = vec![permit_only_selector(&scratch.permitted().to_string_lossy())];

    let required = shell_spec(&script, Vec::new(), writes.clone())
        .with_requirement(ControlRequirement::prevent(CapabilityDomain::NameResolution));
    let refusal = backend.plan(&required).expect_err("an unsupported domain must refuse");
    assert!(
        refusal
            .unmet()
            .iter()
            .any(|(requirement, _)| requirement.domain() == CapabilityDomain::NameResolution),
        "the refusal must name the domain that could not be met: {refusal:?}"
    );
    assert!(!target.exists(), "the program ran despite the refusal");

    let optional = shell_spec(&script, Vec::new(), writes).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::NameResolution)
            .with_posture(aa_isolation::RequirementPosture::Optional),
    );
    let (_, evidence) = run(&backend, &optional);
    assert!(
        target.exists(),
        "the optional twin did not run, so the refusal is not attributable"
    );
    assert_eq!(
        evidence.posture(),
        aa_isolation::LaunchPosture::Degraded,
        "a launch that could not meet a requirement must not present as fully protected"
    );
    measured(
        scenario,
        "a required name-resolution requirement refused before launch; the identical spec with an \
         optional posture ran and reported a degraded launch",
    );
}

/// A process-tree requirement must be refused when descendant coverage was not
/// measured — the direction that keeps an unmeasured boundary from reading as
/// one.
#[test]
fn the_capability_report_is_backed_by_the_probe_on_this_host() {
    let scenario = "reported capabilities match the probe";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let probe = backend.probe_result();
    let capabilities = backend.capabilities();

    for (domain, observation) in [
        (CapabilityDomain::FilesystemRead, &probe.filesystem_read),
        (CapabilityDomain::FilesystemWrite, &probe.filesystem_write),
        (CapabilityDomain::NetworkEgress, &probe.network_egress),
        (CapabilityDomain::ProcessCreation, &probe.process_ceiling),
    ] {
        let report = capabilities.report_for(domain).expect("every domain is reported");
        assert_eq!(
            report.can_prevent(),
            observation.is_denied(),
            "{domain} reports can_prevent={} while its probe says {}",
            report.can_prevent(),
            observation.describe()
        );
        assert_eq!(
            report.descendants() == aa_isolation::DescendantCoverage::ProcessTree,
            observation.is_denied(),
            "{domain} reports descendant coverage that the probe did not establish"
        );
    }

    // The direction that matters: a domain nobody measured must refuse a
    // process-tree requirement rather than accept it.
    let unmeasured: Vec<CapabilityDomain> = [CapabilityDomain::Ipc, CapabilityDomain::Credential]
        .into_iter()
        .collect();
    for domain in unmeasured {
        let spec = ExecutionSpec::new("/bin/true", IdentityRef::root("a"))
            .with_requirement(ControlRequirement::prevent(domain).with_descendants(DescendantRequirement::ProcessTree));
        assert!(
            backend.plan(&spec).is_err(),
            "{domain} was never measured and still accepted a process-tree prevention requirement"
        );
    }
    measured(
        scenario,
        "every reported prevention matches a probe observation on this host",
    );
}

// ---------------------------------------------------------------------------
// Descendant confinement and ambient authority (AAASM-5709).
// ---------------------------------------------------------------------------

/// AC: the boundary reaches ordinary `fork`/`exec` descendants, at every depth
/// the mechanism claims to cover.
///
/// The existing descendant scenario shows that *a* nested process is confined.
/// This one shows the claim is about the tree rather than about one extra level:
/// three processes, at three depths, each attempting the same forbidden write to
/// its own target. A boundary that stopped inheriting after the first `fork`
/// would leave the deepest file behind and this would fail.
///
/// The control is the identical script with the directory made writable. All
/// three land, so the absences above are the boundary and not a shell that never
/// ran the commands — which is the failure mode a nested `sh -c` chain is most
/// likely to have.
#[test]
fn a_child_and_a_grandchild_are_confined_by_the_same_boundary() {
    let scenario = "descendant confinement at three depths";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("depths");
    let depths: Vec<PathBuf> = (0..3).map(|d| scratch.forbidden().join(format!("depth-{d}"))).collect();

    // `;` between the write and the nested shell keeps a POSIX shell from
    // exec-optimising itself away, so each level really is a separate process.
    let script = format!(
        "printf x > {}; /bin/sh -c {}",
        quote(&depths[0].to_string_lossy()),
        quote(&format!(
            "printf x > {}; /bin/sh -c {}",
            quote(&depths[1].to_string_lossy()),
            quote(&format!("printf x > {}", quote(&depths[2].to_string_lossy())))
        ))
    );

    run(
        &backend,
        &shell_spec(
            &script,
            vec![permit_only_selector(&scratch.root.to_string_lossy())],
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    for (depth, target) in depths.iter().enumerate() {
        assert!(
            !target.exists(),
            "the process at depth {depth} wrote where the launch did not permit it: {}",
            target.display()
        );
    }

    // Control: the same script, one grant different.
    run(
        &backend,
        &shell_spec(
            &script,
            vec![permit_only_selector(&scratch.root.to_string_lossy())],
            vec![permit_only_selector(&scratch.root.to_string_lossy())],
        ),
    );
    for (depth, target) in depths.iter().enumerate() {
        assert!(
            target.exists(),
            "the control run produced no effect at depth {depth}, so the denial above proves nothing"
        );
    }
    measured(
        scenario,
        "three processes at three depths were each denied a forbidden write, and each performed it \
         under a control policy that permitted it",
    );
}

/// AC: non-required inherited descriptors do not reach the confined program.
///
/// A descriptor is the one piece of ambient authority an environment plan cannot
/// touch: it carries its access with no name attached and survives `exec`. The
/// backend marks every non-standard descriptor close-on-exec while preparing the
/// boundary, and this is the end-to-end proof that the mark takes effect.
///
/// **The control runs first and is load-bearing.** It spawns the identical
/// command outside the boundary against a descriptor that is deliberately
/// inheritable, so it establishes that the descriptor *can* be read across an
/// `exec` on this host. Without it, the confined run's silence would be equally
/// consistent with a shell that does not support the redirection.
#[cfg(target_os = "linux")]
#[test]
fn an_inherited_descriptor_does_not_reach_the_confined_program() {
    use std::os::fd::AsRawFd;

    let scenario = "inherited descriptors do not cross the boundary";
    let Some(backend) = require_confining_backend(scenario) else {
        return;
    };
    let scratch = Scratch::new("fd");
    let secret_file = scratch.forbidden().join("held-open");
    std::fs::write(&secret_file, SECRET).expect("fixture");
    let file = std::fs::File::open(&secret_file).expect("fixture");

    // `dup` returns a descriptor without the close-on-exec flag, whatever the
    // original carried. That makes the control's premise true by construction
    // rather than by assuming what `File::open` did.
    //
    // SAFETY: `dup` acts on a descriptor owned by the live `File` above and
    // returns a new one or -1; it dereferences nothing.
    let inheritable = unsafe { libc::dup(file.as_raw_fd()) };
    assert!(inheritable >= 0, "the descriptor could not be duplicated");

    let read_it = format!("cat <&{inheritable}");

    // Control, first: outside the boundary the descriptor is readable.
    let control = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(&read_it)
        .output()
        .expect("the control command runs");
    assert!(
        String::from_utf8_lossy(&control.stdout).contains(SECRET),
        "the descriptor was not inheritable to begin with, so the confined run below proves nothing. \
         stderr: {}",
        String::from_utf8_lossy(&control.stderr)
    );

    // Test: the same command through the backend, which seals descriptors while
    // preparing the boundary.
    let (confined, evidence) = run(&backend, &shell_spec(&as_grandchild(&read_it), Vec::new(), Vec::new()));
    assert!(
        !confined.stdout.contains(SECRET),
        "an inherited descriptor reached the confined program: {:?}",
        confined.stdout
    );

    // And the inventory that justifies the claim must be in evidence, with the
    // completeness of the enumeration attached — an inventory nobody could take
    // must never read like one that came back clean.
    let inventory = evidence
        .records_for(CapabilityDomain::Ipc)
        .find(|r| r.detail.starts_with("inherited descriptors"))
        .unwrap_or_else(|| panic!("no descriptor inventory in evidence: {:?}", evidence.records()));
    assert!(
        inventory.detail.contains("every one accounted for"),
        "the boundary was clean and the evidence does not say so: {}",
        inventory.detail
    );
    measured(
        scenario,
        "a descriptor readable across exec outside the boundary was unreadable inside it, and the \
         inventory behind that claim is in evidence",
    );
}

/// AC: the child's environment is an explicit plan, and a variable kept for
/// compatibility is distinguishable from one that was removed.
///
/// Two credential-shaped variables, identical in every way except which list the
/// launch put them in. One reaches the child and one does not, and the evidence
/// says which is which — the pair is what makes "removed" and "could not be
/// removed" different observable states rather than two words for one.
#[test]
fn a_removed_credential_and_a_kept_one_reach_the_child_differently() {
    let scenario = "credential environment plan is explicit";
    let Some(mut backend) = require_confining_backend(scenario) else {
        return;
    };
    let Some(env_program) = ["/usr/bin/env", "/bin/env"].iter().find(|p| Path::new(p).exists()) else {
        decline::<()>(
            scenario,
            Measurement::ToolAbsent,
            "no `env` binary was found, and nothing else prints the child's whole environment",
        );
        return;
    };

    // Set on this process so the launch has something to carry. Safe here
    // because the Linux lane runs under nextest, which gives every test its own
    // process; the names are unique to this scenario in any case.
    std::env::set_var("X_AA5709_REMOVED_TOKEN", "removed-value");
    std::env::set_var("X_AA5709_KEPT_TOKEN", "kept-value");

    let spec = ExecutionSpec::new(*env_program, IdentityRef::root("agent-under-test"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(system_reads())),
        )
        .with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["X_AA5709_REMOVED_TOKEN".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: vec!["X_AA5709_KEPT_TOKEN".to_string()],
        });
    // `with_credentials` still carries the posture the capability report and
    // evidence read; `set_child_environment` is the separate, required step
    // that actually resolves what the child receives (AAASM-5940 refuses to
    // derive it from the posture alone — see AAASM-6009).
    backend.set_child_environment(BTreeMap::from([(
        "X_AA5709_KEPT_TOKEN".to_string(),
        "kept-value".to_string(),
    )]));
    let (completed, evidence) = run(&backend, &spec);

    assert!(
        !completed.stdout.contains("X_AA5709_REMOVED_TOKEN"),
        "a variable reported as removed reached the child: {:?}",
        completed.stdout
    );
    assert!(
        completed.stdout.contains("X_AA5709_KEPT_TOKEN=kept-value"),
        "a variable reported as still reaching the child was withheld from it, so the two states are \
         not distinguishable: {:?}",
        completed.stdout
    );

    // The evidence must name the survivor as authority that could not be
    // removed, and must not present the run as least-authority.
    let residual = evidence
        .records_for(CapabilityDomain::Credential)
        .find(|r| r.detail.starts_with("residual authority"))
        .unwrap_or_else(|| panic!("no residual-authority record: {:?}", evidence.records()));
    assert!(
        residual.detail.contains("X_AA5709_KEPT_TOKEN") && residual.detail.contains("NOT least-authority"),
        "the kept variable is not reported as unremoved ambient authority: {}",
        residual.detail
    );
    assert!(
        !residual.detail.contains("X_AA5709_REMOVED_TOKEN"),
        "a removed variable was reported as residual authority: {}",
        residual.detail
    );

    // Negative control: the same two variables with the second one also
    // removed. It leaves the child, and the evidence stops reporting residue —
    // so the assertions above are about which list a name is in.
    let control = ExecutionSpec::new(*env_program, IdentityRef::root("agent-under-test"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(system_reads())),
        )
        .with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["X_AA5709_REMOVED_TOKEN".to_string(), "X_AA5709_KEPT_TOKEN".to_string()],
            delegated: Vec::new(),
            ambient_unremoved: Vec::new(),
        });
    // Negative control: nothing is delegated or ambient-unremoved, so the
    // child's explicit environment carries neither name.
    backend.set_child_environment(BTreeMap::new());
    let (completed, evidence) = run(&backend, &control);
    assert!(
        !completed.stdout.contains("X_AA5709_KEPT_TOKEN"),
        "the variable reached the child even when nothing asked it to: {:?}",
        completed.stdout
    );
    assert!(evidence
        .records_for(CapabilityDomain::Credential)
        .any(|r| r.detail.contains("none beyond the three standard descriptors")));

    std::env::remove_var("X_AA5709_REMOVED_TOKEN");
    std::env::remove_var("X_AA5709_KEPT_TOKEN");
    measured(
        scenario,
        "a removed credential was absent from the child's environment while a documented compatibility \
         exception was present and reported as unremoved ambient authority",
    );
}

/// AC: AASM's own gateway authority is not exposed to the child merely because
/// the supervisor holds it.
///
/// The supervisor runs outside the boundary (ADR 0035 §5) and holds whatever the
/// operator's shell gave it. The child gets an environment built from nothing,
/// so possession by the parent is not a route into the child — and the control
/// is an ordinary variable delegated through the identical mechanism, which does
/// arrive.
#[test]
fn supervisor_authority_is_not_delegated_to_the_child_by_possession() {
    let scenario = "supervisor credentials do not reach the child";
    let Some(mut backend) = require_confining_backend(scenario) else {
        return;
    };
    let Some(env_program) = ["/usr/bin/env", "/bin/env"].iter().find(|p| Path::new(p).exists()) else {
        decline::<()>(
            scenario,
            Measurement::ToolAbsent,
            "no `env` binary was found, and nothing else prints the child's whole environment",
        );
        return;
    };

    std::env::set_var("AA_GATEWAY_AUTH", "supervisor-bearer-token");
    std::env::set_var("AA_AGENT_ID", "agent-under-test");

    // The planner is asked to delegate both. One is AASM's gateway authority and
    // is withheld; the other is the correlation identifier a governed launch is
    // supposed to hand over.
    let plan = aa_isolation::EnvironmentPlanner::new()
        .delegate("AA_GATEWAY_AUTH")
        .delegate("AA_AGENT_ID")
        .plan(std::env::vars().map(|(name, _)| name));
    assert_eq!(
        plan.withheld_supervisor_credentials(),
        ["AA_GATEWAY_AUTH"],
        "the supervisor credential was not withheld before the launch was even built"
    );

    let spec = ExecutionSpec::new(*env_program, IdentityRef::root("agent-under-test"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(system_reads())),
        )
        .with_credentials(plan.into_posture());
    // `EnvironmentPlanner` only classifies *names* into a posture; a real
    // caller (aa-cli's `build_child_env`) separately resolves the *values* and
    // hands them to `set_child_environment` — mirrored here with the one name
    // the plan actually delegated (`AA_GATEWAY_AUTH` was withheld as a
    // supervisor credential, never delegated, so it has no value to carry).
    backend.set_child_environment(BTreeMap::from([(
        "AA_AGENT_ID".to_string(),
        "agent-under-test".to_string(),
    )]));
    let (completed, _) = run(&backend, &spec);

    assert!(
        !completed.stdout.contains("supervisor-bearer-token"),
        "the supervisor's gateway credential reached the confined child"
    );
    assert!(
        !completed.stdout.contains("AA_GATEWAY_AUTH"),
        "the supervisor's gateway credential name reached the confined child: {:?}",
        completed.stdout
    );
    // The control: the delegation mechanism itself works, so the absence above
    // is the withholding rule and not a launch that delegated nothing.
    assert!(
        completed.stdout.contains("AA_AGENT_ID=agent-under-test"),
        "no delegated variable arrived at all, so the assertion above proves nothing: {:?}",
        completed.stdout
    );

    std::env::remove_var("AA_GATEWAY_AUTH");
    std::env::remove_var("AA_AGENT_ID");
    measured(
        scenario,
        "a supervisor gateway credential explicitly requested for delegation was withheld from the \
         child, while an ordinary correlation variable requested the same way arrived",
    );
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

/// Accept one pending connection and read what it sent, or `None` if nothing
/// arrived.
///
/// The listener is non-blocking and is polled for a bounded window: a scenario
/// that waited indefinitely for a connection it expects *not* to arrive would
/// hang instead of failing.
fn accepted_payload(listener: &TcpListener) -> Option<String> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok((mut stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .expect("read timeout");
                let mut buffer = Vec::new();
                let _ = stream.read_to_end(&mut buffer);
                return Some(String::from_utf8_lossy(&buffer).into_owned());
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
    None
}

/// Whether an executable is on `PATH`.
fn which(program: &str) -> Option<PathBuf> {
    let output = std::process::Command::new("which").arg(program).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
    path.exists().then_some(path)
}
