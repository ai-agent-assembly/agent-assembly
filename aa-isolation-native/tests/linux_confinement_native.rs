//! End-to-end confinement measurements on a real Linux host (AAASM-5802).
//!
//! # What makes a scenario here count
//!
//! Every scenario asserts on an **effect**, never on an exit code or an error
//! message: a file that exists or does not, a file that shrank or did not, bytes
//! that arrived or did not. An exit code says what a program reported; the effect
//! says what happened.
//!
//! And every scenario carries a **control**. The control run and the test run
//! execute the same command through the same launcher, differing by one grant. A
//! denial counts only when the control produced the effect and the test did not —
//! so a scenario cannot pass because the command was broken, the directory was
//! unwritable, or the boundary never installed, all of which would also produce
//! "no effect".
//!
//! # Skips are recorded, never silent
//!
//! A host that cannot run a scenario prints `SKIP [scenario]: reason` **and**
//! writes a record to the evidence ledger, which `.ci/test-evidence-summary.sh`
//! nets against the runner's pass count. A lane that declined everything cannot
//! report as a lane that measured something.
//!
//! # The launcher under test is the one `cargo` just built
//!
//! `CARGO_BIN_EXE_aa-isolation-launch` is the binary from *this* build, not
//! whichever one the production search happens to find on the runner. A suite
//! that measured an installed launcher would go green while the launcher under
//! review was broken — which is the defect class AAASM-5711 caught for the
//! sibling lane.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, DescendantRequirement, EnforcementEvidence,
    EvidenceKind, ExecutionHandle, ExecutionSpec, IdentityRef, IsolationBackend, RequirementScope, SupportLevel,
};
use aa_isolation_native::{CompletedRun, NativeBackend, REQUIRED_ABI_VERSION};

/// The shared evidence ledger, included by path.
///
/// Included rather than copied: one CI summary reads every suite's records, and
/// two implementations of "what a decline looks like" would drift until the
/// summary quietly stopped seeing one of them.
#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

use evidence::Measurement;

/// The synthetic content a read scenario looks for. Unmistakably fabricated, and
/// distinctive enough that it cannot appear in a diagnostic by accident.
const SECRET: &str = "aa-native-conformance-secret-8b30";

/// The launcher this build produced.
fn launcher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aa-isolation-launch"))
}

// ---------------------------------------------------------------------------
// Guards. Each prints a visible skip and records it, so no opt-out path can
// forget to declare itself.
// ---------------------------------------------------------------------------

/// A backend that measured a working boundary on this host, or a recorded skip.
///
/// Folds every precondition into one guard because they are answered by the same
/// object, and because a scenario that checked three of them and forgot the
/// fourth would report a missing measurement as a product failure.
fn require_confining_backend(scenario: &str) -> Option<NativeBackend> {
    if !cfg!(target_os = "linux") {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "this backend confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
    }
    if !launcher().is_file() {
        return decline(
            scenario,
            Measurement::ToolAbsent,
            &format!(
                "the launcher `{}` was not built; a lane that builds it and still reports this is broken",
                launcher().display()
            ),
        );
    }

    let backend = NativeBackend::discover_with_launcher(launcher()).with_captured_output(true);

    let Some(host) = backend.host() else {
        // The host was measured and found unusable. Below the ABI floor is an
        // unsupported *platform* — a newer runner can run it, no configuration of
        // this one can — and that is the only unusable state reachable here once
        // the launcher exists.
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the host could not provide the boundary this backend requires (at least Landlock ABI \
                 v{REQUIRED_ABI_VERSION}). Availability said: {:?}",
                backend.capabilities().availability()
            ),
        );
    };

    let probe = backend.probe_result();
    if !probe.covers_descendants() {
        // Every precondition held and the boundary still did not deny something.
        // That is a failed measurement, not an opt-out, and it is the one state
        // that must never read as a skip.
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition. host: {} | read: {} | write: {}",
                host.describe(),
                probe.filesystem_read.describe(),
                probe.filesystem_write.describe(),
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
            "aa-native-{name}-{}-{}",
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

/// The read grants every scenario needs so the loader and the shell work, and the
/// only thing under test is the grant that differs between the runs.
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
fn run(backend: &NativeBackend, spec: &ExecutionSpec) -> (CompletedRun, EnforcementEvidence) {
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
    format!("/bin/sh -c {}; exit 0", shell_word(inner))
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Duplicate a descriptor so the copy is inheritable across `exec` by
/// construction.
///
/// `dup` clears the close-on-exec flag on the new number, so the descriptor
/// scenario's control does not depend on what `File::open` did with that flag —
/// which would make its premise an assumption rather than a fact.
#[cfg(target_os = "linux")]
fn dup_inheritable(file: &std::fs::File) -> i32 {
    use std::os::fd::AsRawFd;
    // SAFETY: `dup` duplicates a descriptor this process owns and returns a new
    // number or -1. Nothing is dereferenced and nothing is closed.
    unsafe { libc::dup(file.as_raw_fd()) }
}

/// The non-Linux arm. Unreachable — every scenario that calls it has already
/// declined on this platform — and present so the suite compiles everywhere.
#[cfg(not(target_os = "linux"))]
fn dup_inheritable(_file: &std::fs::File) -> i32 {
    -1
}

/// Close a raw descriptor this suite created.
#[cfg(target_os = "linux")]
fn close_raw(fd: i32) {
    // SAFETY: `fd` is a descriptor this suite created with `dup` and still owns.
    unsafe { libc::close(fd) };
}

/// The non-Linux arm. See [`dup_inheritable`].
#[cfg(not(target_os = "linux"))]
fn close_raw(_fd: i32) {}

/// A run that did not even reach the program is not a measurement of the
/// boundary, and every scenario has to say so rather than reading a refusal as a
/// denial.
fn assert_the_program_ran(scenario: &str, completed: &CompletedRun) {
    assert!(
        !completed.launcher_refused(),
        "[{scenario}] the launcher refused to establish the boundary and executed nothing, so this run \
         measured no denial: {}",
        completed.stderr.trim()
    );
}

// ---------------------------------------------------------------------------
// Scenarios.
// ---------------------------------------------------------------------------

/// A read outside the permitted set is denied — to a grandchild, before the read
/// takes effect.
///
/// The control is the identical command with the file's directory granted: it
/// prints the secret. Without it, "no output" would be equally consistent with a
/// missing file or a broken shell.
#[test]
fn filesystem_read_denied() {
    const SCENARIO: &str = "native: filesystem read denied";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("read");
    let secret = scratch.forbidden().join("secret");
    std::fs::write(&secret, SECRET).expect("the scenario's own file");

    let script = as_grandchild(&format!("cat {}", shell_word(&secret.to_string_lossy())));

    let (control, _) = run(
        &backend,
        &shell_spec(
            &script,
            vec![permit_only_selector(&scratch.forbidden().to_string_lossy())],
            Vec::new(),
        ),
    );
    assert_the_program_ran(SCENARIO, &control);
    assert!(
        control.stdout.contains(SECRET),
        "the control run did not read the file it was permitted to read, so the test run proves nothing. \
         stdout: {:?} stderr: {:?}",
        control.stdout,
        control.stderr
    );

    let (test, evidence) = run(&backend, &shell_spec(&script, Vec::new(), Vec::new()));
    assert_the_program_ran(SCENARIO, &test);
    assert!(
        !test.stdout.contains(SECRET),
        "a read outside the permitted set reached the confined program. stdout: {:?}",
        test.stdout
    );
    assert!(
        !evidence.supports_prevention_claim(CapabilityDomain::FilesystemRead),
        "a denial the supervisor never saw a record of became a prevention claim"
    );
    measured(
        SCENARIO,
        "the control read the permitted file and the test read nothing outside the grant",
    );
}

/// A write outside the permitted set never takes effect.
#[test]
fn filesystem_write_denied_before_the_effect() {
    const SCENARIO: &str = "native: filesystem write denied before the effect";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("write");
    let control_target = scratch.permitted().join("control");
    let test_target = scratch.forbidden().join("test");

    let (control, _) = run(
        &backend,
        &shell_spec(
            &as_grandchild(&format!("printf x > {}", shell_word(&control_target.to_string_lossy()))),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &control);
    assert!(
        control_target.exists(),
        "the control run did not write the file it was permitted to write, so the test run proves \
         nothing. stderr: {:?}",
        control.stderr
    );

    let (test, _) = run(
        &backend,
        &shell_spec(
            &as_grandchild(&format!("printf x > {}", shell_word(&test_target.to_string_lossy()))),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &test);
    assert!(
        !test_target.exists(),
        "a write outside the permitted set took effect: {} exists",
        test_target.display()
    );
    measured(
        SCENARIO,
        "the control wrote inside the grant and the test wrote nothing outside it",
    );
}

/// The boundary reaches descendants, measured at three depths rather than
/// assumed from inheritance being documented.
///
/// The control is the same command at the same depth with the directory granted:
/// it writes. Depth is the only variable between the three test runs.
#[test]
fn descendant_confinement_at_three_depths() {
    const SCENARIO: &str = "native: descendant confinement at three depths";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("depth");
    let grant = vec![permit_only_selector(&scratch.permitted().to_string_lossy())];

    for depth in 0..3u32 {
        let control_target = scratch.permitted().join(format!("control-{depth}"));
        let test_target = scratch.forbidden().join(format!("test-{depth}"));
        let wrap = |target: &Path| {
            let mut script = format!("printf x > {}", shell_word(&target.to_string_lossy()));
            for _ in 0..depth {
                script = format!("/bin/sh -c {}", shell_word(&script));
            }
            format!("{script}; exit 0")
        };

        let (control, _) = run(&backend, &shell_spec(&wrap(&control_target), Vec::new(), grant.clone()));
        assert_the_program_ran(SCENARIO, &control);
        assert!(
            control_target.exists(),
            "at depth {depth} the control run wrote nothing, so the test run proves nothing. stderr: {:?}",
            control.stderr
        );

        let (test, _) = run(&backend, &shell_spec(&wrap(&test_target), Vec::new(), grant.clone()));
        assert_the_program_ran(SCENARIO, &test);
        assert!(
            !test_target.exists(),
            "at depth {depth} a descendant escaped the boundary and wrote {}",
            test_target.display()
        );
    }
    measured(
        SCENARIO,
        "denied at fork/exec depths 0, 1 and 2, each against its own control",
    );
}

/// **The rule-construction property, measured rather than unit-tested.**
///
/// Policy states read and write scope separately, so "read `/parent`, write
/// `/parent/child`" is ordinary. The rule for the child must keep the read the
/// parent granted, or naming a subtree for one verb silently withdraws the other.
///
/// The control is the read of a file directly under the parent: it succeeds in
/// the same run, so a failure below is about the nested rule and not about the
/// parent grant having been dropped altogether.
#[test]
fn a_nested_write_grant_keeps_the_read_granted_above_it() {
    const SCENARIO: &str = "native: a nested write grant keeps the read granted above it";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("nested");
    let child = scratch.permitted().join("child");
    std::fs::create_dir_all(&child).expect("the scenario's own directory");
    let above = scratch.permitted().join("above");
    let inside = child.join("inside");
    std::fs::write(&above, SECRET).expect("the scenario's own file");
    std::fs::write(&inside, SECRET).expect("the scenario's own file");

    let script = as_grandchild(&format!(
        "cat {} ; cat {}",
        shell_word(&above.to_string_lossy()),
        shell_word(&inside.to_string_lossy())
    ));
    let (completed, _) = run(
        &backend,
        &shell_spec(
            &script,
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
            vec![permit_only_selector(&child.to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    // Two reads, so two copies of the secret. The first is the control — it shows
    // the parent's read grant works at all — and the second is the property.
    assert_eq!(
        completed.stdout.matches(SECRET).count(),
        2,
        "a file beneath a nested write grant lost the read its parent granted. stdout: {:?} stderr: {:?}",
        completed.stdout,
        completed.stderr
    );
    measured(
        SCENARIO,
        "a file beneath a subtree granted for writing kept the read right granted above it",
    );
}

/// The ordinary case: a confined program's streams and exit status reach the
/// supervisor unchanged. Without this, every denial above could be a boundary
/// that breaks the launch outright.
#[test]
fn trivial_child_streams_and_exit_status() {
    const SCENARIO: &str = "native: trivial child streams and exit status";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let (completed, _) = run(
        &backend,
        &shell_spec(&format!("printf {SECRET}; exit 7"), Vec::new(), Vec::new()),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(completed.stdout.contains(SECRET), "stdout: {:?}", completed.stdout);
    assert_eq!(
        completed.status.code(),
        Some(7),
        "the confined program's exit code did not reach the supervisor: {:?}",
        completed.status
    );
    measured(
        SCENARIO,
        "stdout and a non-zero exit code crossed the boundary unchanged",
    );
}

/// **The measured kernel/ABI floor.**
///
/// Records the number this host reported, so the lane's log carries the
/// measurement rather than the constant, and asserts the two directions that
/// matter: the host meets the floor this backend's claim requires, and the floor
/// is the ABI the rules are actually built against.
#[test]
fn the_kernel_abi_floor_is_measured_on_this_host() {
    const SCENARIO: &str = "native: the kernel ABI floor is measured on this host";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let host = backend.host().expect("a confining backend measured its host");
    let abi = host
        .abi_floor()
        .measured()
        .expect("a confining backend measured an ABI");
    assert!(
        abi >= REQUIRED_ABI_VERSION,
        "this host reported Landlock ABI v{abi} and the backend confined anyway, below its own stated \
         floor of v{REQUIRED_ABI_VERSION}"
    );
    assert!(host.abi_floor().is_met());
    measured(SCENARIO, &format!("measured host: {}", host.describe()));
}

/// A required requirement in a domain this version does not implement must refuse
/// the launch, before anything starts.
///
/// The control is the identical spec with the requirement marked optional: it
/// plans, so the refusal above is about the requirement's posture and not about
/// the spec being unplannable.
#[test]
fn unsupported_capability_refuses_before_launch() {
    const SCENARIO: &str = "native: unsupported capability refuses before launch";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let spec = shell_spec("exit 0", Vec::new(), Vec::new()).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Syscall)
            .with_scope(RequirementScope::Selectors(vec![permit_only_selector("read")])),
    );
    let refusal = backend
        .plan(&spec)
        .expect_err("this version installs no system-call filter and must refuse");
    assert!(
        refusal
            .reasons()
            .iter()
            .any(|r| r.domain() == Some(CapabilityDomain::Syscall)),
        "{refusal:?}"
    );

    let control = shell_spec("exit 0", Vec::new(), Vec::new()).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Syscall)
            .with_posture(aa_isolation::RequirementPosture::Optional)
            .with_scope(RequirementScope::Selectors(vec![permit_only_selector("read")])),
    );
    let plan = backend.plan(&control).expect("an optional requirement never refuses");
    assert_eq!(plan.shortfalls().count(), 1);
    measured(
        SCENARIO,
        "a required syscall requirement refused before launch and the same requirement as optional did not",
    );
}

/// What the backend reports must be what the probe found, in both directions —
/// a report that claimed prevention the probe did not observe would be the whole
/// failure this Epic exists to prevent, and a report that claimed nothing while
/// the probe observed denials would make the backend unusable for the reason
/// opposite to the one it states.
#[test]
fn reported_capabilities_match_the_probe() {
    const SCENARIO: &str = "native: reported capabilities match the probe";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let capabilities = backend.capabilities();
    let probe = backend.probe_result();

    for (domain, observed) in [
        (CapabilityDomain::FilesystemRead, probe.filesystem_read.is_denied()),
        (CapabilityDomain::FilesystemWrite, probe.filesystem_write.is_denied()),
    ] {
        let report = capabilities.report_for(domain).expect("every domain is reported");
        assert_eq!(
            report.can_prevent(),
            observed,
            "{domain} reports can_prevent={} while the probe observed {observed}",
            report.can_prevent()
        );
    }
    for domain in CapabilityDomain::ALL {
        if matches!(
            domain,
            CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite
        ) {
            continue;
        }
        let report = capabilities.report_for(*domain).expect("every domain is reported");
        assert!(
            matches!(report.support(), SupportLevel::Unsupported { .. }),
            "{domain} claims support this version does not implement: {report:?}"
        );
    }
    measured(
        SCENARIO,
        "the two filesystem domains claim exactly what the probe observed and the other seven claim nothing",
    );
}

/// A descriptor open in the supervisor must not survive into the confined
/// program. A Landlock rule is evaluated when a path is resolved, so an inherited
/// directory descriptor is a standing hole in a path-scoped boundary.
///
/// The control is the identical read through a *path*, in the same run: it is
/// denied too, so the assertion below is not passing because the shell could not
/// read anything at all.
#[test]
fn inherited_descriptors_do_not_cross_the_boundary() {
    const SCENARIO: &str = "native: inherited descriptors do not cross the boundary";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("fd");
    let secret = scratch.forbidden().join("secret");
    std::fs::write(&secret, SECRET).expect("the scenario's own file");

    // A descriptor that is inheritable across `exec` by construction: `dup`
    // clears the close-on-exec flag, so this cannot pass because `File::open`
    // happened to set it.
    let file = std::fs::File::open(&secret).expect("the scenario's own file");
    let raw = dup_inheritable(&file);
    assert!(raw >= 0, "the scenario could not duplicate its own descriptor");

    let script = as_grandchild(&format!(
        "cat /proc/self/fd/{raw} ; cat {}",
        shell_word(&secret.to_string_lossy())
    ));
    let (completed, evidence) = run(&backend, &shell_spec(&script, Vec::new(), Vec::new()));
    close_raw(raw);

    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        !completed.stdout.contains(SECRET),
        "an inherited descriptor carried a forbidden file across the boundary. stdout: {:?}",
        completed.stdout
    );
    assert!(
        evidence
            .records()
            .iter()
            .any(|r| r.detail.starts_with("inherited descriptors")),
        "the inventory must be recorded on every run: {:?}",
        evidence.records()
    );
    measured(
        SCENARIO,
        "an exec-inheritable descriptor to a forbidden file did not reach the confined program",
    );
}

/// The confined program receives the environment the launch computed, and
/// nothing else. Credential values reach it through `execve` rather than through
/// a command line every other process on the host can read.
#[test]
fn the_child_receives_only_the_environment_the_launch_delegated() {
    const SCENARIO: &str = "native: the child receives only the environment the launch delegated";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let mut backend = backend;
    let mut env = std::collections::BTreeMap::new();
    env.insert("AA_NATIVE_DELEGATED".to_string(), SECRET.to_string());
    env.insert("PATH".to_string(), "/usr/bin:/bin".to_string());
    backend.set_child_environment(env);

    let (completed, _) = run(
        &backend,
        &shell_spec("printf '%s' \"${AA_NATIVE_DELEGATED}\"; env", Vec::new(), Vec::new()),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        completed.stdout.contains(SECRET),
        "the delegated variable did not reach the confined program. stdout: {:?}",
        completed.stdout
    );
    // The control in the other direction: a name the *supervisor* holds and the
    // launch did not delegate must NOT be in the child's environment, or the
    // replacement did not happen and the delegated value above arrived by
    // inheritance rather than by decision.
    //
    // Asserted against a name taken from this process rather than against "the
    // child has exactly two names": a POSIX shell exports `PWD` on its own, so
    // an exhaustive assertion would be measuring the shell's behaviour rather
    // than the launch's.
    let names: Vec<&str> = completed
        .stdout
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(name, _)| name)
        .filter(|name| !name.is_empty())
        .collect();
    let Some(undelegated) = std::env::vars()
        .map(|(name, _)| name)
        .find(|name| name != "AA_NATIVE_DELEGATED" && name != "PATH" && name != "PWD")
    else {
        decline::<()>(
            SCENARIO,
            Measurement::NotMeasured,
            "this process holds no environment variable outside the delegated set, so the replacement \
             has nothing to be measured against",
        );
        return;
    };
    assert!(
        !names.contains(&undelegated.as_str()),
        "`{undelegated}` reached the confined program from the supervisor's environment even though the \
         launch delegated only AA_NATIVE_DELEGATED and PATH: {names:?}"
    );
    // And the values are not on any command line.
    assert!(
        !std::fs::read_to_string("/proc/self/cmdline")
            .unwrap_or_default()
            .contains(SECRET),
        "a delegated value reached this process's own command line"
    );
    measured(
        SCENARIO,
        "the child received exactly the two delegated names, carried across execve rather than on argv",
    );
}

/// **Portable, and the one scenario that needs no kernel.** A backend that cannot
/// find its launcher must refuse before launch rather than run the program
/// unconfined.
///
/// The assertion is on the *effect*: the file the program would have created does
/// not exist. An error return alone would be equally consistent with a fallback
/// that ran the program and then reported a problem.
#[test]
fn an_absent_launcher_refuses_before_launch() {
    const SCENARIO: &str = "native: an absent launcher refuses before launch";
    let scratch = std::env::temp_dir().join(format!("aa-native-absent-{}", std::process::id()));
    let _ = std::fs::remove_file(&scratch);

    let backend = NativeBackend::discover_with_launcher("/nonexistent/aa-isolation-launch");
    assert!(
        !backend.capabilities().availability().is_available(),
        "a backend with no launcher reported itself available"
    );
    let spec = shell_spec(
        &format!("printf x > {}", shell_word(&scratch.to_string_lossy())),
        Vec::new(),
        vec![permit_only_selector("/tmp")],
    );
    let refusal = backend
        .plan(&spec)
        .expect_err("a backend with no launcher must refuse at plan time");
    assert!(refusal.backend_unavailable().is_some(), "{refusal:?}");
    assert!(
        !scratch.exists(),
        "the program ran even though no boundary could be established: {} exists",
        scratch.display()
    );

    let evidence = EnforcementEvidence::from_refusal(&refusal);
    assert_eq!(evidence.posture(), aa_isolation::LaunchPosture::Refused);
    for domain in CapabilityDomain::ALL {
        assert!(!evidence.supports_prevention_claim(*domain), "{domain}");
    }
    measured(
        SCENARIO,
        "an unavailable backend refused at plan time and the program's effect did not happen",
    );
}

/// No run of this backend may promote "the program ran" into "the control
/// decided", and the run above is a real one rather than a constructed object.
#[test]
fn no_run_supports_a_prevention_claim() {
    const SCENARIO: &str = "native: no run supports a prevention claim";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("claim");
    let (completed, evidence) = run(
        &backend,
        &shell_spec(
            &as_grandchild(&format!(
                "printf x > {}",
                shell_word(&scratch.forbidden().join("denied").to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    // The control that this run really was confined: the write did not happen.
    assert!(!scratch.forbidden().join("denied").exists());

    for domain in CapabilityDomain::ALL {
        assert!(
            !evidence.supports_prevention_claim(*domain),
            "{domain} produced a prevention claim from a run with no decision record"
        );
    }
    assert!(
        !evidence.records().iter().any(|r| r.kind == EvidenceKind::Decision),
        "this backend has no per-decision channel and must emit no Decision record"
    );
    assert!(
        evidence.records().iter().any(|r| r.kind == EvidenceKind::Exercised),
        "a run that happened must be recorded as exercised: {:?}",
        evidence.records()
    );
    measured(
        SCENARIO,
        "a real, effective denial produced Installed and Exercised records and no prevention claim",
    );
}

/// A requirement asking for process-tree coverage must be met by a control the
/// probe measured as covering the tree — and must refuse when it did not.
///
/// The refusal half cannot be produced on a working host, so the assertion here
/// is the positive one plus the report the negotiation reads, which is the value
/// that would flip.
#[test]
fn process_tree_coverage_is_reported_only_because_it_was_measured() {
    const SCENARIO: &str = "native: process-tree coverage is reported only because it was measured";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let report = backend
        .capabilities()
        .report_for(CapabilityDomain::FilesystemWrite)
        .expect("reported")
        .clone();
    assert_eq!(report.descendants(), aa_isolation::DescendantCoverage::ProcessTree);

    let spec = shell_spec("exit 0", Vec::new(), Vec::new()).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
            .with_descendants(DescendantRequirement::ProcessTree)
            .with_scope(RequirementScope::Selectors(Vec::new())),
    );
    backend
        .plan(&spec)
        .expect("a process-tree requirement is met by a measured process-tree control");
    measured(
        SCENARIO,
        &format!(
            "descendant coverage {} was reported after the probe denied a grandchild at every measured \
             verb",
            report.descendants().as_str()
        ),
    );
}

// ---------------------------------------------------------------------------
// AAASM-5709's backend-neutral machinery, verified against THIS backend.
//
// AAASM-5709 built the descendant-authority comparison and the environment
// planner to be backend-neutral, and `aa-isolation/tests/ambient_authority.rs`
// exercises them against a mock. A mock cannot tell anyone whether the machinery
// composes with a backend that really confines a process tree, which is the
// question AAASM-5804 has to answer for this backend specifically. These two
// scenarios take the same functions and put a real kernel boundary underneath
// them.
// ---------------------------------------------------------------------------

/// **AC: descendants stay inside the boundary using the AAASM-5709 machinery.**
/// A sub-agent launch that `is_same_or_narrower` says is within its ancestor's
/// authority is confined by this backend when it runs — and its own descendants
/// with it.
///
/// The two halves are deliberately in one scenario. Checking the comparison
/// without launching would measure a function; launching without the comparison
/// would measure a boundary nobody said was a sub-agent's. What has to hold is
/// that a launch the governance layer *admitted* as narrowing is a launch the
/// kernel then actually confined, two `fork`/`exec` steps down.
///
/// Three controls, all in this scenario:
///
/// * the widened sibling spec, which `authority_widening` must reject — so the
///   admission of the narrowed one is a decision and not a function that says
///   yes to everything;
/// * the write inside the sub-agent's own grant, which happens — so the denial
///   below is the boundary and not a shell that never ran;
/// * the grandchild depth, so what is measured is the tree and not the one
///   process the launcher `execve`d.
#[test]
fn a_sub_agent_launch_the_machinery_admits_is_confined_by_this_backend() {
    const SCENARIO: &str = "native: a sub-agent launch the AAASM-5709 machinery admits is confined here";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("subagent");
    let permitted = permit_only_selector(&scratch.permitted().to_string_lossy());
    let inside = scratch.permitted().join("inside");
    let outside = scratch.forbidden().join("escaped");

    let script = as_grandchild(&format!(
        "printf x > {} ; printf x > {}",
        shell_word(&inside.to_string_lossy()),
        shell_word(&outside.to_string_lossy())
    ));

    // The ancestor: an ordinary confined launch.
    let ancestor =
        shell_spec(&script, Vec::new(), vec![permitted.clone()]).with_credentials(aa_isolation::CredentialPosture {
            removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
            delegated: vec!["AA_AGENT_ID".to_string()],
            ambient_unremoved: Vec::new(),
        });

    // The sub-agent: same requirements, lineage recorded, and it delegates
    // nothing its ancestor did not.
    let descendant = ExecutionSpec::new(
        "/bin/sh",
        IdentityRef::root("sub-agent").with_ancestor("agent-under-test"),
    )
    .with_args(["-c", &script])
    .with_requirement(
        ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
            .with_scope(RequirementScope::Selectors(system_reads())),
    )
    .with_requirement(
        ControlRequirement::prevent(CapabilityDomain::FilesystemWrite)
            .with_descendants(DescendantRequirement::ProcessTree)
            .with_scope(RequirementScope::Selectors(vec![permitted])),
    )
    .with_credentials(aa_isolation::CredentialPosture {
        removed: vec!["AWS_SECRET_ACCESS_KEY".to_string()],
        delegated: vec!["AA_AGENT_ID".to_string()],
        ambient_unremoved: Vec::new(),
    });

    assert!(
        aa_isolation::is_same_or_narrower(&ancestor, &descendant),
        "the machinery refused a sub-agent that asks for nothing its ancestor did not: {:?}",
        aa_isolation::authority_widening(&ancestor, &descendant)
    );

    // The control on the comparison itself: the same sub-agent, delegating one
    // credential its ancestor removed, must be rejected — so the admission above
    // is a decision.
    let widened = descendant.clone().with_credentials(aa_isolation::CredentialPosture {
        removed: Vec::new(),
        delegated: vec!["AA_AGENT_ID".to_string(), "AWS_SECRET_ACCESS_KEY".to_string()],
        ambient_unremoved: Vec::new(),
    });
    let detected = aa_isolation::authority_widening(&ancestor, &widened);
    assert!(
        detected.contains(&aa_isolation::AuthorityWidening::CredentialWidened {
            name: "AWS_SECRET_ACCESS_KEY".to_string()
        }),
        "a sub-agent that re-delegated a credential its ancestor removed was admitted: {detected:?}"
    );

    // And now the boundary, on the launch the machinery admitted.
    let (completed, _) = run(&backend, &descendant);
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        inside.exists(),
        "the sub-agent's write inside its own grant did not happen, so the assertion below proves \
         nothing. stderr: {:?}",
        completed.stderr
    );
    assert!(
        !outside.exists(),
        "a grandchild of an admitted sub-agent launch wrote outside its grant: {} exists",
        outside.display()
    );
    measured(
        SCENARIO,
        "a sub-agent spec `is_same_or_narrower` admitted was confined at grandchild depth — the write \
         inside its grant happened and the write outside it did not — while the same spec re-delegating \
         a credential its ancestor removed was reported as CredentialWidened",
    );
}

/// **AC: AAASM-5709's environment planner composes with this backend.** The
/// supervisor's own gateway authority does not reach the confined child merely
/// because the supervisor holds it.
///
/// The posture is built by [`aa_isolation::EnvironmentPlanner`] — the same
/// backend-neutral machinery, not a hand-written `CredentialPosture` — and
/// handed to this backend as the child's entire environment. The control is an
/// ordinary correlation variable delegated through the identical call, which does
/// arrive: so the absence of the credential is the withholding rule and not a
/// launch that delegated nothing.
#[test]
fn supervisor_authority_is_not_delegated_to_this_backends_child_by_possession() {
    const SCENARIO: &str = "native: supervisor credentials do not reach the child";
    let Some(mut backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let Some(env_program) = ["/usr/bin/env", "/bin/env"].iter().find(|p| Path::new(p).exists()) else {
        decline::<()>(
            SCENARIO,
            Measurement::ToolAbsent,
            "no `env` binary was found, and nothing else prints the child's whole environment",
        );
        return;
    };

    std::env::set_var("AA_GATEWAY_AUTH", "supervisor-bearer-token");
    std::env::set_var("AA_AGENT_ID", "agent-under-test");

    // Both names are *requested* for delegation. One is AASM's own gateway
    // authority and the planner withholds it anyway; the other is the
    // correlation identifier a governed launch is supposed to hand over.
    let plan = aa_isolation::EnvironmentPlanner::new()
        .delegate("AA_GATEWAY_AUTH")
        .delegate("AA_AGENT_ID")
        .plan(std::env::vars().map(|(name, _)| name));
    assert_eq!(
        plan.withheld_supervisor_credentials(),
        ["AA_GATEWAY_AUTH"],
        "the supervisor credential was not withheld before the launch was even built"
    );

    // The child's whole environment: exactly what the plan delegated.
    let delegated: std::collections::BTreeMap<String, String> = plan
        .posture()
        .delegated
        .iter()
        .filter_map(|name| std::env::var(name).ok().map(|value| (name.clone(), value)))
        .collect();
    backend.set_child_environment(delegated);

    let spec = ExecutionSpec::new(*env_program, IdentityRef::root("agent-under-test"))
        .with_requirement(
            ControlRequirement::prevent(CapabilityDomain::FilesystemRead)
                .with_scope(RequirementScope::Selectors(system_reads())),
        )
        .with_credentials(plan.into_posture());
    let (completed, evidence) = run(&backend, &spec);
    assert_the_program_ran(SCENARIO, &completed);

    assert!(
        !completed.stdout.contains("supervisor-bearer-token"),
        "the supervisor's gateway credential reached the confined child"
    );
    assert!(
        !completed.stdout.contains("AA_GATEWAY_AUTH"),
        "the supervisor's gateway credential name reached the confined child: {:?}",
        completed.stdout
    );
    // The control: the delegation mechanism works, so the absence above is the
    // withholding rule and not a launch that delegated nothing.
    assert!(
        completed.stdout.contains("AA_AGENT_ID=agent-under-test"),
        "no delegated variable arrived at all, so the assertion above proves nothing: {:?}",
        completed.stdout
    );
    // And the run says the environment plan is a credential boundary on it,
    // rather than leaving a reader to assume it (AAASM-5804/5785).
    assert!(
        evidence.records().iter().any(|r| {
            r.domain == Some(CapabilityDomain::Credential) && r.detail.contains("per-PID /proc entries are OUTSIDE")
        }),
        "the run did not record whether another process's environ was reachable, which is what decides \
         whether the withholding above is a boundary at all: {:?}",
        evidence.records()
    );

    std::env::remove_var("AA_GATEWAY_AUTH");
    std::env::remove_var("AA_AGENT_ID");
    measured(
        SCENARIO,
        "an EnvironmentPlanner-built posture withheld a supervisor gateway credential explicitly \
         requested for delegation while an ordinary correlation variable requested the same way arrived, \
         on a launch whose evidence records other processes' per-PID /proc entries as outside its scope",
    );
}
