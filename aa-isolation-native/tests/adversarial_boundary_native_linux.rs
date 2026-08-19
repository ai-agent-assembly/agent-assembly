//! Escape attempts against the AASM-native backend's filesystem boundary
//! (AAASM-5802).
//!
//! # Why these are separate from the confinement suite
//!
//! `linux_confinement_native.rs` measures that the boundary does what policy
//! asked. This suite measures that it cannot be *talked out of it*: the attempts
//! here are the ones a program that knows it is confined would make — a symlink
//! into a forbidden tree, a hard link out of one, a rename, a `..` component, an
//! alternate name for the same program, another process's `/proc` entry, and a
//! malformed launcher command line.
//!
//! Landlock is documented as resolving these correctly. That is not the same as
//! *this* backend resolving them correctly on *this* host, and a boundary whose
//! escape resistance is a citation rather than a measurement is exactly what ADR
//! 0035's validation bar forbids. Every scenario below therefore carries a
//! control that produces the effect, so a denial cannot be a broken command.
//!
//! # One deliberate non-finding
//!
//! [`another_processes_proc_entry_is_unreadable_without_a_proc_grant`] measures
//! that the generic path scope covers `/proc/<pid>/environ` — and states the
//! limitation in the same breath: a launch that grants `/proc` wholesale, which
//! is what a program needing `/proc/self` does today, gets the sibling entries
//! too. Scoping `/proc` finely is AAASM-5804, and the gap is recorded here rather
//! than left for a reader to discover.

use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, EnforcementEvidence, EvidenceKind, ExecutionSpec,
    IdentityRef, IsolationBackend, RequirementScope,
};
use aa_isolation_native::{launch, CompletedRun, NativeBackend, REQUIRED_ABI_VERSION};

#[path = "../../aa-integration-tests/tests/evidence/mod.rs"]
mod evidence;

use evidence::Measurement;

const SECRET: &str = "aa-native-adversarial-secret-2f6d";

fn launcher() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_aa-isolation-launch"))
}

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
            &format!("the launcher `{}` was not built", launcher().display()),
        );
    }
    let backend = NativeBackend::discover_with_launcher(launcher()).with_captured_output(true);
    let Some(host) = backend.host() else {
        return decline(
            scenario,
            Measurement::UnsupportedPlatform,
            &format!(
                "the host could not provide the boundary this backend requires (at least Landlock ABI \
                 v{REQUIRED_ABI_VERSION}): {:?}",
                backend.capabilities().availability()
            ),
        );
    };
    if !backend.probe_result().covers_descendants() {
        return decline(
            scenario,
            Measurement::NotMeasured,
            &format!(
                "the discovery probe established no filesystem denial on a host that meets every \
                 precondition: {}",
                host.describe()
            ),
        );
    }
    Some(backend)
}

fn decline<T>(scenario: &str, measurement: Measurement, reason: &str) -> Option<T> {
    println!("SKIP [{scenario}]: {reason}");
    evidence::record(scenario, measurement, reason);
    None
}

fn measured(scenario: &str, detail: &str) {
    evidence::record(scenario, Measurement::Measured, detail);
}

struct Scratch {
    root: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "aa-native-adv-{name}-{}-{}",
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

/// The system paths every scenario grants so the loader and the shell work.
///
/// `include_proc` exists for the one scenario whose whole subject is `/proc`:
/// granting it there would be granting the thing under test.
fn system_reads(include_proc: bool) -> Vec<String> {
    ["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"]
        .iter()
        .filter(|p| include_proc || **p != "/proc")
        .filter(|p| Path::new(p).exists())
        .map(|p| permit_only_selector(p))
        .collect()
}

fn spec_with(
    program: &str,
    script: &str,
    reads: Vec<String>,
    writes: Vec<String>,
    include_proc: bool,
) -> ExecutionSpec {
    let mut all_reads = system_reads(include_proc);
    all_reads.extend(reads);
    ExecutionSpec::new(program, IdentityRef::root("agent-under-test"))
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

fn spec(script: &str, reads: Vec<String>, writes: Vec<String>) -> ExecutionSpec {
    spec_with("/bin/sh", script, reads, writes, true)
}

fn run(backend: &NativeBackend, spec: &ExecutionSpec) -> (CompletedRun, EnforcementEvidence) {
    let plan = backend
        .plan(spec)
        .unwrap_or_else(|refusal| panic!("the backend refused a spec this scenario needs: {refusal:?}"));
    let prepared = backend.prepare(plan).expect("the boundary could not be prepared");
    let handle = backend
        .spawn(prepared)
        .expect("the confined program could not be launched");
    let completed = backend.wait(&handle).expect("waiting for the confined program failed");
    let evidence = backend.evidence(&handle);
    (completed, evidence)
}

fn as_grandchild(inner: &str) -> String {
    format!("/bin/sh -c {}; exit 0", shell_word(inner))
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

fn assert_the_program_ran(scenario: &str, completed: &CompletedRun) {
    assert!(
        !completed.launcher_refused(),
        "[{scenario}] the launcher refused to establish the boundary and executed nothing, so this run \
         measured no denial: {}",
        completed.stderr.trim()
    );
}

// ---------------------------------------------------------------------------
// Escape attempts.
// ---------------------------------------------------------------------------

/// A symlink *inside* the write grant pointing *outside* it must not become a
/// writable path.
///
/// The classic path-boundary escape: a rule tied to `/permitted` and a program
/// that writes to `/permitted/escape/x`, where `escape` is a symlink to
/// `/forbidden`. If the boundary matched on the written string rather than on the
/// resolved hierarchy, this would go through.
///
/// The control is the identical write to a real path under the grant, in the same
/// run: it happens, so a missing file below is the symlink and not a broken
/// shell.
#[test]
fn a_symlinked_write_outside_the_grant_never_takes_effect() {
    const SCENARIO: &str = "native adversarial: a symlinked write outside the grant never takes effect";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("symlink");
    let link = scratch.permitted().join("escape");
    std::os::unix::fs::symlink(scratch.forbidden(), &link).expect("the scenario's own symlink");
    let control_target = scratch.permitted().join("control");
    let escaped = link.join("escaped");

    let (completed, _) = run(
        &backend,
        &spec(
            &as_grandchild(&format!(
                "printf x > {} ; printf x > {}",
                shell_word(&control_target.to_string_lossy()),
                shell_word(&escaped.to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        control_target.exists(),
        "the control write inside the grant did not happen, so the assertion below proves nothing. \
         stderr: {:?}",
        completed.stderr
    );
    assert!(
        !scratch.forbidden().join("escaped").exists(),
        "a write through a symlink escaped the grant: {} exists",
        scratch.forbidden().join("escaped").display()
    );
    measured(
        SCENARIO,
        "a symlink inside the write grant pointing outside it did not make the target writable, while \
         the control write inside the grant did happen",
    );
}

/// A hard link cannot be used to bring a file from outside the grant into it.
///
/// The control is a hard link between two paths *inside* the grant: it is
/// created, so a missing link below is the boundary and not a filesystem that
/// refuses hard links or a shell without `ln`.
#[test]
fn a_hard_link_cannot_bring_a_forbidden_file_into_the_grant() {
    const SCENARIO: &str = "native adversarial: a hard link cannot bring a forbidden file into the grant";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("hardlink");
    let forbidden_secret = scratch.forbidden().join("secret");
    let inside_source = scratch.permitted().join("source");
    std::fs::write(&forbidden_secret, SECRET).expect("the scenario's own file");
    std::fs::write(&inside_source, SECRET).expect("the scenario's own file");
    let control_link = scratch.permitted().join("control-link");
    let escape_link = scratch.permitted().join("escape-link");

    let (completed, _) = run(
        &backend,
        &spec(
            &as_grandchild(&format!(
                "ln {} {} ; ln {} {}",
                shell_word(&inside_source.to_string_lossy()),
                shell_word(&control_link.to_string_lossy()),
                shell_word(&forbidden_secret.to_string_lossy()),
                shell_word(&escape_link.to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        control_link.exists(),
        "the control hard link inside the grant was not created, so the assertion below proves nothing. \
         stderr: {:?}",
        completed.stderr
    );
    assert!(
        !escape_link.exists(),
        "a hard link brought a file from outside the grant into it: {} exists",
        escape_link.display()
    );
    measured(
        SCENARIO,
        "a hard link within the grant was created and a hard link from outside it was not",
    );
}

/// A rename cannot move a file out of the grant, and cannot move one in.
///
/// The control is a rename entirely inside the grant, in the same run.
#[test]
fn a_rename_across_the_boundary_never_takes_effect() {
    const SCENARIO: &str = "native adversarial: a rename across the boundary never takes effect";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("rename");
    let inside = scratch.permitted().join("inside");
    let control_destination = scratch.permitted().join("moved");
    let outside_destination = scratch.forbidden().join("moved-out");
    let outside_source = scratch.forbidden().join("secret");
    let inside_destination = scratch.permitted().join("moved-in");
    std::fs::write(&inside, SECRET).expect("the scenario's own file");
    std::fs::write(&outside_source, SECRET).expect("the scenario's own file");

    let (completed, _) = run(
        &backend,
        &spec(
            &as_grandchild(&format!(
                "mv {} {} ; mv {} {} ; mv {} {}",
                shell_word(&inside.to_string_lossy()),
                shell_word(&control_destination.to_string_lossy()),
                shell_word(&control_destination.to_string_lossy()),
                shell_word(&outside_destination.to_string_lossy()),
                shell_word(&outside_source.to_string_lossy()),
                shell_word(&inside_destination.to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        control_destination.exists(),
        "the control rename inside the grant did not happen, so the assertions below prove nothing. \
         stderr: {:?}",
        completed.stderr
    );
    assert!(
        !outside_destination.exists(),
        "a rename moved a file out of the grant: {} exists",
        outside_destination.display()
    );
    assert!(
        !inside_destination.exists(),
        "a rename moved a file from outside the grant into it: {} exists",
        inside_destination.display()
    );
    // `mv` falls back to copy-and-delete when a rename is refused, so the source
    // still being there is part of the finding rather than incidental.
    assert!(
        outside_source.exists(),
        "the forbidden source was removed even though the move was refused"
    );
    measured(
        SCENARIO,
        "a rename inside the grant happened; renames out of it and into it did not, and the forbidden \
         source survived",
    );
}

/// A `..` component cannot walk out of the grant.
///
/// The policy layer rejects a `..` in an authored prefix, and the launcher
/// rejects a relative grant — but neither of those governs the path the *program*
/// constructs at run time, which is what this measures.
///
/// The control is the same write with the `..` pair removed, in the same run.
#[test]
fn a_parent_traversal_path_does_not_escape_the_grant() {
    const SCENARIO: &str = "native adversarial: a parent-traversal path does not escape the grant";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("traversal");
    let control_target = scratch.permitted().join("control");
    let traversed = scratch.permitted().join("..").join("forbidden").join("escaped");

    let (completed, _) = run(
        &backend,
        &spec(
            &as_grandchild(&format!(
                "printf x > {} ; printf x > {}",
                shell_word(&control_target.to_string_lossy()),
                shell_word(&traversed.to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        control_target.exists(),
        "the control write did not happen, so the assertion below proves nothing. stderr: {:?}",
        completed.stderr
    );
    assert!(
        !scratch.forbidden().join("escaped").exists(),
        "a `..` component walked out of the grant: {} exists",
        scratch.forbidden().join("escaped").display()
    );
    measured(
        SCENARIO,
        "a run-time path containing `..` did not reach outside the grant, while the same write without \
         it did",
    );
}

/// Renaming or symlinking the *program* does not change what it is confined to.
///
/// A boundary keyed on the executable's name rather than on the process would let
/// an agent escape by copying its interpreter. The control is the same script run
/// through the ordinary path, in a separate run.
#[test]
fn an_alternate_executable_path_is_confined_alike() {
    const SCENARIO: &str = "native adversarial: an alternate executable path is confined alike";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("altexec");
    let alias = scratch.permitted().join("not-a-shell");
    std::os::unix::fs::symlink("/bin/sh", &alias).expect("the scenario's own symlink");
    let target = scratch.forbidden().join("escaped");

    let script = as_grandchild(&format!("printf x > {}", shell_word(&target.to_string_lossy())));

    // Control: the same script through the ordinary program name, with the
    // forbidden directory granted, so the write demonstrably can happen.
    let (control, _) = run(
        &backend,
        &spec(
            &script,
            Vec::new(),
            vec![permit_only_selector(&scratch.forbidden().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &control);
    assert!(
        target.exists(),
        "the control run did not write the file, so the assertion below proves nothing. stderr: {:?}",
        control.stderr
    );
    std::fs::remove_file(&target).expect("the scenario's own file");

    // Test: the same script through the alias, with only the permitted directory
    // granted.
    let (test, _) = run(
        &backend,
        &spec_with(
            &alias.to_string_lossy(),
            &script,
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
            true,
        ),
    );
    assert_the_program_ran(SCENARIO, &test);
    assert!(
        !target.exists(),
        "a program reached through an alternate path escaped the boundary: {} exists",
        target.display()
    );
    measured(
        SCENARIO,
        "a symlinked interpreter was confined exactly as the ordinary one, against a control that shows \
         the write is otherwise possible",
    );
}

/// Another process's `/proc/<pid>/environ` is outside a launch that did not grant
/// `/proc`.
///
/// # The limitation this scenario also records
///
/// The grant is all-or-nothing here: a launch that grants `/proc` — which is what
/// a program needing `/proc/self` does today, and what every other scenario in
/// this suite does — gets every sibling entry with it. Scoping `/proc` finely is
/// AAASM-5804. What is measured here is that the *generic path scope* is the
/// mechanism that would carry that scoping, not that the gap is already closed.
///
/// The control is inside the run: the script prints a marker before it reads, so
/// an absent secret cannot be a shell that never started for want of `/proc`.
#[test]
fn another_processes_proc_entry_is_unreadable_without_a_proc_grant() {
    const SCENARIO: &str = "native adversarial: another process's /proc entry is unreadable without a /proc grant";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let marker = "aa-native-proc-marker";
    // This process's own environ, which carries a value no confined program was
    // given. Read through the pid rather than through `self`, because `self` is
    // the confined program's own and is legitimately its to read.
    let sibling = format!("/proc/{}/environ", std::process::id());

    let script = as_grandchild(&format!("printf {marker}; cat {}", shell_word(&sibling)));

    // Control: `/proc` granted. The read succeeds, so the file exists, is
    // readable by this user, and the command works.
    let (control, _) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
    assert_the_program_ran(SCENARIO, &control);
    assert!(control.stdout.contains(marker), "stdout: {:?}", control.stdout);
    assert!(
        control.stdout.len() > marker.len(),
        "the control run read nothing from {sibling}, so the test run proves nothing. stdout: {:?} \
         stderr: {:?}",
        control.stdout,
        control.stderr
    );

    // Test: the same command with `/proc` withheld.
    let (test, _) = run(&backend, &spec_with("/bin/sh", &script, Vec::new(), Vec::new(), false));
    assert_the_program_ran(SCENARIO, &test);
    assert!(
        test.stdout.contains(marker),
        "the confined shell never ran, so its silence about {sibling} means nothing. stdout: {:?} \
         stderr: {:?}",
        test.stdout,
        test.stderr
    );
    assert_eq!(
        test.stdout.trim_end_matches('\0'),
        marker,
        "another process's environ was readable from a launch that did not grant /proc. stdout: {:?}",
        test.stdout
    );
    measured(
        SCENARIO,
        "with /proc granted the sibling environ was readable and without it only the marker came back; \
         finer /proc scoping within a granted /proc remains AAASM-5804",
    );
}

/// **Fail-closed at the launcher.** A command line the launcher does not fully
/// understand must produce no process at all.
///
/// Two shapes, both driven against the real launcher binary: an unrecognised flag
/// and a permitted path that cannot be opened. The second is the important one —
/// dropping an unopenable grant would be *stricter*, so it is not a security
/// failure, but it would install a boundary that differs from the planned one
/// with nothing recording that it did.
///
/// The control is the identical invocation with the offending argument removed:
/// the program runs and leaves its file.
#[test]
fn the_launcher_refuses_a_command_line_it_cannot_fully_honour() {
    const SCENARIO: &str = "native adversarial: the launcher refuses a command line it cannot fully honour";
    if !cfg!(target_os = "linux") {
        decline::<()>(
            SCENARIO,
            Measurement::UnsupportedPlatform,
            &format!(
                "the launcher confines Linux processes; this host is {}",
                std::env::consts::OS
            ),
        );
        return;
    }
    if !launcher().is_file() {
        decline::<()>(
            SCENARIO,
            Measurement::ToolAbsent,
            &format!("the launcher `{}` was not built", launcher().display()),
        );
        return;
    }
    let scratch = Scratch::new("refuse");
    let system: Vec<String> = system_reads(true)
        .iter()
        .map(|s| format!("--fs-read={}", s.trim_start_matches("permit-only:")))
        .collect();

    let attempt = |extra: Vec<String>, target: &Path| -> std::process::Output {
        let mut command = std::process::Command::new(launcher());
        for arg in system.iter().chain(extra.iter()) {
            command.arg(arg);
        }
        command
            .arg(format!("--fs-write={}", scratch.permitted().display()))
            .arg(launch::ARG_SEPARATOR)
            .arg("/bin/sh")
            .arg("-c")
            .arg(format!("printf x > {}", shell_word(&target.to_string_lossy())))
            .output()
            .expect("the launcher could not be executed")
    };

    // Control: nothing extra. The program runs and its effect happens.
    let control_target = scratch.permitted().join("control");
    let control = attempt(Vec::new(), &control_target);
    assert!(
        control_target.exists(),
        "the control invocation produced no file, so the refusals below prove nothing. stderr: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&control.stderr).contains(launch::FAILURE_MARKER),
        "the control invocation was refused: {}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (name, extra) in [
        ("an unrecognised flag", vec!["--allow-everything".to_string()]),
        (
            "a permitted path that cannot be opened",
            vec!["--fs-read=/nonexistent/aa-native-adversarial".to_string()],
        ),
    ] {
        let target = scratch.permitted().join(name.replace(' ', "-"));
        let output = attempt(extra, &target);
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            stderr.contains(launch::FAILURE_MARKER),
            "with {name} the launcher did not report a refusal: {stderr}"
        );
        assert_eq!(
            output.status.code(),
            Some(launch::EXIT_LAUNCH_REFUSED),
            "with {name} the launcher exited {:?}",
            output.status
        );
        assert!(
            !target.exists(),
            "with {name} the launcher executed the program anyway: {} exists",
            target.display()
        );
    }
    measured(
        SCENARIO,
        "an unrecognised flag and an unopenable grant each produced a refusal and no process, against a \
         control invocation that ran",
    );
}

/// **Portable.** Observation is never promoted to prevention, on a run that
/// really happened.
///
/// This backend has no per-decision channel, so the strongest honest record is
/// `Exercised`. The pair that matters: the run produced `Installed` records — so
/// the evidence is not simply empty — and no domain supports a prevention claim.
#[test]
fn observation_is_never_promoted_to_prevention() {
    const SCENARIO: &str = "native adversarial: observation is never promoted to prevention";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("promote");
    let (completed, evidence) = run(
        &backend,
        &spec(
            &as_grandchild(&format!(
                "printf x > {}",
                shell_word(&scratch.forbidden().join("denied").to_string_lossy())
            )),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        !scratch.forbidden().join("denied").exists(),
        "the run this scenario reasons about was not actually confined"
    );
    assert!(
        evidence.records().iter().any(|r| r.kind == EvidenceKind::Installed),
        "no installed control was recorded, so the absence of a prevention claim is vacuous: {:?}",
        evidence.records()
    );
    for domain in CapabilityDomain::ALL {
        assert!(
            !evidence.supports_prevention_claim(*domain),
            "{domain} produced a prevention claim from a run with no decision record"
        );
    }
    assert!(!evidence.records().iter().any(|r| r.kind == EvidenceKind::Decision));
    measured(
        SCENARIO,
        "a genuinely denied write produced installed and exercised records and no prevention claim",
    );
}
