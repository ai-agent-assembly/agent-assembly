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
//! # The two `/proc` scenarios, and why there are two
//!
//! [`another_processes_proc_entry_is_unreadable_without_a_proc_grant`] measures
//! the generic path scope: withhold `/proc` and a per-PID entry beneath it is
//! unreachable like any other path. It reads `cmdline` rather than `environ`,
//! because `environ` is gated by ptrace access rules before this backend is
//! consulted at all — see that scenario for why crediting the boundary with that
//! denial would have been an over-claim, and how its own control caught the first
//! version doing exactly that.
//!
//! [`another_processs_environ_is_outside_a_scoped_proc_grant`] (AAASM-5804)
//! answers the harder question that one deliberately did not: whether a launch
//! that **grants** `/proc` — which is what a program needing its own process
//! state does, and what every other scenario in this suite does — still keeps
//! other processes' `environ` out. That is the route AAASM-5785 and AAASM-5786
//! found open, and it is re-run here against a control that first establishes
//! this host's ptrace rules permit the read, so the denial measured is this
//! backend's and not another LSM's.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use aa_isolation::{
    permit_only_selector, CapabilityDomain, ControlRequirement, EnforcementEvidence, EvidenceKind, ExecutionSpec,
    IdentityRef, IsolationBackend, RequirementScope, SupportLevel, CLOUD_METADATA_ENDPOINTS,
};
use aa_isolation_native::{launch, CompletedRun, NativeBackend, REQUIRED_ABI_VERSION};

// Only for `AttackFamily`, so `measured` below can tag every record with the
// family it belongs to (AAASM-5805) — the same format
// `adversarial::measured` uses, so this lane's ledger records line up with the
// Sandlock lane's. This file keeps its own `require_confining_backend`,
// `decline`, `Scratch` and the rest rather than switching to `adversarial`'s
// versions: `include_proc`/`spec_with`'s shape and `shell_word`'s name differ
// just enough from the neutral core's `system_reads`/`shell_spec_using`/
// `quote` that folding them together is a separate, larger change than this
// ticket's scope of "cover the four families native does not measure".
#[path = "adversarial/mod.rs"]
mod adversarial;

use adversarial::evidence::{self, Measurement};
use adversarial::{assert_prevented, AttackFamily, ControlledPair, Effect};

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

/// Record that a scenario took its measurement, tagged with its family — the
/// same `"{family}: {detail}"` format `adversarial::measured` writes, so a
/// reader of the ledger cannot tell which lane produced a record from its
/// shape.
fn measured(scenario: &str, family: AttackFamily, detail: &str) {
    evidence::record(
        scenario,
        Measurement::Measured,
        &format!("{}: {detail}", family.as_str()),
    );
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

/// The files a detached grandchild's leaf script leaves behind, so the
/// scenario can observe it without racing it.
struct DetachRecord {
    /// The grandchild's own PID, written first — identifies the process to
    /// check for cleanup afterward.
    pid_file: PathBuf,
    /// The grandchild's parent PID, written after it has slept — read late so
    /// the read happens once the orphaning this scenario is measuring has
    /// already occurred, rather than racing it.
    ppid_file: PathBuf,
    /// Written last, after `inner` has run (whether or not `inner` succeeded —
    /// this leaf never sets `-e`). Its presence is the synchronization point:
    /// polling for it, rather than sleeping a fixed duration, is what keeps the
    /// test run's timing identical to the control's instead of guessing at it.
    done_marker: PathBuf,
    /// AAASM-6041: the `getppid()` read's own stderr, kept so a failure of the
    /// *replacement* mechanism (rather than the `/proc/self` one AAASM-5532
    /// diagnosed) still surfaces a real cause instead of a bare empty ppid.
    read_stderr_file: PathBuf,
    /// AAASM-6041: the `getppid()` read's own exit status (`$?`), alongside
    /// `read_stderr_file`.
    read_status_file: PathBuf,
}

/// Detach `inner` from the launched process via `setsid --fork` plus a second
/// fork, and record the surviving grandchild's identity at the returned
/// [`DetachRecord`]'s paths before running it, so AAASM-5532's scenario below
/// can find that process and confirm — rather than assume — that it actually
/// re-parented and that nothing is left running once the scenario is done.
///
/// The shape is a genuine double fork, not the single-fork `setsid cmd &`
/// idiom: `setsid --fork` (the `--fork` is load-bearing — plain `setsid`
/// `exec`s in place instead of forking when its caller is not already a
/// process-group leader, which a non-interactive `sh` under this launcher
/// never is) forks P1 into a new session; P1's script forks a parenthesised
/// subshell that itself backgrounds the leaf command as P2 and then, having
/// started it, exits immediately — orphaning P2 out from under that subshell
/// before P1 even reaches its own `exit 0`. `wait` in the outermost script
/// blocks the launched process (P0) only on P1, not on P2, so P0 finishing
/// tells this scenario nothing about whether P2 has run yet or already
/// re-parented — the leaf sleeps briefly before reading its own parent PID so
/// that read happens after the orphaning, and the caller polls for
/// `done_marker` rather than sleeping a guessed duration before checking the
/// effect.
///
/// # Why the parent PID is read via `python3 -c 'os.getppid()'`, not `/proc/self`
///
/// AAASM-5532's first three passes tried reading `/proc/self/stat` from the
/// leaf, and its fourth pass got a real, reproducible `Permission denied` —
/// which a follow-up research pass (AAASM-5532's proc-self Landlock probe
/// report) then showed was **not** a Landlock or kernel limitation: 4
/// independent CI runs proved `/proc/self` reads work fine for a re-parented
/// descendant under an *unscoped* `/proc` grant. AAASM-6041 found the real
/// cause in this backend's own, deliberate `/proc` scoping
/// (`aa-isolation-native/src/proc_scope.rs`, AAASM-5804): granting `/proc`
/// does not install one rule on `/proc` — to keep every *other* process's
/// `/proc/<pid>/environ` outside the boundary, it installs one rule per
/// non-PID top-level entry plus **the literal string `/proc/self`**, resolved
/// once, in the launched process (P0), before `execve`. That rule's kernel
/// object is P0's own per-PID directory. A grandchild this scenario detaches
/// has a *different* real PID, so *its* `/proc/self` resolves to a directory
/// no rule names — exactly the "descendant cannot read its own per-PID entry
/// either" limitation `proc_scope.rs`'s own module doc already states. This
/// is not a bug to fix: withholding it is what keeps every other process's
/// `/proc/<pid>` out of the boundary, and loosening it back to an unscoped
/// `/proc` grant would undo AAASM-5804.
///
/// `getppid()` is a plain syscall, not filesystem-mediated by Landlock at
/// all, so it sidesteps the scoping limitation entirely rather than working
/// around it — exactly the follow-up direction AAASM-5532's `#[ignore]`
/// doc comment named ("a compiled helper reading its own PPID via
/// `getppid()` instead of `/proc/self/stat`"). `python3` is used instead of a
/// new compiled helper binary because `CPython`'s `os.getppid()` calls the
/// raw syscall directly (no `/proc` read), and `python3` is already proven to
/// exec correctly under this exact `system_reads` grant shape by the
/// AAASM-5849 real-Landlock-enforcement pass (dynamically-linked, needs `/usr`
/// and `/lib` granted for its interpreter and libraries — both already in
/// `system_reads`).
///
/// `read`, not `awk`, is still used to drain `pid_file`'s marker line further
/// down in each scenario that calls this helper for reasons unrelated to
/// `/proc`: spawning `awk` here would make *that new process's* identity, not
/// the leaf's, the thing recorded, and CI caught exactly this on the first
/// version of this scenario.
fn as_detached_grandchild(files: &DetachRecord, inner: &str) -> String {
    // `exec`, not a plain invocation: spawning `python3` as a *child* of the
    // leaf (the first draft of this fix did exactly that) makes `getppid()`
    // report the leaf's own pid, not the leaf's parent — the same "measuring
    // the wrong process's identity" mistake `awk` made in this scenario's
    // very first version, just one syscall later. `exec` replaces the leaf
    // shell's process image with python3 *in place*, keeping the same pid and
    // therefore the same, correctly-current ppid `getppid()` reports — no new
    // process is created to do the reading.
    let py_script = format!(
        "import os\nopen({ppid_file:?}, 'w').write(str(os.getppid()))\nos.system({inner:?})\nopen({done_marker:?}, \
         'w').write('x')\n",
        ppid_file = files.ppid_file.to_string_lossy(),
        inner = inner,
        done_marker = files.done_marker.to_string_lossy(),
    );
    let leaf = format!(
        "echo $$ > {} ; sleep 0.3 ; exec python3 -c {} 2> {} ; echo $? > {}",
        shell_word(&files.pid_file.to_string_lossy()),
        shell_word(&py_script),
        shell_word(&files.read_stderr_file.to_string_lossy()),
        shell_word(&files.read_status_file.to_string_lossy()),
    );
    let subshell = format!("( /bin/sh -c {} & ) ; exit 0", shell_word(&leaf));
    format!("setsid --fork /bin/sh -c {} & wait", shell_word(&subshell))
}

fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Poll `path` for a decimal PID and return it once one is written.
///
/// `None` if nothing appeared inside `timeout` — a scenario turns that into a
/// "proves nothing" failure rather than treating an empty file as pid 0.
fn wait_for_pid_file(path: &Path, timeout: Duration) -> Option<i32> {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if let Ok(pid) = contents.trim().parse::<i32>() {
                return Some(pid);
            }
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    None
}

/// Poll for `path` to exist within `timeout`.
fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    path.exists()
}

/// Poll for `/proc/<pid>` to stop existing within `timeout` — the cleanup half
/// of the detached-grandchild scenario: a boundary that denies the write but
/// leaves the re-parented process running would still be an orphan this suite
/// has to catch.
fn wait_for_pid_exit(pid: i32, timeout: Duration) -> bool {
    let proc_path = PathBuf::from(format!("/proc/{pid}"));
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if !proc_path.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    !proc_path.exists()
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
        AttackFamily::ForbiddenFilesystemWrite,
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
        AttackFamily::ForbiddenFilesystemWrite,
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
        AttackFamily::ForbiddenFilesystemWrite,
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
        AttackFamily::ForbiddenFilesystemWrite,
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
        AttackFamily::ProcessTreeAndAlternateExecutables,
        "a symlinked interpreter was confined exactly as the ordinary one, against a control that shows \
         the write is otherwise possible",
    );
}

/// **AAASM-5532: the one attack class the prior two passes on this ticket found
/// nowhere in this repo.** A grandchild that calls `setsid()` and double-forks to
/// escape the launched process's session and process group is confined
/// identically to an ordinary descendant.
///
/// Every scenario above this one measures descendants that stay inside the
/// launched process's tree — [`descendant_confinement_at_three_depths`] in the
/// sibling confinement suite goes three `fork`/`exec` levels deep, but every one
/// of those descendants is still a *child* of something the launcher started,
/// still in the same process group. `setsid()` plus a second fork is different in
/// kind: the survivor leaves the launched process's session and process group
/// entirely and, once its immediate parent exits, is re-parented by the kernel to
/// the nearest subreaper — PID 1 on this runner, since nothing upstream of the
/// launcher installs one (`prctl(PR_SET_CHILD_SUBREAPER)`). Landlock is
/// documented as scoping a *task's* inherited security credential rather than
/// its process-group or session membership, which predicts the boundary follows
/// the detached grandchild anyway — but that is a claim about the mechanism, not
/// a measurement of this backend on this kernel, and this scenario is the
/// difference between the two. If it fails, that is the honest answer: this
/// backend's reach does not extend to a re-parented descendant, and the
/// prevention claim above cannot be made for this attack class.
///
/// # What is actually measured, not assumed
///
/// * **Re-parenting** — read, not inferred from the shell script's shape. Each
///   grandchild `exec`s into `getppid()` (see `as_detached_grandchild`'s own
///   doc for why `exec`, not a child process, and why `getppid()` rather than
///   `/proc/self`) *after* sleeping past the point its immediate parent has
///   exited, and the scenario asserts
///   that value is `1`: the definition of "re-parented to the nearest
///   subreaper" on a runner where nothing upstream of the launcher installs
///   one. A value other than `1` fails loudly, naming
///   `PR_SET_CHILD_SUBREAPER` as the other explanation, rather than silently
///   passing a scenario that never actually detached.
/// * **The write, via [`ControlledPair`]** — the same adjudicator every other
///   suite in this repo uses, so a broken detach script reads as
///   [`PairVerdict::ControlProducedNoEffect`] and a recorded `not_measured`
///   decline rather than as a silent pass.
/// * **Cleanup** — both grandchildren's PIDs are polled out of `/proc`
///   afterward. A boundary that denies the write but leaves the orphaned
///   process running is a defect this scenario also has to catch, not a
///   partial success.
///
/// Both runs synchronize on a completion marker the leaf writes only after
/// `inner` has run (successfully or not — this leaf never sets `-e`), so the
/// test run's timing is identical to the control's rather than a guessed sleep
/// racing the leaf.
///
/// # Real-CI history: two mechanisms diagnosed and one worked around, not fixed
///
/// Four real-CI iterations on `ubuntu-24.04` (`gh pr checks` on PR #2348,
/// AAASM-5532) converged on a real, reproducible `cat: /proc/self/stat:
/// Permission denied` reading the detached grandchild's own `/proc/self` —
/// via the shell's own `read` builtin (not `awk`, which reads *its own*
/// `/proc/self` as a freshly-forked process and never re-parents; caught on
/// the very first version of this scenario) with output-redirected
/// diagnostics (an input-redirected `read < /proc/self/stat`'s own failure is
/// reported to the shell's unredirected stderr, not the command's `2>`, so it
/// captures nothing — the third iteration's dead end).
///
/// A follow-up research pass (AAASM-5532's proc-self Landlock probe report)
/// then showed this was **not** a Landlock or kernel limitation: 4 zero-cost
/// GitHub-hosted CI runs, each closing one fidelity gap against the real
/// product's exact ruleset and launch order — including genuine PID-1
/// re-parenting — all read `/proc/self/stat` successfully under an *unscoped*
/// `/proc` grant.
///
/// AAASM-6041 found the real, precise cause: this backend's own `/proc`
/// scoping (`aa-isolation-native/src/proc_scope.rs`, AAASM-5804) trades a
/// deliberate, documented limitation for a real security property. See
/// `as_detached_grandchild`'s own doc for the mechanism and why the fix here
/// is `getppid()`, not a `/proc` grant change — a `/proc` grant that reached
/// every descendant's own per-PID directory would have to stop excluding
/// other *processes'* per-PID directories too, undoing AAASM-5804. Restored
/// to `.ci/isolation-native-lane-scenarios.txt` alongside this fix.
#[test]
fn a_detached_and_reparented_grandchild_is_confined_alike() {
    const SCENARIO: &str = "native adversarial: a detached and re-parented grandchild is confined alike";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("detach");
    let control_target = scratch.permitted().join("control-write");
    let control_files = DetachRecord {
        pid_file: scratch.permitted().join("control-pid"),
        ppid_file: scratch.permitted().join("control-ppid"),
        done_marker: scratch.permitted().join("control-done"),
        read_stderr_file: scratch.permitted().join("control-read-stderr"),
        read_status_file: scratch.permitted().join("control-read-status"),
    };
    let test_target = scratch.forbidden().join("escaped-write");
    let test_files = DetachRecord {
        pid_file: scratch.permitted().join("test-pid"),
        ppid_file: scratch.permitted().join("test-ppid"),
        done_marker: scratch.permitted().join("test-done"),
        read_stderr_file: scratch.permitted().join("test-read-stderr"),
        read_status_file: scratch.permitted().join("test-read-status"),
    };

    let (control, _) = run(
        &backend,
        &spec(
            &as_detached_grandchild(
                &control_files,
                &format!("printf x > {}", shell_word(&control_target.to_string_lossy())),
            ),
            // The leaf reads its own re-parented identity from `/proc/self/stat`
            // (see `as_detached_grandchild`'s doc) — without an explicit read
            // grant covering `/proc`, that read is denied like any other
            // ungranted path, and `read` silently sets `$ppid` to the empty
            // string on EOF rather than failing loudly (CI caught exactly this:
            // an empty `ppid_file` reads as "harness bug", per
            // `assert_reparented_to_the_nearest_subreaper`'s own panic message,
            // not a Landlock finding about this attack class).
            vec![permit_only_selector("/proc")],
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &control);
    let control_pid = wait_for_pid_file(&control_files.pid_file, Duration::from_secs(5)).unwrap_or_else(|| {
        panic!("[{SCENARIO}] the control's detached grandchild never recorded its PID, so nothing below is measured")
    });
    assert!(
        wait_for_path(&control_files.done_marker, Duration::from_secs(5)),
        "the control's detached grandchild never finished, so the effect check below proves nothing. stderr: \
         {:?}",
        control.stderr
    );
    assert_reparented_to_the_nearest_subreaper(SCENARIO, "control", &control_files);
    assert!(
        control_target.exists(),
        "the control's detached, re-parented grandchild did not write the file it was permitted to write, so \
         the test run below proves nothing. stderr: {:?}",
        control.stderr
    );
    assert!(
        wait_for_pid_exit(control_pid, Duration::from_secs(5)),
        "the control's detached grandchild (pid {control_pid}) was still running after completing its write, \
         so this scenario's cleanup check cannot be trusted"
    );

    let (test, _) = run(
        &backend,
        &spec(
            &as_detached_grandchild(
                &test_files,
                &format!("printf x > {}", shell_word(&test_target.to_string_lossy())),
            ),
            // Same /proc read grant as the control run above — the two must
            // stay identical except for the write target, or a difference in
            // the leaf's own read behaviour (not the attack) could explain a
            // divergence in the pair.
            vec![permit_only_selector("/proc")],
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &test);
    let test_pid = wait_for_pid_file(&test_files.pid_file, Duration::from_secs(5)).unwrap_or_else(|| {
        panic!("[{SCENARIO}] the test's detached grandchild never recorded its PID, so its escape attempt never ran")
    });
    assert!(
        wait_for_path(&test_files.done_marker, Duration::from_secs(5)),
        "the test's detached grandchild never finished its escape attempt, so the effect check below proves \
         nothing. stderr: {:?}",
        test.stderr
    );
    assert_reparented_to_the_nearest_subreaper(SCENARIO, "test", &test_files);

    let pair = ControlledPair::new(
        AttackFamily::ProcessTreeAndAlternateExecutables,
        Effect::new(
            "a detached, re-parented grandchild writes outside its grant",
            test_target.exists(),
            format!("{} exists: {}", test_target.display(), test_target.exists()),
        ),
        Effect::new(
            "the identical detach sequence writes inside its grant",
            control_target.exists(),
            format!("{} exists: {}", control_target.display(), control_target.exists()),
        ),
    );
    let detail = assert_prevented(SCENARIO, &pair);

    assert!(
        wait_for_pid_exit(test_pid, Duration::from_secs(5)),
        "the detached, re-parented grandchild (pid {test_pid}) that attempted the forbidden write was still \
         running after this scenario's wait window — a denied write must not leave an orphan behind either"
    );

    measured(
        SCENARIO,
        AttackFamily::ProcessTreeAndAlternateExecutables,
        &format!(
            "{detail}; both grandchildren's parent PID read 1 after re-parenting, and neither was left \
             running once the scenario finished"
        ),
    );
}

/// Assert that `ppid_file` — read by the leaf after it slept past the point its
/// immediate parent exited — names PID 1, the nearest subreaper on a runner
/// where nothing upstream of the launcher installs one via
/// `prctl(PR_SET_CHILD_SUBREAPER)`. That is what "re-parented" means here, read
/// from `/proc` rather than assumed from the detach script's shape.
fn assert_reparented_to_the_nearest_subreaper(scenario: &str, run_label: &str, files: &DetachRecord) {
    let ppid_file = &files.ppid_file;
    let contents = std::fs::read_to_string(ppid_file).unwrap_or_else(|e| {
        panic!(
            "[{scenario}] the {run_label} run's grandchild never recorded its parent PID at {}: {e}",
            ppid_file.display()
        )
    });
    let ppid: i32 = contents.trim().parse().unwrap_or_else(|e| {
        // AAASM-5532 diagnostic pass: read back what the leaf's own `read <
        // /proc/self/stat` actually did, rather than guess a third time —
        // two prior real-CI-driven fixes both left this empty.
        let status = std::fs::read_to_string(&files.read_status_file).unwrap_or_else(|_| "<not written>".to_string());
        let stderr = std::fs::read_to_string(&files.read_stderr_file).unwrap_or_else(|_| "<not written>".to_string());
        panic!(
            "[{scenario}] the {run_label} run's grandchild wrote a non-numeric parent PID {:?}: {e}. The \
             read's own exit status was {status:?} and its stderr was {stderr:?}.",
            contents.trim()
        )
    });
    assert_eq!(
        ppid, 1,
        "[{scenario}] the {run_label} run's detached grandchild reports parent PID {ppid}, not 1 — either it \
         never actually re-parented (its immediate parent had not yet exited when it called \
         getppid()) or this runner has a subreaper other than PID 1 installed via \
         PR_SET_CHILD_SUBREAPER upstream of the launcher"
    );
}

/// Another process's per-PID `/proc` entry is outside a launch that did not grant
/// `/proc`.
///
/// # Why this reads `cmdline` and not `environ`
///
/// `environ` was the obvious target — ADR 0035's AAASM-5801 amendment names it —
/// and it is the wrong one for *this* measurement. Reading another process's
/// `environ` requires `PTRACE_MODE_READ`, and on a host running Yama (the CI
/// runner reports `lockdown,capability,landlock,yama,apparmor,ima,evm`) a
/// descendant may not ptrace an ancestor. So the control run could not read it
/// either, with `/proc` fully granted — the first version of this scenario failed
/// on exactly that, which is the control doing its job: the boundary would have
/// been credited with a denial that a different LSM had already made.
///
/// `cmdline` is world-readable and needs no ptrace access, so the *only* thing
/// standing between the confined program and another process's copy of it is this
/// backend's path scope. That makes it the honest probe of the mechanism, and the
/// `environ` result above is recorded as the defence-in-depth fact it is rather
/// than claimed as this backend's.
///
/// # What this scenario measures, and what the sibling scenario measures
///
/// This one is about the **generic path scope**: withhold `/proc` and a per-PID
/// entry beneath it is unreachable like any other path. Whether a *granted*
/// `/proc` still hides other processes' entries is a different question, answered
/// by [`another_processs_environ_is_outside_a_scoped_proc_grant`] (AAASM-5804) —
/// and because that scope now applies to every launch this backend makes, the
/// control below is taken through the launcher directly, which is the only
/// remaining way to ask for an unscoped `/proc`.
///
/// A second control is inside the run: the script prints a marker before it
/// reads, so an absent payload cannot be a shell that never started for want of
/// `/proc`.
#[test]
fn another_processes_proc_entry_is_unreadable_without_a_proc_grant() {
    const SCENARIO: &str = "native adversarial: another process's /proc entry is unreadable without a /proc grant";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let marker = "aa-native-proc-marker";
    // This process's own entry, read through the pid rather than through `self`:
    // `self` is the confined program's own and is legitimately its to read.
    let sibling = format!("/proc/{}/cmdline", std::process::id());

    let script = as_grandchild(&format!("printf {marker}; cat {}", shell_word(&sibling)));

    // Control: `/proc` granted whole. The read succeeds, so the file exists, is
    // readable by this user, and the command works.
    let (control, control_stderr) = unscoped_proc_run(&script);
    assert!(
        !control_stderr.contains(launch::FAILURE_MARKER),
        "the control launcher invocation refused to establish a boundary: {control_stderr}"
    );
    assert!(control.contains(marker), "stdout: {control:?}");
    assert!(
        control.len() > marker.len(),
        "the control run read nothing from {sibling} even with /proc granted whole, so the test run \
         proves nothing. output: {control:?}"
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
        "another process's per-PID entry was readable from a launch that did not grant /proc. \
         stdout: {:?}",
        test.stdout
    );
    measured(
        SCENARIO,
        AttackFamily::ProcessInspection,
        "with /proc granted whole the sibling cmdline was readable and without any /proc grant only the \
         marker came back. Note what this does NOT claim: `environ` is separately gated by ptrace access \
         rules, so a denial of it on a Yama host is not this backend's — the scenario that measures a \
         granted /proc withholding another process's environ, against a control that shows ptrace \
         permitted the read, is `another process's environ is outside a scoped /proc grant`",
    );
}

/// **The AAASM-5785 scenario, re-run against this backend.** Another process's
/// `/proc/<pid>/environ` is outside a launch that granted `/proc`, and the
/// confined program keeps its own process state.
///
/// # Why this is the closing evidence for AAASM-5785 and AAASM-5786 rather than a
/// new test
///
/// The Sandlock suite's `process_inspection_is_available_only_where_the_launch
/// _granted_it` carries a *finding probe*: with `/proc` granted — which nearly
/// every launch grants — the confined program read a marker out of another
/// process's environment, so replacing the child's environment was not a
/// credential boundary. That probe is recorded and never asserted there, because
/// nothing in that backend could close it. This asserts it, on this backend,
/// against the same route: an `environ` belonging to a process that is not the
/// confined one.
///
/// # The predicate is *openability*, not a grep for a marker
///
/// The Sandlock probe greps `/proc/*/environ` for a marker. It cannot be lifted
/// verbatim: `grep` is a child of the shell, so every process the shell forked is
/// `grep`'s **sibling**, and on a Yama host a sibling's `environ` is refused by
/// ptrace access rules before this backend is consulted — the trap AAASM-5802's
/// own `/proc` scenario fell into and recorded. So the reads here are done by the
/// shell itself, through a redirection on a builtin, which is performed in the
/// shell process without forking. The shell is the **parent** of the process
/// whose `environ` it opens, which is a relationship Yama permits, so a refusal
/// is this backend's or it is nothing.
///
/// `if true < PATH` succeeds exactly when the open succeeded, which is where the
/// kernel primitive makes its decision. It is not a weaker question than the
/// grep: a marker that cannot be opened cannot be read.
///
/// # The control is an unscoped `/proc`, through the same launcher
///
/// The control run drives the launcher binary directly with `--fs-read=/proc` —
/// the boundary this backend installed before this ticket — and differs from the
/// test run by that one grant. It establishes three things at once, all of which
/// the assertions below would otherwise be assuming: the child was forked, this
/// host's ptrace rules permit a parent to open its child's `environ`, and the
/// per-PID entries are reachable when nothing scopes them. If the control does
/// not show the leak, the scenario **declines** rather than passing — a boundary
/// credited with a denial some other mechanism already made is the exact
/// over-claim this suite exists to refuse.
#[test]
fn another_processs_environ_is_outside_a_scoped_proc_grant() {
    const SCENARIO: &str = "native adversarial: another process's environ is outside a scoped /proc grant";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    // A process outside the confined tree entirely, whose `cmdline` needs no
    // ptrace access at all — so its denial cannot be attributed to any LSM but
    // this backend's path scope.
    let sibling = format!("/proc/{}/cmdline", std::process::id());
    let script = proc_inspection_script(&sibling);

    // Control: the launcher, driven directly, with `/proc` granted whole. The
    // streams stay apart because a refused open writes to stderr and every tag
    // is on stdout.
    let (control, control_stderr) = unscoped_proc_run(&script);
    assert!(
        !control_stderr.contains(launch::FAILURE_MARKER),
        "the control launcher invocation refused to establish a boundary, so it measured nothing: \
         {control_stderr}"
    );
    for tag in ["RAN;", "OWNENV;", "SYSCTL;", "CHILDCMD;", "SIBLINGCMD;"] {
        assert!(
            control.contains(tag),
            "the control run with /proc granted whole did not report `{tag}`, so the test run's silence \
             establishes nothing. stdout: {control:?}"
        );
    }
    if !control.contains("CHILDENV;") {
        // Not a failure of this backend: on a host whose ptrace policy refuses
        // even a parent reading its child's `environ`, the route AAASM-5785 found
        // is closed by something else and this scenario cannot measure the scope
        // closing it.
        decline::<()>(
            SCENARIO,
            Measurement::NotMeasured,
            &format!(
                "with /proc granted whole the confined program still could not open its own child's \
                 environ, so this host's ptrace policy — not this backend — is what closes that route, \
                 and crediting the scope with the denial below would be an over-claim. control stdout: \
                 {control:?}"
            ),
        );
        return;
    }

    // Test: the same script through the backend, which scopes the same grant.
    let (test, evidence) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
    assert_the_program_ran(SCENARIO, &test);
    assert!(
        test.stdout.contains("RAN;"),
        "the confined shell never ran, so its silence about /proc means nothing. stdout: {:?} stderr: {:?}",
        test.stdout,
        test.stderr
    );
    // The half that must still work: its own process state, and the parts of
    // `/proc` that belong to no process.
    for tag in ["OWNENV;", "SYSCTL;"] {
        assert!(
            test.stdout.contains(tag),
            "the scope withheld `{tag}`, which is the confined program's own process state or a non-PID \
             part of /proc that the grant covered. stdout: {:?}",
            test.stdout
        );
    }
    // The half AAASM-5785 is about.
    assert!(
        !test.stdout.contains("CHILDENV;"),
        "another process's environ was readable from a launch that granted /proc — the AAASM-5785 gap is \
         open on this backend. stdout: {:?}",
        test.stdout
    );
    for tag in ["CHILDCMD;", "SIBLINGCMD;"] {
        assert!(
            !test.stdout.contains(tag),
            "a per-PID /proc entry belonging to another process was readable (`{tag}`). stdout: {:?}",
            test.stdout
        );
    }
    // And the run says so in its own evidence, so a consumer does not have to
    // re-derive it from the path list.
    assert!(
        evidence.records().iter().any(|r| {
            r.domain == Some(CapabilityDomain::Credential) && r.detail.contains("per-PID /proc entries are OUTSIDE")
        }),
        "the run did not record that it scoped /proc: {:?}",
        evidence.records()
    );

    measured(
        SCENARIO,
        AttackFamily::ProcessInspection,
        "with /proc granted whole the confined program opened its own child's environ, its child's \
         cmdline and an unrelated process's cmdline; with the same grant scoped by this backend it opened \
         none of the three, while its own /proc/self/environ and /proc/sys stayed reachable. This is the \
         AAASM-5785 route, re-run against this backend and closed",
    );
}

/// The script both runs of the `/proc` scenario execute, verbatim.
///
/// Every read is done by the shell through a redirection on a builtin, so the
/// process that opens the file is the shell itself — see the scenario's doc
/// comment for why that matters. Each success prints its own tag, so an absent
/// tag is a refused open and never a command that was not reached.
///
/// **No `2>/dev/null` anywhere.** Writing to `/dev/null` needs write access to
/// it, which no scenario in this suite grants, so an ordinary-looking
/// `if true 2>/dev/null < PATH` fails on the *redirection* rather than on the
/// path under test — measured on the lane, where every probe including the
/// controls came back as `cannot create /dev/null: Permission denied`. The
/// shell's diagnostics go to standard error and every tag goes to standard
/// output, so the two are simply read separately.
///
/// Deliberately **not** wrapped in [`as_grandchild`]: the rule this scope
/// installs is tied to the launched process's own per-PID directory, which is the
/// only one that exists when the boundary is installed, so `/proc/self` from a
/// grandchild is a different directory and would measure the recorded limitation
/// rather than the property. Descendant coverage is measured by
/// `linux_confinement_native.rs`, on the grant that carries it.
fn proc_inspection_script(sibling_cmdline: &str) -> String {
    format!(
        "printf 'RAN;'; \
         /bin/sleep 5 & \
         c=$!; \
         if true < /proc/self/environ; then printf 'OWNENV;'; fi; \
         if true < /proc/sys/kernel/ostype; then printf 'SYSCTL;'; fi; \
         if true < /proc/$c/environ; then printf 'CHILDENV;'; fi; \
         if true < /proc/$c/cmdline; then printf 'CHILDCMD;'; fi; \
         if true < {sibling}; then printf 'SIBLINGCMD;'; fi; \
         kill $c; \
         exit 0",
        sibling = shell_word(sibling_cmdline)
    )
}

/// Run `script` through the launcher with `/proc` granted whole — the boundary
/// this backend installed before AAASM-5804.
///
/// Driven against the launcher binary directly because there is no longer a
/// supported way to ask the backend for an unscoped `/proc`, which is the point.
/// Same launcher, same kernel, same system grants; one grant differs.
fn unscoped_proc_run(script: &str) -> (String, String) {
    let mut command = std::process::Command::new(launcher());
    for selector in system_reads(true) {
        command.arg(format!("--fs-read={}", selector.trim_start_matches("permit-only:")));
    }
    let output = command
        .arg(launch::ARG_SEPARATOR)
        .arg("/bin/sh")
        .arg("-c")
        .arg(script)
        .output()
        .expect("the launcher could not be executed");
    (
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
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
        AttackFamily::BackendPosture,
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
        AttackFamily::ObserveAndDegradedTruthfulness,
        "a genuinely denied write produced installed and exercised records and no prevention claim",
    );
}

/// **The measurement this backend's ABI floor turns on.**
///
/// `truncate(2)` takes a path and needs no writable descriptor. Below the ABI
/// this backend's rules are built against, the kernel does not handle the
/// truncate right, so a path-scoped write restriction denies `open(O_WRONLY)` on
/// a forbidden file and still lets a confined program destroy its contents.
///
/// # Why this is not part of the discovery probe
///
/// An earlier draft measured it there with the shell's `> file` redirection.
/// That is `open(O_TRUNC)`, which the *write* right already governs — so the
/// denial observed was the same denial the write pair observes, and the pair was
/// a second measurement of the first thing wearing the name of the syscall it
/// did not exercise. Reaching the standalone syscall needs an interpreter, and
/// making the backend's write claim depend on `python3` being installed would be
/// a worse trade than measuring it here, where a host without one declines
/// visibly instead.
///
/// The control is the identical call on a file *inside* the write grant: it
/// shrinks, so a file that did not shrink below is the boundary and not a
/// misspelled call or an interpreter that refused.
#[test]
fn a_standalone_truncate_syscall_outside_the_grant_never_takes_effect() {
    const SCENARIO: &str = "native adversarial: a standalone truncate(2) outside the grant never takes effect";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let Some(interpreter) = truncate_interpreter() else {
        decline::<()>(
            SCENARIO,
            Measurement::ToolAbsent,
            "no interpreter on PATH can call truncate(2) by path, and no POSIX shell builtin can — the \
             standalone syscall was not exercised on this host",
        );
        return;
    };

    let scratch = Scratch::new("truncate");
    let control_target = scratch.permitted().join("control");
    let test_target = scratch.forbidden().join("test");
    for path in [&control_target, &test_target] {
        std::fs::write(path, SECRET).expect("the scenario's own file");
    }
    let shrank = |path: &Path| {
        std::fs::metadata(path)
            .map(|m| (m.len() as usize) < SECRET.len())
            .unwrap_or(false)
    };
    let truncate = |path: &Path| {
        as_grandchild(&format!(
            "{interpreter} -c \"import os,sys;os.truncate(sys.argv[1],0)\" {}",
            shell_word(&path.to_string_lossy())
        ))
    };

    let (completed, _) = run(
        &backend,
        &spec(
            &format!("{} ; {}", truncate(&control_target), truncate(&test_target)),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        ),
    );
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        shrank(&control_target),
        "the control truncate(2) inside the write grant did not shrink the file, so the assertion below \
         proves nothing. stdout: {:?} stderr: {:?}",
        completed.stdout,
        completed.stderr
    );
    assert!(
        !shrank(&test_target),
        "truncate(2) destroyed a file outside the write grant: {} is now {} bytes. The kernel is not \
         handling the truncate right this backend's ABI floor requires",
        test_target.display(),
        std::fs::metadata(&test_target).map(|m| m.len()).unwrap_or_default()
    );
    measured(
        SCENARIO,
        AttackFamily::ForbiddenFilesystemWrite,
        "truncate(2) shrank a file inside the write grant and could not shrink one outside it",
    );
}

/// An interpreter that can call `truncate(2)` by path, if this host has one.
///
/// No POSIX shell builtin reaches the standalone syscall — `> file` is
/// `open(O_TRUNC)` and answers a different question — so the scenario above needs
/// one of these or it declines.
fn truncate_interpreter() -> Option<&'static str> {
    ["python3", "python"].into_iter().find(|program| {
        std::process::Command::new("which")
            .arg(program)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    })
}

// ---------------------------------------------------------------------------
// AAASM-5803: the syscall filter.
// ---------------------------------------------------------------------------

/// The loader/shell-needed calls this file's syscall scenarios grant so `/bin/sh`
/// itself can run, deliberately excluding `write` — the call under test.
fn syscall_loader_baseline() -> Vec<String> {
    [
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
    ]
    .iter()
    .map(|s| permit_only_selector(s))
    .collect()
}

/// **AC: `DescendantCoverage::ProcessTree` for the syscall domain is earned, not
/// assumed.** A grandchild of the launched process — two `fork`/`exec` steps
/// below the one the launcher `execve`d — cannot make a syscall the launch did
/// not permit.
///
/// The control is the identical grandchild-depth attempt with `write`
/// additionally allowlisted: it produces the effect, so the denial below is
/// about the filter and not about the grandchild failing to run at all.
#[test]
fn a_descendant_cannot_make_a_syscall_the_launch_did_not_permit() {
    const SCENARIO: &str = "native adversarial: a descendant cannot make a syscall the launch did not permit";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    let scratch = Scratch::new("syscall-descendant");
    let test_target = scratch.permitted().join("test");
    let control_target = scratch.permitted().join("control");

    let base = |target: &Path| {
        spec(
            &as_grandchild(&format!("printf x > {}", shell_word(&target.to_string_lossy()))),
            Vec::new(),
            vec![permit_only_selector(&scratch.permitted().to_string_lossy())],
        )
    };

    // `openat(O_CREAT)` is in the loader baseline either way, so the target
    // file's mere *existence* is a false positive: it exists whether or not
    // `write` ran. What `write` decides is whether the empty file `openat`
    // created gets any bytes in it, so the observable is the file's content.
    let has_content = |p: &Path| p.exists() && std::fs::read(p).map(|b| !b.is_empty()).unwrap_or(false);

    let test = base(&test_target).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Syscall)
            .with_scope(RequirementScope::Selectors(syscall_loader_baseline())),
    );
    let (completed, _) = run(&backend, &test);
    assert_the_program_ran(SCENARIO, &completed);
    assert!(
        !has_content(&test_target),
        "a grandchild made a syscall the launch did not permit: {} has content",
        test_target.display()
    );

    let mut control_names = syscall_loader_baseline();
    control_names.push(permit_only_selector("write"));
    let control = base(&control_target).with_requirement(
        ControlRequirement::prevent(CapabilityDomain::Syscall).with_scope(RequirementScope::Selectors(control_names)),
    );
    let (control_completed, _) = run(&backend, &control);
    assert_the_program_ran(SCENARIO, &control_completed);
    assert!(
        has_content(&control_target),
        "the control grandchild, with `write` allowlisted, produced no effect, so the denial above proves \
         nothing. stderr: {:?}",
        control_completed.stderr
    );
    measured(
        SCENARIO,
        AttackFamily::SyscallAndResource,
        "a grandchild of the launched process was killed for a syscall the launch did not permit, while \
         the identical grandchild with that syscall allowlisted produced its effect",
    );
}

/// The launcher refuses a syscall filter it cannot fully honour — a name
/// outside the closed vocabulary on the command line — rather than installing
/// one that differs from what the supervisor asked for.
///
/// The control is the identical command line with a valid name in place of the
/// unrecognised one: it runs and produces the effect.
#[test]
fn the_launcher_refuses_a_syscall_filter_it_cannot_fully_honour() {
    const SCENARIO: &str = "native adversarial: the launcher refuses a syscall filter it cannot fully honour";
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
    let scratch = Scratch::new("syscall-refuse");
    let system: Vec<String> = system_reads(true)
        .iter()
        .map(|s| format!("--fs-read={}", s.trim_start_matches("permit-only:")))
        .collect();

    let attempt = |syscall_args: Vec<String>, target: &Path| -> std::process::Output {
        let mut command = std::process::Command::new(launcher());
        for arg in system.iter().chain(syscall_args.iter()) {
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

    let mut valid_args: Vec<String> = vec![launch::FLAG_SYSCALL_FILTER.to_string()];
    for name in [
        "read",
        "write",
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
    ] {
        valid_args.push(format!("{}={name}", launch::FLAG_SYSCALL_ALLOW));
    }
    let control_target = scratch.permitted().join("control");
    let control = attempt(valid_args, &control_target);
    assert!(
        control_target.exists(),
        "the control invocation, naming only valid syscalls, produced no file, so the refusal below \
         proves nothing. stderr: {}",
        String::from_utf8_lossy(&control.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&control.stderr).contains(launch::FAILURE_MARKER),
        "the control invocation was refused: {}",
        String::from_utf8_lossy(&control.stderr)
    );

    let unknown_args = vec![
        launch::FLAG_SYSCALL_FILTER.to_string(),
        format!("{}=ptrace", launch::FLAG_SYSCALL_ALLOW),
    ];
    let unknown_target = scratch.permitted().join("unknown");
    let output = attempt(unknown_args, &unknown_target);
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        stderr.contains(launch::FAILURE_MARKER),
        "a syscall name outside the closed vocabulary did not produce a refusal: {stderr}"
    );
    assert_eq!(
        output.status.code(),
        Some(launch::EXIT_LAUNCH_REFUSED),
        "the launcher exited {:?} instead of refusing",
        output.status
    );
    assert!(
        !unknown_target.exists(),
        "the launcher executed the program anyway despite an unhonourable syscall filter: {} exists",
        unknown_target.display()
    );
    measured(
        SCENARIO,
        AttackFamily::BackendPosture,
        "a syscall filter naming a call outside the closed vocabulary was refused with no process started, \
         against a control invocation naming only valid calls that ran",
    );
}

// ---------------------------------------------------------------------------
// AAASM-5805: four families this backend does not cover, measured as gaps.
// ---------------------------------------------------------------------------
//
// This backend installs a filesystem boundary and a syscall filter, and
// nothing else — see `aa-isolation-native/src/capability.rs`'s module
// documentation, "Six domains are unsupported on purpose". Four
// `AttackFamily` variants have no protection here to measure:
// `DirectEgressBypass`, `CloudMetadata` and `AddressRepresentation` all live
// on `CapabilityDomain::NetworkEgress`, which this backend does not lower at
// all, and `UnixSocketsAndDescriptors` lives on `CapabilityDomain::Ipc`, which
// it does not lower either. Each scenario below follows
// `adversarial_boundary_linux.rs`'s pattern for a declared gap rather than a
// protection (see that file's header, "Two scenarios measure a gap instead of
// a protection"): measure the effect actually happening, assert the domain's
// `CapabilityReport` is `Unsupported`, assert a required prevention
// requirement for it refuses to plan, and record the measurement tagged with
// its family — never assert the effect was prevented when it was not.

/// A required prevention requirement for `domain` refuses to plan, and the
/// domain's own capability report says it is unsupported. The precondition
/// every gap scenario below states before it measures the effect: an
/// assertion that the domain is uncovered should not depend on nobody having
/// wired it up since, it should be checked every time.
fn assert_domain_is_unsupported_and_prevention_refuses(
    scenario: &str,
    backend: &NativeBackend,
    domain: CapabilityDomain,
) {
    let report = backend
        .capabilities()
        .report_for(domain)
        .cloned()
        .unwrap_or_else(|| panic!("[{scenario}] every domain is reported, including {domain}"));
    assert!(
        matches!(report.support(), SupportLevel::Unsupported { .. }),
        "[{scenario}] {domain} is no longer reported as unsupported on this backend: {report:?}"
    );
    assert!(
        !report.can_prevent(),
        "[{scenario}] {domain} reports that it can prevent, on a backend that lowers nothing for it: {report:?}"
    );
    let refusal = backend
        .plan(
            &ExecutionSpec::new("/bin/true", IdentityRef::root("adversary"))
                .with_requirement(ControlRequirement::prevent(domain)),
        )
        .expect_err(&format!(
            "[{scenario}] a required prevention requirement for {domain} planned on a backend that reports \
             the domain unsupported"
        ));
    assert!(
        refusal.unmet().iter().any(|(r, _)| r.domain() == domain),
        "[{scenario}] the refusal did not name {domain}: {refusal:?}"
    );
}

/// Whether a connection arrived at a non-blocking loopback listener within two
/// seconds.
fn arrived(listener: &std::net::TcpListener) -> bool {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match listener.accept() {
            Ok(_) => return true,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return false,
        }
    }
    false
}

/// **A declared gap, not a silent one.** This backend does not lower a
/// `NetworkEgress` requirement at all, so nothing about a launch's grants can
/// state a connection destination as "inside" or "outside" them — a direct
/// connection to a listener this test owns arrives from inside a confined
/// launch exactly as it would from an unconfined process.
#[test]
fn a_direct_connection_outside_any_egress_grant_arrives_and_the_launch_states_the_domain_is_uncovered() {
    const SCENARIO: &str =
        "native adversarial: a direct connection outside any egress grant arrives, and the launch states \
         the domain is uncovered";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    if adversarial::require_program(SCENARIO, "python3").is_none() {
        return;
    }
    assert_domain_is_unsupported_and_prevention_refuses(SCENARIO, &backend, CapabilityDomain::NetworkEgress);

    let Some((listener, port)) = adversarial::listener_on("127.0.0.1") else {
        decline::<()>(
            SCENARIO,
            Measurement::NotMeasured,
            "no loopback listener could be bound on this host",
        );
        return;
    };
    let script = as_grandchild(&format!(
        "python3 -c \"import socket;s=socket.create_connection(('127.0.0.1',{port}),2);s.sendall(b'REACHED')\""
    ));
    let (completed, evidence) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
    assert_the_program_ran(SCENARIO, &completed);
    let landed = arrived(&listener);
    assert!(
        landed,
        "a direct connection outside any egress grant did not arrive — this backend unexpectedly \
         restricted network egress. stderr: {:?}",
        completed.stderr
    );
    assert!(
        !evidence.supports_prevention_claim(CapabilityDomain::NetworkEgress),
        "a network-egress prevention claim was produced from a run this backend cannot mediate the network \
         for"
    );

    measured(
        SCENARIO,
        AttackFamily::DirectEgressBypass,
        "a required network-egress prevention requirement refused to plan, the domain reports Unsupported, \
         and a direct connection from a launch that could not have restricted it arrived unimpeded",
    );
}

/// **A declared gap.** The product's own list of instance-metadata endpoints
/// (`CLOUD_METADATA_ENDPOINTS`) is attacked here the same way
/// `adversarial_boundary_linux.rs` attacks it — but where that scenario
/// measures a boundary refusing the connection, this one measures that a
/// confined attempt and an unconfined attempt reach an identical outcome per
/// endpoint, because nothing here mediates the network at all.
#[test]
fn cloud_metadata_endpoints_are_reachable_and_the_launch_states_the_domain_is_uncovered() {
    const SCENARIO: &str = "native adversarial: cloud metadata endpoints are reachable and the launch states \
                             the domain is uncovered";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    if adversarial::require_program(SCENARIO, "python3").is_none() {
        return;
    }
    assert_domain_is_unsupported_and_prevention_refuses(SCENARIO, &backend, CapabilityDomain::NetworkEgress);
    assert_domain_is_unsupported_and_prevention_refuses(SCENARIO, &backend, CapabilityDomain::Credential);

    let endpoints: Vec<String> = CLOUD_METADATA_ENDPOINTS
        .iter()
        .filter(|e| e.parse::<Ipv4Addr>().is_ok())
        .map(|e| (*e).to_string())
        .collect();
    assert!(
        !endpoints.is_empty(),
        "the product's metadata endpoint list no longer contains an address this scenario can attack"
    );
    let endpoint = &endpoints[0];

    let attempt = |confined: bool| -> bool {
        let probe = format!(
            "import socket
try:
    socket.create_connection(('{endpoint}',80),2)
    print('REACHED')
except Exception:
    print('BLOCKED')"
        );
        if confined {
            let script = as_grandchild(&format!("python3 -c \"{}\"", probe.replace('"', "\\\"")));
            let (completed, _) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
            assert_the_program_ran(SCENARIO, &completed);
            completed.stdout.contains("REACHED")
        } else {
            let output = std::process::Command::new("python3")
                .arg("-c")
                .arg(&probe)
                .output()
                .expect("python3 runs unconfined");
            String::from_utf8_lossy(&output.stdout).contains("REACHED")
        }
    };

    let confined_result = attempt(true);
    let unconfined_result = attempt(false);
    assert_eq!(
        confined_result, unconfined_result,
        "a confined attempt to reach a cloud-metadata address behaved differently from an unconfined one \
         ({confined_result} vs {unconfined_result}), which this backend's capability report does not claim \
         it can do"
    );

    measured(
        SCENARIO,
        AttackFamily::CloudMetadata,
        &format!(
            "network-egress and credential prevention requirements both refused to plan; a confined and an \
             unconfined attempt to reach {endpoint}:80 produced the identical outcome ({confined_result}), \
             which is what 'this domain is not covered' predicts"
        ),
    );
}

/// **A declared gap.** Three spellings of one loopback address — dotted,
/// decimal and octal — are equally reachable from inside a confined launch,
/// because nothing here scopes a destination by any representation at all.
#[test]
fn an_alternate_address_representation_is_not_scoped_by_this_backend() {
    const SCENARIO: &str = "native adversarial: an alternate address representation is not scoped by this backend";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    if adversarial::require_program(SCENARIO, "python3").is_none() {
        return;
    }
    assert_domain_is_unsupported_and_prevention_refuses(SCENARIO, &backend, CapabilityDomain::NetworkEgress);

    let Some((listener, port)) = adversarial::listener_on("127.0.0.1") else {
        decline::<()>(
            SCENARIO,
            Measurement::NotMeasured,
            "no loopback listener could be bound on this host",
        );
        return;
    };

    let spellings = [
        ("127.0.0.1", "dotted"),
        ("2130706433", "decimal"),
        ("0177.0.0.1", "octal"),
    ];
    let mut arrivals: Vec<(&str, bool)> = Vec::new();
    for (address, name) in spellings {
        let script = as_grandchild(&format!(
            "python3 -c \"import socket;s=socket.create_connection(('{address}',{port}),2);s.sendall(b'X')\""
        ));
        let (completed, _) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
        assert_the_program_ran(SCENARIO, &completed);
        arrivals.push((name, arrived(&listener)));
    }

    let unreached: Vec<&str> = arrivals.iter().filter(|(_, ok)| !ok).map(|(name, _)| *name).collect();
    assert!(
        unreached.is_empty(),
        "these representations of the same address did not arrive at a listener this backend does not \
         scope by address at all: {unreached:?}. Either this host does not resolve them the way the C \
         library does, or this backend has started scoping destinations and this scenario's premise no \
         longer holds"
    );

    measured(
        SCENARIO,
        AttackFamily::AddressRepresentation,
        "a required network-egress prevention requirement refused to plan, and connections spelled dotted, \
         decimal and octal all reached the same loopback listener from inside a confined launch",
    );
}

/// **A declared gap.** An abstract-namespace unix socket is connectable from
/// inside a confined launch: this backend does not lower a `CapabilityDomain
/// ::Ipc` requirement, so nothing here is in a position to scope it.
///
/// `#[cfg(target_os = "linux")]`, matching
/// `adversarial_boundary_linux.rs`'s identical scenario: the abstract-namespace
/// socket API (`std::os::linux::net::SocketAddrExt`) is Linux-only at the
/// standard-library level and is compiled out entirely on other platforms,
/// unlike the rest of this file's logic.
#[cfg(target_os = "linux")]
#[test]
fn abstract_unix_sockets_and_inherited_descriptors_are_outside_this_backends_domains() {
    const SCENARIO: &str =
        "native adversarial: abstract unix sockets and inherited descriptors are outside this backend's \
         domains";
    let Some(backend) = require_confining_backend(SCENARIO) else {
        return;
    };
    if adversarial::require_program(SCENARIO, "python3").is_none() {
        return;
    }
    assert_domain_is_unsupported_and_prevention_refuses(SCENARIO, &backend, CapabilityDomain::Ipc);

    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixListener};

    let name = format!("aa-native-adversarial-{}", std::process::id());
    let Ok(address) = SocketAddr::from_abstract_name(name.as_bytes()) else {
        decline::<()>(
            SCENARIO,
            Measurement::UnsupportedPlatform,
            "this host has no abstract unix socket namespace",
        );
        return;
    };
    let Ok(abstract_listener) = UnixListener::bind_addr(&address) else {
        decline::<()>(
            SCENARIO,
            Measurement::UnsupportedPlatform,
            "an abstract unix socket could not be bound on this host",
        );
        return;
    };
    abstract_listener.set_nonblocking(true).expect("non-blocking");

    let script = as_grandchild(&format!(
        "python3 -c \"import socket;s=socket.socket(socket.AF_UNIX, socket.SOCK_STREAM);\
         s.connect('\\0{name}');s.sendall(b'ABSTRACT')\""
    ));
    let (completed, evidence) = run(&backend, &spec(&script, Vec::new(), Vec::new()));
    assert_the_program_ran(SCENARIO, &completed);

    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut connected = false;
    while std::time::Instant::now() < deadline {
        match abstract_listener.accept() {
            Ok(_) => {
                connected = true;
                break;
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => break,
        }
    }
    assert!(
        connected,
        "an abstract-namespace unix socket was not connectable from inside a confined launch — this \
         backend unexpectedly restricted ipc. stderr: {:?}",
        completed.stderr
    );
    assert!(
        !evidence.supports_prevention_claim(CapabilityDomain::Ipc),
        "an ipc prevention claim was produced from a run this backend cannot mediate ipc for"
    );

    measured(
        SCENARIO,
        AttackFamily::UnixSocketsAndDescriptors,
        "a required ipc prevention requirement refused to plan, and an abstract-namespace unix socket \
         connection reached its listener unimpeded from inside a confined launch",
    );
}
