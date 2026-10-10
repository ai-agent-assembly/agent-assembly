//! Adversarial proof for `aa_isolation::deadline` (AAASM-6165).
//!
//! # Why this test lives here, and what it actually proves
//!
//! `aa-isolation` ships no process-spawning backend of its own — that is by
//! design, see `src/lib.rs`. So this test brings its own tiny one,
//! `ProcessGroupBackend`, whose only job is to prove that
//! `deadline::supervise_wall_clock` really does what its documentation claims:
//! it races a blocking `wait_for_exit` against a ceiling, and on expiry it asks
//! the backend to terminate the run and that termination — when the backend
//! implements it as a process-group kill, the shape any real multi-process
//! confined run needs — reaches every descendant, not just the one process the
//! supervisor started.
//!
//! This is a fork-bomb-shaped adversarial fixture at a **safe, low bound**: the
//! confined command backgrounds five `sleep 30` children and waits on them. Five
//! is enough to prove group coverage without creating meaningful load, and
//! `sleep 30` self-terminates even if the kill somehow failed, so a failing
//! assertion here still cannot leave anything running against this host for
//! more than half a minute.
#![cfg(unix)]

use std::collections::HashMap;
use std::io;
use std::os::unix::process::CommandExt as _;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use aa_core::attestation::ClaimTerm;
use aa_isolation::{
    deadline::{supervise_wall_clock, WallClockOutcome},
    negotiate, BackendAvailability, BackendCapabilities, BackendIdentity, EnforcementEvidence, EnforcementPlan,
    EvidenceKind, EvidenceRecord, ExecutionHandle, ExecutionSpec, ExitDisposition, IdentityRef, IsolationBackend,
    Lowering, PlanRefusal, PlatformBoundary, PreparedExecution, Provenance, SpawnError, TerminationRequest,
};

/// A real backend, for this test only, that puts the confined command in its
/// own process group and terminates by signalling the whole group.
///
/// # Why a process group and not the single spawned pid
///
/// `libc::kill(pid, sig)` reaches exactly the process named. A confined command
/// that itself backgrounds children — deliberately, or as a fork bomb — leaves
/// every one of them running when only the direct child is signalled, because
/// they are not *that* pid. Putting the leader in a fresh group at spawn
/// (`process_group(0)`, stable in `std` since 1.64, no `unsafe`) means its pid
/// **is** the group id, and `kill(-pgid, sig)` reaches the leader and everything
/// it spawned, with no need to enumerate them.
struct ProcessGroupBackend {
    identity: BackendIdentity,
    capabilities: BackendCapabilities,
    running: Mutex<HashMap<String, Child>>,
    /// The group-leader pid per token, kept separately from `running` because
    /// `wait_for_exit` has to take the `Child` out of `running` to call the
    /// blocking `wait()` on it. Without this, a `terminate` racing a `wait` in
    /// progress would find no pid to signal — mirrors
    /// `aa-isolation-native::NativeBackend`'s own `pids` field for the same
    /// reason.
    pids: Mutex<HashMap<String, u32>>,
    next_token: AtomicU64,
}

impl ProcessGroupBackend {
    fn new() -> Self {
        Self {
            identity: BackendIdentity {
                id: "test-process-group".to_string(),
                version: "0".to_string(),
                provenance: Provenance {
                    source: "aa-isolation/tests/wall_clock_deadline.rs".to_string(),
                    license: "Apache-2.0".to_string(),
                    modified: false,
                },
            },
            // No `CapabilityDomain` requirement is exercised by this test's specs, so
            // an empty report list is enough for `negotiate` to accept them.
            capabilities: BackendCapabilities::new(
                BackendAvailability::Available,
                PlatformBoundary::SharedHostKernel,
                Vec::new(),
            )
            .expect("empty report list has no duplicate domains"),
            running: Mutex::new(HashMap::new()),
            pids: Mutex::new(HashMap::new()),
            next_token: AtomicU64::new(0),
        }
    }
}

impl IsolationBackend for ProcessGroupBackend {
    fn identity(&self) -> BackendIdentity {
        self.identity.clone()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal> {
        negotiate(spec, &self.identity, &self.capabilities, &|requirement, _outcome| {
            Lowering::new([format!(
                "test backend: no mechanism applied for domain `{}`",
                requirement.domain()
            )])
        })
    }

    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError> {
        let token = format!("pg-{}", self.next_token.fetch_add(1, Ordering::Relaxed));
        Ok(PreparedExecution::new(plan, token))
    }

    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError> {
        let spec = prepared.plan().spec();
        let mut command = Command::new(spec.program());
        command.args(spec.args());
        // The one line this whole fixture exists to exercise: the confined
        // command becomes the leader of a brand new process group, so its pid
        // doubles as the group id every descendant it forks inherits.
        command.process_group(0);
        let child = command.spawn().map_err(|e| SpawnError::Spawn {
            detail: format!("could not spawn `{}`: {e}", spec.program()),
        })?;
        let handle = ExecutionHandle::new(self.identity.clone(), prepared.token(), prepared.plan().posture());
        self.pids
            .lock()
            .expect("test backend state poisoned")
            .insert(prepared.token().to_string(), child.id());
        self.running
            .lock()
            .expect("test backend state poisoned")
            .insert(prepared.token().to_string(), child);
        Ok(handle)
    }

    fn wait_for_exit(&self, handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError> {
        // Held only for the duration of `wait`, which blocks: a concurrent
        // `terminate` for a different handle must not be locked out by this one
        // waiting, but this test only ever has one handle in flight at a time.
        let mut child = {
            let mut running = self.running.lock().expect("test backend state poisoned");
            running.remove(handle.token()).ok_or_else(|| SpawnError::Supervision {
                detail: format!("no running child recorded for handle `{}`", handle.token()),
            })?
        };
        let status = child.wait().map_err(|e| SpawnError::Supervision {
            detail: format!("wait failed: {e}"),
        })?;
        Ok(match status.code() {
            Some(code) => ExitDisposition::Code(code),
            None => ExitDisposition::NoCode {
                detail: format!("ended by signal: {status}"),
            },
        })
    }

    fn terminate(&self, handle: &ExecutionHandle, request: TerminationRequest) -> Result<(), SpawnError> {
        let pid = self
            .pids
            .lock()
            .expect("test backend state poisoned")
            .get(handle.token())
            .copied()
            .ok_or_else(|| SpawnError::Supervision {
                detail: format!("no launch recorded for handle `{}`", handle.token()),
            })?;
        let signal = match request {
            TerminationRequest::Graceful => libc::SIGTERM,
            TerminationRequest::Immediate => libc::SIGKILL,
            // `TerminationRequest` is `#[non_exhaustive]`, so a caller in this
            // workspace still has to handle a variant added elsewhere. This
            // test backend picks the strictest available signal for anything
            // it does not otherwise recognise.
            _ => libc::SIGKILL,
        };
        // The negative pid is the whole-group form of `kill(2)`: every process
        // whose group id is `pid` receives the signal, not only `pid` itself.
        let result = unsafe { libc::kill(-(pid as libc::pid_t), signal) };
        if result == 0 {
            Ok(())
        } else {
            Err(SpawnError::Supervision {
                detail: format!("killpg({pid}, {signal}) failed: {}", io::Error::last_os_error()),
            })
        }
    }

    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence {
        EnforcementEvidence::new(self.identity.clone(), handle.posture()).with_record(EvidenceRecord::about_run(
            EvidenceKind::Configured,
            ClaimTerm::Unmeasured,
            format!(
                "test backend recorded no per-domain mechanism for handle `{}`",
                handle.token()
            ),
        ))
    }
}

/// Whether a process with this pid still exists, checked the same way this
/// crate's own adversarial suites check it elsewhere in this workspace:
/// `kill(pid, 0)` delivers no signal and only reports whether the pid is
/// live.
fn process_exists(pid: i32) -> bool {
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

/// Poll until every listed pid is gone, or `bound` elapses. Returns the pids
/// still alive when it gives up, so a failing assertion says exactly which
/// ones survived instead of just "not all of them died".
fn wait_for_all_gone(pids: &[i32], bound: Duration) -> Vec<i32> {
    let start = Instant::now();
    loop {
        let alive: Vec<i32> = pids.iter().copied().filter(|&p| process_exists(p)).collect();
        if alive.is_empty() || start.elapsed() > bound {
            return alive;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn spec_with_no_requirements(program: &str, args: &[&str]) -> ExecutionSpec {
    ExecutionSpec::new(program, IdentityRef::root("wall-clock-test")).with_args(args.iter().map(|s| s.to_string()))
}

fn launch(backend: &ProcessGroupBackend, spec: &ExecutionSpec) -> ExecutionHandle {
    let plan = backend
        .plan(spec)
        .expect("a spec with no requirements is never refused");
    let prepared = backend.prepare(plan).expect("this backend's prepare never fails");
    backend
        .spawn(prepared)
        .expect("this backend's spawn never fails for /bin/sh")
}

/// A pid-file fixture: five backgrounded `sleep 30` children of a leader shell
/// that then blocks on `wait`. Safe because `sleep 30` self-terminates even if
/// this test's kill assertion is wrong, and five processes is not a load any
/// host notices.
fn fork_fan_out_spec(pidfile: &std::path::Path) -> ExecutionSpec {
    let script = format!(
        "for i in 1 2 3 4 5; do sleep 30 & echo $! >> {path}; done; wait",
        path = pidfile.display()
    );
    spec_with_no_requirements("/bin/sh", &["-c", &script])
}

fn read_pids(pidfile: &std::path::Path) -> Vec<i32> {
    std::fs::read_to_string(pidfile)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| line.trim().parse().ok())
        .collect()
}

/// The load-bearing property: a runaway process tree — leader plus every
/// backgrounded child — is entirely gone once the wall-clock ceiling is
/// exceeded, not just the one pid the supervisor originally spawned.
#[test]
fn deadline_exceeded_terminates_the_whole_process_group_with_no_orphans() {
    let backend = ProcessGroupBackend::new();
    let pidfile = std::env::temp_dir().join(format!("aa-isolation-wallclock-{}.pids", std::process::id()));
    let _ = std::fs::remove_file(&pidfile);

    let spec = fork_fan_out_spec(&pidfile);
    let handle = launch(&backend, &spec);
    let leader_pid = {
        // Recovered here only to assert on it after termination, not used to
        // drive the supervision call itself.
        let pids = backend.pids.lock().expect("state poisoned");
        pids.get(handle.token()).map(|&pid| pid as i32)
    };

    let ceiling = Duration::from_millis(300);
    let outcome =
        supervise_wall_clock(&backend, &handle, ceiling).expect("wait_for_exit on this backend does not fail");

    let WallClockOutcome::DeadlineExceeded { termination, .. } = &outcome else {
        panic!("a fixture that blocks on `sleep 30 & ... & wait` must exceed a 300ms ceiling: {outcome:?}");
    };
    assert!(
        termination.is_ok(),
        "the group-kill termination request must be delivered: {termination:?}"
    );

    let mut expected_gone: Vec<i32> = read_pids(&pidfile);
    assert_eq!(
        expected_gone.len(),
        5,
        "the fixture must have recorded all five backgrounded pids before the kill"
    );
    if let Some(pid) = leader_pid {
        expected_gone.push(pid);
    }

    let still_alive = wait_for_all_gone(&expected_gone, Duration::from_secs(2));
    assert!(
        still_alive.is_empty(),
        "process(es) {still_alive:?} survived the process-group termination — an orphan, which is exactly what \
         AAASM-6165's 'no orphan workloads' requirement forbids"
    );

    let record = outcome.evidence_record();
    assert_eq!(record.kind, EvidenceKind::Decision);
    assert_eq!(record.claim, ClaimTerm::Detected);
    assert!(
        !record.claim.is_prevention(),
        "a wall-clock kill happens after the process has already run past the ceiling; it must never be \
         reportable as prevention"
    );

    let _ = std::fs::remove_file(&pidfile);
}

/// The control for the test above: the identical fixture, given a ceiling long
/// enough that it finishes on its own, must report `Completed` and never claim
/// a decision was made. Without this pair, the assertions above could pass
/// because `supervise_wall_clock` always reports a kill, not because it
/// correctly distinguishes the two cases.
#[test]
fn a_run_that_finishes_within_the_ceiling_is_not_reported_as_a_decision() {
    let backend = ProcessGroupBackend::new();
    let spec = spec_with_no_requirements("/bin/sh", &["-c", "exit 0"]);
    let handle = launch(&backend, &spec);

    let outcome = supervise_wall_clock(&backend, &handle, Duration::from_secs(10))
        .expect("wait_for_exit on this backend does not fail");

    let WallClockOutcome::Completed { disposition, .. } = &outcome else {
        panic!("`exit 0` finishes immediately, far inside a 10s ceiling: {outcome:?}");
    };
    assert_eq!(disposition.code(), Some(0));

    let record = outcome.evidence_record();
    assert_eq!(record.kind, EvidenceKind::Exercised);
    assert_eq!(record.claim, ClaimTerm::Observed);
}

/// A unique marker for the detached descendant this test spawns, split into
/// two halves that are only concatenated **at runtime, inside Perl** (see
/// [`fork_daemon_spec`]). `pgrep -f` matches a command line's full text as a
/// substring/regex, and this fixture's own leader process is `/bin/sh -c
/// "<the whole script, including this marker>"` — if the marker appeared as
/// one contiguous literal in that script text, `pgrep -f marker` would match
/// the **leader** the instant it was spawned, before the daemon chain had
/// run at all, making the "has the daemon actually appeared yet" check
/// below vacuously true. Splitting the marker so the two halves are joined
/// by Perl's `.` operator (`"{a}" . "{b}"`) keeps "{a} . {b}" out of the
/// leader's own argv while the final, exec'd process still receives the
/// complete, contiguous string as one real argv element.
fn marker_halves(test_name: &str) -> (String, String) {
    let full = format!(
        "aaasm-6294-marker-{test_name}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the system clock is after 1970")
            .as_nanos()
    );
    let mid = full.len() / 2;
    (full[..mid].to_string(), full[mid..].to_string())
}

/// Builds the leader's script: a double-fork daemon (POSIX's standard
/// double-fork idiom, via Perl's `fork`/`POSIX::setsid`). Perl, not this
/// repo's own `setsid(1)` tool (a Linux `util-linux` binary this macOS
/// authoring host does not have), because `/usr/bin/perl` ships on both
/// platforms this file's `#![cfg(unix)]` covers. **This test is not
/// macOS-only** despite being written for the macOS-only AAASM-6294
/// ticket — it compiles and runs wherever this crate's test suite does,
/// including the `ubuntu-latest` GitHub Actions runners `.github/workflows/ci.yml`
/// uses for every job in this repo (`perl` and `pgrep`/`pkill` — from
/// `procps`, a base-image package — are both part of `ubuntu-latest`'s
/// default toolset, not something this test installs), followed by the
/// leader itself staying alive long enough to exceed the wall-clock
/// ceiling.
///
/// `detach` controls the one line that distinguishes the two tests below:
/// when `true`, the first fork calls `setsid()` before forking again,
/// putting everything below it in a **new** session and process group —
/// detached from the leader's. When `false`, that call is omitted, so the
/// final process stays in the leader's own process group the whole time,
/// the same as any ordinary (non-adversarial) forked child.
///
/// # Why Perl, and why `env -i`
///
/// No `unsafe` `libc::fork()` is needed in *this* process — only the
/// confined *child* needs to double-fork, and it is a real OS-level process
/// this test spawns, exactly like every other backend's real child.
///
/// Per this ticket's security note: the daemon chain is launched under
/// `env -i`, an empty environment, so nothing ambient (credentials, tokens)
/// can reach a process this test deliberately detaches from supervision and
/// leaves for `pgrep -f` to find — even though this fixture's own command
/// line and the marker string are the only things that could appear in any
/// panic/log output here, clearing the environment removes the leak path
/// entirely rather than relying on that observation staying true.
///
/// The final, detached process is bounded to `sleep 10` — not an infinite
/// loop — so this test's own invariant ("nothing survives longer than a
/// could-be-flaky assertion") holds even if every assertion below is wrong:
/// the marker process self-terminates within 10s regardless of what the
/// test observes or asserts.
fn fork_daemon_spec(marker_a: &str, marker_b: &str, detach: bool) -> ExecutionSpec {
    let setsid_call = if detach { "setsid();" } else { "" };
    let script = format!(
        "env -i /usr/bin/perl -e 'use POSIX qw(setsid); my $m = \"{marker_a}\" . \"{marker_b}\"; if (fork() == 0) \
         {{ {setsid_call} if (fork() == 0) {{ exec(\"/usr/bin/perl\", \"-e\", \"sleep 10\", $m) or exit(1); }} \
         exit(0); }} exit(0);'\nsleep 30\n"
    );
    spec_with_no_requirements("/bin/sh", &["-c", &script])
}

/// Counts live processes matching `marker` via `pgrep -f`, the same
/// mechanism this ticket's AC specifies for counting survivors.
fn pgrep_count(marker: &str) -> usize {
    let output = Command::new("/usr/bin/pgrep")
        .arg("-f")
        .arg(marker)
        .env_clear()
        .output()
        .expect("pgrep must be runnable on this host");
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .count()
}

/// Best-effort cleanup for the marker process, run regardless of whether the
/// test's assertions pass — this fixture's `sleep 10` bound makes this belt,
/// not suspenders, but there is no reason to wait out the full 10s if the
/// test already knows the pid pattern.
fn pkill(marker: &str) {
    let _ = Command::new("/usr/bin/pkill")
        .arg("-f")
        .arg(marker)
        .env_clear()
        .status();
}

/// **AAASM-6294 ST-7, live test**: a `setsid` + double-forked descendant —
/// detached from the leader's process group and session before the
/// wall-clock ceiling fires — is not reached by a process-group-kill
/// termination.
///
/// # What this test actually exercises, precisely
///
/// `ProcessGroupBackend` is this file's own pre-existing, test-only
/// `IsolationBackend` (see its module doc comment at the top of this file,
/// written for the sibling AAASM-6165 test above) — it is **not**
/// `aa-isolation-native`'s or `aa-isolation-macos-vm`'s real production
/// `terminate()`. This test proves a mechanism-level property —
/// *"process-group kill cannot reach a session/group that left via
/// `setsid()`, independent of which backend issues the kill"* — against a
/// real `kill(-pgid, sig)` call, not a claim that every real backend in
/// this workspace issues a process-group kill. The negative control
/// [`a_double_forked_descendant_without_setsid_does_not_survive_the_process_group_kill`]
/// below is what isolates `setsid()` specifically as the cause, rather than
/// "detached descendants in general survive this fixture".
///
/// Two real-backend data points, found while writing this test and recorded
/// rather than silently assumed either way:
/// - `aa-isolation-native::backend::deliver_termination`
///   (`aa-isolation-native/src/backend.rs`, `#[cfg(target_os = "linux")]`)
///   issues a single-pid `libc::kill(pid, signal)` — not even a
///   process-group kill. Observed by reading the source only; this is a
///   Linux-only code path this macOS host cannot compile or run, and its
///   live verification is explicitly out of scope here (tracked
///   separately as ST-12a / AAASM-6299, BLOCKED-NO-INFRA). If confirmed
///   live there, it would mean *any* forked child — setsid'd or not —
///   survives a native-backend wall-clock termination, a strictly bigger
///   gap than the one this test demonstrates.
/// - `aa-isolation-macos-vm::MacosVmBackend::terminate` sends a
///   `TerminateRequest` wire message into the guest; its handler,
///   `check_for_terminate` in
///   `aa-isolation-macos-vm-poc/guest-init/src/protocol.rs:511`, issues the
///   *identical* single-pid `libc::kill(child_pid, signal)` the native
///   backend does — no `setpgid`/process-group setup appears anywhere in
///   this file's own `fork()` call either (`protocol.rs:255`). This is the
///   in-scope macOS surface for this ticket, read from source with the
///   same confidence as the native finding above, but **not live-booted**:
///   no VM substrate is configured on this host (see
///   `resource_ceiling_refusal.rs` in the sibling crate for the same
///   caveat applied to that backend's `plan()`). If an ordinary (non-setsid)
///   forked child of a confined `aasm-macos-vm` launch were live-tested
///   against a real guest boot, this reading predicts it would also
///   survive a wall-clock termination — a strictly bigger gap than the
///   setsid-specific one this test demonstrates live.
///
/// ADR 0041 ("Resource ceiling enforcement, round 1") discloses the
/// product-level property this test's *conclusion* is consistent with,
/// under "Residual: AC5, orphan-freedom": *"There is no
/// `cgroup.kill`-equivalent group-kill in this round: a confined tree whose
/// immediate process ignores a `terminate()` relies on the pre-existing
/// best-effort termination semantics, nothing stronger... this round's AC5
/// claim is honestly partial."* This test does not newly discover that —
/// it live-verifies the sharpest version of it the crate's own
/// `ProcessGroupBackend` fixture can produce.
#[test]
fn a_setsid_double_forked_descendant_survives_the_process_group_kill() {
    let survivors = run_fork_daemon_and_count_survivors(true);
    assert!(
        survivors >= 1,
        "expected the setsid-double-forked marker to survive the process-group kill (ADR 0041's disclosed, \
         honestly-partial AC5 coverage), but pgrep -f found {survivors} — either this host's kill(-pgid) now \
         reaches a process that left the group (a real improvement worth updating ADR 0041 for) or this fixture \
         is not actually detaching the way it intends to"
    );
}

/// The control for the test above: the identical double-fork fixture, minus
/// the `setsid()` call, must have its final process die with the rest of
/// the group. Without this, "the marker survived" in the test above could
/// mean "nothing this fixture spawns is ever reachable by a group kill",
/// which would say nothing about `setsid()` specifically.
#[test]
fn a_double_forked_descendant_without_setsid_does_not_survive_the_process_group_kill() {
    let survivors = run_fork_daemon_and_count_survivors(false);
    assert_eq!(
        survivors, 0,
        "a double-forked descendant that never called `setsid()` should stay in the leader's original process \
         group and die with it — {survivors} survived, which would mean this fixture's `kill(-pgid)` does not \
         actually reach an ordinary forked grandchild either, undermining the control this test exists to provide"
    );
}

/// Shared body for the pair above: launch the leader, wait for the daemon
/// chain to actually reach its final, marker-bearing process, exceed the
/// ceiling, confirm the leader itself died, then return the survivor count
/// for the caller to assert on.
fn run_fork_daemon_and_count_survivors(detach: bool) -> usize {
    let (marker_a, marker_b) = marker_halves(if detach { "survivor" } else { "control" });
    let marker = format!("{marker_a}{marker_b}");
    let backend = ProcessGroupBackend::new();
    let spec = fork_daemon_spec(&marker_a, &marker_b, detach);
    let handle = launch(&backend, &spec);

    // Give the leader's script time to actually run the double-fork and
    // exec into the final, marker-bearing process before the ceiling fires
    // — otherwise this test could race the assertion below against a
    // daemon that simply hasn't execed yet, which would prove nothing about
    // group-kill coverage either way. `marker` (not a half) is used here
    // deliberately: see `marker_halves`'s doc comment for why only the
    // final, exec'd process's argv can ever match it.
    let appeared = wait_for_marker(&marker, Duration::from_secs(2));
    assert!(
        appeared,
        "the detached marker process never appeared within 2s — the double-fork fixture itself is broken, \
         not the property this test means to check"
    );

    let ceiling = Duration::from_millis(300);
    let outcome =
        supervise_wall_clock(&backend, &handle, ceiling).expect("wait_for_exit on this backend does not fail");
    let WallClockOutcome::DeadlineExceeded { termination, .. } = &outcome else {
        panic!("a fixture that sleeps 30s in the leader must exceed a 300ms ceiling: {outcome:?}");
    };
    assert!(
        termination.is_ok(),
        "the group-kill termination request must still be delivered to the leader: {termination:?}"
    );

    // The leader itself must actually be gone — the group-kill's reach is
    // real, just not total. Without this, a survivor count could mean
    // "termination did nothing at all" rather than "termination reached
    // everything in the group except whatever left it".
    let leader_pid = {
        let pids = backend.pids.lock().expect("state poisoned");
        pids.get(handle.token()).copied()
    };
    if let Some(pid) = leader_pid {
        let still_alive = wait_for_all_gone(&[pid as i32], Duration::from_secs(2));
        assert!(
            still_alive.is_empty(),
            "the leader process {pid} must be gone after the group-kill — otherwise a survivor count would say \
             nothing about group-kill coverage, only that termination never ran: {still_alive:?}"
        );
    }

    // The non-detached case's final process should die quickly once its
    // group is killed; give it the same window the detached case's "give up
    // and call it a survivor" bound uses, so both tests measure on the same
    // timescale rather than the control looking artificially faster.
    let _ = wait_for_marker_gone(&marker, Duration::from_millis(500));

    let survivors = pgrep_count(&marker);
    pkill(&marker);
    survivors
}

/// Poll until `pgrep -f marker` reports no match or `bound` elapses —
/// the mirror of [`wait_for_marker`], used so the non-detached control
/// doesn't get counted as a "survivor" purely from a reaping race.
fn wait_for_marker_gone(marker: &str, bound: Duration) -> bool {
    let start = Instant::now();
    loop {
        if pgrep_count(marker) == 0 {
            return true;
        }
        if start.elapsed() > bound {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll `pgrep -f marker` until it reports at least one match or `bound`
/// elapses.
fn wait_for_marker(marker: &str, bound: Duration) -> bool {
    let start = Instant::now();
    loop {
        if pgrep_count(marker) > 0 {
            return true;
        }
        if start.elapsed() > bound {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
