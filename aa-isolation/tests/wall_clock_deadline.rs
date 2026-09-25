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
