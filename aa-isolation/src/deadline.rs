//! Supervisor-side wall-clock ceiling enforcement (AAASM-6165).
//!
//! # Why this is not a [`CapabilityDomain::Resource`] prevention control
//!
//! [`crate::plan::negotiate`] only grants [`RequirementIntent::PreventBeforeEffect`]
//! to a capability whose decision precedes the effect
//! ([`DecisionTiming::Pre`]). A wall-clock ceiling cannot be that: the only way
//! to enforce one is to let the process run and kill it once it has overstayed,
//! which is a decision *after* the effect has already been running for however
//! long the ceiling allowed. `aa-isolation-sandlock/src/lower.rs` already states
//! this for its own mechanism ("a wall-clock ceiling is ... a termination after
//! the process has already run, which is detection and not prevention") and
//! refuses to lower it as a `Resource` requirement for exactly that reason. This
//! module holds to the same doctrine: [`WallClockOutcome::evidence_record`]
//! never emits [`ClaimTerm::DeniedBeforeExecution`], only
//! [`ClaimTerm::Detected`], so nothing built on this module can promote a kill
//! after the fact into a claim of prevention.
//!
//! # Why this lives here rather than in a backend
//!
//! Every [`IsolationBackend`] already exposes [`IsolationBackend::wait_for_exit`]
//! and [`IsolationBackend::terminate`], and both are backend-neutral by the
//! trait's own contract — an opaque handle in, a request or a disposition out,
//! no operating-system object named. A wall-clock ceiling needs nothing else: it
//! is "wait, and if that takes too long, ask the backend to stop it," which is
//! expressible entirely in those two methods. Writing it once here means every
//! backend — `aasm-native`, `sandlock`, the macOS VM backend, and any future one
//! — gets the same ceiling for free, instead of each reimplementing its own
//! timer.
//!
//! This does not spawn a process or name an operating-system facility — the
//! crate-level constraint this crate holds itself to. [`std::thread`] and
//! [`std::sync::mpsc`] are portable standard-library primitives used here purely
//! to race a blocking [`IsolationBackend::wait_for_exit`] call against a
//! deadline; no platform type crosses this module's boundary.
//!
//! # What this does not claim about descendants
//!
//! Whether the termination this module requests actually reaches every
//! descendant process is a fact about the concrete backend's own
//! [`IsolationBackend::terminate`] implementation, not about this module —
//! [`DescendantCoverage`] on the backend's own capability report is the honest
//! place to read that from. This module's contribution is limited to *asking*
//! for termination once the ceiling is exceeded and reporting, truthfully,
//! whether the request was delivered.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use aa_core::attestation::ClaimTerm;

use crate::backend::{ExecutionHandle, ExitDisposition, IsolationBackend, SpawnError, TerminationRequest};
use crate::capability::CapabilityDomain;
use crate::evidence::{EvidenceKind, EvidenceRecord};
use crate::spec::{ExecutionSpec, RequirementScope};

/// How a wall-clock-bounded execution ended.
#[derive(Debug)]
pub enum WallClockOutcome {
    /// The execution ended on its own before the ceiling elapsed.
    Completed {
        /// How it ended.
        disposition: ExitDisposition,
        /// How long it ran, if the timing could be observed.
        elapsed: Duration,
    },
    /// The ceiling elapsed first. A termination request was sent; whether it was
    /// *delivered* is `termination`, and whether the execution actually stopped
    /// is `final_disposition` — [`IsolationBackend::terminate`] is best-effort by
    /// its own contract, so this module does not assume the second from the
    /// first.
    DeadlineExceeded {
        /// The ceiling that was exceeded.
        ceiling: Duration,
        /// Whether the termination request reached the backend.
        termination: Result<(), SpawnError>,
        /// How the execution ended after termination was requested, if this
        /// module could still observe it.
        final_disposition: Option<ExitDisposition>,
    },
}

impl WallClockOutcome {
    /// The evidence record this outcome supports for
    /// [`CapabilityDomain::Resource`].
    ///
    /// Never [`ClaimTerm::DeniedBeforeExecution`] — see this module's
    /// documentation for why a wall-clock kill can never be prevention. A
    /// completed-in-time run is [`ClaimTerm::Observed`]
    /// ([`EvidenceKind::Exercised`]: the ceiling was in force and reached no
    /// decision because nothing needed one); an exceeded ceiling is
    /// [`ClaimTerm::Detected`] ([`EvidenceKind::Decision`]: the ceiling itself
    /// decided to end the run).
    pub fn evidence_record(&self) -> EvidenceRecord {
        match self {
            Self::Completed { elapsed, .. } => EvidenceRecord::new(
                EvidenceKind::Exercised,
                CapabilityDomain::Resource,
                ClaimTerm::Observed,
                format!(
                    "wall-clock ceiling was in force for the run's full {elapsed:.3?}; the run ended on its own \
                     before the ceiling elapsed, so the ceiling reached no decision"
                ),
            ),
            Self::DeadlineExceeded {
                ceiling, termination, ..
            } => EvidenceRecord::new(
                EvidenceKind::Decision,
                CapabilityDomain::Resource,
                ClaimTerm::Detected,
                match termination {
                    Ok(()) => format!(
                        "wall-clock ceiling of {ceiling:.3?} was exceeded; a termination request was delivered to \
                         the running execution. This is detection and termination after the effect, not \
                         prevention: the process ran for at least the full ceiling before anything acted on it"
                    ),
                    Err(e) => format!(
                        "wall-clock ceiling of {ceiling:.3?} was exceeded and the termination request could not \
                         be delivered: {e}. The run is not known to have stopped"
                    ),
                },
            ),
        }
    }
}

/// The strictest (smallest) wall-clock ceiling any requirement in `spec` states
/// for [`CapabilityDomain::Resource`], if any.
///
/// Mirrors [`ExecutionSpec::required`]'s "strictest wins" reading used
/// elsewhere in this crate (see `descendant::strictest`): a spec is free to
/// carry more than one `Resource` requirement, and the effective ceiling is the
/// smallest one stated, never the largest — a caller who wants *any* upper
/// bound honoured must not have it silently relaxed by a looser duplicate.
pub fn requested_wall_clock_ceiling(spec: &ExecutionSpec) -> Option<Duration> {
    spec.requirements()
        .iter()
        .filter(|r| r.domain() == CapabilityDomain::Resource)
        .filter_map(|r| match r.scope() {
            RequirementScope::Limits(limits) => limits.max_wall_clock_seconds,
            _ => None,
        })
        .min()
        .map(Duration::from_secs)
}

/// Block until the execution behind `handle` ends, or `ceiling` elapses,
/// whichever comes first.
///
/// On a ceiling expiry this requests [`TerminationRequest::Immediate`] and then
/// waits again (uninterrupted, until the backend's own `wait_for_exit` returns)
/// so the returned [`WallClockOutcome::DeadlineExceeded::final_disposition`] can
/// report how the run actually ended rather than leaving it unknown. That
/// second wait has no ceiling of its own: once termination has been requested,
/// this function's job is to find out what happened, not to bound how long that
/// takes.
///
/// # Errors
///
/// [`SpawnError::Supervision`] when the backend's own `wait_for_exit` fails
/// (a fact about the backend, not about the ceiling).
pub fn supervise_wall_clock(
    backend: &dyn IsolationBackend,
    handle: &ExecutionHandle,
    ceiling: Duration,
) -> Result<WallClockOutcome, SpawnError> {
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();

    // `IsolationBackend::wait_for_exit` is blocking by the trait's own contract,
    // so racing it against a deadline needs a thread of our own — there is no
    // async runtime here to select against, and this crate must not acquire one
    // just to add a timeout.
    thread::scope(|scope| {
        scope.spawn(|| {
            let result = backend.wait_for_exit(handle);
            // The receiver may already be gone (the ceiling fired first and this
            // function returned); a dropped channel is not an error here, it is
            // exactly the race this function exists to resolve.
            let _ = tx.send(result);
        });

        match rx.recv_timeout(ceiling) {
            Ok(result) => result.map(|disposition| WallClockOutcome::Completed {
                disposition,
                elapsed: started.elapsed(),
            }),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let termination = backend.terminate(handle, TerminationRequest::Immediate);
                // No ceiling on this second wait: termination was requested,
                // and what remains is finding out whether it worked, not
                // bounding how long that takes. `recv()` blocks on the same
                // spawned thread's eventual send.
                let final_disposition = rx.recv().ok().and_then(Result::ok);
                Ok(WallClockOutcome::DeadlineExceeded {
                    ceiling,
                    termination,
                    final_disposition,
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(SpawnError::Supervision {
                detail: "the thread waiting on the confined execution ended without reporting a result".to_string(),
            }),
        }
    })
}
