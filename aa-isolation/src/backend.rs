//! The trait a concrete isolation backend implements.
//!
//! Five stages, in the order ADR 0035 §2 fixes them: discover what the host can
//! do, resolve the spec against it, prepare the boundary, hand the process off,
//! and report what actually happened. The separation is normative even though
//! the exact signatures are not — a backend that prepares its boundary inside
//! `spawn` has no point at which a caller can inspect the plan, which is the
//! point of resolving before the untrusted process starts.
//!
//! # Supervision, added by AAASM-5711
//!
//! ADR 0035 §2's illustrative trait ends at `spawn`, and that was enough while
//! nothing consumed it. It is not enough for `aasm run`, whose contract with an
//! operator predates isolation entirely: the launcher exits with the launched
//! program's exit code, and a `SIGTERM` or `SIGINT` delivered to the launcher
//! reaches the program. Both are properties of the *supervisor*, and once the
//! program lives behind a boundary the supervisor holds no operating-system
//! object it could use to provide either — [`ExecutionHandle`] is deliberately
//! opaque, and the running child belongs to the backend.
//!
//! So the contract gains exactly two stages, and no more:
//! [`wait_for_exit`](IsolationBackend::wait_for_exit) and
//! [`terminate`](IsolationBackend::terminate). Neither hands the caller anything
//! that reaches into the confined tree: one returns a value describing how the
//! execution ended, the other passes a request in the other direction. The
//! supervisor stays structurally outside the boundary (ADR 0035 §5), which is
//! why this is two narrow methods rather than "give me the child".
//!
//! This is an internal contract change — the crate is `publish = false` and every
//! implementor is in this workspace — so it is made in the open rather than
//! bolted on as an inherent method the trait cannot see. A backend reachable
//! only as `dyn IsolationBackend`, which is how run-time selection reaches one,
//! cannot be supervised through an inherent method at all.

use crate::capability::BackendCapabilities;
use crate::evidence::EnforcementEvidence;
use crate::plan::{BackendIdentity, EnforcementPlan, LaunchPosture, PlanRefusal};
use crate::spec::ExecutionSpec;

/// A boundary that has been set up but not yet entered.
///
/// # Why this is an opaque token
///
/// It carries no operating-system object. Two reasons:
///
/// 1. This crate must stay platform-free. Naming a process type here would put
///    a process model in the contract, and ADR 0035 anticipates backends whose
///    unit of execution is not a host process at all.
/// 2. [`IsolationBackend`] has to be usable as `dyn IsolationBackend`, because
///    backend selection happens at run time. Associated types would give each
///    backend its own `Prepared` and destroy object safety.
///
/// A backend keeps its real resources in its own state, keyed by
/// [`token`](Self::token). The cost is that every type here stays plain,
/// comparable, printable data — which is also the benefit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedExecution {
    plan: EnforcementPlan,
    token: String,
}

impl PreparedExecution {
    /// Bind a backend-owned token to the plan it prepared.
    pub fn new(plan: EnforcementPlan, token: impl Into<String>) -> Self {
        Self {
            plan,
            token: token.into(),
        }
    }

    /// The plan this boundary realizes.
    pub fn plan(&self) -> &EnforcementPlan {
        &self.plan
    }

    /// The backend-owned identifier for the prepared boundary.
    pub fn token(&self) -> &str {
        &self.token
    }
}

/// A launched execution, from the supervisor's side of the boundary.
///
/// Opaque for the same reasons as [`PreparedExecution`]. It also keeps the
/// supervisor structurally outside the confined tree (ADR 0035 §5): holding a
/// handle grants a caller no descriptor, no memory and no channel into the
/// agent's process, only the identity needed to ask the backend about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionHandle {
    backend: BackendIdentity,
    token: String,
    posture: LaunchPosture,
}

impl ExecutionHandle {
    /// Bind a backend-owned token to the posture the launch started in.
    pub fn new(backend: BackendIdentity, token: impl Into<String>, posture: LaunchPosture) -> Self {
        Self {
            backend,
            token: token.into(),
            posture,
        }
    }

    /// Which backend launched this.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// The backend-owned identifier for the running execution.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The posture the launch started in.
    pub fn posture(&self) -> LaunchPosture {
        self.posture
    }
}

/// How a launched execution ended, as the supervisor outside the boundary can
/// see it.
///
/// # Why the two states are not one `Option<i32>`
///
/// "It exited 0" and "nothing this backend can see reports an exit code" are
/// different facts, and an `Option` invites the caller to write
/// `code.unwrap_or(0)` — which turns the second into the first, on exactly the
/// runs where something went wrong. The second state carries its own sentence so
/// a caller has to decide what to do with it, and so a log of the run says which
/// of the two it was.
///
/// Nothing here names an operating-system termination mechanism. A backend whose
/// unit of execution is not a host process still has to answer this question,
/// and it answers it in these terms.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExitDisposition {
    /// The execution ended and reported this exit code.
    Code(i32),
    /// The execution ended without an exit code the backend could observe.
    ///
    /// On an ordinary host this is what a program killed by a signal produces.
    /// It is *not* a synonym for failure and must never be rendered as one: what
    /// it says is that the code is unknown, and `detail` says why.
    NoCode {
        /// What the backend could say about the ending, verbatim.
        detail: String,
    },
}

impl ExitDisposition {
    /// The exit code, when the backend observed one.
    pub fn code(&self) -> Option<i32> {
        match self {
            Self::Code(code) => Some(*code),
            Self::NoCode { .. } => None,
        }
    }

    /// The exit code, or `fallback` when there was none.
    ///
    /// The fallback is a parameter rather than a constant because the right
    /// answer belongs to the caller: `aasm run` has propagated `1` for an
    /// unobservable exit since long before isolation existed, and this contract
    /// has no business changing that from underneath it.
    pub fn code_or(&self, fallback: i32) -> i32 {
        self.code().unwrap_or(fallback)
    }
}

impl core::fmt::Display for ExitDisposition {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Code(code) => write!(f, "exit code {code}"),
            Self::NoCode { detail } => write!(f, "no exit code observed: {detail}"),
        }
    }
}

/// What a supervisor is asking a running execution to do.
///
/// Two requests, named by what they mean rather than by any host signal. The
/// backend maps them onto whatever its mechanism provides — a signal, an API
/// call, a hypervisor stop — and this crate stays free of that vocabulary for
/// the same reason [`crate::plan::Lowering`] is opaque.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TerminationRequest {
    /// Ask the execution to stop, letting it run whatever it does on the way
    /// out.
    Graceful,
    /// Stop the execution without giving it the opportunity to decline.
    Immediate,
}

/// Something went wrong after the plan was accepted.
///
/// Distinct from [`PlanRefusal`], which is a *decision* rather than a failure: a
/// refusal means the boundary could not be guaranteed and the launch was
/// correctly stopped, while these variants mean the mechanism broke. Conflating
/// them would make "we protected you by refusing" and "we could not tell what
/// happened" the same error.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpawnError {
    /// The boundary could not be established.
    Prepare {
        /// What failed.
        detail: String,
    },
    /// The process could not be started inside the prepared boundary.
    Spawn {
        /// What failed.
        detail: String,
    },
    /// A prepared execution from one backend was handed to another.
    BackendMismatch {
        /// The backend that was asked to act.
        expected: String,
        /// The backend that produced the prepared execution.
        found: String,
    },
    /// The launch succeeded and the supervisor then lost track of it.
    ///
    /// Its own variant rather than a reuse of [`Spawn`](Self::Spawn), because the
    /// two differ in the one way that matters to a caller: after a `Spawn` error
    /// nothing is running, and after this one something may well be. Reporting a
    /// failed `wait` as a failed spawn would tell an operator that no process
    /// exists at the exact moment one does.
    Supervision {
        /// What failed.
        detail: String,
    },
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prepare { detail } => write!(f, "failed to prepare execution boundary: {detail}"),
            Self::Spawn { detail } => write!(f, "failed to spawn into prepared boundary: {detail}"),
            Self::BackendMismatch { expected, found } => {
                write!(f, "prepared execution belongs to backend `{found}`, not `{expected}`")
            }
            Self::Supervision { detail } => {
                write!(f, "lost track of a running confined execution: {detail}")
            }
        }
    }
}

impl std::error::Error for SpawnError {}

/// A pluggable execution isolation mechanism.
///
/// Object-safe on purpose: backend selection is a run-time decision, so callers
/// hold `Box<dyn IsolationBackend>` and this trait must survive that.
///
/// Implementors must not weaken negotiation. [`plan`](Self::plan) is expected to
/// delegate to [`crate::plan::negotiate`] rather than decide for itself which
/// requirements it can meet; the refusal rules belong to the contract, not to
/// the mechanism.
pub trait IsolationBackend: Send + Sync {
    /// What this backend is, and where it came from.
    fn identity(&self) -> BackendIdentity;

    /// What this backend can do on this host, right now.
    ///
    /// Discovery, not a claim about any run. Whether the backend is usable at
    /// all is [`BackendCapabilities::availability`], which is deliberately not
    /// reachable from [`EnforcementEvidence`].
    fn capabilities(&self) -> BackendCapabilities;

    /// Resolve a spec against those capabilities, before anything starts.
    ///
    /// # Errors
    ///
    /// [`PlanRefusal`] when a required requirement cannot be met, or when the
    /// backend is unavailable.
    // See `crate::plan::negotiate` for why this allow is correct rather than
    // convenient: the `Ok` variant is the larger of the two, so boxing the error
    // would not shrink the `Result` — it would only put a `Box` in the contract
    // that every backend implementation then has to repeat. Pinned by
    // `plan::tests::refusal_is_free_to_carry_by_value`.
    #[allow(clippy::result_large_err)]
    fn plan(&self, spec: &ExecutionSpec) -> Result<EnforcementPlan, PlanRefusal>;

    /// Establish the boundary described by an accepted plan.
    ///
    /// # Errors
    ///
    /// [`SpawnError::Prepare`] if the boundary cannot be established.
    fn prepare(&self, plan: EnforcementPlan) -> Result<PreparedExecution, SpawnError>;

    /// Start the target process inside the prepared boundary.
    ///
    /// The supervisor stays outside it (ADR 0035 §5); the returned handle is a
    /// reference, not a channel into the confined tree.
    ///
    /// # Errors
    ///
    /// [`SpawnError::Spawn`] if the process cannot be started, or
    /// [`SpawnError::BackendMismatch`] if the prepared execution came from a
    /// different backend.
    fn spawn(&self, prepared: PreparedExecution) -> Result<ExecutionHandle, SpawnError>;

    /// Block until the execution behind `handle` ends, and report how it ended.
    ///
    /// Blocking, not asynchronous. This crate takes no async runtime — the
    /// crate documentation is explicit that acquiring one would change what the
    /// contract costs to depend on — so a caller that must not block moves the
    /// call to a thread it owns. That is a decision the caller is in a position
    /// to make and this trait is not.
    ///
    /// Calling it twice for the same handle is permitted and must return the
    /// same disposition. A supervisor that has to re-ask because a signal
    /// interleaved with its wait would otherwise have to model "already reaped"
    /// itself, and would get it wrong under exactly the timing this method
    /// exists to survive.
    ///
    /// # Errors
    ///
    /// [`SpawnError::Supervision`] when the handle names no execution this
    /// backend launched, or the wait itself fails. Note what this error does
    /// **not** mean: it is not evidence that the execution stopped.
    fn wait_for_exit(&self, handle: &ExecutionHandle) -> Result<ExitDisposition, SpawnError>;

    /// Pass a termination request across the boundary to a running execution.
    ///
    /// Best-effort by construction, and deliberately so: whether the request is
    /// honoured is a fact about the confined program, which is untrusted. `Ok`
    /// means the request was delivered, never that anything stopped — the only
    /// way to learn that is [`wait_for_exit`](Self::wait_for_exit).
    ///
    /// # Errors
    ///
    /// [`SpawnError::Supervision`] when the handle names no execution this
    /// backend launched, or the request could not be delivered.
    fn terminate(&self, handle: &ExecutionHandle, request: TerminationRequest) -> Result<(), SpawnError>;

    /// What can be claimed about the run behind this handle.
    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence;
}
