//! The trait a concrete isolation backend implements.
//!
//! Five stages, in the order ADR 0035 §2 fixes them: discover what the host can
//! do, resolve the spec against it, prepare the boundary, hand the process off,
//! and report what actually happened. The separation is normative even though
//! the exact signatures are not — a backend that prepares its boundary inside
//! `spawn` has no point at which a caller can inspect the plan, which is the
//! point of resolving before the untrusted process starts.

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
}

impl core::fmt::Display for SpawnError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Prepare { detail } => write!(f, "failed to prepare execution boundary: {detail}"),
            Self::Spawn { detail } => write!(f, "failed to spawn into prepared boundary: {detail}"),
            Self::BackendMismatch { expected, found } => {
                write!(f, "prepared execution belongs to backend `{found}`, not `{expected}`")
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

    /// What can be claimed about the run behind this handle.
    fn evidence(&self, handle: &ExecutionHandle) -> EnforcementEvidence;
}
