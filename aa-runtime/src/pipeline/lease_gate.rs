//! Capability-lease gate seam for the runtime policy chokepoint (AAASM-6259, J81).
//!
//! # What this is
//!
//! A seam only. [`LeaseGate`] is the question `handle_policy_query` asks, after
//! the op-control halt and before the gateway forward, when a gate is installed:
//! *does the server-side agent identity hold a valid lease covering this
//! action?* Nothing in this repository implements the trait for production —
//! the lease source, the store design (in-memory vs durable) and the
//! publish-strip treatment of `aa-isolation` are open decisions (see
//! ADR 0038, "Runtime gate seam"). Until a gate is installed the pipeline
//! behaves exactly as it did before this module existed.
//!
//! # Invariants the caller enforces, independent of the gate
//!
//! * The subject is the runtime's server-side agent id, never the
//!   SDK-asserted `CheckActionRequest.agent_id` (same-UID threat model,
//!   AAASM-5533).
//! * A gate can only restrict. A `Permit` falls through to the gateway and
//!   local policy; it never short-circuits a later deny.
//! * Anything other than an explicit `Permit` is a deny: an unknown action
//!   code, an empty subject, a gate error, and a gate panic.

use aa_proto::assembly::common::v1::ActionType;
use std::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Why a gate refused an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseDenial {
    /// The subject holds no lease for the action's capability.
    NoLease,
    /// A lease exists but its lifetime has ended.
    Expired,
    /// A lease exists but was revoked.
    Revoked,
    /// The lease on record belongs to a different subject.
    WrongSubject,
    /// The action maps to no capability domain (fail closed, finding F3).
    UnmappedAction,
    /// No server-side subject was available to check.
    NoSubject,
    /// The gate failed (error or panic) and so could not vouch for the action.
    GateFailure,
}

impl LeaseDenial {
    /// Stable token used in the deny reason sent to the SDK.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoLease => "no_lease",
            Self::Expired => "expired",
            Self::Revoked => "revoked",
            Self::WrongSubject => "wrong_subject",
            Self::UnmappedAction => "unmapped_action",
            Self::NoSubject => "no_subject",
            Self::GateFailure => "gate_failure",
        }
    }
}

impl fmt::Display for LeaseDenial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The gate's answer for one (subject, action) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseVerdict {
    /// A valid lease covers the action. This is necessary, not sufficient:
    /// op-control, gateway and local policy still apply afterwards.
    Permit,
    /// No valid covering lease.
    Deny(LeaseDenial),
}

/// The gate itself could not be consulted. Treated as a deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseGateError(pub String);

/// Supplier of lease verdicts. Implementations live outside this crate.
///
/// Contract for implementors (AAASM-6259 review):
/// * **Non-blocking and cheap.** `check` runs inline in the single pipeline loop,
///   so a gate that blocks (disk, lock, network) stalls every agent's policy
///   checks and event ingestion; a hang is neither a deny nor an allow. There is
///   no timeout here. A gate that needs I/O must answer from an in-memory
///   snapshot.
/// * **Point-in-time.** The verdict is taken when the query arrives. A lease
///   revoked or expired while an approval is pending is not re-checked when the
///   approval resolves.
/// * **Panics are only contained under `panic = "unwind"`** (the workspace
///   default); under `panic = "abort"` a panicking gate takes the runtime down.
/// * The subject is the runtime-wide `PipelineConfig::agent_id`, shared by every
///   connection to this runtime, so a lease means "this runtime process", not
///   "this agent connection".
pub trait LeaseGate: Send + Sync {
    /// Check whether `subject` (the server-side agent id) may perform `action`.
    fn check(&self, subject: &str, action: ActionType) -> Result<LeaseVerdict, LeaseGateError>;
}

/// Apply `gate` to a raw wire `action_type`, collapsing every non-`Permit`
/// outcome into a denial.
pub(crate) fn enforce(gate: &dyn LeaseGate, subject: &str, raw_action_type: i32) -> Result<(), LeaseDenial> {
    if subject.is_empty() {
        return Err(LeaseDenial::NoSubject);
    }
    // `Unspecified` (wire code 0) is a valid enum value but names no action, so
    // it can map to no capability domain: deny it here rather than trusting
    // every future gate to (AAASM-6259 review F4).
    let action = match ActionType::try_from(raw_action_type) {
        Ok(ActionType::ActionUnspecified) | Err(_) => return Err(LeaseDenial::UnmappedAction),
        Ok(action) => action,
    };
    match catch_unwind(AssertUnwindSafe(|| gate.check(subject, action))) {
        Ok(Ok(LeaseVerdict::Permit)) => Ok(()),
        Ok(Ok(LeaseVerdict::Deny(why))) => Err(why),
        Ok(Err(_)) | Err(_) => Err(LeaseDenial::GateFailure),
    }
}
