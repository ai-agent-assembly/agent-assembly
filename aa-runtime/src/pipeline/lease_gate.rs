//! Capability-lease gate seam for the runtime policy chokepoint (AAASM-6259).
//!
//! A seam only: [`LeaseGate`] is the question `handle_policy_query` asks, after
//! the op-control halt and before the gateway forward, when a gate is
//! installed. No production implementation exists yet, and with no gate the
//! pipeline behaves exactly as it did before this module existed.
//!
//! # Invariants enforced here, independent of the gate
//!
//! * The subject is the runtime's server-side agent id, never the SDK-asserted
//!   `CheckActionRequest.agent_id`, which a same-UID process controls.
//! * A gate can only restrict. `Permit` falls through to the gateway and local
//!   policy; it never short-circuits a later deny.
//! * Anything other than an explicit `Permit` is a deny, including an empty
//!   subject and a gate that panics.
//! * The gate is consulted for **every** action type. `action_type` is
//!   asserted by the SDK, so exempting a class here would let a
//!   non-cooperative SDK relabel a `NETWORK_CALL` or `PROCESS_EXEC` as
//!   `LLM_CALL` and skip the gate. Which classes need no lease is the gate's
//!   decision, not the seam's.
//!
//! # Known limitation
//!
//! `action_type` and the rest of the request are SDK-asserted, so this seam is
//! part of the advisory layer: it binds cooperative, SDK-wrapped calls and
//! does not stop a process that bypasses the SDK.

use aa_proto::assembly::policy::v1::CheckActionRequest;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::SystemTime;

/// The gate's answer for one (subject, request) pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseVerdict {
    /// A valid lease covers the action. Necessary, not sufficient: the gateway
    /// and local policy still apply afterwards.
    Permit,
    /// No valid covering lease.
    Deny {
        /// Detail for the runtime's own log. It is deliberately not relayed to
        /// the SDK, which receives only a generic message.
        reason: String,
    },
}

/// Supplier of lease verdicts. Implementations live outside this crate.
///
/// Implementors must be cheap and non-blocking: `check` runs inline in the
/// single pipeline loop, so a gate that waits on disk, a lock or the network
/// stalls every agent's policy checks, and there is no timeout here. The
/// verdict is point-in-time; a lease that lapses while an approval is pending
/// is not re-checked when the approval resolves. Panics are contained only
/// under `panic = "unwind"` (the workspace default). A gate that holds a
/// `std::sync::Mutex` across a panic poisons it and then denies every later
/// call: fail-closed, but persistent.
pub trait LeaseGate: Send + Sync {
    /// Decide whether `subject` may perform the action in `req` at `now`.
    ///
    /// Called for every action type, so the gate owns classification. `now` is
    /// read once per query by the caller so a gate that evaluates several
    /// leases compares them against one instant.
    fn check(&self, subject: &str, req: &CheckActionRequest, now: SystemTime) -> LeaseVerdict;
}

/// Apply `gate` to `req`, collapsing every non-`Permit` outcome into
/// `Err(reason)`.
pub(crate) fn enforce(
    gate: &dyn LeaseGate,
    subject: &str,
    req: &CheckActionRequest,
    now: SystemTime,
) -> Result<(), String> {
    if subject.is_empty() {
        return Err("no server-side agent identity to check a lease against".to_string());
    }
    match catch_unwind(AssertUnwindSafe(|| gate.check(subject, req, now))) {
        Ok(LeaseVerdict::Permit) => Ok(()),
        Ok(LeaseVerdict::Deny { reason }) => Err(reason),
        Err(_) => Err("lease gate failed".to_string()),
    }
}
