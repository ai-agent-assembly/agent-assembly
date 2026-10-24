//! Capability-lease gate seam for the runtime policy chokepoint (AAASM-6259).
//!
//! A seam only: [`LeaseGate`] is the question `handle_policy_query` asks, after
//! the op-control halt and before the gateway forward, when a gate is
//! installed. The runtime installs `PolicyLeaseGate` only in governed mode
//! (`AA_LEASE_POLICY` set); with no gate the pipeline behaves exactly as it did
//! before this module existed.
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

/// The tool a request names, for the runtime's own deny log only.
///
/// The name is SDK-supplied, so it is escaped (no raw control characters or
/// newlines reach a log line) and cut at [`MAX_TOOL_LABEL_CHARS`]. Empty when
/// the request carries no tool call.
pub(crate) fn tool_label(req: &CheckActionRequest) -> String {
    use aa_proto::assembly::policy::v1::action_context::Action;
    let Some(Action::ToolCall(call)) = req.context.as_ref().and_then(|c| c.action.as_ref()) else {
        return String::new();
    };
    let mut out: String = call
        .tool_name
        .chars()
        .take(MAX_TOOL_LABEL_CHARS)
        .flat_map(char::escape_debug)
        .collect();
    if call.tool_name.chars().count() > MAX_TOOL_LABEL_CHARS {
        out.push_str("...");
    }
    out
}

const MAX_TOOL_LABEL_CHARS: usize = 64;

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

#[cfg(test)]
mod label_tests {
    use super::*;
    use aa_proto::assembly::policy::v1::action_context::Action;
    use aa_proto::assembly::policy::v1::{ActionContext, ToolCallContext};

    fn call(name: &str) -> CheckActionRequest {
        CheckActionRequest {
            context: Some(ActionContext {
                action: Some(Action::ToolCall(ToolCallContext {
                    tool_name: name.to_string(),
                    ..Default::default()
                })),
            }),
            ..Default::default()
        }
    }

    #[test]
    fn the_label_is_escaped_and_bounded() {
        assert_eq!(tool_label(&call("reader")), "reader");
        assert_eq!(tool_label(&call("a\nb\u{1b}[0m")), "a\\nb\\u{1b}[0m");
        let long = tool_label(&call(&"x".repeat(500)));
        assert_eq!(long.len(), MAX_TOOL_LABEL_CHARS + 3);
        assert!(long.ends_with("..."));
        assert_eq!(tool_label(&CheckActionRequest::default()), "");
    }
}
