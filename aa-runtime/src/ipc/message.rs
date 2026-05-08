//! IPC message types for the Unix domain socket protocol.
//!
//! `IpcFrame` represents messages arriving from an SDK process (inbound).
//! `IpcResponse` represents messages sent back to an SDK process (outbound).

use aa_proto::assembly::audit::v1::AuditEvent;
use aa_proto::assembly::event::v1::ApprovalDecision;
use aa_proto::assembly::policy::v1::CheckActionRequest;

/// A decoded message received from an SDK process over the Unix socket.
///
/// Each variant corresponds to a 1-byte wire tag:
/// - `1` = PolicyQuery
/// - `2` = EventReport
/// - `3` = ApprovalResponse
/// - `4` = Heartbeat
// AuditEvent grew with AAASM-934 lineage fields; the size disparity between
// EventReport and the other variants is inherent to the design.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum IpcFrame {
    /// A policy check request — SDK asks the runtime to evaluate an action.
    PolicyQuery(CheckActionRequest),
    /// An audit event report — SDK sends a governance event for recording.
    EventReport(AuditEvent),
    /// An approval decision — SDK sends the human reviewer's verdict.
    ApprovalResponse(ApprovalDecision),
    /// A liveness ping — no payload. Runtime echoes an `Ack`.
    Heartbeat,
}

use aa_proto::assembly::audit::v1::PolicyViolation;
use aa_proto::assembly::policy::v1::CheckActionResponse;

/// A message sent from the runtime back to an SDK process over the Unix socket.
///
/// Each variant corresponds to a 1-byte wire tag:
/// - `1` = PolicyResponse
/// - `2` = ApprovalDecision (async push when a PENDING decision resolves)
/// - `3` = Ack
/// - `4` = ViolationAlert (runtime pushes a policy violation back to the originating SDK)
#[derive(Debug)]
pub enum IpcResponse {
    /// The policy engine's verdict for a `PolicyQuery`.
    /// When `decision == PENDING`, `CheckActionResponse.approval_id` is set.
    PolicyResponse(CheckActionResponse),
    /// Async push from runtime → SDK when a pending approval is resolved.
    ApprovalDecision(ApprovalDecision),
    /// Acknowledgement of a received `EventReport` or `Heartbeat`.
    Ack,
    /// Runtime-initiated push: a policy violation was detected on an event
    /// submitted by this connection. Contains the full `PolicyViolation` proto.
    ViolationAlert(PolicyViolation),
}
