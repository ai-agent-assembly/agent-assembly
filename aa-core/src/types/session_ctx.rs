//! Ephemeral, TTL-bound context for one agent execution session.

use alloc::string::String;

use crate::time::Timestamp;
use crate::types::AgentId;

/// Context for a single agent execution session.
///
/// Stored by the `SessionStore` with a TTL; `expires_at` is the absolute
/// instant past which the session is invalid, letting drivers expire entries
/// without a separate clock round-trip.
///
/// # Wire format
///
/// ```json
/// {
///   "agent_id": "acme/billing-bot",
///   "session_id": "01HZX9V8…",
///   "expires_at": 1717400600000000000
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct SessionCtx {
    /// Agent that owns the session.
    pub agent_id: AgentId,
    /// Opaque session identifier.
    pub session_id: String,
    /// Absolute expiry (nanoseconds since the Unix epoch); the session is
    /// invalid once the wall clock passes this instant.
    pub expires_at: Timestamp,
}
