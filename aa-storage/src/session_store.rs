//! [`SessionStore`] — persistence for per-execution session records.

use crate::{AgentId, SessionId};

/// A persisted record of a single agent execution session.
///
/// One record is created per execution run and ties together all governance
/// events within that run. Backends key the record by its
/// [`session_id`](SessionRecord::session_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// Stable identifier for this execution run.
    pub session_id: SessionId,
    /// The agent that owns this session.
    pub agent_id: AgentId,
    /// Wall-clock start time of the session, in nanoseconds since the Unix epoch.
    pub started_at_ns: u64,
}
