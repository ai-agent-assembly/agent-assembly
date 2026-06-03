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

#[cfg(all(test, feature = "serde"))]
mod serde_round_trip {
    use super::SessionCtx;
    use crate::time::Timestamp;
    use crate::types::AgentId;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn session_ctx_round_trips(
            tenant in "[a-z][a-z0-9-]{0,7}",
            agent in "[a-z][a-z0-9-]{0,7}",
            session_id in "[A-Z0-9]{1,26}",
            expires_at in any::<u64>(),
        ) {
            let original = SessionCtx {
                agent_id: AgentId::parse(format!("{tenant}/{agent}")).unwrap(),
                session_id,
                expires_at: Timestamp::from_nanos(expires_at),
            };
            let json = serde_json::to_string(&original).unwrap();
            let restored: SessionCtx = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(original, restored);
        }
    }
}
