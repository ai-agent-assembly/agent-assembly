//! Metadata-only governance audit event persisted by audit sinks.

use alloc::string::String;

use crate::audit::AuditEventType;
use crate::time::Timestamp;
use crate::types::AgentId;

/// A metadata-only record of a governance event.
///
/// An `AuditEvent` describes *that* something happened and *in what context* —
/// it deliberately **never** carries the raw tool payload or any secret value
/// (see Epic D / D4). `event_type` reuses the canonical
/// [`crate::audit::AuditEventType`] so the audit wire shape cannot drift from
/// the runtime's event taxonomy. `deny_unknown_fields` makes a field renamed on
/// the writer side fail loudly on the reader side.
///
/// # Wire format
///
/// ```json
/// {
///   "agent_id": "acme/billing-bot",
///   "session_id": "01HZX9V8…",
///   "event_type": "PolicyViolation",
///   "timestamp": 1717400000000000000,
///   "policy_version": 7
/// }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(deny_unknown_fields))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct AuditEvent {
    /// Agent that triggered the event.
    pub agent_id: AgentId,
    /// Opaque session identifier the event belongs to.
    pub session_id: String,
    /// Category of the event, drawn from the canonical event taxonomy.
    pub event_type: AuditEventType,
    /// When the event occurred (nanoseconds since the Unix epoch).
    pub timestamp: Timestamp,
    /// Policy version in force when the event was recorded, if any.
    pub policy_version: Option<u64>,
}

#[cfg(all(test, feature = "serde"))]
mod serde_round_trip {
    use super::AuditEvent;
    use crate::audit::AuditEventType;
    use crate::time::Timestamp;
    use crate::types::AgentId;
    use proptest::prelude::*;

    fn event_type_strategy() -> impl Strategy<Value = AuditEventType> {
        prop_oneof![
            Just(AuditEventType::ToolCallIntercepted),
            Just(AuditEventType::PolicyViolation),
            Just(AuditEventType::CredentialLeakBlocked),
            Just(AuditEventType::ApprovalGranted),
            Just(AuditEventType::BudgetLimitExceeded),
        ]
    }

    proptest! {
        #[test]
        fn audit_event_round_trips(
            tenant in "[a-z][a-z0-9-]{0,7}",
            agent in "[a-z][a-z0-9-]{0,7}",
            session_id in "[A-Z0-9]{1,26}",
            event_type in event_type_strategy(),
            ts in any::<u64>(),
            policy_version in proptest::option::of(any::<u64>()),
        ) {
            let original = AuditEvent {
                agent_id: AgentId::parse(format!("{tenant}/{agent}")).unwrap(),
                session_id,
                event_type,
                timestamp: Timestamp::from_nanos(ts),
                policy_version,
            };
            let json = serde_json::to_string(&original).unwrap();
            let restored: AuditEvent = serde_json::from_str(&json).unwrap();
            prop_assert_eq!(original, restored);
        }
    }
}
