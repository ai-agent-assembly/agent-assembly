//! Unified governance event model for WebSocket streaming.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::event_type::EventType;
// Used in #[schema(value_type = ...)] attribute for OpenAPI generation.
#[allow(unused_imports)]
use super::ws_payloads::EventPayload;

/// Unique identifier for a governance event in the replay buffer.
pub type EventId = u64;

/// A governance event delivered to WebSocket subscribers.
///
/// This is the unified JSON representation sent over the wire.
/// It wraps events from all three domain channels (pipeline,
/// approval, budget) into a single schema that clients can
/// filter by [`EventType`].
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct GovernanceEvent {
    /// Monotonically increasing event identifier.
    #[schema(value_type = u64)]
    pub id: EventId,
    /// Classification of the event for client-side filtering.
    pub event_type: EventType,
    /// Agent that produced or is associated with the event.
    pub agent_id: String,
    /// Event-specific payload whose schema depends on `event_type`:
    /// `ViolationPayload`, `ApprovalPayload`, or `BudgetAlertPayload`.
    #[schema(value_type = EventPayload)]
    pub payload: serde_json::Value,
    /// Timestamp when the event was received by the API layer (ISO 8601).
    #[schema(value_type = String)]
    pub timestamp: DateTime<Utc>,
    /// Owning team of the event, resolved from the source event's tenant
    /// context (AAASM-3980). Server-side only: `#[serde(skip)]` keeps it
    /// off the wire (no OpenAPI change) so it is never disclosed to
    /// clients — it exists solely so the WebSocket dispatch loop can gate
    /// both live and replayed events by tenant. `None` means the event
    /// carries no resolvable owning team.
    #[serde(skip)]
    pub team_id: Option<String>,
    /// Owning org of the event, resolved from the agent-registry lineage
    /// (AAASM-3980). Server-side only for the same reason as
    /// [`Self::team_id`]; `None` when no org could be resolved.
    #[serde(skip)]
    pub org_id: Option<String>,
}
