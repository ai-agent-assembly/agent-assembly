//! Query parameters for the WebSocket events endpoint.

use serde::Deserialize;
use utoipa::IntoParams;

use crate::models::{EventId, EventType};

/// Query parameters accepted by `GET /api/v1/ws/events`.
///
/// All parameters are optional:
/// - `types`: comma-separated event type filter (e.g. `violation,budget`).
///   All types are included when omitted.
/// - `agent_id`: restrict events to a single agent.
/// - `since`: replay buffered events whose id is greater than this value.
#[derive(Debug, Deserialize, IntoParams)]
pub struct WsQueryParams {
    /// Comma-separated event type filter (e.g. `violation,budget`).
    /// All types are included when omitted.
    pub types: Option<String>,
    /// Filter events by agent identifier (hex-encoded).
    pub agent_id: Option<String>,
    /// Replay buffered events whose id is greater than this value.
    /// The server keeps the last 1000 events in a circular buffer.
    #[param(value_type = Option<u64>)]
    pub since: Option<EventId>,
    /// Short-lived, single-use WebSocket ticket (AAASM-4861). Browsers can't set
    /// an `Authorization` header on a WS handshake, so the dashboard mints a
    /// ticket via `POST /api/v1/auth/ws-ticket` and presents it here instead of
    /// putting a long-lived credential in the URL. Non-browser clients may
    /// instead send an `Authorization: Bearer` header and omit this.
    pub ticket: Option<String>,
}

impl WsQueryParams {
    /// Resolve the event type filter to a concrete list.
    pub fn event_types(&self) -> Vec<EventType> {
        EventType::parse_filter(self.types.as_deref())
    }
}
