//! Event type classification for WebSocket filtering.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Classification of governance events for client-side filtering.
///
/// Clients specify a comma-separated list of these values in the `types`
/// query parameter to receive only matching events on the WebSocket.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Audit / pipeline events (policy violations, enriched events).
    Violation,
    /// Human-in-the-loop approval requests.
    Approval,
    /// Budget threshold alerts.
    Budget,
    /// In-flight ops registry state transitions (AAASM-1422 PR-B).
    /// Emitted on every `OpsRegistry` transition; payload is
    /// [`super::ws_payloads::OpsChangePayload`].
    OpsChange,
}

impl EventType {
    /// Parse a comma-separated filter string into a set of event types.
    ///
    /// Returns all variants when the input is empty or `None`.
    pub fn parse_filter(input: Option<&str>) -> Vec<EventType> {
        match input {
            None | Some("") => vec![Self::Violation, Self::Approval, Self::Budget, Self::OpsChange],
            Some(s) => s
                .split(',')
                .filter_map(|t| match t.trim() {
                    "violation" => Some(Self::Violation),
                    "approval" => Some(Self::Approval),
                    "budget" => Some(Self::Budget),
                    "ops_change" => Some(Self::OpsChange),
                    _ => None,
                })
                .collect(),
        }
    }
}
