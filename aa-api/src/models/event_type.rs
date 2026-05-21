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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_filter_includes_ops_change() {
        let result = EventType::parse_filter(None);
        assert!(result.contains(&EventType::OpsChange));
        assert_eq!(result.len(), 4);
    }

    #[test]
    fn ops_change_filter_string_resolves_to_variant() {
        assert_eq!(EventType::parse_filter(Some("ops_change")), vec![EventType::OpsChange]);
    }

    #[test]
    fn multi_filter_keeps_order_and_includes_ops_change() {
        let result = EventType::parse_filter(Some("violation,ops_change,budget"));
        assert_eq!(
            result,
            vec![EventType::Violation, EventType::OpsChange, EventType::Budget]
        );
    }

    #[test]
    fn unknown_filter_token_is_dropped() {
        assert_eq!(
            EventType::parse_filter(Some("bogus,ops_change")),
            vec![EventType::OpsChange]
        );
    }

    #[test]
    fn ops_change_variant_serializes_snake_case() {
        let json = serde_json::to_string(&EventType::OpsChange).unwrap();
        assert_eq!(json, "\"ops_change\"");
    }
}
