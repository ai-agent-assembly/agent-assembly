//! Query parameters for `GET /api/v1/alerts/ws` (AAASM-1389).
//!
//! Parses the optional `events` / `severity` / `agent_id` filter and
//! produces an [`AlertsFilter`] applied per-frame inside the WebSocket
//! handler. Invalid filter values produce a [`FilterError`] that
//! renders as RFC 7807 `400 Bad Request` *before* the upgrade switches
//! protocols.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use utoipa::IntoParams;

use crate::alerts::{AlertEvent, AlertSeverity};
use crate::error::ProblemDetail;

/// Raw query parameters accepted by `GET /api/v1/alerts/ws`.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct AlertsWsQueryParams {
    /// Comma-separated lifecycle filter: `fire`, `resolve`, `silence`.
    /// All three are included when omitted.
    pub events: Option<String>,
    /// Comma-separated severity filter: `CRITICAL`, `HIGH`, `MEDIUM`,
    /// `LOW`. All four are included when omitted.
    pub severity: Option<String>,
    /// Restrict the stream to a single hex-encoded agent id.
    pub agent_id: Option<String>,
}

/// Discriminator for the three [`AlertEvent`] variants. Carried in
/// the filter so callers don't depend on the enum's payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AlertEventKind {
    Fire,
    Resolve,
    Silence,
}

impl AlertEventKind {
    /// Classify an [`AlertEvent`] without inspecting its payload.
    pub fn of(event: &AlertEvent) -> Self {
        match event {
            AlertEvent::Fire(_) => Self::Fire,
            AlertEvent::Resolve(_) => Self::Resolve,
            AlertEvent::Silence(_) => Self::Silence,
        }
    }
}

/// The 4-value severity vocabulary spoken by the `/alerts/ws` API.
///
/// The store's underlying [`AlertSeverity`] only has 3 variants
/// (Info / Warning / Critical) — see [`Self::from_stored`] for the
/// mapping. `Low` is reserved: no current alert source emits it, but
/// the wire schema accepts it so future producers can land without an
/// API revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WireSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl WireSeverity {
    /// Project the store's 3-variant severity onto the 4-value wire
    /// vocabulary. Stored `Critical` is wire `Critical`; `Warning`
    /// becomes `High`; `Info` becomes `Medium`. No stored variant
    /// projects to `Low` today.
    pub fn from_stored(s: AlertSeverity) -> Self {
        match s {
            AlertSeverity::Critical => Self::Critical,
            AlertSeverity::Warning => Self::High,
            AlertSeverity::Info => Self::Medium,
        }
    }

    fn parse(raw: &str) -> Result<Self, FilterError> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "CRITICAL" => Ok(Self::Critical),
            "HIGH" => Ok(Self::High),
            "MEDIUM" => Ok(Self::Medium),
            "LOW" => Ok(Self::Low),
            "" => Err(FilterError::UnknownSeverity(raw.to_string())),
            _ => Err(FilterError::UnknownSeverity(raw.to_string())),
        }
    }
}

/// Concrete filter resolved from [`AlertsWsQueryParams`]. The sets are
/// populated with every variant when the corresponding query param is
/// absent, so an empty inbound request matches everything.
#[derive(Debug, Clone)]
pub struct AlertsFilter {
    pub events: BTreeSet<AlertEventKind>,
    pub severities: BTreeSet<WireSeverity>,
    pub agent_id: Option<String>,
}

impl AlertsFilter {
    /// Build a filter that matches every event of every severity for
    /// every agent — the default when no query params are supplied.
    pub fn unfiltered() -> Self {
        Self {
            events: [AlertEventKind::Fire, AlertEventKind::Resolve, AlertEventKind::Silence]
                .into_iter()
                .collect(),
            severities: [
                WireSeverity::Critical,
                WireSeverity::High,
                WireSeverity::Medium,
                WireSeverity::Low,
            ]
            .into_iter()
            .collect(),
            agent_id: None,
        }
    }

    /// Decide whether the WS handler should forward this event to the
    /// client. Returns `true` when every configured dimension matches.
    pub fn matches(&self, event: &AlertEvent) -> bool {
        if !self.events.contains(&AlertEventKind::of(event)) {
            return false;
        }
        let stored = match event {
            AlertEvent::Fire(s) | AlertEvent::Resolve(s) | AlertEvent::Silence(s) => s,
        };
        if !self.severities.contains(&WireSeverity::from_stored(stored.severity)) {
            return false;
        }
        if let Some(want) = self.agent_id.as_deref() {
            if stored.agent_id != want {
                return false;
            }
        }
        true
    }
}

/// Error returned when a query parameter carries an unrecognised value.
/// Renders as RFC 7807 `400 Bad Request` so the WebSocket upgrade is
/// rejected before protocol switch (AC requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterError {
    UnknownEvent(String),
    UnknownSeverity(String),
}

impl IntoResponse for FilterError {
    fn into_response(self) -> Response {
        let detail = match &self {
            Self::UnknownEvent(v) => format!("Unknown event filter value: {v:?}"),
            Self::UnknownSeverity(v) => format!("Unknown severity filter value: {v:?}"),
        };
        ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(detail)
            .into_response()
    }
}

impl AlertsWsQueryParams {
    /// Convert the raw query params into a concrete [`AlertsFilter`].
    /// Empty or absent params yield an unfiltered filter. Unknown
    /// values short-circuit with a [`FilterError`].
    pub fn try_into_filter(&self) -> Result<AlertsFilter, FilterError> {
        let mut filter = AlertsFilter::unfiltered();

        if let Some(raw) = &self.events {
            if raw.trim().is_empty() {
                // Treat empty string as "no filter override".
            } else {
                filter.events.clear();
                for tok in raw.split(',') {
                    let tok = tok.trim();
                    if tok.is_empty() {
                        continue;
                    }
                    let kind = match tok.to_ascii_lowercase().as_str() {
                        "fire" => AlertEventKind::Fire,
                        "resolve" => AlertEventKind::Resolve,
                        "silence" => AlertEventKind::Silence,
                        _ => return Err(FilterError::UnknownEvent(tok.to_string())),
                    };
                    filter.events.insert(kind);
                }
                if filter.events.is_empty() {
                    // Whitespace-only csv → fall back to unfiltered.
                    filter.events = AlertsFilter::unfiltered().events;
                }
            }
        }

        if let Some(raw) = &self.severity {
            if !raw.trim().is_empty() {
                filter.severities.clear();
                for tok in raw.split(',') {
                    let tok = tok.trim();
                    if tok.is_empty() {
                        continue;
                    }
                    filter.severities.insert(WireSeverity::parse(tok)?);
                }
                if filter.severities.is_empty() {
                    filter.severities = AlertsFilter::unfiltered().severities;
                }
            }
        }

        filter.agent_id = self
            .agent_id
            .as_ref()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        Ok(filter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::{AlertCategory, StoredAlert};

    fn params(events: Option<&str>, severity: Option<&str>, agent_id: Option<&str>) -> AlertsWsQueryParams {
        AlertsWsQueryParams {
            events: events.map(str::to_string),
            severity: severity.map(str::to_string),
            agent_id: agent_id.map(str::to_string),
        }
    }

    fn stored(severity: AlertSeverity, agent_id: &str) -> StoredAlert {
        StoredAlert {
            id: "01JC0000000000000000000001".to_string(),
            severity,
            category: AlertCategory::Budget,
            message: "test".to_string(),
            agent_id: agent_id.to_string(),
            team_id: None,
            timestamp: "2026-05-20T00:00:00Z".to_string(),
            threshold_pct: 80,
            spent_usd: 8.0,
            limit_usd: 10.0,
            status: "unresolved".to_string(),
            prior_status: None,
            updated_at: None,
            detected_pattern_type: None,
            redacted_value: None,
            first_fired_at: "2026-05-20T00:00:00Z".to_string(),
            resolved_at: None,
            rule_context: None,
        }
    }

    #[test]
    fn defaults_match_all_events_and_severities() {
        let f = params(None, None, None).try_into_filter().unwrap();
        assert_eq!(f.events.len(), 3);
        assert_eq!(f.severities.len(), 4);
        assert!(f.agent_id.is_none());
        // The default filter matches every kind / severity / agent.
        for sev in [AlertSeverity::Critical, AlertSeverity::Warning, AlertSeverity::Info] {
            assert!(f.matches(&AlertEvent::Fire(stored(sev, "abc"))));
            assert!(f.matches(&AlertEvent::Resolve(stored(sev, "abc"))));
            assert!(f.matches(&AlertEvent::Silence(stored(sev, "abc"))));
        }
    }

    #[test]
    fn events_csv_subset_parses() {
        let f = params(Some("fire,resolve"), None, None).try_into_filter().unwrap();
        assert!(f.events.contains(&AlertEventKind::Fire));
        assert!(f.events.contains(&AlertEventKind::Resolve));
        assert!(!f.events.contains(&AlertEventKind::Silence));
    }

    #[test]
    fn severity_csv_mixed_case_accepted() {
        let f = params(None, Some("critical,High,mEdIuM"), None)
            .try_into_filter()
            .unwrap();
        assert!(f.severities.contains(&WireSeverity::Critical));
        assert!(f.severities.contains(&WireSeverity::High));
        assert!(f.severities.contains(&WireSeverity::Medium));
        assert!(!f.severities.contains(&WireSeverity::Low));
    }

    #[test]
    fn unknown_event_rejected() {
        let err = params(Some("fire,bogus"), None, None).try_into_filter().unwrap_err();
        assert_eq!(err, FilterError::UnknownEvent("bogus".to_string()));
    }

    #[test]
    fn unknown_severity_rejected() {
        let err = params(None, Some("CRITICAL,EXTREME"), None)
            .try_into_filter()
            .unwrap_err();
        assert_eq!(err, FilterError::UnknownSeverity("EXTREME".to_string()));
    }

    #[test]
    fn agent_id_passes_through() {
        let f = params(None, None, Some("agent-xyz")).try_into_filter().unwrap();
        assert_eq!(f.agent_id.as_deref(), Some("agent-xyz"));

        // Empty agent_id is treated as absent (no filter).
        let f = params(None, None, Some("   ")).try_into_filter().unwrap();
        assert!(f.agent_id.is_none());
    }

    #[test]
    fn whitespace_in_csv_trimmed() {
        let f = params(Some("  fire ,, resolve  "), Some("  CRITICAL ,  HIGH  "), None)
            .try_into_filter()
            .unwrap();
        assert_eq!(f.events.len(), 2);
        assert!(f.events.contains(&AlertEventKind::Fire));
        assert!(f.events.contains(&AlertEventKind::Resolve));
        assert_eq!(f.severities.len(), 2);
        assert!(f.severities.contains(&WireSeverity::Critical));
        assert!(f.severities.contains(&WireSeverity::High));
    }

    #[test]
    fn matches_excludes_wrong_event_kind() {
        let f = params(Some("resolve"), None, None).try_into_filter().unwrap();
        assert!(!f.matches(&AlertEvent::Fire(stored(AlertSeverity::Critical, "agent-1"))));
        assert!(f.matches(&AlertEvent::Resolve(stored(AlertSeverity::Critical, "agent-1"))));
    }

    #[test]
    fn matches_excludes_wrong_severity() {
        // AC: severity=CRITICAL excludes a MEDIUM fire (stored Info → wire Medium).
        let f = params(None, Some("CRITICAL"), None).try_into_filter().unwrap();
        assert!(!f.matches(&AlertEvent::Fire(stored(AlertSeverity::Info, "agent-1"))));
        assert!(!f.matches(&AlertEvent::Fire(stored(AlertSeverity::Warning, "agent-1"))));
        assert!(f.matches(&AlertEvent::Fire(stored(AlertSeverity::Critical, "agent-1"))));
    }

    #[test]
    fn matches_excludes_wrong_agent_id() {
        let f = params(None, None, Some("agent-allow")).try_into_filter().unwrap();
        assert!(!f.matches(&AlertEvent::Fire(stored(AlertSeverity::Critical, "agent-deny"))));
        assert!(f.matches(&AlertEvent::Fire(stored(AlertSeverity::Critical, "agent-allow"))));
    }

    #[test]
    fn filter_error_renders_400_problem_detail() {
        let resp = FilterError::UnknownEvent("bogus".to_string()).into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let ct = resp.headers().get(axum::http::header::CONTENT_TYPE);
        assert_eq!(ct.map(|v| v.to_str().unwrap()), Some("application/problem+json"));
    }

    #[test]
    fn wire_severity_low_is_reserved_unmapped() {
        // The store can't currently produce LOW (no source). Make sure
        // requesting LOW alone leaves the filter accepting nothing
        // from the current store — but the parser must still accept
        // the value so future producers don't need an API revision.
        let f = params(None, Some("LOW"), None).try_into_filter().unwrap();
        for sev in [AlertSeverity::Critical, AlertSeverity::Warning, AlertSeverity::Info] {
            assert!(!f.matches(&AlertEvent::Fire(stored(sev, "agent-1"))));
        }
    }
}
