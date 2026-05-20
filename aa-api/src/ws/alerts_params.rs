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
