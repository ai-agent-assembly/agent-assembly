//! Notification connectors — per-kind outbound dispatch (AAASM-1388).
//!
//! `POST /alerts/destinations/{id}/test` invokes the kind-appropriate
//! [`NotificationConnector`]. Real connector impls live in the per-kind
//! sub-modules; PagerDuty and OpsGenie are gated behind cargo features so
//! the binary footprint stays small when only webhook / Slack are needed.

use std::sync::OnceLock;
use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::destinations::types::Destination;

pub mod slack;
pub mod webhook;

#[cfg(feature = "connector-opsgenie")]
pub mod opsgenie;
#[cfg(feature = "connector-pagerduty")]
pub mod pagerduty;

/// Body of a test-fire request.
///
/// Both fields default so callers can `POST` with an empty body and still
/// get a meaningful payload at the connector.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct DispatchRequest {
    /// Severity label propagated to the connector (e.g. `"LOW"`, `"CRITICAL"`).
    #[serde(default = "default_severity")]
    pub severity: String,
    /// Human-readable message body.
    #[serde(default = "default_message")]
    pub message: String,
}

fn default_severity() -> String {
    "LOW".to_string()
}

fn default_message() -> String {
    "AAASM test fire".to_string()
}

impl Default for DispatchRequest {
    fn default() -> Self {
        Self {
            severity: default_severity(),
            message: default_message(),
        }
    }
}

/// Outcome of a successful dispatch.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    /// RFC 3339 timestamp captured immediately after the connector returned.
    pub delivered_at: String,
    /// HTTP status the connector observed.
    pub connector_response_status: u16,
    /// Up-to-2048-byte snippet of the connector response body.
    pub connector_response_body: String,
}

/// Error returned by a `NotificationConnector::dispatch`.
#[derive(Debug)]
pub enum ConnectorError {
    /// The connector reached the destination but it responded non-2xx.
    Http {
        /// Observed HTTP status.
        status: u16,
        /// Up-to-2048-byte snippet of the connector response body.
        body: String,
    },
    /// The connector failed before getting an HTTP response (DNS, TCP,
    /// TLS handshake, timeout). The carried `String` is a human-readable
    /// description suitable for surfacing as the 502 `connector_body`.
    Transport(String),
}

/// Trait implemented by each per-kind connector.
#[async_trait::async_trait]
pub trait NotificationConnector: Send + Sync {
    /// Dispatch `req` to `destination` and return the outcome.
    async fn dispatch(
        &self,
        destination: &Destination,
        req: &DispatchRequest,
    ) -> Result<DispatchOutcome, ConnectorError>;
}

/// Shared `reqwest::Client` used by every connector. Constructed once so
/// connection pooling and rustls config are reused.
#[allow(dead_code)] // wired up by per-kind connectors in subsequent commits
pub(crate) fn shared_client() -> &'static Client {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        Client::builder()
            .connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(15))
            .build()
            .expect("reqwest client construction failed")
    })
}

/// Cap a response body at 2048 bytes so error envelopes stay bounded.
#[allow(dead_code)] // wired up by per-kind connectors in subsequent commits
pub(crate) fn truncate_body(body: String) -> String {
    if body.len() > 2048 {
        body[..2048].to_string()
    } else {
        body
    }
}
