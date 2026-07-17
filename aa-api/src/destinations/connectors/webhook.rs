//! Webhook notification connector — generic outbound JSON POST.
//!
//! POSTs `{ severity, message, sent_at }` to the destination URL. When
//! the destination carries a `secret_header` the value is shipped in the
//! `X-AAASM-Token` header so the receiving service can authenticate the
//! webhook before acting on it.

use std::net::SocketAddr;

use chrono::Utc;

use crate::destinations::connectors::{
    egress_client, ConnectorError, DispatchOutcome, DispatchRequest, NotificationConnector,
};
use crate::destinations::types::{Destination, DestinationConfig};

/// Webhook connector. Stateless — uses the per-process shared `reqwest::Client`.
pub struct WebhookConnector;

#[async_trait::async_trait]
impl NotificationConnector for WebhookConnector {
    async fn dispatch(
        &self,
        destination: &Destination,
        req: &DispatchRequest,
        pinned: &[SocketAddr],
    ) -> Result<DispatchOutcome, ConnectorError> {
        let (url, secret_header) = match &destination.config {
            DestinationConfig::Webhook { url, secret_header } => (url.clone(), secret_header.clone()),
            _ => {
                return Err(ConnectorError::Transport(
                    "WebhookConnector dispatched on non-webhook destination".into(),
                ))
            }
        };

        // AAASM-3826: pin the connection to the SSRF-vetted address so a
        // DNS-rebind after the egress check cannot redirect this POST to an
        // internal host. The host is extracted from the already-validated URL.
        let host = url::Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_owned))
            .unwrap_or_default();
        let client = egress_client(&host, pinned);

        let mut builder = client.post(&url).json(&serde_json::json!({
            "severity": req.severity,
            "message": req.message,
            "sent_at": Utc::now().to_rfc3339(),
        }));
        if let Some(value) = secret_header {
            builder = builder.header("X-AAASM-Token", value);
        }

        let resp = builder
            .send()
            .await
            // AAASM-4744: strip the destination URL from the surfaced error. A
            // reqwest error's Display embeds the request URL, which for a
            // caller-controlled webhook can carry a query token; `without_url`
            // drops it so the token never lands in the 502 body or logs.
            .map_err(|e| ConnectorError::Transport(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        // AAASM-3789: do NOT capture or return the upstream response body. A
        // webhook test-fire must not reflect origin/internal response content
        // back to the caller (SSRF data-exfiltration vector). Drain and discard
        // the body so only the observed status is surfaced.
        drop(resp.bytes().await);

        if (200..300).contains(&status) {
            Ok(DispatchOutcome {
                delivered_at: Utc::now().to_rfc3339(),
                connector_response_status: status,
                connector_response_body: String::new(),
            })
        } else {
            Err(ConnectorError::Http {
                status,
                body: String::new(),
            })
        }
    }
}
