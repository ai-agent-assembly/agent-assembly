//! Webhook notification connector — generic outbound JSON POST.
//!
//! POSTs `{ severity, message, sent_at }` to the destination URL. When
//! the destination carries a `secret_header` the value is shipped in the
//! `X-AAASM-Token` header so the receiving service can authenticate the
//! webhook before acting on it.

use chrono::Utc;

use crate::destinations::connectors::{
    shared_client, truncate_body, ConnectorError, DispatchOutcome, DispatchRequest, NotificationConnector,
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
    ) -> Result<DispatchOutcome, ConnectorError> {
        let (url, secret_header) = match &destination.config {
            DestinationConfig::Webhook { url, secret_header } => (url.clone(), secret_header.clone()),
            _ => {
                return Err(ConnectorError::Transport(
                    "WebhookConnector dispatched on non-webhook destination".into(),
                ))
            }
        };

        let mut builder = shared_client().post(&url).json(&serde_json::json!({
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
            .map_err(|e| ConnectorError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body = truncate_body(body);

        if (200..300).contains(&status) {
            Ok(DispatchOutcome {
                delivered_at: Utc::now().to_rfc3339(),
                connector_response_status: status,
                connector_response_body: body,
            })
        } else {
            Err(ConnectorError::Http { status, body })
        }
    }
}
