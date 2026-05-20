//! Slack notification connector — Slack incoming-webhook payloads.
//!
//! Slack's incoming-webhook contract: POST JSON `{ "text": ..., "channel": ... }`
//! to the per-team webhook URL. We reuse the same shared `reqwest::Client`
//! as the generic webhook connector so connection pooling and rustls
//! configuration are shared.

use chrono::Utc;

use crate::destinations::connectors::{
    shared_client, truncate_body, ConnectorError, DispatchOutcome, DispatchRequest, NotificationConnector,
};
use crate::destinations::types::{Destination, DestinationConfig};

/// Slack connector. Stateless — reuses the per-process shared client.
pub struct SlackConnector;

#[async_trait::async_trait]
impl NotificationConnector for SlackConnector {
    async fn dispatch(
        &self,
        destination: &Destination,
        req: &DispatchRequest,
    ) -> Result<DispatchOutcome, ConnectorError> {
        let (webhook_url, channel_override) = match &destination.config {
            DestinationConfig::Slack {
                webhook_url,
                channel_override,
            } => (webhook_url.clone(), channel_override.clone()),
            _ => {
                return Err(ConnectorError::Transport(
                    "SlackConnector dispatched on non-slack destination".into(),
                ))
            }
        };

        let mut body = serde_json::json!({
            "text": format!("[{}] {}", req.severity, req.message),
        });
        if let Some(channel) = channel_override {
            body["channel"] = serde_json::Value::String(channel);
        }

        let resp = shared_client()
            .post(&webhook_url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ConnectorError::Transport(e.to_string()))?;
        let status = resp.status().as_u16();
        let resp_body = resp.text().await.unwrap_or_default();
        let resp_body = truncate_body(resp_body);

        if (200..300).contains(&status) {
            Ok(DispatchOutcome {
                delivered_at: Utc::now().to_rfc3339(),
                connector_response_status: status,
                connector_response_body: resp_body,
            })
        } else {
            Err(ConnectorError::Http {
                status,
                body: resp_body,
            })
        }
    }
}
