//! PagerDuty notification connector — Events API v2.
//!
//! Gated behind the `connector-pagerduty` feature so deployments that only
//! need webhook + Slack avoid pulling the PagerDuty payload schema into the
//! binary.

use chrono::Utc;

use crate::destinations::connectors::{
    shared_client, truncate_body, ConnectorError, DispatchOutcome, DispatchRequest, NotificationConnector,
};
use crate::destinations::types::{Destination, DestinationConfig};

const EVENTS_V2_URL: &str = "https://events.pagerduty.com/v2/enqueue";

/// PagerDuty Events API v2 connector.
pub struct PagerDutyConnector;

#[async_trait::async_trait]
impl NotificationConnector for PagerDutyConnector {
    async fn dispatch(
        &self,
        destination: &Destination,
        req: &DispatchRequest,
    ) -> Result<DispatchOutcome, ConnectorError> {
        let (routing_key, severity_map) = match &destination.config {
            DestinationConfig::PagerDuty {
                routing_key,
                severity_map,
            } => (routing_key.clone(), severity_map.clone()),
            _ => {
                return Err(ConnectorError::Transport(
                    "PagerDutyConnector dispatched on non-pagerduty destination".into(),
                ))
            }
        };

        // Map AAASM severity → PagerDuty severity if a map is configured;
        // otherwise pass through (PagerDuty accepts critical/error/warning/info).
        let severity = severity_map
            .as_ref()
            .and_then(|m| m.get(&req.severity).cloned())
            .unwrap_or_else(|| req.severity.clone());

        let body = serde_json::json!({
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": req.message,
                "severity": severity,
                "source": "aaasm",
            },
        });

        let resp = shared_client()
            .post(EVENTS_V2_URL)
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
