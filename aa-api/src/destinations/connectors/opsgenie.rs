//! OpsGenie notification connector — REST alerts API.
//!
//! Gated behind the `connector-opsgenie` feature so deployments that only
//! need webhook + Slack avoid the OpsGenie payload schema in the binary.

use chrono::Utc;

use crate::destinations::connectors::{
    shared_client, truncate_body, ConnectorError, DispatchOutcome, DispatchRequest, NotificationConnector,
};
use crate::destinations::types::{Destination, DestinationConfig};

const ALERTS_URL: &str = "https://api.opsgenie.com/v2/alerts";

/// OpsGenie REST alerts connector.
pub struct OpsGenieConnector;

/// Translate the AAASM severity label into the OpsGenie `priority` enum
/// (P1–P5). Anything we don't recognise falls back to P3.
fn severity_to_priority(severity: &str) -> &'static str {
    match severity.to_ascii_uppercase().as_str() {
        "CRITICAL" => "P1",
        "HIGH" => "P2",
        "MEDIUM" => "P3",
        "LOW" => "P4",
        "INFO" | "INFORMATIONAL" => "P5",
        _ => "P3",
    }
}

#[async_trait::async_trait]
impl NotificationConnector for OpsGenieConnector {
    async fn dispatch(
        &self,
        destination: &Destination,
        req: &DispatchRequest,
    ) -> Result<DispatchOutcome, ConnectorError> {
        let (api_key, team_id) = match &destination.config {
            DestinationConfig::OpsGenie { api_key, team_id } => (api_key.clone(), team_id.clone()),
            _ => {
                return Err(ConnectorError::Transport(
                    "OpsGenieConnector dispatched on non-opsgenie destination".into(),
                ))
            }
        };

        let body = serde_json::json!({
            "message": req.message,
            "teams": [{ "id": team_id }],
            "priority": severity_to_priority(&req.severity),
        });

        let resp = shared_client()
            .post(ALERTS_URL)
            .header("Authorization", format!("GenieKey {api_key}"))
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
