//! Data feed — REST polling and WebSocket event streaming for the dashboard.

use std::sync::Arc;

use futures_util::StreamExt;
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message;

use crate::commands::status::client::StatusClient;
use crate::commands::status::fetch;
use crate::commands::status::models::{AgentRow, ApprovalResponse, ApprovalsSummary, BudgetRow, RuntimeHealth};
use crate::sanitize::sanitize_terminal;

/// Sanitize every server/agent-controlled string field of an [`AgentRow`] so
/// terminal escape sequences can never reach the dashboard's rendered output.
/// Numeric fields (`sessions`, `violations_today`) are left untouched.
fn sanitize_agent_row(mut row: AgentRow) -> AgentRow {
    row.id = sanitize_terminal(&row.id);
    row.name = sanitize_terminal(&row.name);
    row.framework = sanitize_terminal(&row.framework);
    row.status = sanitize_terminal(&row.status);
    row.last_event = sanitize_terminal(&row.last_event);
    row.layer = sanitize_terminal(&row.layer);
    row
}

/// Sanitize every server/agent-controlled string field of an [`ApprovalResponse`].
/// Covers both the approve/reject confirmation dialog and the approvals panel.
fn sanitize_approval(mut ap: ApprovalResponse) -> ApprovalResponse {
    ap.id = sanitize_terminal(&ap.id);
    ap.agent_id = sanitize_terminal(&ap.agent_id);
    ap.action = sanitize_terminal(&ap.action);
    ap.reason = sanitize_terminal(&ap.reason);
    ap.status = sanitize_terminal(&ap.status);
    ap.created_at = sanitize_terminal(&ap.created_at);
    ap.team_id = sanitize_terminal(&ap.team_id);
    ap.routing_status = sanitize_terminal(&ap.routing_status);
    ap
}

/// Sanitize every server-supplied string field of a [`BudgetRow`], including the
/// per-agent cost breakdown. Numeric ratios are computed downstream by parsing
/// these strings, so stripped escapes leave well-formed amounts intact.
fn sanitize_budget(mut budget: BudgetRow) -> BudgetRow {
    budget.daily_spend_usd = sanitize_terminal(&budget.daily_spend_usd);
    budget.monthly_spend_usd = budget.monthly_spend_usd.as_deref().map(sanitize_terminal);
    budget.daily_limit_usd = budget.daily_limit_usd.as_deref().map(sanitize_terminal);
    budget.monthly_limit_usd = budget.monthly_limit_usd.as_deref().map(sanitize_terminal);
    budget.date = sanitize_terminal(&budget.date);
    for entry in &mut budget.per_agent {
        entry.agent_id = sanitize_terminal(&entry.agent_id);
        entry.daily_spend_usd = sanitize_terminal(&entry.daily_spend_usd);
    }
    budget
}

/// Sanitize the server-supplied `status` string of [`RuntimeHealth`], which is
/// rendered raw in the agents-panel health header. Numeric fields are untouched.
fn sanitize_runtime(mut runtime: RuntimeHealth) -> RuntimeHealth {
    runtime.status = sanitize_terminal(&runtime.status);
    runtime
}

/// Sanitize the string field of an [`ApprovalsSummary`]. The count is numeric.
fn sanitize_approvals_summary(mut summary: ApprovalsSummary) -> ApprovalsSummary {
    summary.oldest_pending_age = summary.oldest_pending_age.as_deref().map(sanitize_terminal);
    summary
}

use super::state::EventEntry;

/// Messages sent from background data tasks to the main event loop.
#[derive(Debug)]
pub enum FeedMessage {
    /// A full status snapshot from REST polling.
    StatusUpdate {
        runtime: RuntimeHealth,
        agents: Vec<AgentRow>,
        approvals_summary: ApprovalsSummary,
        pending_approvals: Vec<ApprovalResponse>,
        budget: BudgetRow,
    },
    /// A single governance event from the WebSocket stream.
    Event(EventEntry),
    /// The WebSocket connection was closed or failed.
    WsDisconnected,
}

/// A governance event as received from the WebSocket stream.
#[derive(Debug, Deserialize)]
struct WsEvent {
    #[allow(dead_code)]
    id: u64,
    event_type: String,
    agent_id: String,
    payload: serde_json::Value,
    timestamp: String,
}

/// Interval between REST status polls.
const POLL_INTERVAL_SECS: u64 = 5;

/// Spawn the REST polling task that periodically fetches all status data.
///
/// Sends `FeedMessage::StatusUpdate` on every successful poll cycle.
pub fn spawn_rest_poller(api_url: &str, tx: mpsc::UnboundedSender<FeedMessage>) {
    let client = StatusClient::new(api_url);

    tokio::spawn(async move {
        loop {
            let snapshot = fetch::fetch_all(&client).await;

            // Fetch the raw approvals list so we have individual pending items.
            // Sanitize every server/agent-controlled field at ingestion (mirroring
            // the WebSocket path) so escape sequences can never reach a render.
            let pending_approvals = client
                .list_approvals()
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|a| a.status == "pending")
                .map(sanitize_approval)
                .collect();

            let msg = FeedMessage::StatusUpdate {
                runtime: sanitize_runtime(snapshot.runtime),
                agents: snapshot.agents.into_iter().map(sanitize_agent_row).collect(),
                approvals_summary: sanitize_approvals_summary(snapshot.approvals),
                pending_approvals,
                budget: sanitize_budget(snapshot.budget),
            };

            if tx.send(msg).is_err() {
                break; // receiver dropped — main loop exited
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
        }
    });
}

/// Spawn the WebSocket event streaming task.
///
/// Connects to the gateway's `/api/v1/ws/events` endpoint and forwards
/// each governance event as `FeedMessage::Event`. Sends
/// `FeedMessage::WsDisconnected` if the connection drops.
pub fn spawn_ws_listener(api_url: &str, tx: mpsc::UnboundedSender<FeedMessage>) {
    let ws_url = build_ws_url(api_url);
    let tx = Arc::new(tx);

    tokio::spawn(async move {
        let (ws_stream, _) = match tokio_tungstenite::connect_async(&ws_url).await {
            Ok(conn) => conn,
            Err(_) => {
                let _ = tx.send(FeedMessage::WsDisconnected);
                return;
            }
        };

        let (_write, mut read) = ws_stream.split();

        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    let event: WsEvent = match serde_json::from_str(&text) {
                        Ok(e) => e,
                        Err(_) => continue,
                    };
                    let entry = ws_event_to_entry(&event);
                    if tx.send(FeedMessage::Event(entry)).is_err() {
                        break;
                    }
                }
                Ok(Message::Close(_)) => break,
                Ok(_) => {} // ping/pong/binary
                Err(_) => break,
            }
        }

        let _ = tx.send(FeedMessage::WsDisconnected);
    });
}

/// Convert the HTTP API URL to a WebSocket URL for the events endpoint.
fn build_ws_url(api_url: &str) -> String {
    let base = api_url
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    format!("{base}/api/v1/ws/events")
}

/// Convert a deserialized WsEvent into an EventEntry for the dashboard state.
fn ws_event_to_entry(event: &WsEvent) -> EventEntry {
    let message = match &event.payload {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    // Every field is server-supplied; sanitize at ingestion so escapes can
    // never reach the dashboard's rendered output.
    EventEntry {
        timestamp: sanitize_terminal(&event.timestamp),
        event_type: sanitize_terminal(&event.event_type),
        agent_id: sanitize_terminal(&event.agent_id),
        message: sanitize_terminal(&message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ws_url_http() {
        assert_eq!(
            build_ws_url("http://localhost:8080"),
            "ws://localhost:8080/api/v1/ws/events"
        );
    }

    #[test]
    fn build_ws_url_https() {
        assert_eq!(
            build_ws_url("https://api.example.com"),
            "wss://api.example.com/api/v1/ws/events"
        );
    }

    #[test]
    fn ws_event_string_payload() {
        let event = WsEvent {
            id: 1,
            event_type: "violation".to_string(),
            agent_id: "a1".to_string(),
            payload: serde_json::Value::String("denied".to_string()),
            timestamp: "2026-04-30T10:00:00Z".to_string(),
        };
        let entry = ws_event_to_entry(&event);
        assert_eq!(entry.message, "denied");
        assert_eq!(entry.event_type, "violation");
    }

    #[test]
    fn ws_event_to_entry_sanitizes_server_fields() {
        let event = WsEvent {
            id: 3,
            event_type: "viol\x1b[31mation".to_string(),
            agent_id: "a\x1b]52;c;ZXZpbA==\x07b".to_string(),
            payload: serde_json::Value::String("denied\ninjected".to_string()),
            timestamp: "2026-04-30T10:00:00Z".to_string(),
        };
        let entry = ws_event_to_entry(&event);
        assert_eq!(entry.event_type, "violation");
        assert_eq!(entry.agent_id, "ab");
        assert_eq!(entry.message, "deniedinjected");
        assert!(!entry.agent_id.contains('\x1b'));
    }

    #[test]
    fn ws_event_object_payload() {
        let event = WsEvent {
            id: 2,
            event_type: "budget".to_string(),
            agent_id: "a2".to_string(),
            payload: serde_json::json!({"action": "alert", "amount": 100}),
            timestamp: "2026-04-30T11:00:00Z".to_string(),
        };
        let entry = ws_event_to_entry(&event);
        assert!(entry.message.contains("alert"));
        assert!(entry.message.contains("100"));
    }

    // Port 1 is reserved and never listened on, so both background tasks hit
    // their connection-failure paths fast and deterministically. The REST
    // poller still emits a (degraded) StatusUpdate even when the gateway is
    // unreachable; the WS listener emits WsDisconnected when the connect fails.
    const DEAD_URL: &str = "http://127.0.0.1:1";

    #[tokio::test]
    async fn rest_poller_emits_status_update_even_when_gateway_unreachable() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_rest_poller(DEAD_URL, tx);
        let msg = rx.recv().await.expect("poller must emit at least one message");
        assert!(matches!(msg, FeedMessage::StatusUpdate { .. }));
        // Dropping rx makes the next send fail, breaking the poller loop.
        drop(rx);
    }

    #[tokio::test]
    async fn ws_listener_emits_disconnected_on_connect_failure() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        spawn_ws_listener(DEAD_URL, tx);
        let msg = rx.recv().await.expect("ws listener must report disconnect");
        assert!(matches!(msg, FeedMessage::WsDisconnected));
    }
}
