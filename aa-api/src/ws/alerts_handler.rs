//! WebSocket handler for `GET /api/v1/alerts/ws` (AAASM-1389).
//!
//! The handler:
//! 1. Authenticates the upgrade (Bearer API key) via the
//!    [`AuthenticatedCaller`] extractor.
//! 2. Requires the client to offer the `aaasm-alerts-v1`
//!    subprotocol; otherwise rejects the upgrade with `400`.
//! 3. Parses the optional `events` / `severity` / `agent_id` filter
//!    via [`AlertsWsQueryParams::try_into_filter`]; rejects with
//!    `400` on invalid values.
//! 4. Subscribes to the [`AlertStore`] event bus and forwards each
//!    matching event as an [`AlertWsFrame`].
//! 5. Emits a `heartbeat` frame every 30 s when no other frame was
//!    sent in that window.
//! 6. On `broadcast::error::RecvError::Lagged`, logs a `lag` warn
//!    record tagged with the connection id (AC backpressure item).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{CloseFrame, Message, WebSocket};
use axum::extract::{Query, WebSocketUpgrade};
use axum::http::header::SEC_WEBSOCKET_PROTOCOL;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Extension;
use futures::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use crate::alerts::{AlertEvent, AlertStore};
use crate::auth::AuthenticatedCaller;
use crate::error::ProblemDetail;
use crate::models::alert_ws_payloads::AlertWsFrame;
use crate::routes::alerts::alert_response_from_stored;
use crate::state::AppState;
use crate::ws::alerts_params::{AlertsFilter, AlertsWsQueryParams};

/// Required client-offered WebSocket subprotocol.
pub const SUBPROTOCOL: &str = "aaasm-alerts-v1";

/// Interval between server-initiated heartbeat frames when otherwise idle.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(30);

/// Per-process monotonic connection id used in the `lag` log entry so
/// operators can correlate a backpressure warn record with a specific
/// dashboard client session.
static NEXT_CONNECTION_ID: AtomicU64 = AtomicU64::new(1);

/// `GET /api/v1/alerts/ws` — upgrade to a WebSocket and stream
/// real-time alert lifecycle events.
///
/// **Subprotocol**: clients MUST offer `aaasm-alerts-v1` in the
/// `Sec-WebSocket-Protocol` upgrade header. Upgrades without it are
/// rejected with `400` before protocol switch. The committed
/// `openapi/v1.yaml` carries this as `x-ws-subprotocol:
/// aaasm-alerts-v1` on the path object.
#[utoipa::path(
    get,
    path = "/api/v1/alerts/ws",
    params(AlertsWsQueryParams),
    responses(
        (status = 101, description = "WebSocket upgrade successful. Server streams AlertWsFrame JSON text frames."),
        (status = 200, description = "Frame schema (delivered as WebSocket text frames, not as an HTTP response body).", body = AlertWsFrame),
        (status = 400, description = "Bad request — missing subprotocol or invalid filter query parameter")
    ),
    tag = "alerts-stream"
)]
pub async fn ws_alerts_handler(
    _caller: AuthenticatedCaller,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
    Query(params): Query<AlertsWsQueryParams>,
    Extension(state): Extension<AppState>,
) -> Response {
    if !client_offered_subprotocol(&headers, SUBPROTOCOL) {
        return ProblemDetail::from_status(StatusCode::BAD_REQUEST)
            .with_detail(format!(
                "WebSocket upgrade requires Sec-WebSocket-Protocol: {SUBPROTOCOL}"
            ))
            .into_response();
    }

    let filter = match params.try_into_filter() {
        Ok(f) => f,
        Err(err) => return err.into_response(),
    };

    let conn_id = NEXT_CONNECTION_ID.fetch_add(1, Ordering::Relaxed);
    let alert_store = state.alert_store.clone();
    ws.protocols([SUBPROTOCOL])
        .on_upgrade(move |socket| run_alerts_socket(socket, filter, alert_store, conn_id))
        .into_response()
}

/// Did the client offer the given subprotocol in its
/// `Sec-WebSocket-Protocol` request header?
fn client_offered_subprotocol(headers: &HeaderMap, wanted: &str) -> bool {
    headers
        .get_all(SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .any(|p| p.trim().eq_ignore_ascii_case(wanted))
}

/// Drive a single WebSocket connection: subscribe to the alert bus,
/// forward filtered events, send periodic heartbeats, and close on
/// client disconnect or unexpected client frame.
async fn run_alerts_socket(socket: WebSocket, filter: AlertsFilter, alert_store: Arc<dyn AlertStore>, conn_id: u64) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = alert_store.subscribe();

    let mut heartbeat = tokio::time::interval(HEARTBEAT_INTERVAL);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Drop the immediate first tick — heartbeats should fire only
    // after a real idle interval has elapsed.
    heartbeat.tick().await;

    loop {
        tokio::select! {
            biased;

            // Client → server: only Close is expected for MVP. Any
            // other frame is a policy violation (AC) and triggers a
            // 1008 close.
            client_msg = receiver.next() => {
                match client_msg {
                    None => break,
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                    Some(Ok(_)) => {
                        let _ = sender
                            .send(Message::Close(Some(CloseFrame {
                                code: 1008,
                                reason: "unexpected client frame".into(),
                            })))
                            .await;
                        break;
                    }
                    Some(Err(_)) => break,
                }
            }

            // Server → client: alert event from the broadcast bus.
            event_result = rx.recv() => {
                match event_result {
                    Ok(event) => {
                        if !filter.matches(&event) {
                            continue;
                        }
                        let frame = build_frame(&event);
                        let Ok(json) = serde_json::to_string(&frame) else { continue };
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                        // A real frame was just sent — push the next
                        // heartbeat 30 s out from now.
                        heartbeat.reset();
                    }
                    Err(broadcast::error::RecvError::Lagged(count)) => {
                        // AC: backpressure drop emits a `lag` log
                        // entry tagged with the connection id.
                        tracing::warn!(
                            connection_id = conn_id,
                            dropped = count,
                            "ws_alerts lag — broadcast receiver lagged behind"
                        );
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }

            // Server → client: idle heartbeat.
            _ = heartbeat.tick() => {
                let frame = AlertWsFrame::Heartbeat {
                    ts: chrono::Utc::now().to_rfc3339(),
                };
                let Ok(json) = serde_json::to_string(&frame) else { continue };
                if sender.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// Convert a runtime [`AlertEvent`] into the wire-frame schema. The
/// `ts` field is filled with the current server time per AC.
fn build_frame(event: &AlertEvent) -> AlertWsFrame {
    let ts = chrono::Utc::now().to_rfc3339();
    match event {
        AlertEvent::Fire(stored) => AlertWsFrame::Fire {
            ts,
            alert: alert_response_from_stored(stored.clone()),
        },
        AlertEvent::Resolve(stored) => AlertWsFrame::Resolve {
            ts,
            alert: alert_response_from_stored(stored.clone()),
        },
        AlertEvent::Silence(stored) => AlertWsFrame::Silence {
            ts,
            alert: alert_response_from_stored(stored.clone()),
            silence: serde_json::Value::Null,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_map_with(header: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(SEC_WEBSOCKET_PROTOCOL, header.parse().unwrap());
        h
    }

    #[test]
    fn subprotocol_match_exact() {
        let h = header_map_with("aaasm-alerts-v1");
        assert!(client_offered_subprotocol(&h, SUBPROTOCOL));
    }

    #[test]
    fn subprotocol_match_in_csv_list() {
        let h = header_map_with("graphql-ws, aaasm-alerts-v1, other");
        assert!(client_offered_subprotocol(&h, SUBPROTOCOL));
    }

    #[test]
    fn subprotocol_case_insensitive() {
        let h = header_map_with("AAASM-Alerts-V1");
        assert!(client_offered_subprotocol(&h, SUBPROTOCOL));
    }

    #[test]
    fn subprotocol_missing_rejected() {
        let h = HeaderMap::new();
        assert!(!client_offered_subprotocol(&h, SUBPROTOCOL));
    }

    #[test]
    fn subprotocol_wrong_value_rejected() {
        let h = header_map_with("aaasm-alerts-v2");
        assert!(!client_offered_subprotocol(&h, SUBPROTOCOL));
    }
}
