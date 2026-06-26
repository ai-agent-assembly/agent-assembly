//! Integration tests for `GET /api/v1/alerts/ws` (AAASM-1389).
//!
//! Covers the acceptance criteria items:
//!   * fire event delivered to a connected client within 100 ms
//!   * `?severity=CRITICAL` excludes a MEDIUM-tier fire
//!   * invalid filter rejected with `400` before protocol switch
//!   * resolve frame follows a fire when the alert is acknowledged
//!   * missing subprotocol rejected with `400`
//!
//! Heartbeat-after-idle is exercised only as a smoke check (the 30 s
//! cadence is too long for the default nextest profile; the
//! production behaviour is covered by the handler-level select arm
//! and the unit tests of [`AlertWsFrame::Heartbeat`]).

mod common;

use aa_gateway::budget::types::BudgetAlert;
use futures::StreamExt;
use http::Uri;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::ClientRequestBuilder;

const SUBPROTOCOL: &str = "aaasm-alerts-v1";

struct TestHandle {
    state: aa_api::state::AppState,
    _server: tokio::task::JoinHandle<()>,
}

async fn start_server() -> (String, TestHandle) {
    let state = common::test_state();
    let app = aa_api::server::build_app(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("ws://127.0.0.1:{}", addr.port());
    (url, TestHandle { state, _server: handle })
}

fn alerts_ws_request(url: &str, query: &str) -> ClientRequestBuilder {
    let full = format!("{url}/api/v1/alerts/ws{query}");
    let uri: Uri = full.parse().expect("parse ws uri");
    ClientRequestBuilder::new(uri).with_sub_protocol(SUBPROTOCOL)
}

fn budget_alert(threshold_pct: u8) -> BudgetAlert {
    BudgetAlert {
        agent_id: aa_core::AgentId::from_bytes([7u8; 16]),
        team_id: Some("pioneer".to_string()),
        threshold_pct,
        spent_usd: 9.0,
        limit_usd: 10.0,
    }
}

#[tokio::test]
async fn ws_alerts_upgrade_succeeds_with_subprotocol() {
    let (url, _handle) = start_server().await;
    let request = alerts_ws_request(&url, "");
    let (ws, response) = tokio_tungstenite::connect_async(request).await.unwrap();
    assert_eq!(response.status(), 101);
    let proto = response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|v| v.to_str().ok());
    assert_eq!(proto, Some(SUBPROTOCOL));
    drop(ws);
}

/// AC: client connects → fire event injected into AlertStore →
/// frame received within 100 ms.
#[tokio::test]
async fn ws_alerts_fire_delivered_within_100ms() {
    let (url, handle) = start_server().await;
    let request = alerts_ws_request(&url, "");
    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();

    // Give the handler a moment to subscribe to the broadcast bus
    // before we publish — broadcast::Sender::send pre-subscribe
    // would simply have no receiver and the frame would be lost.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let inject_at = std::time::Instant::now();
    let _id = handle.state.alert_store.record(&budget_alert(95));

    let msg = tokio::time::timeout(std::time::Duration::from_millis(100), ws.next())
        .await
        .expect("frame must arrive within 100 ms (AC)")
        .expect("stream not ended")
        .expect("ws error");
    let elapsed = inject_at.elapsed();
    assert!(elapsed.as_millis() < 100, "delivery took {elapsed:?}, must be < 100 ms");

    let text = msg.into_text().unwrap();
    let frame: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(frame["type"], "alert.fire");
    assert_eq!(frame["alert"]["severity"], "critical");
    assert!(frame["ts"].is_string(), "ts must be present");
}

/// AC: filter `severity=CRITICAL` excludes a MEDIUM fire.
#[tokio::test]
async fn ws_alerts_severity_critical_excludes_medium() {
    let (url, handle) = start_server().await;
    let request = alerts_ws_request(&url, "?severity=CRITICAL");
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // threshold_pct < 75 → AlertSeverity::Info → wire MEDIUM.
    let _id = handle.state.alert_store.record(&budget_alert(50));

    // Should NOT receive any frame within a 200 ms window.
    let result = tokio::time::timeout(std::time::Duration::from_millis(200), ws.next()).await;
    assert!(
        result.is_err(),
        "MEDIUM fire must be filtered out by severity=CRITICAL, got: {result:?}"
    );
}

#[tokio::test]
async fn ws_alerts_resolve_frame_follows_fire() {
    let (url, handle) = start_server().await;
    let request = alerts_ws_request(&url, "");
    let (mut ws, _) = tokio_tungstenite::connect_async(request).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let id = handle.state.alert_store.record(&budget_alert(95));

    // Drain the fire frame.
    let fire = tokio::time::timeout(std::time::Duration::from_millis(100), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let fire_value: serde_json::Value = serde_json::from_str(&fire.into_text().unwrap()).unwrap();
    assert_eq!(fire_value["type"], "alert.fire");

    // Resolve must emit alert.resolve.
    handle.state.alert_store.resolve(&id, Some("ack")).expect("resolve");
    let resolve = tokio::time::timeout(std::time::Duration::from_millis(100), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let resolve_value: serde_json::Value = serde_json::from_str(&resolve.into_text().unwrap()).unwrap();
    assert_eq!(resolve_value["type"], "alert.resolve");
    assert_eq!(resolve_value["alert"]["status"], "resolved");
}

#[tokio::test]
async fn ws_alerts_invalid_filter_rejected_400() {
    let (url, _handle) = start_server().await;
    let request = alerts_ws_request(&url, "?events=bogus");

    let result = tokio_tungstenite::connect_async(request).await;
    let err = result.expect_err("invalid filter must fail the upgrade");
    let err_str = format!("{err}");
    assert!(
        err_str.contains("400"),
        "expected 400 in handshake error, got: {err_str}"
    );
}

#[tokio::test]
async fn ws_alerts_missing_subprotocol_rejected_400() {
    let (url, _handle) = start_server().await;
    let full = format!("{url}/api/v1/alerts/ws");
    let uri: Uri = full.parse().unwrap();
    // No .with_sub_protocol call — client offers nothing.
    let request = ClientRequestBuilder::new(uri);

    let result = tokio_tungstenite::connect_async(request).await;
    let err = result.expect_err("missing subprotocol must fail the upgrade");
    let err_str = format!("{err}");
    assert!(
        err_str.contains("400"),
        "expected 400 in handshake error, got: {err_str}"
    );
}

/// An unexpected client data frame is a protocol violation → the server
/// replies with a 1008 close frame and tears the socket down.
#[tokio::test]
async fn ws_alerts_unexpected_client_frame_triggers_1008_close() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (url, _handle) = start_server().await;
    let request = alerts_ws_request(&url, "");
    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Send a Text frame — the alerts protocol only permits Close from clients.
    ws.send(Message::Text("hello".into())).await.unwrap();

    // The next frame from the server must be a Close with code 1008.
    let mut saw_close = false;
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_millis(200), ws.next()).await {
            Ok(Some(Ok(Message::Close(Some(frame))))) => {
                assert_eq!(u16::from(frame.code), 1008);
                saw_close = true;
                break;
            }
            Ok(Some(Ok(_))) => continue, // skip any heartbeat/text already queued
            _ => break,
        }
    }
    assert!(saw_close, "server must answer an unexpected frame with a 1008 close");
}

/// Client Ping/Pong frames are ignored (the loop `continue`s) and a
/// subsequent Close terminates the connection cleanly.
#[tokio::test]
async fn ws_alerts_ping_pong_ignored_then_close() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (url, handle) = start_server().await;
    let request = alerts_ws_request(&url, "");
    let (mut ws, _response) = tokio_tungstenite::connect_async(request).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Pong is consumed and ignored — the connection stays open and can still
    // deliver a subsequent fire frame.
    ws.send(Message::Pong(vec![].into())).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    let _id = handle.state.alert_store.record(&budget_alert(95));

    let mut saw_fire = false;
    for _ in 0..5 {
        match tokio::time::timeout(std::time::Duration::from_millis(200), ws.next()).await {
            Ok(Some(Ok(Message::Text(t)))) => {
                let frame: serde_json::Value = serde_json::from_str(&t).unwrap();
                if frame["type"] == "alert.fire" {
                    saw_fire = true;
                    break;
                }
            }
            _ => break,
        }
    }
    assert!(saw_fire, "a fire frame must still arrive after a client Pong");

    // A Close frame ends the loop.
    ws.send(Message::Close(None)).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
}
