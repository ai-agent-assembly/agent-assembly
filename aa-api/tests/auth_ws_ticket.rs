//! Integration tests for the WebSocket ticket auth flow (AAASM-4861).
//!
//! A browser can't set an `Authorization` header on a WS handshake, so the
//! dashboard mints a short-lived, single-use ticket over REST
//! (`POST /api/v1/auth/ws-ticket`) and presents it as `?ticket=` on the upgrade.
//! These tests exercise the mint endpoint and the ticket→upgrade flow end to end
//! against a live server, plus the negative cases the security decision requires:
//! unauth mint rejected, single-use / replay, wrong-purpose, malformed, the
//! ticket being useless as a REST credential, and the header fallback still
//! working for non-browser clients.

mod common;

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use futures::StreamExt;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tower::ServiceExt;

/// A live server bound to a random port, exposing both the HTTP mint endpoint
/// and the WS upgrade handlers over the same `AppState`.
struct Live {
    port: u16,
    state: aa_api::state::AppState,
    _server: tokio::task::JoinHandle<()>,
}

async fn start_live() -> Live {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::server::build_app(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    Live {
        port,
        state,
        _server: server,
    }
}

/// Mint a ticket via the authenticated REST endpoint and return the raw response.
async fn mint(port: u16, bearer: &str, purpose: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/api/v1/auth/ws-ticket"))
        .bearer_auth(bearer)
        .json(&serde_json::json!({ "purpose": purpose }))
        .send()
        .await
        .unwrap()
}

/// Mint and extract just the opaque ticket string.
async fn mint_ticket(port: u16, bearer: &str, purpose: &str) -> String {
    let body: serde_json::Value = mint(port, bearer, purpose).await.json().await.unwrap();
    body["ticket"].as_str().expect("ticket in response").to_string()
}

/// A WS handshake request carrying a `Sec-WebSocket-Protocol` (needed by the
/// alerts stream) plus, optionally, an `Authorization` header.
fn ws_request(
    url: &str,
    subprotocol: Option<&str>,
    bearer: Option<&str>,
) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = url.into_client_request().expect("valid ws url");
    if let Some(sp) = subprotocol {
        req.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL,
            sp.parse().unwrap(),
        );
    }
    if let Some(token) = bearer {
        req.headers_mut().insert(
            tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
    }
    req
}

// --- Mint endpoint ----------------------------------------------------------

#[tokio::test]
async fn mint_requires_authentication() {
    // The mint endpoint is on the protected router: no bearer → 401, before any
    // ticket is created.
    let app = common::test_app_with_auth(&[], 1000);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/ws-ticket")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"purpose":"events"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mint_returns_opaque_single_use_ticket() {
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let response = mint(live.port, &token, "events").await;
    assert_eq!(response.status(), 200);

    let body: serde_json::Value = response.json().await.unwrap();
    let ticket = body["ticket"].as_str().unwrap();
    assert!(ticket.starts_with("wst_"), "ticket is opaque, wst_-prefixed");
    assert_eq!(body["purpose"], "events", "response echoes the requested purpose");
    assert!(body["expires_at"].as_u64().unwrap() > 0, "carries an absolute expiry");
    // The long-lived JWT must never appear inside the ticket.
    assert!(!ticket.contains(&token), "ticket must not embed the session token");
}

#[tokio::test]
async fn ws_ticket_is_not_valid_for_rest_auth() {
    // A ticket is only accepted by the WS upgrade. Presented as a Bearer to a
    // protected REST route it fails validation (it is neither an aa_ key nor a
    // JWT), so it cannot be escalated into a REST credential.
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let ticket = mint_ticket(live.port, &token, "events").await;

    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{}/api/v1/agents", live.port))
        .bearer_auth(&ticket)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401, "a WS ticket must not authenticate a REST call");
}

// --- Ticket → upgrade -------------------------------------------------------

#[tokio::test]
async fn valid_ticket_opens_events_stream() {
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let ticket = mint_ticket(live.port, &token, "events").await;

    let url = format!("ws://127.0.0.1:{}/api/v1/ws/events?ticket={ticket}", live.port);
    let (ws, response) = tokio_tungstenite::connect_async(&url).await.expect("upgrade succeeds");
    assert_eq!(response.status(), 101);
    drop(ws);
}

#[tokio::test]
async fn ticket_is_single_use_second_connect_is_rejected() {
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let ticket = mint_ticket(live.port, &token, "events").await;
    let url = format!("ws://127.0.0.1:{}/api/v1/ws/events?ticket={ticket}", live.port);

    let (ws1, resp1) = tokio_tungstenite::connect_async(&url).await.expect("first connect");
    assert_eq!(resp1.status(), 101);
    drop(ws1);

    // Replay the same ticket — it was atomically consumed, so this must fail.
    let replay = tokio_tungstenite::connect_async(&url).await;
    assert!(replay.is_err(), "a consumed ticket must not open a second socket");
}

#[tokio::test]
async fn events_stream_rejects_alerts_purpose_ticket() {
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    // Mint for the ALERTS stream, then try to open the EVENTS stream with it.
    let ticket = mint_ticket(live.port, &token, "alerts").await;

    let url = format!("ws://127.0.0.1:{}/api/v1/ws/events?ticket={ticket}", live.port);
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(
        result.is_err(),
        "a ticket minted for a different stream must be rejected"
    );
}

#[tokio::test]
async fn malformed_ticket_is_rejected() {
    let live = start_live().await;
    let url = format!(
        "ws://127.0.0.1:{}/api/v1/ws/events?ticket=wst_deadbeefdeadbeef",
        live.port
    );
    let result = tokio_tungstenite::connect_async(&url).await;
    assert!(result.is_err(), "an unknown ticket must be rejected");
}

#[tokio::test]
async fn header_bearer_still_opens_stream_without_ticket() {
    // Non-browser clients (CLI / tests) that CAN set the Authorization header
    // keep working with no ticket — the fallback path.
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let url = format!("ws://127.0.0.1:{}/api/v1/ws/events", live.port);
    let (ws, response) = tokio_tungstenite::connect_async(ws_request(&url, None, Some(&token)))
        .await
        .expect("header-authenticated upgrade succeeds");
    assert_eq!(response.status(), 101);
    drop(ws);
}

#[tokio::test]
async fn ticket_carries_the_minting_callers_tenant() {
    // A ticket minted by a team-a caller reconstructs a team-a caller on consume,
    // so the stream is tenant-gated to team-a — a team-b event never arrives.
    let live = start_live().await;
    let token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ticket = mint_ticket(live.port, &token, "events").await;

    let url = format!(
        "ws://127.0.0.1:{}/api/v1/ws/events?types=budget&ticket={ticket}",
        live.port
    );
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.expect("upgrade");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let tx = live.state.events.budget_sender();
    // A team-b alert must never reach the team-a caller.
    let _ = tx.send(aa_gateway::budget::types::BudgetAlert {
        agent_id: aa_core::identity::AgentId::from_bytes([2u8; 16]),
        team_id: Some("team-b".to_string()),
        threshold_pct: 95,
        spent_usd: 95.0,
        limit_usd: 100.0,
    });
    // ... but the team-a alert must.
    let _ = tx.send(aa_gateway::budget::types::BudgetAlert {
        agent_id: aa_core::identity::AgentId::from_bytes([1u8; 16]),
        team_id: Some("team-a".to_string()),
        threshold_pct: 95,
        spent_usd: 95.0,
        limit_usd: 100.0,
    });

    // The first frame the team-a caller sees must be the team-a event, proving
    // the team-b event was filtered by the ticket-derived tenant.
    let frame = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("a frame arrives")
        .expect("stream open")
        .expect("frame ok");
    let text = frame.into_text().expect("text frame");
    let event: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(
        event["payload"]["spent_usd"], 95.0,
        "the delivered frame is a budget alert"
    );
    // The agent id on the envelope is the team-a agent (all-ones), not team-b.
    assert!(
        event["agent_id"].as_str().unwrap().contains("01"),
        "only the team-a event crossed the ticket-derived tenant gate"
    );
}

// --- Alerts stream ----------------------------------------------------------

#[tokio::test]
async fn valid_ticket_opens_alerts_stream() {
    let live = start_live().await;
    let token = common::generate_test_jwt("key-a", &[Scope::Read]);
    let ticket = mint_ticket(live.port, &token, "alerts").await;

    let url = format!("ws://127.0.0.1:{}/api/v1/alerts/ws?ticket={ticket}", live.port);
    let (ws, response) = tokio_tungstenite::connect_async(ws_request(&url, Some("aaasm-alerts-v1"), None))
        .await
        .expect("alerts upgrade succeeds");
    assert_eq!(response.status(), 101);
    drop(ws);
}
