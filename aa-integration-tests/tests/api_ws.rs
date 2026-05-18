#![allow(unused_imports)]
//! AAASM-1497 / F122 ST-P — live-gateway integration tests for `GET /api/v1/ws/events`.
//!
//! ## Endpoint under test
//!
//! `GET /api/v1/ws/events` — WebSocket upgrade endpoint that streams `GovernanceEvent`
//! JSON text frames from the gateway's `EventBroadcast` channel. Supports replay
//! via `?since=<id>` and type filtering via `?types=<csv>`.
//!
//! ## Divergences from the ticket AC
//!
//! | Ticket expectation | Actual behaviour |
//! |---|---|
//! | Filter param `event_types=` | Actual param is `types=` (from `WsQueryParams`) |
//! | `?types=garbage` → 400 | 101 upgrade + silent empty stream; `EventType::parse_filter` drops unknowns |
//! | `AuthMode::ApiKey` variant | Auth mode is `AuthMode::On`; `start_with_auth` already exists |
//! | Replay buffer capacity unspecified | Confirmed 1000 events (circular, oldest dropped) |

mod common;

use std::time::Duration;

use aa_api::models::{EventType, GovernanceEvent};
use aa_core::{AgentId, PolicyResult};
use aa_gateway::budget::types::BudgetAlert;
use aa_runtime::approval::ApprovalRequest;
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource, PipelineEvent};
use chrono::Utc;
use common::TopologyTestEnv;
use futures::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use uuid::Uuid;

/// Read the next WebSocket text frame and deserialise it as a `GovernanceEvent`.
/// Panics if the 2-second timeout expires or the frame cannot be parsed.
#[allow(dead_code)]
async fn recv_event(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
) -> GovernanceEvent {
    let msg = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timeout waiting for WS message")
        .expect("stream closed unexpectedly")
        .expect("ws error");
    serde_json::from_str(&msg.into_text().unwrap()).unwrap()
}

#[allow(dead_code)]
fn make_pipeline_event(agent_id: &str) -> PipelineEvent {
    PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: agent_id.to_string(),
        connection_id: 0,
        sequence_number: 0,
    }))
}

#[allow(dead_code)]
fn make_approval_request() -> ApprovalRequest {
    ApprovalRequest {
        request_id: Uuid::new_v4(),
        agent_id: "test-agent".into(),
        action: "test-action".into(),
        condition_triggered: "test-condition".into(),
        submitted_at: 0,
        timeout_secs: 60,
        fallback: PolicyResult::Deny {
            reason: "timeout".into(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

#[allow(dead_code)]
fn make_budget_alert() -> BudgetAlert {
    BudgetAlert {
        agent_id: AgentId::from_bytes([0u8; 16]),
        team_id: None,
        threshold_pct: 80,
        spent_usd: 8.0,
        limit_usd: 10.0,
    }
}

#[allow(dead_code)]
fn make_governance_event(id: u64) -> GovernanceEvent {
    GovernanceEvent {
        id,
        event_type: EventType::Violation,
        agent_id: "test-agent".to_string(),
        payload: serde_json::json!({}),
        timestamp: Utc::now(),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_connect_returns_101_upgrade() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    let (_ws, resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("WS connect should succeed");
    assert_eq!(resp.status(), 101, "expected 101 Switching Protocols");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_close_during_idle_returns_clean() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    drop(ws);
    // No panic means clean close.
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_malformed_upgrade_returns_400_or_426() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("http://{}/api/v1/ws/events", env.addr);

    // Plain HTTP GET without WebSocket upgrade headers.
    let resp = reqwest::get(&url).await.expect("request should complete");
    let status = resp.status().as_u16();
    assert!(
        status == 400 || status == 426,
        "expected 400 or 426 for missing WS upgrade headers, got {status}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_receives_subsequent_events() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    // Give the handler time to subscribe to the broadcast channel.
    tokio::time::sleep(Duration::from_millis(50)).await;

    env.events
        .pipeline_sender()
        .send(make_pipeline_event("agent-ws-test"))
        .unwrap();

    let event = recv_event(&mut ws).await;
    assert_eq!(event.event_type, EventType::Violation);
    assert_eq!(event.agent_id, "agent-ws-test");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_multiple_concurrent_clients_each_receive_events() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    let mut clients = Vec::with_capacity(3);
    for _ in 0..3 {
        let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
        clients.push(ws);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;

    env.events
        .pipeline_sender()
        .send(make_pipeline_event("fan-out-agent"))
        .unwrap();

    for ws in &mut clients {
        let event = recv_event(ws).await;
        assert_eq!(event.agent_id, "fan-out-agent");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_event_types_filter_only_delivers_matching() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    // Only subscribe to approval events.
    let url = format!("ws://{}/api/v1/ws/events?types=approval", env.addr);

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Publish a violation (should be filtered out).
    env.events
        .pipeline_sender()
        .send(make_pipeline_event("filter-agent"))
        .unwrap();

    // Publish an approval (should be delivered).
    env.events.approval_sender().send(make_approval_request()).unwrap();

    // Must receive the approval event, not the violation.
    let event = recv_event(&mut ws).await;
    assert_eq!(
        event.event_type,
        EventType::Approval,
        "only approval events should be delivered when types=approval"
    );
}

/// Documents live behaviour: unknown `types` values are silently dropped by
/// `EventType::parse_filter`, so the filter list is empty → no events delivered.
/// Connection still upgrades successfully (101); this is not a 400.
#[tokio::test(flavor = "multi_thread")]
async fn ws_event_types_unknown_value_delivers_nothing() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events?types=garbage", env.addr);

    let (mut ws, resp) = tokio_tungstenite::connect_async(&url).await.unwrap();
    assert_eq!(resp.status(), 101, "unknown types value should still upgrade");
    tokio::time::sleep(Duration::from_millis(50)).await;

    env.events
        .pipeline_sender()
        .send(make_pipeline_event("filter-agent"))
        .unwrap();

    // Nothing should be delivered within a short window.
    let result = tokio::time::timeout(Duration::from_millis(300), ws.next()).await;
    assert!(
        result.is_err(),
        "unknown types filter should result in no events delivered"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_no_filter_delivers_all_event_types() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    env.events
        .pipeline_sender()
        .send(make_pipeline_event("all-types-agent"))
        .unwrap();
    env.events.approval_sender().send(make_approval_request()).unwrap();
    env.events.budget_sender().send(make_budget_alert()).unwrap();

    let mut received_types = Vec::new();
    for _ in 0..3 {
        let event = recv_event(&mut ws).await;
        received_types.push(event.event_type);
    }

    received_types.sort_by_key(|t| match t {
        EventType::Violation => 0,
        EventType::Approval => 1,
        EventType::Budget => 2,
    });
    assert_eq!(
        received_types,
        vec![EventType::Violation, EventType::Approval, EventType::Budget],
        "all three event types should be delivered when no filter is set"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_since_event_id_replays_buffered() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Seed three events directly into the replay buffer.
    for i in 1u64..=3 {
        env.replay_buffer.push(make_governance_event(i));
    }

    let url = format!("ws://{}/api/v1/ws/events?since=0", env.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let ev1 = recv_event(&mut ws).await;
    let ev2 = recv_event(&mut ws).await;
    let ev3 = recv_event(&mut ws).await;

    assert_eq!(ev1.id, 1);
    assert_eq!(ev2.id, 2);
    assert_eq!(ev3.id, 3);
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_since_future_id_starts_live_only() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Seed some events into the replay buffer.
    for i in 1u64..=3 {
        env.replay_buffer.push(make_governance_event(i));
    }

    // Connect with a since value beyond the latest buffered id — no replay.
    let url = format!("ws://{}/api/v1/ws/events?since=9999999", env.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    // No replay message should arrive.
    let no_replay = tokio::time::timeout(Duration::from_millis(200), ws.next()).await;
    assert!(
        no_replay.is_err(),
        "no buffered events should be replayed for a future since id"
    );

    // A subsequently published live event should arrive.
    env.events
        .pipeline_sender()
        .send(make_pipeline_event("live-only-agent"))
        .unwrap();

    let event = recv_event(&mut ws).await;
    assert_eq!(event.agent_id, "live-only-agent");
}

/// Replay buffer capacity is 1000 events (circular). Pushing 1001 events
/// causes the oldest (id=1) to be dropped; reconnecting with `?since=0`
/// returns 1000 events starting from id=2.
#[tokio::test(flavor = "multi_thread")]
async fn ws_replay_buffer_capacity_is_1000() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    for i in 1u64..=1001 {
        env.replay_buffer.push(make_governance_event(i));
    }

    let url = format!("ws://{}/api/v1/ws/events?since=0", env.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    let first = recv_event(&mut ws).await;
    assert_eq!(first.id, 2, "oldest event (id=1) should have been dropped");

    // Drain the rest.
    for _ in 0..998 {
        recv_event(&mut ws).await;
    }

    let last = recv_event(&mut ws).await;
    assert_eq!(last.id, 1001, "last event should be id=1001");
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_reconnect_with_last_event_id_resumes_correctly() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    env.replay_buffer.push(make_governance_event(1));
    env.replay_buffer.push(make_governance_event(2));
    env.replay_buffer.push(make_governance_event(3));

    // First connection: replay from beginning, read all three.
    let url0 = format!("ws://{}/api/v1/ws/events?since=0", env.addr);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url0).await.unwrap();
    let _ev1 = recv_event(&mut ws).await;
    let ev2 = recv_event(&mut ws).await;
    assert_eq!(ev2.id, 2);
    let ev3 = recv_event(&mut ws).await;
    assert_eq!(ev3.id, 3);
    drop(ws);

    // Reconnect from the last received id (2) — should get only id=3.
    let url2 = format!("ws://{}/api/v1/ws/events?since=2", env.addr);
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url2).await.unwrap();
    let replayed = recv_event(&mut ws2).await;
    assert_eq!(replayed.id, 3, "reconnect from since=2 should replay only id=3");

    // No further replay messages.
    let no_more = tokio::time::timeout(Duration::from_millis(200), ws2.next()).await;
    assert!(no_more.is_err(), "no further replay after the buffer is exhausted");
}

/// A slow client (client A that doesn't read) must not block event delivery to
/// other clients (client B). Tokio broadcast channels are non-blocking for the
/// sender, so lagging receivers get RecvError::Lagged rather than stalling
/// other subscribers.
#[tokio::test(flavor = "multi_thread")]
async fn ws_slow_client_does_not_block_other_clients() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    // Client A: connect but never read.
    let (_ws_a, _) = tokio_tungstenite::connect_async(&url).await.unwrap();

    // Client B: will read all events.
    let (mut ws_b, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publish 50 events.
    for i in 0..50 {
        env.events
            .pipeline_sender()
            .send(make_pipeline_event(&format!("agent-{i}")))
            .unwrap();
    }

    // Client B must receive all 50 within the timeout.
    for _ in 0..50 {
        recv_event(&mut ws_b).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn ws_publish_to_disconnected_client_does_not_panic() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let url = format!("ws://{}/api/v1/ws/events", env.addr);

    // Connect then immediately drop (abrupt disconnect).
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    drop(ws);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Publishing after disconnect must not panic the server.
    for _ in 0..10 {
        let _ = env
            .events
            .pipeline_sender()
            .send(make_pipeline_event("post-disconnect"));
    }

    // Server must still accept new connections.
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    env.events
        .pipeline_sender()
        .send(make_pipeline_event("after-cleanup"))
        .unwrap();

    let event = recv_event(&mut ws2).await;
    assert_eq!(event.agent_id, "after-cleanup");
}
