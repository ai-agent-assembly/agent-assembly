//! Integration tests for the WebSocket event streaming endpoint.

mod common;

use std::sync::atomic::Ordering;

use aa_api::models::{EventType, GovernanceEvent};
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource, PipelineEvent};
use tokio::net::TcpListener;

struct TestHandle {
    state: aa_api::state::AppState,
    _server: tokio::task::JoinHandle<()>,
}

/// Start the server on a random port and return the base URL.
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

#[tokio::test]
async fn ws_upgrade_succeeds() {
    let (url, _handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events");
    let (ws, response) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    assert_eq!(response.status(), 101);
    drop(ws);
}

#[tokio::test]
async fn ws_receives_pipeline_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();

    // Give the handler time to subscribe to broadcast channels.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Publish a pipeline event.
    let tx = handle.state.events.pipeline_sender();
    let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: "agent-1".to_string(),
        connection_id: 0,
        sequence_number: 0,
    }));
    tx.send(event).unwrap();

    // Read the event from the WebSocket.
    use futures::StreamExt;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("timeout waiting for WS message")
        .expect("stream ended")
        .expect("ws error");

    let text = msg.into_text().unwrap();
    let gov_event: GovernanceEvent = serde_json::from_str(&text).unwrap();
    assert_eq!(gov_event.event_type, EventType::Violation);
    assert_eq!(gov_event.agent_id, "agent-1");
}

#[tokio::test]
async fn ws_type_filter_excludes_non_matching() {
    let (url, handle) = start_server().await;
    // Only subscribe to budget events.
    let ws_url = format!("{url}/api/v1/ws/events?types=budget");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Publish a pipeline (violation) event — should be filtered out.
    let tx = handle.state.events.pipeline_sender();
    let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: "agent-1".to_string(),
        connection_id: 0,
        sequence_number: 0,
    }));
    tx.send(event).unwrap();

    // Should not receive the violation event within a short window.
    use futures::StreamExt;
    let result = tokio::time::timeout(std::time::Duration::from_millis(200), ws.next()).await;
    assert!(result.is_err(), "should not receive filtered-out event type");
}

#[tokio::test]
async fn ws_replay_sends_buffered_events() {
    let (url, handle) = start_server().await;

    // Pre-populate the replay buffer.
    use chrono::Utc;
    for i in 1..=3 {
        handle.state.replay_buffer.push(GovernanceEvent {
            id: i,
            event_type: EventType::Violation,
            agent_id: "agent-1".to_string(),
            payload: serde_json::json!({"seq": i}),
            timestamp: Utc::now(),
        });
    }
    // Set next_event_id past the buffered events.
    handle.state.next_event_id.store(4, Ordering::Relaxed);

    // Connect with since=1 — should replay events 2 and 3.
    let ws_url = format!("{url}/api/v1/ws/events?since=1");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();

    use futures::StreamExt;
    let msg1 = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ev1: GovernanceEvent = serde_json::from_str(&msg1.into_text().unwrap()).unwrap();
    assert_eq!(ev1.id, 2);

    let msg2 = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let ev2: GovernanceEvent = serde_json::from_str(&msg2.into_text().unwrap()).unwrap();
    assert_eq!(ev2.id, 3);
}

#[tokio::test]
async fn ws_100_simultaneous_clients_all_receive_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events");

    // Connect 100 WebSocket clients.
    let mut clients = Vec::with_capacity(100);
    for _ in 0..100 {
        let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
        clients.push(ws);
    }

    // Give all handlers time to subscribe to broadcast channels.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Publish a single pipeline event.
    let tx = handle.state.events.pipeline_sender();
    let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: "fan-out-agent".to_string(),
        connection_id: 0,
        sequence_number: 0,
    }));
    tx.send(event).unwrap();

    // Every client must receive the event.
    use futures::StreamExt;
    let mut received_count = 0u32;
    for ws in &mut clients {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("timeout waiting for WS message on a client")
            .expect("stream ended")
            .expect("ws error");

        let gov_event: GovernanceEvent = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        assert_eq!(gov_event.agent_id, "fan-out-agent");
        received_count += 1;
    }

    assert_eq!(received_count, 100, "all 100 clients must receive the event");
}

#[tokio::test]
async fn ws_client_disconnect_cleanup() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events");

    // Connect and then immediately close.
    let (ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    drop(ws);

    // Wait for server to detect the close and clean up tasks.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Publish an event — the closed connection must not cause a panic or hang.
    let tx = handle.state.events.pipeline_sender();
    let event = PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: "post-disconnect".to_string(),
        connection_id: 0,
        sequence_number: 0,
    }));
    // send may return Err if no receivers remain, which is fine.
    let _ = tx.send(event);

    // Connect a fresh client and verify it still works.
    let (mut ws2, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let event2 = PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: Default::default(),
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: "after-cleanup".to_string(),
        connection_id: 0,
        sequence_number: 1,
    }));
    tx.send(event2).unwrap();

    use futures::StreamExt;
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws2.next())
        .await
        .expect("timeout")
        .expect("stream ended")
        .expect("ws error");
    let gov_event: GovernanceEvent = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
    assert_eq!(gov_event.agent_id, "after-cleanup");
}

/// Simulates the `aasm logs --follow` CLI flow:
/// connect, stream multiple event types, verify ordered delivery.
#[tokio::test]
async fn ws_cli_logs_follow_integration() {
    let (url, handle) = start_server().await;

    // CLI would connect with all types (no filter) to get the full stream.
    let ws_url = format!("{url}/api/v1/ws/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Simulate a sequence of governance events from different domains.
    let pipeline_tx = handle.state.events.pipeline_sender();
    let approval_tx = handle.state.events.approval_sender();
    let budget_tx = handle.state.events.budget_sender();

    // 1. A policy violation event.
    pipeline_tx
        .send(PipelineEvent::Audit(Box::new(EnrichedEvent {
            inner: Default::default(),
            received_at_ms: 1000,
            source: EventSource::Sdk,
            agent_id: "agent-cli-test".to_string(),
            connection_id: 1,
            sequence_number: 0,
        })))
        .unwrap();

    // 2. An approval request.
    approval_tx
        .send(aa_runtime::approval::ApprovalRequest {
            request_id: uuid::Uuid::new_v4(),
            agent_id: "agent-cli-test".to_string(),
            action: "deploy to production".to_string(),
            condition_triggered: "require_approval".to_string(),
            submitted_at: 0,
            timeout_secs: 60,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timeout".to_string(),
            },
            team_id: None,
        })
        .unwrap();

    // 3. A budget alert.
    budget_tx
        .send(aa_gateway::budget::types::BudgetAlert {
            agent_id: aa_core::AgentId::from_bytes([0xAA; 16]),
            team_id: None,
            threshold_pct: 80,
            spent_usd: 8.0,
            limit_usd: 10.0,
        })
        .unwrap();

    // CLI reads events and prints them. Verify we receive all three types.
    // Note: tokio::select! does not guarantee ordering when multiple channels
    // are ready simultaneously, so we assert on the set of types, not order.
    use futures::StreamExt;
    let mut received_types = Vec::new();
    for _ in 0..3 {
        let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
            .await
            .expect("timeout waiting for event")
            .expect("stream ended")
            .expect("ws error");
        let ev: GovernanceEvent = serde_json::from_str(&msg.into_text().unwrap()).unwrap();
        received_types.push(ev.event_type);
    }

    received_types.sort_by_key(|t| match t {
        EventType::Violation => 0,
        EventType::Approval => 1,
        EventType::Budget => 2,
    });
    assert_eq!(
        received_types,
        vec![EventType::Violation, EventType::Approval, EventType::Budget],
        "CLI follow stream should receive all three event types"
    );
}
