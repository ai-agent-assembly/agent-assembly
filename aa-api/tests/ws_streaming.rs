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
        observed_sdk_identity: Default::default(),
        tamper: None,
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
        observed_sdk_identity: Default::default(),
        tamper: None,
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
            team_id: None,
            org_id: None,
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
        observed_sdk_identity: Default::default(),
        tamper: None,
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
        observed_sdk_identity: Default::default(),
        tamper: None,
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
        observed_sdk_identity: Default::default(),
        tamper: None,
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
            observed_sdk_identity: Default::default(),
            tamper: None,
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
            timeout_override_secs: None,
            escalation_role_override: None,
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
        EventType::OpsChange => 3,
    });
    assert_eq!(
        received_types,
        vec![EventType::Violation, EventType::Approval, EventType::Budget],
        "CLI follow stream should receive all three event types"
    );
}

// ── Non-pipeline dispatch arms: approval / budget / ops-change ───────────────

fn make_approval_request() -> aa_runtime::approval::ApprovalRequest {
    aa_runtime::approval::ApprovalRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_id: "approver-agent".to_string(),
        action: "read_file /etc/shadow".to_string(),
        condition_triggered: "sensitive-file".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 600,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timeout".to_string(),
        },
        team_id: None,
        timeout_override_secs: None,
        escalation_role_override: None,
    }
}

async fn read_gov_event(
    ws: &mut (impl futures::StreamExt<
        Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    > + Unpin),
) -> GovernanceEvent {
    let msg = tokio::time::timeout(std::time::Duration::from_secs(2), ws.next())
        .await
        .expect("timeout waiting for WS message")
        .expect("stream ended")
        .expect("ws error");
    serde_json::from_str(&msg.into_text().unwrap()).unwrap()
}

#[tokio::test]
async fn ws_receives_approval_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events?types=approval");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handle
        .state
        .events
        .approval_sender()
        .send(make_approval_request())
        .unwrap();

    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Approval);
    assert_eq!(ev.agent_id, "approver-agent");
}

#[tokio::test]
async fn ws_receives_approval_expiry_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events?types=approval");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handle
        .state
        .events
        .approval_expiry_sender()
        .send(make_approval_request())
        .unwrap();

    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Approval);
    // The expiry arm marks the payload status as "expired".
    assert_eq!(ev.payload["status"], "expired");
}

#[tokio::test]
async fn ws_receives_budget_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events?types=budget");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handle
        .state
        .events
        .budget_sender()
        .send(aa_gateway::budget::types::BudgetAlert {
            agent_id: aa_core::identity::AgentId::from_bytes([7u8; 16]),
            team_id: Some("team-a".to_string()),
            threshold_pct: 95,
            spent_usd: 95.0,
            limit_usd: 100.0,
        })
        .unwrap();

    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Budget);
}

#[tokio::test]
async fn ws_receives_ops_change_event() {
    let (url, handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events?types=ops_change");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handle
        .state
        .events
        .ops_change_sender()
        .send(aa_api::events::OpsChangeBroadcast {
            agent_id: "ops-agent".to_string(),
            payload: aa_api::models::ws_payloads::OpsChangePayload {
                op_id: "trace-1:span-1".to_string(),
                state: aa_api::ops::OpState::Running,
                updated_at: "2026-06-25T00:00:00Z".to_string(),
            },
        })
        .unwrap();

    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::OpsChange);
    assert_eq!(ev.agent_id, "ops-agent");
    assert_eq!(ev.payload["op_id"], "trace-1:span-1");
}

// ── AAASM-3980: tenant isolation of the event stream ─────────────────────────

use aa_api::auth::config::AuthMode;
use aa_api::auth::scope::Scope;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// Start a server with auth enabled (JWT via the shared test secret) so tenant
/// isolation can be exercised with real team/admin bearer tokens.
async fn start_auth_server() -> (String, TestHandle) {
    let state = common::test_state_with_auth(AuthMode::On, &[], 1000);
    let app = aa_api::server::build_app(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let url = format!("ws://127.0.0.1:{}", addr.port());
    (url, TestHandle { state, _server: handle })
}

/// Build a WebSocket handshake request carrying `Authorization: Bearer <token>`.
fn ws_request(url: &str, token: &str) -> tokio_tungstenite::tungstenite::handshake::client::Request {
    let mut req = url.into_client_request().expect("valid ws url");
    req.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::AUTHORIZATION,
        format!("Bearer {token}").parse().unwrap(),
    );
    req
}

/// Assert the socket yields no frame within a short idle window.
async fn assert_no_event(
    ws: &mut (impl futures::StreamExt<
        Item = Result<tokio_tungstenite::tungstenite::Message, tokio_tungstenite::tungstenite::Error>,
    > + Unpin),
) {
    // `next()` comes from the `StreamExt` bound on the parameter.
    let res = tokio::time::timeout(std::time::Duration::from_millis(250), ws.next()).await;
    assert!(res.is_err(), "expected no cross-tenant frame, got one");
}

fn budget_alert(team: &str, agent_byte: u8) -> aa_gateway::budget::types::BudgetAlert {
    aa_gateway::budget::types::BudgetAlert {
        agent_id: aa_core::identity::AgentId::from_bytes([agent_byte; 16]),
        team_id: Some(team.to_string()),
        threshold_pct: 95,
        spent_usd: 95.0,
        limit_usd: 100.0,
    }
}

fn pipeline_for_team(team: &str, agent_id: &str) -> PipelineEvent {
    PipelineEvent::Audit(Box::new(EnrichedEvent {
        inner: aa_proto::assembly::audit::v1::AuditEvent {
            team_id: team.to_string(),
            ..Default::default()
        },
        received_at_ms: 0,
        source: EventSource::Sdk,
        agent_id: agent_id.to_string(),
        connection_id: 0,
        sequence_number: 0,
        observed_sdk_identity: Default::default(),
        tamper: None,
    }))
}

#[tokio::test]
async fn ws_budget_stream_blocks_cross_tenant_and_allows_own_team() {
    let (url, handle) = start_auth_server().await;
    let token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ws_url = format!("{url}/api/v1/ws/events?types=budget");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let tx = handle.state.events.budget_sender();
    // A team-b alert must never reach the team-a caller.
    tx.send(budget_alert("team-b", 0xBB)).unwrap();
    assert_no_event(&mut ws).await;

    // The caller's own team-a alert is delivered.
    tx.send(budget_alert("team-a", 0xAA)).unwrap();
    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Budget);
}

#[tokio::test]
async fn ws_admin_receives_every_tenant_budget() {
    let (url, handle) = start_auth_server().await;
    // Admin scope, no team tenant — must see all tenants.
    let token = common::generate_test_jwt("admin", &[Scope::Read, Scope::Admin]);
    let ws_url = format!("{url}/api/v1/ws/events?types=budget");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    handle
        .state
        .events
        .budget_sender()
        .send(budget_alert("team-b", 0xBB))
        .unwrap();
    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Budget);
}

#[tokio::test]
async fn ws_pipeline_stream_blocks_cross_tenant_and_allows_own_team() {
    let (url, handle) = start_auth_server().await;
    let token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ws_url = format!("{url}/api/v1/ws/events?types=violation");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let tx = handle.state.events.pipeline_sender();
    tx.send(pipeline_for_team("team-b", "agent-b")).unwrap();
    assert_no_event(&mut ws).await;

    tx.send(pipeline_for_team("team-a", "agent-a")).unwrap();
    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Violation);
}

#[tokio::test]
async fn ws_approval_stream_blocks_cross_tenant() {
    let (url, handle) = start_auth_server().await;
    let token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ws_url = format!("{url}/api/v1/ws/events?types=approval");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut req = make_approval_request();
    req.team_id = Some("team-b".to_string());
    handle.state.events.approval_sender().send(req).unwrap();
    assert_no_event(&mut ws).await;

    let mut own = make_approval_request();
    own.team_id = Some("team-a".to_string());
    handle.state.events.approval_sender().send(own).unwrap();
    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.event_type, EventType::Approval);
}

#[tokio::test]
async fn ws_ops_change_is_admin_only_when_tenant_unresolvable() {
    // The ops-change envelope carries no tenant and its agent is not in the
    // registry, so it is fail-closed to admins. A team-scoped caller sees
    // nothing; an admin sees it.
    let (url, handle) = start_auth_server().await;
    let ops = || aa_api::events::OpsChangeBroadcast {
        agent_id: "ops-agent".to_string(),
        payload: aa_api::models::ws_payloads::OpsChangePayload {
            op_id: "trace-1:span-1".to_string(),
            state: aa_api::ops::OpState::Running,
            updated_at: "2026-06-25T00:00:00Z".to_string(),
        },
    };

    let team_token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ws_url = format!("{url}/api/v1/ws/events?types=ops_change");
    let (mut team_ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &team_token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.state.events.ops_change_sender().send(ops()).unwrap();
    assert_no_event(&mut team_ws).await;

    let admin_token = common::generate_test_jwt("admin", &[Scope::Read, Scope::Admin]);
    let (mut admin_ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &admin_token))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    handle.state.events.ops_change_sender().send(ops()).unwrap();
    let ev = read_gov_event(&mut admin_ws).await;
    assert_eq!(ev.event_type, EventType::OpsChange);
}

#[tokio::test]
async fn ws_replay_is_tenant_isolated() {
    use chrono::Utc;
    let (url, handle) = start_auth_server().await;

    // Buffer one team-b and one team-a event. The tenant tags live on the
    // server-only fields, mirroring what the live dispatch path stamps.
    handle.state.replay_buffer.push(GovernanceEvent {
        id: 1,
        event_type: EventType::Violation,
        agent_id: "agent-b".to_string(),
        payload: serde_json::json!({"seq": 1}),
        timestamp: Utc::now(),
        team_id: Some("team-b".to_string()),
        org_id: None,
    });
    handle.state.replay_buffer.push(GovernanceEvent {
        id: 2,
        event_type: EventType::Violation,
        agent_id: "agent-a".to_string(),
        payload: serde_json::json!({"seq": 2}),
        timestamp: Utc::now(),
        team_id: Some("team-a".to_string()),
        org_id: None,
    });
    handle.state.next_event_id.store(3, Ordering::Relaxed);

    // team-a caller replays from the start: only its own event 2 comes through;
    // team-b's event 1 is dropped by the replay-path tenant gate.
    let token = common::generate_test_jwt_for_team("key-a", &[Scope::Read], "team-a");
    let ws_url = format!("{url}/api/v1/ws/events?since=0");
    let (mut ws, _) = tokio_tungstenite::connect_async(ws_request(&ws_url, &token))
        .await
        .unwrap();

    let ev = read_gov_event(&mut ws).await;
    assert_eq!(ev.id, 2, "team-a caller must only replay its own team's event");
    assert_no_event(&mut ws).await;
}

#[tokio::test]
async fn ws_handles_client_pong_then_close_frame() {
    use futures::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (url, _handle) = start_server().await;
    let ws_url = format!("{url}/api/v1/ws/events");
    let (mut ws, _) = tokio_tungstenite::connect_async(&ws_url).await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // A client Pong is consumed by the reader loop (keep-alive bookkeeping).
    ws.send(Message::Pong(vec![].into())).await.unwrap();
    // A client Close frame terminates the reader loop cleanly.
    ws.send(Message::Close(None)).await.unwrap();

    // The server acknowledges the close; the stream then ends without error.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
}
