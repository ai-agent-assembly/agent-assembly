//! Integration tests for the webhook delivery pipeline.
//!
//! Spins up a minimal TCP listener as a mock webhook endpoint, triggers events
//! through the broadcast channels, and verifies that the delivery loop POSTs
//! the correct JSON envelopes.

use tokio::io::AsyncReadExt;
use tokio::sync::broadcast;

use aa_gateway::budget::BudgetAlert;
use aa_gateway::events::delivery::webhook_delivery_loop;
use aa_gateway::events::webhook::WebhookTarget;
use aa_runtime::approval::{ApprovalQueue, ApprovalRequest};

/// Read one HTTP request from a TCP listener and return the body.
async fn accept_one_request(listener: &tokio::net::TcpListener) -> String {
    let (mut stream, _addr) = listener.accept().await.unwrap();
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await.unwrap();
    let raw = String::from_utf8_lossy(&buf[..n]).to_string();

    // Send a 200 OK response so the client doesn't get a connection error.
    use tokio::io::AsyncWriteExt;
    let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    let _ = stream.write_all(response.as_bytes()).await;

    // Extract the JSON body (everything after the blank line).
    if let Some(idx) = raw.find("\r\n\r\n") {
        raw[idx + 4..].to_string()
    } else {
        String::new()
    }
}

#[tokio::test]
async fn approval_event_is_delivered_as_webhook_post() {
    // Start mock HTTP server.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/webhook");

    // Set up broadcast channels.
    let approval_queue = ApprovalQueue::new();
    let (_budget_tx, budget_rx) = broadcast::channel::<BudgetAlert>(16);

    let client = reqwest::Client::new();
    let target = WebhookTarget::new(client, url);
    let approval_rx = approval_queue.subscribe_events();

    // Spawn the delivery loop.
    let handle = tokio::spawn(webhook_delivery_loop(target, approval_rx, budget_rx));

    // Submit an approval request — this triggers the broadcast.
    let req = ApprovalRequest {
        request_id: uuid::Uuid::new_v4(),
        agent_id: "test-agent-007".to_string(),
        action: "delete /etc/shadow".to_string(),
        condition_triggered: "destructive-action".to_string(),
        submitted_at: 1_700_000_000,
        timeout_secs: 300,
        fallback: aa_core::PolicyResult::Deny {
            reason: "timed out".to_string(),
        },
        team_id: None,
    };
    let expected_agent = req.agent_id.clone();
    let (_id, _fut) = approval_queue.submit(req);

    // Accept the webhook POST.
    let body = accept_one_request(&listener).await;

    // Parse and verify the JSON envelope.
    let envelope: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");
    assert_eq!(envelope["event_type"], "approval.requested");
    assert_eq!(envelope["source"], "aa-gateway");
    assert_eq!(envelope["payload"]["approval_request"]["agent_id"], expected_agent);
    assert_eq!(
        envelope["payload"]["approval_request"]["action_summary"],
        "delete /etc/shadow"
    );

    // Verify event_id is a valid UUID v7.
    let event_id = envelope["event_id"].as_str().unwrap();
    let parsed = uuid::Uuid::parse_str(event_id).expect("valid UUID");
    assert_eq!(parsed.get_version_num(), 7);

    handle.abort();
}

#[tokio::test]
async fn budget_alert_is_delivered_as_webhook_post() {
    // Start mock HTTP server.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let url = format!("http://{addr}/webhook");

    // Set up broadcast channels.
    let approval_queue = ApprovalQueue::new();
    let (budget_tx, budget_rx) = broadcast::channel::<BudgetAlert>(16);

    let client = reqwest::Client::new();
    let target = WebhookTarget::new(client, url);
    let approval_rx = approval_queue.subscribe_events();

    // Spawn the delivery loop.
    let handle = tokio::spawn(webhook_delivery_loop(target, approval_rx, budget_rx));

    // Send a budget alert through the broadcast channel.
    let alert = BudgetAlert {
        agent_id: aa_core::AgentId::from_bytes([42; 16]),
        team_id: None,
        threshold_pct: 95,
        spent_usd: 95.0,
        limit_usd: 100.0,
    };
    budget_tx.send(alert).expect("send should succeed");

    // Accept the webhook POST.
    let body = accept_one_request(&listener).await;

    // Parse and verify the JSON envelope.
    let envelope: serde_json::Value = serde_json::from_str(&body).expect("valid JSON body");
    assert_eq!(envelope["event_type"], "budget.threshold_hit");
    assert_eq!(envelope["source"], "aa-gateway");
    assert_eq!(envelope["payload"]["budget_alert"]["current_spend"], 95.0);
    assert_eq!(envelope["payload"]["budget_alert"]["budget_limit"], 100.0);
    assert_eq!(envelope["payload"]["budget_alert"]["percent_used"], 95);

    handle.abort();
}
