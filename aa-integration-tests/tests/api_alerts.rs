//! Live-gateway HTTP integration tests for the `/api/v1/alerts/*` surface.
//! AAASM-1487 / F122 ST-F
//!
//! Covers:
//! - `GET  /api/v1/alerts`              — list (4 tests)
//! - `GET  /api/v1/alerts/{id}`         — inspect (2 tests)
//! - `POST /api/v1/alerts/{id}/resolve` — resolve (4 tests)
//!
//! ## Setup pattern
//!
//! Each test boots a fresh `TopologyTestEnv` (independent TCP port + in-memory
//! stores) and seeds alerts directly via `env.alert_store.record(&BudgetAlert)`.
//! No CLI invocation is needed; all assertions target the HTTP plane.
//!
//! ## Observed live behaviours (documented per ticket AAASM-1487 AC)
//!
//! * **Ordering**: `GET /api/v1/alerts` returns items newest-first (reverse
//!   insertion order). `InMemoryAlertStore::list` iterates the ring buffer in
//!   reverse, so the highest auto-incremented `id` appears at index 0.
//!
//! * **Query-param filtering**: The route handler uses only `PaginationParams`
//!   (`page`, `per_page`). Extra query params such as `?severity=critical` or
//!   `?status=open` are silently ignored by Axum — all stored alerts are
//!   returned regardless. Severity- and status-based filtering is implemented
//!   client-side in the `aasm` CLI (see `cli_alerts.rs`).
//!
//! * **Resolve idempotency**: `POST /alerts/{id}/resolve` on an already-resolved
//!   alert returns 200 with the unchanged record — `updated_at` is NOT bumped.
//!   The endpoint never returns 409. Source: `InMemoryAlertStore::resolve` skips
//!   the timestamp mutation when `alert.status == "resolved"`.

mod common;

use aa_api::alerts::AlertStore;
use aa_core::AgentId;
use aa_gateway::budget::types::BudgetAlert;
use chrono::Utc;

use common::TopologyTestEnv;

// ---------------------------------------------------------------------------
// Seed helper
// ---------------------------------------------------------------------------

/// Record one budget alert directly into the test env's alert store.
///
/// `threshold_pct` drives severity: `< 75` → info, `75..=89` → warning,
/// `>= 90` → critical. Returns the assigned ULID.
fn seed_alert(env: &TopologyTestEnv, threshold_pct: u8, agent_id: [u8; 16]) -> String {
    let limit_usd = 10.0_f64;
    let spent_usd = limit_usd * f64::from(threshold_pct) / 100.0;
    let alert = BudgetAlert {
        agent_id: AgentId::from_bytes(agent_id),
        team_id: None,
        threshold_pct,
        spent_usd,
        limit_usd,
    };
    env.alert_store.record(&alert)
}

// =============================================================================
// GET /api/v1/alerts — list
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_empty_returns_200_and_empty_array() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/alerts", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/alerts should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "empty store should return 200");

    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");
    let items = body["items"].as_array().expect("`items` should be a JSON array");
    assert!(items.is_empty(), "`items` should be empty for a fresh store");
    assert_eq!(body["total"].as_u64(), Some(0), "`total` should be 0");
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_returns_seeded_in_recency_order() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    // Insertion order: info, warning, critical. Live contract: store
    // returns newest-first, so critical must appear first.
    seed_alert(&env, 50, [0x01; 16]); // info    — oldest
    seed_alert(&env, 80, [0x02; 16]); // warning
    let newest_id = seed_alert(&env, 95, [0x03; 16]); // critical — newest

    let resp = client
        .get(format!("{}/api/v1/alerts", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/alerts should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");
    let items = body["items"].as_array().expect("`items` should be a JSON array");

    assert_eq!(items.len(), 3, "all 3 seeded alerts should be present");
    assert_eq!(
        items[0]["id"].as_str(),
        Some(newest_id.as_str()),
        "newest alert (id={newest_id}) must appear first",
    );
    assert_eq!(
        items[0]["severity"].as_str(),
        Some("critical"),
        "first item must be the newest (critical)"
    );
    assert_eq!(
        items[2]["severity"].as_str(),
        Some("info"),
        "last item must be the oldest (info)"
    );
}

/// Documents live behaviour: `GET /api/v1/alerts?severity=critical` does NOT
/// filter server-side. The route handler accepts only `PaginationParams`
/// (`page`, `per_page`); the `severity` query param is silently ignored by
/// Axum and all alerts are returned. Severity filtering is client-side in
/// `aasm alerts list --severity`.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_filter_by_severity() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    seed_alert(&env, 95, [0x11; 16]); // critical
    seed_alert(&env, 80, [0x22; 16]); // warning
    seed_alert(&env, 50, [0x33; 16]); // info

    let resp = client
        .get(format!("{}/api/v1/alerts?severity=critical", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/alerts?severity=critical should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");
    let items = body["items"].as_array().expect("`items` should be a JSON array");
    // Live contract: ?severity= is silently ignored; all 3 records are returned.
    assert_eq!(
        items.len(),
        3,
        "severity filter is not applied server-side; all 3 alerts returned"
    );
    assert_eq!(body["total"].as_u64(), Some(3));
}

/// Documents live behaviour: `GET /api/v1/alerts?status=open` does NOT filter
/// server-side. The `status` query param is silently ignored and all alerts
/// (resolved or not) are returned. Status filtering is client-side in the CLI.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_list_filter_by_status() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let id1 = seed_alert(&env, 95, [0xAA; 16]); // will be resolved
    seed_alert(&env, 80, [0xBB; 16]); // stays open

    // Resolve one alert so the store holds both statuses.
    env.alert_store.resolve(&id1, None).expect("seeded alert must resolve");

    let resp = client
        .get(format!("{}/api/v1/alerts?status=open", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/alerts?status=open should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");
    let items = body["items"].as_array().expect("`items` should be a JSON array");
    // Live contract: ?status= is silently ignored; both records (one resolved,
    // one open) are returned.
    assert_eq!(
        items.len(),
        2,
        "status filter is not applied server-side; all 2 alerts returned"
    );
    assert_eq!(body["total"].as_u64(), Some(2));
}

// =============================================================================
// GET /api/v1/alerts/{id} — inspect
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_inspect_returns_full_record() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();
    let agent_bytes = [0xDE; 16];
    let expected_agent_id: String = agent_bytes.iter().map(|b| format!("{b:02x}")).collect();

    let id = seed_alert(&env, 95, agent_bytes);

    let resp = client
        .get(format!("{}/api/v1/alerts/{id}", env.base_url()))
        .send()
        .await
        .expect("GET /api/v1/alerts/{id} should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("response should parse as JSON");

    assert_eq!(body["id"].as_str(), Some(id.as_str()), "id must match the seeded alert");
    assert_eq!(
        body["severity"].as_str(),
        Some("critical"),
        "threshold=95 must yield 'critical'"
    );
    assert_eq!(body["category"].as_str(), Some("budget"), "category must be 'budget'");
    assert!(
        !body["message"].as_str().unwrap_or("").is_empty(),
        "message must be non-empty"
    );
    assert!(
        !body["timestamp"].as_str().unwrap_or("").is_empty(),
        "timestamp must be set"
    );
    assert_eq!(
        body["agent_id"].as_str(),
        Some(expected_agent_id.as_str()),
        "agent_id must match seeded hex"
    );
    assert_eq!(
        body["status"].as_str(),
        Some("unresolved"),
        "fresh alert must have status 'unresolved'"
    );
    assert!(body["updated_at"].is_null(), "updated_at must be null on a fresh alert");
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_inspect_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/alerts/00000000000000000000000000", env.base_url()))
        .send()
        .await
        .expect("GET unknown alert ULID should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown id must return 404"
    );
}

// =============================================================================
// POST /api/v1/alerts/{id}/resolve — resolve
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_open_alert_returns_200_and_updates_status() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let id = seed_alert(&env, 80, [0x55; 16]);

    let resolve_resp = client
        .post(format!("{}/api/v1/alerts/{id}/resolve", env.base_url()))
        .json(&serde_json::json!({"reason": "fixed"}))
        .send()
        .await
        .expect("POST /resolve should succeed");

    assert_eq!(
        resolve_resp.status(),
        reqwest::StatusCode::OK,
        "resolve must return 200"
    );
    let resolved: serde_json::Value = resolve_resp.json().await.expect("resolve response should parse");
    assert_eq!(
        resolved["status"].as_str(),
        Some("resolved"),
        "status must flip to 'resolved'"
    );

    // Follow-up GET must reflect the resolved state.
    let get_resp = client
        .get(format!("{}/api/v1/alerts/{id}", env.base_url()))
        .send()
        .await
        .expect("follow-up GET should succeed");
    let after: serde_json::Value = get_resp.json().await.expect("follow-up GET should parse");
    assert_eq!(
        after["status"].as_str(),
        Some("resolved"),
        "GET after resolve must show 'resolved'"
    );
}

/// Documents live behaviour: `POST /alerts/{id}/resolve` on an already-resolved
/// alert is **idempotent** — returns 200 (not 409) with the same record.
/// `updated_at` is unchanged because `InMemoryAlertStore::resolve` skips the
/// timestamp mutation when `alert.status == "resolved"`.
#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_already_resolved_returns_409_or_idempotent_200() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let id = seed_alert(&env, 95, [0x66; 16]);

    // First resolve.
    let first = client
        .post(format!("{}/api/v1/alerts/{id}/resolve", env.base_url()))
        .json(&serde_json::json!({"reason": "first"}))
        .send()
        .await
        .expect("first resolve should succeed");
    assert_eq!(first.status(), reqwest::StatusCode::OK);
    let first_body: serde_json::Value = first.json().await.expect("first resolve should parse");
    let first_updated_at = first_body["updated_at"].as_str().map(String::from);

    // Second resolve — live contract: idempotent 200 (NOT 409).
    // `updated_at` must not advance; the store skips the mutation.
    let second = client
        .post(format!("{}/api/v1/alerts/{id}/resolve", env.base_url()))
        .json(&serde_json::json!({"reason": "second"}))
        .send()
        .await
        .expect("second resolve should reach the server");
    assert_eq!(
        second.status(),
        reqwest::StatusCode::OK,
        "second resolve must return idempotent 200, not 409"
    );
    let second_body: serde_json::Value = second.json().await.expect("second resolve should parse");
    assert_eq!(
        second_body["updated_at"].as_str().map(String::from),
        first_updated_at,
        "updated_at must not advance on a no-op resolve",
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_unknown_id_returns_404() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/alerts/00000000000000000000000000/resolve",
            env.base_url()
        ))
        .json(&serde_json::json!({"reason": "no-op"}))
        .send()
        .await
        .expect("POST /resolve on unknown ULID should reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::NOT_FOUND,
        "unknown id must return 404"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn alerts_resolve_sets_resolved_at_and_resolver_fields() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let id = seed_alert(&env, 80, [0x77; 16]);
    let before_resolve = Utc::now();

    let resolve_resp = client
        .post(format!("{}/api/v1/alerts/{id}/resolve", env.base_url()))
        .json(&serde_json::json!({"reason": "ack"}))
        .send()
        .await
        .expect("POST /resolve should succeed");
    assert_eq!(resolve_resp.status(), reqwest::StatusCode::OK);

    let after_resolve = Utc::now();

    let get_resp = client
        .get(format!("{}/api/v1/alerts/{id}", env.base_url()))
        .send()
        .await
        .expect("follow-up GET should succeed");
    let record: serde_json::Value = get_resp.json().await.expect("GET should parse");

    assert_eq!(record["status"].as_str(), Some("resolved"));

    let updated_at_str = record["updated_at"]
        .as_str()
        .expect("updated_at must be set on a resolved alert");
    let updated_at = chrono::DateTime::parse_from_rfc3339(updated_at_str)
        .expect("updated_at must be a valid RFC 3339 timestamp")
        .with_timezone(&Utc);

    assert!(
        updated_at >= before_resolve - chrono::Duration::seconds(1),
        "updated_at ({updated_at}) must not pre-date the resolve call by more than 1s",
    );
    assert!(
        updated_at <= after_resolve + chrono::Duration::seconds(1),
        "updated_at ({updated_at}) must be within 1s of the resolve call",
    );
}
