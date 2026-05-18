//! AAASM-1490 / F122 ST-I — Live-gateway HTTP integration tests for `/api/v1/costs`.
//!
//! ## Discovered response shape (aa-api/src/routes/costs.rs)
//!
//! ```text
//! GET /api/v1/costs → 200 application/json
//! {
//!   "daily_spend_usd":   String,         // global today spend in USD
//!   "monthly_spend_usd": String | null,  // global month spend (null if not tracked)
//!   "date":              "YYYY-MM-DD",   // calendar date the spend applies to
//!   "daily_limit_usd":   String,         // omitted when no limit configured
//!   "monthly_limit_usd": String,         // omitted when no limit configured
//!   "per_agent": [
//!     { "agent_id": String, "daily_spend_usd": String, "monthly_spend_usd": String | null, "date": "YYYY-MM-DD" }
//!   ],
//!   "per_team": [
//!     { "team_id": String, "daily_spend_usd": String, "monthly_spend_usd": String | null, "date": "YYYY-MM-DD" }
//!   ]
//! }
//! ```
//!
//! ## Seeding strategy
//!
//! The gateway exposes no HTTP route for recording spend, so tests seed
//! `env.budget_tracker.record_raw_spend(AgentId, Option<&str>, Decimal)`
//! directly — the same pattern used for `agent_registry` and `trace_store`.
//!
//! ## No query-param filtering
//!
//! The current `GET /api/v1/costs` handler returns a flat summary without
//! team_id / agent_id / time-range filter support. The three "date field"
//! tests (TC-5 through TC-7) cover the time-range aspect of the AC by
//! asserting the `date` field is present and well-formed in all response
//! levels (global, per_agent, per_team). Query-param filter support is
//! deferred to a follow-up subtask.

mod common;

use aa_core::AgentId;
use common::TopologyTestEnv;
use rust_decimal::Decimal;

// ── Stable agent IDs for cost seeding (distinct from topology-it IDs) ────────

const AGENT_A_BYTES: [u8; 16] = [0xc0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const AGENT_B_BYTES: [u8; 16] = [0xc0, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
const TEAM_ID: &str = "f122-costs-it";
const TEAM_ID_B: &str = "f122-costs-it-b";

fn agent_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── TC-1: happy path — 200 with correct Content-Type ─────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_returns_200_with_correct_content_type() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let resp = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("GET /api/v1/costs should succeed");

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "expected 200 OK");
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("application/json"),
        "expected application/json Content-Type, got: {content_type}",
    );
}

// ── TC-2: happy path — all required top-level fields present ─────────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_response_has_required_fields() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    assert!(body["daily_spend_usd"].as_str().is_some(), "missing daily_spend_usd");
    assert!(body["date"].as_str().is_some(), "missing date");
    assert!(body["per_agent"].is_array(), "missing per_agent array");
    assert!(body["per_team"].is_array(), "missing per_team array");
}

// ── TC-3: happy path — fresh tracker has zero global spend ───────────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_initial_global_spend_is_zero() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let spend = body["daily_spend_usd"]
        .as_str()
        .expect("daily_spend_usd should be a string");
    assert_eq!(spend, "0", "fresh tracker should report 0 daily spend");
}

// ── TC-4: happy path — fresh tracker has empty per_agent and per_team ────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_initial_per_agent_and_per_team_are_empty() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let per_agent = body["per_agent"].as_array().expect("per_agent should be array");
    assert!(per_agent.is_empty(), "fresh tracker should have empty per_agent");
    let per_team = body["per_team"].as_array().expect("per_team should be array");
    assert!(per_team.is_empty(), "fresh tracker should have empty per_team");
}

// ── TC-5: time range — global date field is a YYYY-MM-DD string ──────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_global_date_field_is_iso_date_string() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Seed one record so the global state is initialised with a real date.
    env.budget_tracker.record_raw_spend(
        AgentId::from_bytes(AGENT_A_BYTES),
        Some(TEAM_ID),
        Decimal::new(100, 2), // 1.00 USD
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let date = body["date"].as_str().expect("date should be a string");
    // YYYY-MM-DD format: length 10, dashes at positions 4 and 7
    assert_eq!(date.len(), 10, "date should be 10 chars (YYYY-MM-DD), got: {date}");
    assert_eq!(&date[4..5], "-", "date[4] should be '-', got: {date}");
    assert_eq!(&date[7..8], "-", "date[7] should be '-', got: {date}");
}

// ── TC-6: time range — per_agent entry carries a YYYY-MM-DD date field ───────

#[tokio::test(flavor = "multi_thread")]
async fn costs_per_agent_entry_has_date_field_in_iso_format() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    env.budget_tracker.record_raw_spend(
        AgentId::from_bytes(AGENT_A_BYTES),
        Some(TEAM_ID),
        Decimal::new(250, 2), // 2.50 USD
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let agents = body["per_agent"].as_array().expect("per_agent array");
    assert!(!agents.is_empty(), "per_agent should be non-empty after seeding");
    let date = agents[0]["date"]
        .as_str()
        .expect("per_agent[0].date should be a string");
    assert_eq!(date.len(), 10, "per_agent date should be YYYY-MM-DD, got: {date}");
    assert_eq!(&date[4..5], "-", "per_agent date[4] should be '-'");
    assert_eq!(&date[7..8], "-", "per_agent date[7] should be '-'");
}

// ── TC-7: time range — per_team entry carries a YYYY-MM-DD date field ────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_per_team_entry_has_date_field_in_iso_format() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    env.budget_tracker.record_raw_spend(
        AgentId::from_bytes(AGENT_A_BYTES),
        Some(TEAM_ID),
        Decimal::new(300, 2), // 3.00 USD
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let teams = body["per_team"].as_array().expect("per_team array");
    assert!(
        !teams.is_empty(),
        "per_team should be non-empty after seeding with a team_id"
    );
    let date = teams[0]["date"].as_str().expect("per_team[0].date should be a string");
    assert_eq!(date.len(), 10, "per_team date should be YYYY-MM-DD, got: {date}");
    assert_eq!(&date[4..5], "-", "per_team date[4] should be '-'");
    assert_eq!(&date[7..8], "-", "per_team date[7] should be '-'");
}

// ── TC-8: grouping — seeded per-agent spend appears in per_agent ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_reflects_seeded_per_agent_spend() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent_id = AgentId::from_bytes(AGENT_A_BYTES);
    let expected_hex = agent_hex(&AGENT_A_BYTES);

    env.budget_tracker.record_raw_spend(
        agent_id,
        Some(TEAM_ID),
        Decimal::new(475, 2), // 4.75 USD
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let agents = body["per_agent"].as_array().expect("per_agent array");
    let entry = agents.iter().find(|e| e["agent_id"].as_str() == Some(&expected_hex));
    assert!(
        entry.is_some(),
        "per_agent should contain entry for agent {expected_hex}"
    );
    let spend = entry.unwrap()["daily_spend_usd"].as_str().expect("daily_spend_usd");
    assert_eq!(spend, "4.75", "per_agent spend should be 4.75, got: {spend}");
}

// ── TC-9: grouping — seeded per-team spend appears in per_team ───────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_reflects_seeded_per_team_spend_and_sorted_order() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Two different teams so we can verify sort order as well.
    env.budget_tracker.record_raw_spend(
        AgentId::from_bytes(AGENT_B_BYTES),
        Some(TEAM_ID_B),
        Decimal::new(600, 2), // 6.00 USD
    );
    env.budget_tracker.record_raw_spend(
        AgentId::from_bytes(AGENT_A_BYTES),
        Some(TEAM_ID),
        Decimal::new(200, 2), // 2.00 USD
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let teams = body["per_team"].as_array().expect("per_team array");
    assert!(teams.len() >= 2, "per_team should have at least 2 entries");

    let find_team = |id: &str| teams.iter().find(|e| e["team_id"].as_str() == Some(id)).cloned();

    let entry_a = find_team(TEAM_ID).expect("per_team should contain f122-costs-it");
    let spend_a: Decimal = entry_a["daily_spend_usd"]
        .as_str()
        .expect("daily_spend_usd")
        .parse()
        .expect("parseable decimal");
    assert_eq!(
        spend_a,
        Decimal::new(200, 2),
        "f122-costs-it daily spend should be 2.00"
    );

    let entry_b = find_team(TEAM_ID_B).expect("per_team should contain f122-costs-it-b");
    let spend_b: Decimal = entry_b["daily_spend_usd"]
        .as_str()
        .expect("daily_spend_usd")
        .parse()
        .expect("parseable decimal");
    assert_eq!(
        spend_b,
        Decimal::new(600, 2),
        "f122-costs-it-b daily spend should be 6.00"
    );

    // Verify the handler's sort_by(team_id) — lexicographic ascending.
    let team_ids: Vec<&str> = teams.iter().filter_map(|e| e["team_id"].as_str()).collect();
    let mut sorted = team_ids.clone();
    sorted.sort_unstable();
    assert_eq!(team_ids, sorted, "per_team entries should be sorted by team_id");
}

// ── TC-10: edge — global spend accumulates across multiple agents ─────────────

#[tokio::test(flavor = "multi_thread")]
async fn costs_global_spend_accumulates_across_agents() {
    let env = TopologyTestEnv::start().await.expect("harness should start");

    // Agent A: 3.25 USD; Agent B: 1.75 USD → total 5.00 USD.
    env.budget_tracker
        .record_raw_spend(AgentId::from_bytes(AGENT_A_BYTES), Some(TEAM_ID), Decimal::new(325, 2));
    env.budget_tracker
        .record_raw_spend(AgentId::from_bytes(AGENT_B_BYTES), Some(TEAM_ID), Decimal::new(175, 2));

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("request")
        .json()
        .await
        .expect("body as JSON");

    let global = body["daily_spend_usd"].as_str().expect("daily_spend_usd");
    let global_decimal: Decimal = global.parse().expect("daily_spend_usd should parse as Decimal");
    assert_eq!(
        global_decimal,
        Decimal::new(500, 2),
        "global daily spend should be 5.00, got: {global}",
    );
}
