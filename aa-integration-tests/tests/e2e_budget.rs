//! AAASM-1518 / F116 ST-F — E2E budget enforcement tests.
//!
//! Verifies that per-team daily spend accumulates correctly across calls and
//! that `BudgetStatus::LimitExceeded` is returned once the configured team
//! cap is reached. The HTTP plane (`GET /api/v1/costs`) is asserted in parallel
//! to verify the budget tracker and HTTP layer agree.
//!
//! ## Platform divergences vs ticket AC
//!
//! | AC item | Divergence | Reason |
//! |---|---|---|
//! | Token-count tracking (`limit_tokens: 1000`) | USD amounts via `record_raw_spend` | `BudgetTracker` tracks USD spend, not raw tokens |
//! | Python SDK driver + mock LLM server | In-process `record_raw_spend` seeding | No HTTP route for spend ingestion; same pattern as `api_costs.rs` |
//! | Sub-day window (`window: "5s"`) | TC-4 marked `#[ignore]` | `BudgetTracker` resets at midnight UTC only; sub-day windows not in v0.0.1 |
//! | `BudgetExhaustedError` from SDK | `BudgetStatus::LimitExceeded` from tracker | No SDK layer in integration harness |
//!
//! ## Seeding strategy
//!
//! `env.budget_tracker.record_raw_spend(AgentId, Option<&str>, Decimal)`
//! injects spend and returns `BudgetStatus` synchronously — the same pattern
//! used by `api_costs.rs` (AAASM-1490 / F122 ST-I).

mod common;

use aa_core::AgentId;
use aa_gateway::budget::BudgetStatus;
use common::TopologyTestEnv;
use rust_decimal::Decimal;

// ── Agent / team IDs (distinct from topology-it and cost-it suites) ───────────

const BUDGET_AGENT_A: [u8; 16] = [0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];
const BUDGET_AGENT_B: [u8; 16] = [0xba, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];
const TEAM_A: &str = "f116-budget-it-a";
const TEAM_B: &str = "f116-budget-it-b";

fn agent_hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ── TC-1: spend accumulates per-agent and per-team ────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn budget_spend_accumulates_per_agent_and_team() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = AgentId::from_bytes(BUDGET_AGENT_A);

    for _ in 0..5 {
        env.budget_tracker
            .record_raw_spend(agent, Some(TEAM_A), Decimal::new(50, 2)); // 0.50 USD each
    }

    let agent_state = env
        .budget_tracker
        .agent_state(&agent)
        .expect("agent state should be present after seeding");
    assert_eq!(
        agent_state.spent_usd,
        Decimal::new(250, 2),
        "agent should have 2.50 USD accumulated after 5 × 0.50 USD calls"
    );

    let team_state = env
        .budget_tracker
        .team_state(TEAM_A)
        .expect("team state should be present after seeding");
    assert_eq!(
        team_state.spent_usd,
        Decimal::new(250, 2),
        "team should have 2.50 USD accumulated after 5 × 0.50 USD calls"
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("GET /api/v1/costs")
        .json()
        .await
        .expect("body as JSON");

    let agents = body["per_agent"].as_array().expect("per_agent array");
    let hex = agent_hex(&BUDGET_AGENT_A);
    let agent_entry = agents
        .iter()
        .find(|e| e["agent_id"].as_str() == Some(&hex))
        .expect("per_agent should contain the seeded agent");
    assert_eq!(
        agent_entry["daily_spend_usd"].as_str(),
        Some("2.50"),
        "HTTP per_agent daily_spend_usd should be 2.50"
    );

    let teams = body["per_team"].as_array().expect("per_team array");
    let team_entry = teams
        .iter()
        .find(|e| e["team_id"].as_str() == Some(TEAM_A))
        .expect("per_team should contain the seeded team");
    assert_eq!(
        team_entry["daily_spend_usd"].as_str(),
        Some("2.50"),
        "HTTP per_team daily_spend_usd should be 2.50"
    );
}

// ── TC-2: limit exceeded returns LimitExceeded status ────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn budget_deny_at_exhaustion_returns_limit_exceeded() {
    // Team daily cap: 2.00 USD.
    let env = TopologyTestEnv::start_with_team_budget(Decimal::new(200, 2))
        .await
        .expect("harness should start with team budget");
    let agent = AgentId::from_bytes(BUDGET_AGENT_A);

    // 1.80 USD — within the 2.00 USD cap.
    let status_before = env
        .budget_tracker
        .record_raw_spend(agent, Some(TEAM_A), Decimal::new(180, 2));
    assert!(
        matches!(
            status_before,
            BudgetStatus::WithinBudget { .. } | BudgetStatus::ThresholdAlert { .. }
        ),
        "1.80 USD should be within the 2.00 USD cap, got: {status_before:?}"
    );

    // Additional 0.50 USD pushes total to 2.30 — over the cap.
    let status_over = env
        .budget_tracker
        .record_raw_spend(agent, Some(TEAM_A), Decimal::new(50, 2));
    assert_eq!(
        status_over,
        BudgetStatus::LimitExceeded,
        "exceeding the 2.00 USD team daily limit should return LimitExceeded"
    );
}

// ── TC-3: enforcement is per-call — subsequent calls after exhaustion also denied

#[tokio::test(flavor = "multi_thread")]
async fn budget_exhausted_request_is_rejected_at_tracking_layer() {
    // Team daily cap: 1.00 USD.
    let env = TopologyTestEnv::start_with_team_budget(Decimal::new(100, 2))
        .await
        .expect("harness should start with team budget");
    let agent = AgentId::from_bytes(BUDGET_AGENT_A);

    // Push team over the cap in one call.
    env.budget_tracker
        .record_raw_spend(agent, Some(TEAM_A), Decimal::new(150, 2)); // 1.50 > 1.00

    // A subsequent call must still return LimitExceeded — proving enforcement
    // is checked on every call, not just the first one that crosses the limit.
    let follow_up = env
        .budget_tracker
        .record_raw_spend(agent, Some(TEAM_A), Decimal::new(10, 2));
    assert_eq!(
        follow_up,
        BudgetStatus::LimitExceeded,
        "follow-up call after limit exceeded should still return LimitExceeded"
    );

    // The HTTP layer reflects the accumulated spend.
    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("GET /api/v1/costs")
        .json()
        .await
        .expect("body as JSON");
    let teams = body["per_team"].as_array().expect("per_team array");
    let team_entry = teams
        .iter()
        .find(|e| e["team_id"].as_str() == Some(TEAM_A))
        .expect("per_team should contain the seeded team");
    let spent: Decimal = team_entry["daily_spend_usd"]
        .as_str()
        .expect("daily_spend_usd string")
        .parse()
        .expect("parseable Decimal");
    assert!(
        spent >= Decimal::new(150, 2),
        "HTTP per_team spend should reflect ≥ 1.50 USD accumulated, got: {spent}"
    );
}

// ── TC-4: sub-day window rollover (ignored — not implemented in v0.0.1) ───────

/// Budget spend resets after the configured time window elapses.
///
/// Marked `#[ignore]` because `BudgetTracker` only resets at midnight UTC;
/// sub-day budget windows (e.g. `window: "5s"`) are not supported in v0.0.1.
/// Remove the `#[ignore]` and implement once a configurable flush interval is
/// added to `BudgetTracker`.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn budget_resets_after_daily_window() {
    unimplemented!(
        "sub-day budget window rollover not supported in v0.0.1 (BudgetTracker resets at midnight UTC only)"
    );
}

// ── TC-5: per-team isolation — exhausting team A does not block team B ─────────

#[tokio::test(flavor = "multi_thread")]
async fn budget_per_team_isolation_prevents_cross_team_bleed() {
    // Both teams share a 2.00 USD daily cap.
    let env = TopologyTestEnv::start_with_team_budget(Decimal::new(200, 2))
        .await
        .expect("harness should start with team budget");
    let agent_a = AgentId::from_bytes(BUDGET_AGENT_A);
    let agent_b = AgentId::from_bytes(BUDGET_AGENT_B);

    // Exhaust team A: 2.50 USD > 2.00 USD cap.
    let status_a = env
        .budget_tracker
        .record_raw_spend(agent_a, Some(TEAM_A), Decimal::new(250, 2));
    assert_eq!(status_a, BudgetStatus::LimitExceeded, "team A should be over its cap");

    // Team B: 1.00 USD — independent cap, should be allowed.
    let status_b = env
        .budget_tracker
        .record_raw_spend(agent_b, Some(TEAM_B), Decimal::new(100, 2));
    assert!(
        matches!(
            status_b,
            BudgetStatus::WithinBudget { .. } | BudgetStatus::ThresholdAlert { .. }
        ),
        "team B should be within budget even after team A is exhausted, got: {status_b:?}"
    );
}

// ── TC-6: partial spend charged exactly — no rounding or double-counting ───────

#[tokio::test(flavor = "multi_thread")]
async fn budget_partial_spend_charged_exactly() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = AgentId::from_bytes(BUDGET_AGENT_A);

    // Seed a non-round amount: 1.37 USD.
    env.budget_tracker
        .record_raw_spend(agent, Some(TEAM_A), Decimal::new(137, 2));

    let agent_state = env
        .budget_tracker
        .agent_state(&agent)
        .expect("agent state should be present");
    assert_eq!(
        agent_state.spent_usd,
        Decimal::new(137, 2),
        "agent spend should be exactly 1.37 USD without rounding or truncation"
    );

    let body: serde_json::Value = reqwest::get(format!("{}/api/v1/costs", env.base_url()))
        .await
        .expect("GET /api/v1/costs")
        .json()
        .await
        .expect("body as JSON");
    let agents = body["per_agent"].as_array().expect("per_agent array");
    let hex = agent_hex(&BUDGET_AGENT_A);
    let entry = agents
        .iter()
        .find(|e| e["agent_id"].as_str() == Some(&hex))
        .expect("per_agent should contain the seeded agent");
    assert_eq!(
        entry["daily_spend_usd"].as_str(),
        Some("1.37"),
        "HTTP per_agent daily_spend_usd should be exactly '1.37'"
    );
}
