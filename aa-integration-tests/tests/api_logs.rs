//! Live-gateway HTTP integration tests for `GET /api/v1/logs` (AAASM-1493 / F122 ST-L).
//!
//! Exercises the audit log REST endpoint end-to-end via a real running
//! `TopologyTestEnv` and `reqwest` HTTP calls. Entries are seeded by writing
//! JSONL directly to `env.audit_dir` — the same pattern used by
//! `CliFixture::seed_audit_event` in `common/cli.rs`.
//!
//! Test matrix:
//! - Empty ×1: no entries → 200 + empty array
//! - Returns seeded ×1: 5 seeded entries appear in response
//! - Response shape ×1: all LogEntry fields present and well-formed
//! - Agent filter ×2: matching-only, unknown agent → empty
//! - Event-type filter ×1: matching-only
//! - Combined filter ×1: agent + event_type together
//! - Pagination ×3: page 1, page 2, total reflects full count
//! - Per-page cap ×1: per_page > 100 is clamped to 100

mod common;

use std::fs::OpenOptions;
use std::io::Write;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aa_core::audit::AuditEventType;
use aa_core::{AgentId, AuditEntry, SessionId};
use common::TopologyTestEnv;

// =============================================================================
// Seed helper — mirrors CliFixture::seed_audit_event without requiring CliFixture
// =============================================================================

fn seed_audit_event(
    env: &TopologyTestEnv,
    timestamp_ns: u64,
    agent_id: [u8; 16],
    event_type: AuditEventType,
    payload: &str,
) {
    let entry = AuditEntry::new(
        0,
        timestamp_ns,
        event_type,
        AgentId::from_bytes(agent_id),
        SessionId::from_bytes([0u8; 16]),
        payload.to_string(),
        [0u8; 32],
    );
    let line = serde_json::to_string(&entry).expect("AuditEntry should serialize");
    let path = env.audit_dir.join("seed.jsonl");
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .expect("audit seed file should open");
    file.write_all(line.as_bytes()).expect("write should succeed");
    file.write_all(b"\n").expect("newline write should succeed");
}

fn seed_audit_events(env: &TopologyTestEnv, n: usize, agent_id: [u8; 16], event_type: AuditEventType) {
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos() as u64;
    let stride_ns = Duration::from_secs(1).as_nanos() as u64;
    let oldest_ns = now_ns.saturating_sub(stride_ns * n as u64);
    for i in 0..n {
        seed_audit_event(
            env,
            oldest_ns + stride_ns * i as u64,
            agent_id,
            event_type,
            &format!("seed-{i}"),
        );
    }
}

fn hex_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_agent_id(tag: u8) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = 0xf1;
    id[1] = 0x22;
    id[2] = tag;
    id
}

// =============================================================================
// Empty
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_empty_returns_200_and_empty_array() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

// =============================================================================
// Seeded entries returned
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_returns_all_seeded_entries() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x01);
    seed_audit_events(&env, 5, agent, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 5, "total should equal seeded count");
    assert_eq!(
        json["items"].as_array().unwrap().len(),
        5,
        "items array length should equal seeded count"
    );
}

// =============================================================================
// Response shape
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_entry_has_all_required_fields() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x02);
    let ts_ns: u64 = 1_700_000_000 * 1_000_000_000;
    seed_audit_event(&env, ts_ns, agent, AuditEventType::PolicyViolation, "shape-check");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    let item = &json["items"][0];

    assert!(item["seq"].is_number(), "seq must be a number");
    assert!(item["timestamp"].is_string(), "timestamp must be a string");
    assert!(item["agent_id"].is_string(), "agent_id must be a string");
    assert!(item["session_id"].is_string(), "session_id must be a string");
    assert!(item["event_type"].is_string(), "event_type must be a string");
    assert!(item["payload"].is_string(), "payload must be a string");

    assert_eq!(item["agent_id"], hex_id(&agent), "agent_id should match seeded value");
    assert_eq!(
        item["event_type"], "PolicyViolation",
        "event_type should match seeded type"
    );
}

// =============================================================================
// Timestamp is RFC 3339
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_timestamp_is_rfc3339() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x03);
    let ts_ns: u64 = 1_700_000_000 * 1_000_000_000;
    seed_audit_event(&env, ts_ns, agent, AuditEventType::PolicyViolation, "ts-check");
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    let json: serde_json::Value = resp.json().await.unwrap();
    let ts = json["items"][0]["timestamp"]
        .as_str()
        .expect("timestamp must be a string");
    chrono::DateTime::parse_from_rfc3339(ts).unwrap_or_else(|_| panic!("timestamp '{ts}' should be valid RFC 3339"));
}

// =============================================================================
// Agent filter
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_agent_filter_returns_only_matching_entries() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent_a = make_agent_id(0x0a);
    let agent_b = make_agent_id(0x0b);
    seed_audit_events(&env, 3, agent_a, AuditEventType::PolicyViolation);
    seed_audit_events(&env, 2, agent_b, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?agent_id={}", env.base_url(), hex_id(&agent_a)))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 3, "total should only count agent_a events");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    for item in items {
        assert_eq!(
            item["agent_id"],
            hex_id(&agent_a),
            "stray non-matching agent_id in items"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_unknown_agent_filter_returns_empty() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent_a = make_agent_id(0x0c);
    seed_audit_events(&env, 3, agent_a, AuditEventType::PolicyViolation);
    let unknown_hex = hex_id(&make_agent_id(0xff));
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?agent_id={unknown_hex}", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 0);
    assert!(json["items"].as_array().unwrap().is_empty());
}

// =============================================================================
// Event-type filter
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_event_type_filter_returns_only_matching_entries() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x10);
    seed_audit_events(&env, 3, agent, AuditEventType::PolicyViolation);
    seed_audit_events(&env, 2, agent, AuditEventType::ApprovalGranted);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?event_type=PolicyViolation", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 3, "only PolicyViolation events expected in total");
    let items = json["items"].as_array().unwrap();
    assert_eq!(items.len(), 3);
    for item in items {
        assert_eq!(
            item["event_type"], "PolicyViolation",
            "stray non-PolicyViolation event in items"
        );
    }
}

// =============================================================================
// Combined filter
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_combined_agent_and_type_filter_narrows_correctly() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent_a = make_agent_id(0x20);
    let agent_b = make_agent_id(0x21);
    seed_audit_events(&env, 3, agent_a, AuditEventType::PolicyViolation);
    seed_audit_events(&env, 2, agent_a, AuditEventType::ApprovalGranted);
    seed_audit_events(&env, 4, agent_b, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/api/v1/logs?agent_id={}&event_type=PolicyViolation",
            env.base_url(),
            hex_id(&agent_a)
        ))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 3, "combined filter should yield agent_a violations only");
    let items = json["items"].as_array().unwrap();
    for item in items {
        assert_eq!(item["agent_id"], hex_id(&agent_a));
        assert_eq!(item["event_type"], "PolicyViolation");
    }
}

// =============================================================================
// Pagination
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_pagination_page1_returns_first_page() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x30);
    seed_audit_events(&env, 5, agent, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?per_page=3&page=1", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["page"], 1);
    assert_eq!(json["per_page"], 3);
    assert_eq!(json["total"], 5, "total reflects all 5 seeded entries");
    assert_eq!(
        json["items"].as_array().unwrap().len(),
        3,
        "page 1 with per_page=3 should return 3 items"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_pagination_page2_returns_second_page() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x31);
    seed_audit_events(&env, 5, agent, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?per_page=3&page=2", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["page"], 2);
    assert_eq!(json["total"], 5, "total should still be 5 on page 2");
    assert_eq!(
        json["items"].as_array().unwrap().len(),
        2,
        "page 2 with per_page=3 and 5 total entries should return 2 items"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn logs_total_reflects_full_count_regardless_of_page_size() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x32);
    seed_audit_events(&env, 5, agent, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?per_page=2&page=1", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(json["total"], 5, "total must reflect full entry count, not page size");
    assert_eq!(json["items"].as_array().unwrap().len(), 2);
}

// =============================================================================
// per_page exceeds server maximum
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn logs_per_page_above_max_is_clamped_to_100() {
    let env = TopologyTestEnv::start().await.expect("harness should start");
    let agent = make_agent_id(0x40);
    seed_audit_events(&env, 5, agent, AuditEventType::PolicyViolation);
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/api/v1/logs?per_page=200", env.base_url()))
        .send()
        .await
        .expect("request should succeed");

    assert_eq!(resp.status(), 200);
    let json: serde_json::Value = resp.json().await.unwrap();
    // Server clamps per_page to MAX_PER_PAGE (100); all 5 entries still returned.
    assert_eq!(json["per_page"], 100, "per_page should be clamped to 100");
    assert_eq!(json["items"].as_array().unwrap().len(), 5);
}
