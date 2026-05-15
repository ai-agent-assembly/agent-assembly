//! Audit aggregation endpoints.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use aa_core::AgentId;
use aa_core::AuditEntry;

use crate::state::AppState;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

/// A single node in the policy-violations-by-lineage heatmap.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ViolationNode {
    /// Hex-encoded agent ID.
    pub agent_id: String,
    /// Hex-encoded parent agent ID, if known.
    pub parent_agent_id: Option<String>,
    /// Team the agent belongs to, if registered.
    pub team_id: Option<String>,
    /// Delegation depth (0 = root agent).
    pub depth: Option<u32>,
    /// Number of `PolicyViolation` audit events in the requested window.
    pub violation_count: u64,
    /// Top 3 most-frequently violated policy rules in the window.
    pub top_policies: Vec<String>,
}

/// Response for `GET /api/v1/audit/violations-by-lineage`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ViolationsByLineageResponse {
    /// Heatmap nodes — one entry per agent that recorded at least one violation.
    pub nodes: Vec<ViolationNode>,
    /// Time window used for aggregation, in seconds.
    pub window_secs: u64,
    /// ISO 8601 UTC timestamp when this response was generated.
    pub generated_at: String,
}

// ---------------------------------------------------------------------------
// Query params
// ---------------------------------------------------------------------------

/// Query parameters for the violations-by-lineage endpoint.
#[derive(Debug, Deserialize, IntoParams)]
pub struct ViolationsParams {
    /// Hex-encoded root agent ID; scopes results to that delegation subtree.
    pub root: Option<String>,
    /// Time window as a duration string: `24h` (default), `1h`, `7d`, `30m`.
    pub window: Option<String>,
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

/// `GET /api/v1/audit/violations-by-lineage` — policy violation heatmap by lineage.
///
/// Returns all agents that recorded at least one `PolicyViolation` event within
/// the requested time window, together with their violation count and the top 3
/// most-violated policy rules.  The optional `root` parameter scopes the result
/// to a single delegation subtree.
#[utoipa::path(
    get,
    path = "/api/v1/audit/violations-by-lineage",
    params(ViolationsParams),
    responses(
        (status = 200, description = "Violation heatmap nodes", body = ViolationsByLineageResponse),
        (status = 400, description = "Invalid query parameter")
    ),
    tag = "audit"
)]
pub async fn get_violations_by_lineage(
    Extension(state): Extension<AppState>,
    axum::extract::Query(params): axum::extract::Query<ViolationsParams>,
) -> impl IntoResponse {
    let window_secs = parse_window(params.window.as_deref()).unwrap_or(86_400);
    let now_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let since_ns = now_ns.saturating_sub(window_secs * 1_000_000_000);

    let root_agent: Option<AgentId> = params.root.as_deref().and_then(parse_agent_id);

    let entries = state
        .audit_reader
        .list_violations(since_ns, root_agent)
        .await
        .unwrap_or_default();

    let nodes = aggregate_violations(&entries);

    (
        StatusCode::OK,
        Json(ViolationsByLineageResponse {
            nodes,
            window_secs,
            generated_at: Utc::now().to_rfc3339(),
        }),
    )
}

/// Aggregate a slice of audit entries into per-agent [`ViolationNode`]s.
///
/// For each distinct `agent_id`:
/// * counts how many entries reference it,
/// * extracts the top-3 most-frequently violated `policy_rule` values from
///   each entry's JSON payload,
/// * carries lineage metadata (parent, team, depth) from the first entry seen
///   for that agent.
///
/// The result is sorted by `violation_count` descending for stable output.
pub(crate) fn aggregate_violations(entries: &[AuditEntry]) -> Vec<ViolationNode> {
    struct AgentAccum {
        violation_count: u64,
        policy_counts: HashMap<String, u64>,
        parent_agent_id: Option<String>,
        team_id: Option<String>,
        depth: Option<u32>,
    }

    let mut by_agent: HashMap<String, AgentAccum> = HashMap::new();

    for entry in entries {
        let aid = hex::encode(entry.agent_id().as_bytes());
        let accum = by_agent.entry(aid).or_insert_with(|| AgentAccum {
            violation_count: 0,
            policy_counts: HashMap::new(),
            parent_agent_id: entry.parent_agent_id().map(|id| hex::encode(id.as_bytes())),
            team_id: entry.team_id().map(str::to_string),
            depth: entry.depth(),
        });
        accum.violation_count += 1;

        // Extract policy_rule from the JSON payload.
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(entry.payload()) {
            if let Some(rule) = v.get("policy_rule").and_then(|r| r.as_str()) {
                if !rule.is_empty() {
                    *accum.policy_counts.entry(rule.to_string()).or_default() += 1;
                }
            }
        }
    }

    let mut nodes: Vec<ViolationNode> = by_agent
        .into_iter()
        .map(|(agent_id, accum)| {
            let mut ranked: Vec<(String, u64)> = accum.policy_counts.into_iter().collect();
            ranked.sort_by_key(|(_, count)| std::cmp::Reverse(*count));
            let top_policies = ranked.into_iter().take(3).map(|(k, _)| k).collect();

            ViolationNode {
                agent_id,
                parent_agent_id: accum.parent_agent_id,
                team_id: accum.team_id,
                depth: accum.depth,
                violation_count: accum.violation_count,
                top_policies,
            }
        })
        .collect();

    // Sort by violation_count descending for stable output.
    nodes.sort_by_key(|n| std::cmp::Reverse(n.violation_count));

    nodes
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a duration string ("24h", "1h", "7d", "30m") into seconds.
/// Returns `None` for unrecognised strings so the caller can use a default.
fn parse_window(s: Option<&str>) -> Option<u64> {
    let s = s?;
    if let Some(h) = s.strip_suffix('h') {
        return h.parse::<u64>().ok().map(|n| n * 3600);
    }
    if let Some(d) = s.strip_suffix('d') {
        return d.parse::<u64>().ok().map(|n| n * 86_400);
    }
    if let Some(m) = s.strip_suffix('m') {
        return m.parse::<u64>().ok().map(|n| n * 60);
    }
    None
}

/// Parse a hex-encoded 16-byte agent ID string into an [`AgentId`].
fn parse_agent_id(s: &str) -> Option<AgentId> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 16 {
        return None;
    }
    let mut arr = [0u8; 16];
    arr.copy_from_slice(&bytes);
    Some(AgentId::from_bytes(arr))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::audit::{AuditEventType, Lineage};
    use aa_core::{AgentId, SessionId};

    #[test]
    fn window_parsing_hours() {
        assert_eq!(parse_window(Some("24h")), Some(86_400));
        assert_eq!(parse_window(Some("1h")), Some(3_600));
    }

    #[test]
    fn window_parsing_days() {
        assert_eq!(parse_window(Some("7d")), Some(604_800));
    }

    #[test]
    fn window_parsing_minutes() {
        assert_eq!(parse_window(Some("30m")), Some(1_800));
    }

    #[test]
    fn window_parsing_invalid_returns_none() {
        assert_eq!(parse_window(Some("bad")), None);
        assert_eq!(parse_window(None), None);
    }

    #[test]
    fn parse_agent_id_round_trip() {
        let bytes: [u8; 16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        let hex = hex::encode(bytes);
        assert_eq!(parse_agent_id(&hex), Some(AgentId::from_bytes(bytes)));
    }

    #[test]
    fn parse_agent_id_rejects_invalid_hex() {
        assert_eq!(parse_agent_id("zz"), None);
    }

    #[test]
    fn parse_agent_id_rejects_wrong_length() {
        assert_eq!(parse_agent_id("0102030405060708"), None);
    }

    fn entry(agent: AgentId, parent: Option<AgentId>, team: Option<&str>, payload: &str) -> AuditEntry {
        AuditEntry::new_with_lineage(
            0,
            0,
            AuditEventType::PolicyViolation,
            agent,
            SessionId::from_bytes([0xEE; 16]),
            payload.to_string(),
            [0u8; 32],
            Lineage {
                parent_agent_id: parent,
                team_id: team.map(str::to_string),
                depth: Some(1),
                ..Lineage::default()
            },
        )
    }

    #[test]
    fn aggregate_violations_returns_empty_for_no_entries() {
        let nodes = aggregate_violations(&[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn aggregate_violations_counts_per_agent_and_sorts_desc() {
        let a = AgentId::from_bytes([0xAA; 16]);
        let b = AgentId::from_bytes([0xBB; 16]);

        let entries = vec![
            entry(a, None, None, r#"{"policy_rule":"rule-x"}"#),
            entry(a, None, None, r#"{"policy_rule":"rule-x"}"#),
            entry(b, None, None, r#"{"policy_rule":"rule-y"}"#),
        ];
        let nodes = aggregate_violations(&entries);

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].agent_id, hex::encode(a.as_bytes()));
        assert_eq!(nodes[0].violation_count, 2);
        assert_eq!(nodes[1].violation_count, 1);
    }

    #[test]
    fn aggregate_violations_extracts_lineage_metadata() {
        let a = AgentId::from_bytes([0xAA; 16]);
        let parent = AgentId::from_bytes([0xCC; 16]);
        let entries = vec![entry(a, Some(parent), Some("eng-platform"), "{}")];

        let nodes = aggregate_violations(&entries);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].parent_agent_id, Some(hex::encode(parent.as_bytes())));
        assert_eq!(nodes[0].team_id.as_deref(), Some("eng-platform"));
        assert_eq!(nodes[0].depth, Some(1));
    }

    #[test]
    fn aggregate_violations_returns_top_three_policies_by_frequency() {
        let a = AgentId::from_bytes([0xAA; 16]);
        let mut entries = Vec::new();
        for (rule, count) in [("rule-a", 4), ("rule-b", 3), ("rule-c", 2), ("rule-d", 1)] {
            for _ in 0..count {
                entries.push(entry(a, None, None, &format!(r#"{{"policy_rule":"{rule}"}}"#)));
            }
        }

        let nodes = aggregate_violations(&entries);
        assert_eq!(nodes.len(), 1);
        let top = &nodes[0].top_policies;
        assert_eq!(top.len(), 3);
        assert_eq!(top[0], "rule-a");
        assert_eq!(top[1], "rule-b");
        assert_eq!(top[2], "rule-c");
        assert!(!top.contains(&"rule-d".to_string()));
    }

    #[test]
    fn aggregate_violations_ignores_malformed_and_missing_policy_rule() {
        let a = AgentId::from_bytes([0xAA; 16]);
        let entries = vec![
            entry(a, None, None, "not-json"),
            entry(a, None, None, r#"{"no_rule_here":true}"#),
            entry(a, None, None, r#"{"policy_rule":""}"#),
            entry(a, None, None, r#"{"policy_rule":"good"}"#),
        ];
        let nodes = aggregate_violations(&entries);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].violation_count, 4);
        assert_eq!(nodes[0].top_policies, vec!["good".to_string()]);
    }
}
