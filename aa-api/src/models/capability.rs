//! Capability matrix data model — agent × resource × verb × decision view
//! consumed by the dashboard Capability Matrix page (AAASM-1280).
//!
//! Field names use `serde(rename_all = "camelCase")` on response structs so
//! the wire shape matches the dashboard's TypeScript types in
//! `dashboard/src/api/capability.ts`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Verb a capability cell scopes its decision to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Verb {
    Read,
    Write,
    Delete,
    Exec,
}

/// Decision recorded for a single (agent, resource, verb) tuple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Narrow,
    Approval,
    Deny,
    Na,
}

/// Coarse group a resource belongs to, used for matrix column headings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ResourceGroup {
    Comm,
    Files,
    Data,
    Infra,
    Code,
}

/// A resource that an agent may interact with — one column family in the
/// dashboard Capability Matrix.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Resource {
    /// Stable identifier — the wire-format [`aa_core::Capability`] family this
    /// column projects (`"filesystem"`, `"terminal"`, `"network_outbound"`) or
    /// the declared MCP tool name for a tool column.
    pub id: String,
    /// Human-readable display name.
    pub name: String,
    /// Coarse group this resource belongs to.
    ///
    /// Only populated for the fixed system capability families, whose domain
    /// the `Capability` enum itself names (`file_*` → `files`, `network_*` /
    /// `terminal_exec` → `infra`). An MCP tool is an operator-supplied string
    /// with no classification anywhere in the policy model, so its group is
    /// left absent rather than guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<ResourceGroup>,
    /// Globbed paths covered by this resource.
    ///
    /// Always empty: the capability model grants a whole family or tool, it
    /// does not carry per-path sub-scopes, so there is no real source for this.
    pub paths: Vec<String>,
}

/// One cell in the (agent × resource) matrix: a decision per verb, plus an
/// optional `flag` marker the UI uses to highlight over-permissioned cells.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CapCell {
    pub read: Decision,
    pub write: Decision,
    pub delete: Decision,
    pub exec: Decision,
    /// `Some(true)` when this cell's grant is over-permission — the agent is
    /// effectively allowed a destructive system verb its declared `RiskTier`
    /// baseline does not warrant (AAASM-5175, ADR 0029). Absent when the cell is
    /// within baseline, or when the agent is not evaluated (no resolvable tier,
    /// or an empty cascade). Only the offending marker is emitted; a per-cell
    /// `false` is not, so the UI highlights positives without negative clutter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flag: Option<bool>,
}

/// Enforcement mode for an agent's capability policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentMode {
    Enforce,
    Shadow,
}

/// Liveness status surfaced to the matrix view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Idle,
    Suspended,
}

/// Lifecycle status of a policy version in the capability view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    Active,
    Proposed,
    Archived,
}

/// A single rule inside a policy — resource, verbs scoped, action, and an
/// optional condition expression.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PolicyRule {
    pub resource: String,
    pub verb: Vec<Verb>,
    pub action: String,
    pub condition: String,
}

/// A policy version shown in the dashboard Capability Matrix's policies tab.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Policy {
    pub id: String,
    pub name: String,
    /// Revision from the policy document's `metadata.version`. Absent for
    /// documents parsed from the flat (non-envelope) format, which declare none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub scope: String,
    pub status: PolicyStatus,
    /// Number of times this policy document fired in the last 24 hours.
    ///
    /// Sourced (AAASM-5107) by joining this row's document content digest against
    /// the per-document decision counts from the last-24h audit window — each
    /// policy decision records the deciding document's digest on its audit entry.
    /// Absent, never `0`, when the document recorded no decision in the window: a
    /// `0` would be indistinguishable from "fired zero times".
    #[serde(default, rename = "hits24h", skip_serializing_if = "Option::is_none")]
    pub hits_24h: Option<u64>,
    /// Ids of the agents whose cascade includes this policy scope.
    pub affects: Vec<String>,
    pub rules: Vec<PolicyRule>,
}

/// Classifier for what a proposed-vs-current decision change represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "kebab-case")]
pub enum ChangeType {
    NewlyBlocked,
    Narrowed,
    Unchanged,
    Tightened,
    FalsePositive,
}

/// A representative call sample shown alongside the matrix to explain the
/// effect of the current (and any proposed) policy.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct SampleCall {
    pub ts: String,
    pub agent: String,
    pub verb: Verb,
    pub resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    pub current_decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proposed_decision: Option<Decision>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_type: Option<ChangeType>,
    /// Free-form explanation for a `false-positive` change classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fp_reason: Option<String>,
}

/// Top-level response shape for `GET /api/v1/capability/matrix`. Mirrors
/// the `CapabilityMatrix` interface in `dashboard/src/api/capability.ts`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityMatrix {
    pub resources: Vec<Resource>,
    pub agents: Vec<CapabilityAgent>,
    pub policies: Vec<Policy>,
    pub sample_calls: Vec<SampleCall>,
}

/// One agent row in the dashboard Capability Matrix.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityAgent {
    /// Hex-encoded agent UUID, as registered.
    pub id: String,
    pub name: String,
    pub framework: String,
    /// Owning team, from the registry's first-class `team_id` (falling back to
    /// `org_id`). Absent when the agent registered without either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Trust score as an integer on a 0–100 scale, or `null` when no
    /// trust-analytics source exists yet.
    ///
    /// Always `null`: no trust score is computed anywhere in the gateway today.
    /// Deriving one would be a new scoring rule, which is the subject of its own
    /// story (AAASM-5083) — emitting a placeholder here would be indistinguishable
    /// from a real score to every consumer.
    //
    // AAASM-5104 — one representation and one null contract for `trust` across
    // every schema that carries it ([`crate::models::topology::AgentNode`],
    // [`crate::models::topology::AgentTree`], and here): an integer 0–100,
    // required-but-nullable. Integer because the ratified mock renders a whole
    // number (`design/v1/hi-fi/fleet.jsx:90`, `agent-detail.jsx:27`) and a float
    // implies a precision no formula has agreed to. Required-but-nullable
    // because an *absent* key invites `?? 0`, which silently turns "unmeasured"
    // into "scored zero" — the worst possible misread for a trust score; an
    // explicit `null` on an always-present key surfaces in TypeScript as a
    // non-optional `| null` the consumer has to handle. Same discipline as
    // `TeamPoliciesResponse::policies` (AAASM-5096).
    #[schema(required = true, minimum = 0, maximum = 100)]
    pub trust: Option<u8>,
    /// Enforcement posture, from the agent's registered `enforcement_mode`
    /// override. Absent when the agent declared none (the effective mode is then
    /// per-policy-document, so there is no single agent-level answer) or when it
    /// declared `Disabled`, which this two-value view cannot represent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<AgentMode>,
    pub status: AgentStatus,
    /// ISO 8601 UTC timestamp of the agent's most recent heartbeat.
    pub last_seen: String,
    /// Over-permission verdict (AAASM-5175, ADR 0029): `Some(true)` when the
    /// agent is effectively granted a destructive system capability its declared
    /// `RiskTier` baseline does not warrant, `Some(false)` when it was evaluated
    /// and found within baseline. Absent when the agent is *not* evaluated — it
    /// declared no resolvable risk tier, or its policy cascade is empty (in which
    /// case every cell is `Allow` by fall-through and flagging would be a false
    /// positive). This is a structural grant-vs-posture signal, distinct from the
    /// behavioural `trust` score (ADR 0019) and the topology violation-volume flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flagged: Option<bool>,
    /// When `flagged` is `Some(true)`, a human-readable explanation naming the
    /// tier and the offending grants (e.g. "Low-risk agent granted file_delete,
    /// terminal_exec beyond its tier baseline"). Absent otherwise — there is no
    /// operator-authored note source, so a note only ever accompanies a flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Resource-id → CapCell mapping for this agent.
    pub caps: BTreeMap<String, CapCell>,
}

/// Request payload for `POST /api/v1/capability/override` — apply a single
/// (resource, verb, decision) override across one or more agents.
#[derive(Debug, Clone, Deserialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityOverrideRequest {
    /// Agents to apply the override to.
    pub agent_ids: Vec<String>,
    /// Identifier of the resource whose cell is being overridden.
    pub resource_id: String,
    /// Verb (read / write / delete / exec) within the cell.
    pub verb: Verb,
    /// New decision to record for that (resource, verb) pair.
    pub decision: Decision,
    /// Optional TTL in seconds. When set, the override is automatically
    /// reverted to the pre-override value after this duration elapses.
    /// The endpoint returns 201 Created instead of 200 OK when TTL is provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

/// Response envelope for `POST /api/v1/capability/override`: the stable UUID
/// assigned to this override (use it to `DELETE /capability/override/{id}`)
/// plus the subset of agent rows that actually changed.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityOverrideResponse {
    /// Stable UUID for this override; pass to `DELETE /capability/override/{id}` to revert.
    pub override_id: String,
    pub updated: Vec<CapabilityAgent>,
}

/// A recorded capability override entry returned by
/// `GET /api/v1/capability/override`.
///
/// Each `POST /capability/override` call that successfully mutates at least
/// one cell appends one of these records. The log is in-memory and lives as
/// long as the server process; TTL-based expiry is not yet implemented.
#[derive(Debug, Clone, Serialize, ToSchema)]
#[serde(rename_all = "camelCase")]
pub struct OverrideRecord {
    /// Unique identifier for this override entry (UUID v4).
    pub id: String,
    /// Agent identifiers this override was applied to.
    pub agent_ids: Vec<String>,
    /// Resource whose cell was overridden.
    pub resource_id: String,
    /// Verb within the cell that was changed.
    pub verb: Verb,
    /// New decision recorded for that (resource, verb) pair.
    pub decision: Decision,
    /// ISO 8601 UTC timestamp when the override was applied.
    pub created_at: String,
    /// Whether the override is still replayed over the projection. Set to
    /// `false` by an explicit `DELETE /capability/override/{id}` or by the TTL
    /// timer firing; entries are never removed, so a revoked override stays
    /// visible in the log with `active: false`.
    pub active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verb_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&Verb::Read).unwrap(), r#""read""#);
        assert_eq!(serde_json::to_string(&Verb::Write).unwrap(), r#""write""#);
        assert_eq!(serde_json::to_string(&Verb::Delete).unwrap(), r#""delete""#);
        assert_eq!(serde_json::to_string(&Verb::Exec).unwrap(), r#""exec""#);
    }

    #[test]
    fn decision_serializes_lowercase_including_na() {
        assert_eq!(serde_json::to_string(&Decision::Allow).unwrap(), r#""allow""#);
        assert_eq!(serde_json::to_string(&Decision::Narrow).unwrap(), r#""narrow""#);
        assert_eq!(serde_json::to_string(&Decision::Approval).unwrap(), r#""approval""#);
        assert_eq!(serde_json::to_string(&Decision::Deny).unwrap(), r#""deny""#);
        assert_eq!(serde_json::to_string(&Decision::Na).unwrap(), r#""na""#);
    }

    #[test]
    fn verb_deserializes_lowercase() {
        let v: Verb = serde_json::from_str(r#""exec""#).unwrap();
        assert_eq!(v, Verb::Exec);
    }

    #[test]
    fn resource_group_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&ResourceGroup::Comm).unwrap(), r#""comm""#);
        assert_eq!(serde_json::to_string(&ResourceGroup::Files).unwrap(), r#""files""#);
        assert_eq!(serde_json::to_string(&ResourceGroup::Infra).unwrap(), r#""infra""#);
    }

    #[test]
    fn resource_serializes_fields_in_order() {
        let r = Resource {
            id: "pg".to_string(),
            name: "Postgres".to_string(),
            group: Some(ResourceGroup::Data),
            paths: vec!["pg.public.*".to_string(), "pg.public.users".to_string()],
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["id"], "pg");
        assert_eq!(json["name"], "Postgres");
        assert_eq!(json["group"], "data");
        assert_eq!(json["paths"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn cap_cell_omits_flag_when_none() {
        let cell = CapCell {
            read: Decision::Allow,
            write: Decision::Narrow,
            delete: Decision::Deny,
            exec: Decision::Na,
            flag: None,
        };
        let json = serde_json::to_value(&cell).unwrap();
        assert_eq!(json["read"], "allow");
        assert_eq!(json["write"], "narrow");
        assert_eq!(json["delete"], "deny");
        assert_eq!(json["exec"], "na");
        assert!(json.get("flag").is_none(), "flag should be omitted when None");
    }

    #[test]
    fn cap_cell_includes_flag_when_set() {
        let cell = CapCell {
            read: Decision::Allow,
            write: Decision::Allow,
            delete: Decision::Allow,
            exec: Decision::Na,
            flag: Some(true),
        };
        let json = serde_json::to_value(&cell).unwrap();
        assert_eq!(json["flag"], true);
    }

    #[test]
    fn policy_serializes_hits_24h_field_name() {
        let p = Policy {
            id: "policy-1".to_string(),
            name: "Default Policy".to_string(),
            version: Some("1".to_string()),
            scope: "global".to_string(),
            status: PolicyStatus::Active,
            hits_24h: Some(1234),
            affects: vec!["support-triage".to_string()],
            rules: vec![PolicyRule {
                resource: "pg".to_string(),
                verb: vec![Verb::Write, Verb::Delete],
                action: "approval".to_string(),
                condition: "amount > 100".to_string(),
            }],
        };
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["status"], "active");
        assert_eq!(json["hits24h"], 1234, "field must be `hits24h`, not `hits_24h`");
        assert!(json.get("hits_24h").is_none());
        assert_eq!(json["rules"][0]["verb"][0], "write");
    }

    #[test]
    fn capability_agent_emits_trust_null_not_omitted() {
        // AAASM-5104 — `trust` has no data source yet, but the key is always on
        // the wire so the client must handle an explicit "no data" rather than
        // shrug off a missing key with `?? 0`. Same contract as `AgentNode` /
        // `AgentTree`.
        let agent = CapabilityAgent {
            id: "a".to_string(),
            name: "a".to_string(),
            framework: "CrewAI".to_string(),
            owner: None,
            trust: None,
            mode: None,
            status: AgentStatus::Active,
            last_seen: "12s ago".to_string(),
            flagged: None,
            note: None,
            caps: BTreeMap::new(),
        };
        let json = serde_json::to_value(&agent).unwrap();
        assert!(json.get("trust").is_some(), "trust key must be present");
        assert!(json["trust"].is_null(), "trust must serialize as null");
        assert!(!json["trust"].is_number(), "an unmeasured trust must not be a number");
        assert_ne!(json["trust"], 0, "trust must never fold to a scored zero");
    }

    #[test]
    fn capability_agent_deserializes_a_missing_trust_key_as_no_score() {
        // Dropping `skip_serializing_if` must not make the key mandatory on the
        // way in: an older producer that omits it still reads back as "no
        // score", never as a zero.
        let raw = r#"{
            "id": "a",
            "name": "a",
            "framework": "CrewAI",
            "status": "active",
            "lastSeen": "12s ago",
            "caps": {}
        }"#;
        let agent: CapabilityAgent = serde_json::from_str(raw).unwrap();
        assert!(agent.trust.is_none(), "a missing trust key is no score, not 0");
    }

    #[test]
    fn capability_matrix_serializes_sample_calls_in_camel_case() {
        let matrix = CapabilityMatrix {
            resources: vec![],
            agents: vec![],
            policies: vec![],
            sample_calls: vec![],
        };
        let json = serde_json::to_value(&matrix).unwrap();
        assert!(json["resources"].is_array());
        assert!(json["agents"].is_array());
        assert!(json["policies"].is_array());
        assert!(json["sampleCalls"].is_array(), "field must be `sampleCalls`");
        assert!(json.get("sample_calls").is_none());
    }

    #[test]
    fn sample_call_serializes_change_type_kebab_case() {
        let call = SampleCall {
            ts: "2026-04-23T14:23:01Z".to_string(),
            agent: "support-triage".to_string(),
            verb: Verb::Write,
            resource: "pg".to_string(),
            detail: Some("UPDATE users SET ...".to_string()),
            current_decision: Decision::Approval,
            proposed_decision: Some(Decision::Deny),
            change_type: Some(ChangeType::NewlyBlocked),
            fp_reason: None,
        };
        let json = serde_json::to_value(&call).unwrap();
        assert_eq!(json["currentDecision"], "approval");
        assert_eq!(json["proposedDecision"], "deny");
        assert_eq!(json["changeType"], "newly-blocked");
        assert!(json.get("fpReason").is_none());
        assert!(json.get("change_type").is_none(), "snake_case must not appear");
    }

    #[test]
    fn capability_agent_serializes_last_seen_in_camel_case() {
        let mut caps = BTreeMap::new();
        caps.insert(
            "pg".to_string(),
            CapCell {
                read: Decision::Allow,
                write: Decision::Approval,
                delete: Decision::Deny,
                exec: Decision::Na,
                flag: None,
            },
        );
        let agent = CapabilityAgent {
            id: "support-triage".to_string(),
            name: "support-triage".to_string(),
            framework: "CrewAI".to_string(),
            owner: Some("cx-tools".to_string()),
            trust: Some(78),
            mode: Some(AgentMode::Enforce),
            status: AgentStatus::Active,
            last_seen: "12s ago".to_string(),
            flagged: None,
            note: None,
            caps,
        };
        let json = serde_json::to_value(&agent).unwrap();
        assert_eq!(json["id"], "support-triage");
        assert_eq!(json["trust"], 78);
        assert_eq!(json["mode"], "enforce");
        assert_eq!(json["status"], "active");
        assert_eq!(json["lastSeen"], "12s ago", "field must be camelCase");
        assert!(json.get("last_seen").is_none(), "snake_case field must not appear");
        assert!(json.get("flagged").is_none(), "flagged should be omitted when None");
        assert!(json.get("note").is_none(), "note should be omitted when None");
        assert_eq!(json["caps"]["pg"]["write"], "approval");
    }

    #[test]
    fn override_response_serializes_updated_array() {
        let resp = CapabilityOverrideResponse {
            override_id: "test-id".into(),
            updated: vec![],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["overrideId"], "test-id");
        assert!(json["updated"].is_array());
        assert_eq!(json["updated"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn override_request_deserializes_camel_case() {
        let raw = r#"{
            "agentIds": ["support-triage", "research-bot-04"],
            "resourceId": "pg",
            "verb": "write",
            "decision": "deny"
        }"#;
        let req: CapabilityOverrideRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.agent_ids, vec!["support-triage", "research-bot-04"]);
        assert_eq!(req.resource_id, "pg");
        assert_eq!(req.verb, Verb::Write);
        assert_eq!(req.decision, Decision::Deny);
        assert_eq!(req.ttl_seconds, None, "ttl_seconds defaults to None when absent");
    }

    #[test]
    fn override_request_deserializes_ttl_seconds() {
        let raw = r#"{
            "agentIds": ["research-bot-04"],
            "resourceId": "pg",
            "verb": "write",
            "decision": "deny",
            "ttlSeconds": 30
        }"#;
        let req: CapabilityOverrideRequest = serde_json::from_str(raw).unwrap();
        assert_eq!(req.ttl_seconds, Some(30));
    }
}
