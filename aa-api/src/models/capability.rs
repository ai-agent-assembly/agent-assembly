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
    /// Stable identifier (e.g. `"gmail"`, `"pg"`, `"shell"`).
    pub id: String,
    /// Human-readable display name (e.g. `"Postgres"`).
    pub name: String,
    /// Coarse group this resource belongs to.
    pub group: ResourceGroup,
    /// Globbed paths covered by this resource (e.g. `["pg.public.*"]`).
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
    /// Marks this cell for UI attention (e.g. over-permissioned).
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
    pub version: String,
    pub scope: String,
    pub status: PolicyStatus,
    /// Number of times this policy fired in the last 24 hours.
    #[serde(rename = "hits24h")]
    pub hits_24h: u64,
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
    pub id: String,
    pub name: String,
    pub framework: String,
    pub owner: String,
    /// Trust score on a 0–100 scale.
    pub trust: u8,
    pub mode: AgentMode,
    pub status: AgentStatus,
    /// Human-readable relative-time string (e.g. `"2m ago"`).
    pub last_seen: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flagged: Option<bool>,
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
            group: ResourceGroup::Data,
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
            version: "1".to_string(),
            scope: "global".to_string(),
            status: PolicyStatus::Active,
            hits_24h: 1234,
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
            owner: "cx-tools".to_string(),
            trust: 78,
            mode: AgentMode::Enforce,
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
    }
}
