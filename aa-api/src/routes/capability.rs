//! Capability matrix endpoints (AAASM-1366).
//!
//! The store holds an in-memory `CapabilityMatrix` seeded to mirror the
//! dashboard's typed mock client (`dashboard/src/api/capability.ts`). This
//! lets the dashboard swap the mock for the generated `openapi-fetch`
//! client without a shape change; a follow-up Story can replace the seed
//! with a live projection from the policy engine.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::{Extension, Json};
use tokio::sync::RwLock;

use crate::models::capability::{
    AgentMode, AgentStatus, CapCell, CapabilityAgent, CapabilityMatrix, ChangeType, Decision, Policy, PolicyRule,
    PolicyStatus, Resource, ResourceGroup, SampleCall, Verb,
};
use crate::state::AppState;

/// Thread-safe holder for the dashboard Capability Matrix snapshot.
#[derive(Debug)]
pub struct CapabilityStore {
    inner: RwLock<CapabilityMatrix>,
}

impl CapabilityStore {
    /// Build a store seeded with the dashboard fixture data.
    pub fn new_seeded() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(seeded_matrix()),
        })
    }

    /// Return a cloned snapshot of the matrix.
    pub async fn snapshot(&self) -> CapabilityMatrix {
        self.inner.read().await.clone()
    }
}

/// `GET /api/v1/capability/matrix` — return the full agent × resource ×
/// verb × decision matrix that backs the dashboard Capability Matrix page.
#[utoipa::path(
    get,
    path = "/api/v1/capability/matrix",
    responses(
        (status = 200, description = "Full capability matrix snapshot", body = CapabilityMatrix)
    ),
    tag = "capability"
)]
pub async fn get_matrix(Extension(state): Extension<AppState>) -> (StatusCode, Json<CapabilityMatrix>) {
    let matrix = state.capability_store.snapshot().await;
    (StatusCode::OK, Json(matrix))
}

// ── Seed data — kept in sync with `dashboard/src/features/capability/fixtures.ts` ──

fn seeded_matrix() -> CapabilityMatrix {
    CapabilityMatrix {
        resources: seeded_resources(),
        agents: seeded_agents(),
        policies: seeded_policies(),
        sample_calls: seeded_sample_calls(),
    }
}

fn resource(id: &str, name: &str, group: ResourceGroup, paths: &[&str]) -> Resource {
    Resource {
        id: id.to_string(),
        name: name.to_string(),
        group,
        paths: paths.iter().map(|p| (*p).to_string()).collect(),
    }
}

fn seeded_resources() -> Vec<Resource> {
    vec![
        resource(
            "gmail",
            "Gmail",
            ResourceGroup::Comm,
            &[
                "gmail/*",
                "gmail/labels/INBOX/*",
                "gmail/labels/INBOX/read",
                "gmail/send",
            ],
        ),
        resource(
            "gdrive",
            "Google Drive",
            ResourceGroup::Files,
            &["gdrive/*", "gdrive/shared/*", "gdrive/personal/*"],
        ),
        resource(
            "s3",
            "AWS S3",
            ResourceGroup::Files,
            &["s3://*", "s3://reports/*", "s3://customer-pii/*"],
        ),
        resource(
            "pg",
            "Postgres",
            ResourceGroup::Data,
            &[
                "pg.public.*",
                "pg.public.users",
                "pg.public.orders",
                "pg.public.audit_log",
            ],
        ),
        resource("shell", "Shell exec", ResourceGroup::Infra, &["shell:*"]),
        resource("http", "HTTP egress", ResourceGroup::Infra, &["http://*", "https://*"]),
        resource(
            "github",
            "GitHub",
            ResourceGroup::Code,
            &["github.com/acme/*", "github.com/acme/infra/*"],
        ),
        resource(
            "slack",
            "Slack",
            ResourceGroup::Comm,
            &["slack/channels/*", "slack/dm/*"],
        ),
    ]
}

fn cell(read: Decision, write: Decision, delete: Decision, exec: Decision, flag: bool) -> CapCell {
    CapCell {
        read,
        write,
        delete,
        exec,
        flag: if flag { Some(true) } else { None },
    }
}

fn caps_for(entries: &[(&str, CapCell)]) -> BTreeMap<String, CapCell> {
    entries.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect()
}

fn seeded_agents() -> Vec<CapabilityAgent> {
    use Decision::*;
    vec![
        CapabilityAgent {
            id: "research-bot-04".into(),
            name: "research-bot-04".into(),
            framework: "LangChain".into(),
            owner: "data-platform".into(),
            trust: 42,
            mode: AgentMode::Enforce,
            status: AgentStatus::Active,
            last_seen: "2m ago".into(),
            flagged: Some(true),
            note: Some("over-permissioned · 6 resources still allow, 4 narrowed, 0 deny".into()),
            caps: caps_for(&[
                ("gmail", cell(Allow, Allow, Allow, Na, true)),
                ("gdrive", cell(Allow, Narrow, Allow, Na, true)),
                ("s3", cell(Allow, Allow, Approval, Na, true)),
                ("pg", cell(Allow, Approval, Deny, Na, false)),
                ("shell", cell(Na, Na, Na, Allow, true)),
                ("http", cell(Allow, Allow, Na, Na, true)),
                ("github", cell(Allow, Narrow, Deny, Na, false)),
                ("slack", cell(Allow, Narrow, Na, Na, false)),
            ]),
        },
        CapabilityAgent {
            id: "support-triage".into(),
            name: "support-triage".into(),
            framework: "CrewAI".into(),
            owner: "cx-tools".into(),
            trust: 78,
            mode: AgentMode::Enforce,
            status: AgentStatus::Active,
            last_seen: "12s ago".into(),
            flagged: None,
            note: None,
            caps: caps_for(&[
                ("gmail", cell(Allow, Narrow, Deny, Na, false)),
                ("gdrive", cell(Narrow, Deny, Deny, Na, false)),
                ("s3", cell(Narrow, Deny, Deny, Na, false)),
                ("pg", cell(Narrow, Approval, Deny, Na, false)),
                ("shell", cell(Na, Na, Na, Deny, false)),
                ("http", cell(Narrow, Narrow, Na, Na, false)),
                ("github", cell(Narrow, Deny, Deny, Na, false)),
                ("slack", cell(Allow, Narrow, Na, Na, false)),
            ]),
        },
        CapabilityAgent {
            id: "infra-ops-bot".into(),
            name: "infra-ops-bot".into(),
            framework: "AutoGen".into(),
            owner: "platform".into(),
            trust: 88,
            mode: AgentMode::Enforce,
            status: AgentStatus::Active,
            last_seen: "1m ago".into(),
            flagged: None,
            note: None,
            caps: caps_for(&[
                ("gmail", cell(Deny, Deny, Deny, Na, false)),
                ("gdrive", cell(Deny, Deny, Deny, Na, false)),
                ("s3", cell(Narrow, Narrow, Approval, Na, false)),
                ("pg", cell(Narrow, Narrow, Approval, Na, false)),
                ("shell", cell(Na, Na, Na, Narrow, false)),
                ("http", cell(Allow, Narrow, Na, Na, false)),
                ("github", cell(Allow, Narrow, Approval, Na, false)),
                ("slack", cell(Narrow, Approval, Na, Na, false)),
            ]),
        },
        CapabilityAgent {
            id: "analytics-runner".into(),
            name: "analytics-runner".into(),
            framework: "LangChain".into(),
            owner: "analytics".into(),
            trust: 71,
            mode: AgentMode::Enforce,
            status: AgentStatus::Active,
            last_seen: "4s ago".into(),
            flagged: None,
            note: None,
            caps: caps_for(&[
                ("gmail", cell(Deny, Deny, Deny, Na, false)),
                ("gdrive", cell(Narrow, Deny, Deny, Na, false)),
                ("s3", cell(Allow, Narrow, Deny, Na, false)),
                ("pg", cell(Allow, Narrow, Deny, Na, false)),
                ("shell", cell(Na, Na, Na, Deny, false)),
                ("http", cell(Narrow, Deny, Na, Na, false)),
                ("github", cell(Narrow, Deny, Deny, Na, false)),
                ("slack", cell(Narrow, Deny, Na, Na, false)),
            ]),
        },
    ]
}

fn seeded_policies() -> Vec<Policy> {
    vec![
        Policy {
            id: "platform-baseline".into(),
            name: "Platform baseline".into(),
            version: "v3".into(),
            scope: "global".into(),
            status: PolicyStatus::Active,
            hits_24h: 1284,
            affects: vec!["research-bot-04".into(), "support-triage".into()],
            rules: vec![
                PolicyRule {
                    resource: "shell".into(),
                    verb: vec![Verb::Exec],
                    action: "deny".into(),
                    condition: "trust < 60".into(),
                },
                PolicyRule {
                    resource: "pg".into(),
                    verb: vec![Verb::Write, Verb::Delete],
                    action: "approval".into(),
                    condition: "table in (public.users, public.orders)".into(),
                },
            ],
        },
        Policy {
            id: "pii-guardrail".into(),
            name: "PII guardrail".into(),
            version: "v1".into(),
            scope: "team:cx-tools".into(),
            status: PolicyStatus::Proposed,
            hits_24h: 0,
            affects: vec!["support-triage".into()],
            rules: vec![PolicyRule {
                resource: "s3".into(),
                verb: vec![Verb::Read],
                action: "narrow".into(),
                condition: "prefix = customer-pii/".into(),
            }],
        },
    ]
}

fn seeded_sample_calls() -> Vec<SampleCall> {
    vec![
        SampleCall {
            ts: "2026-04-23T14:23:01Z".into(),
            agent: "support-triage".into(),
            verb: Verb::Read,
            resource: "pg".into(),
            detail: Some("SELECT * FROM public.users WHERE id = 4521".into()),
            current_decision: Decision::Allow,
            proposed_decision: None,
            change_type: Some(ChangeType::Unchanged),
            fp_reason: None,
        },
        SampleCall {
            ts: "2026-04-23T14:24:00Z".into(),
            agent: "support-triage".into(),
            verb: Verb::Write,
            resource: "pg".into(),
            detail: Some("UPDATE public.orders SET refund = 250 WHERE id = 99".into()),
            current_decision: Decision::Approval,
            proposed_decision: Some(Decision::Deny),
            change_type: Some(ChangeType::NewlyBlocked),
            fp_reason: None,
        },
        SampleCall {
            ts: "2026-04-23T15:01:00Z".into(),
            agent: "research-bot-04".into(),
            verb: Verb::Exec,
            resource: "shell".into(),
            detail: Some("bash -c 'curl http://unauthorized'".into()),
            current_decision: Decision::Allow,
            proposed_decision: Some(Decision::Deny),
            change_type: Some(ChangeType::NewlyBlocked),
            fp_reason: None,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seeded_store_contains_eight_resources() {
        let store = CapabilityStore::new_seeded();
        let m = store.snapshot().await;
        assert_eq!(m.resources.len(), 8);
        let ids: Vec<&str> = m.resources.iter().map(|r| r.id.as_str()).collect();
        assert!(ids.contains(&"pg"));
        assert!(ids.contains(&"shell"));
    }

    #[tokio::test]
    async fn every_agent_has_a_cell_for_every_resource() {
        let store = CapabilityStore::new_seeded();
        let m = store.snapshot().await;
        let resource_ids: Vec<&str> = m.resources.iter().map(|r| r.id.as_str()).collect();
        assert!(!m.agents.is_empty());
        for agent in &m.agents {
            for rid in &resource_ids {
                assert!(
                    agent.caps.contains_key(*rid),
                    "agent {} missing cell for resource {rid}",
                    agent.id
                );
            }
        }
    }
}
