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
use axum::response::IntoResponse;
use axum::{Extension, Json};
use tokio::sync::RwLock;

use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;

use axum::extract::Query;

use crate::auth::policy_auth::{PolicyAuthorizationDenied, PolicyWriteAuth};
use crate::error::ProblemDetail;
use crate::models::capability::{
    AgentMode, AgentStatus, CapCell, CapabilityAgent, CapabilityMatrix, CapabilityOverrideRequest,
    CapabilityOverrideResponse, ChangeType, Decision, OverrideRecord, Policy, PolicyRule, PolicyStatus, Resource,
    ResourceGroup, SampleCall, Verb,
};
use crate::state::AppState;

/// Reasons an override request can fail before reaching the handler's
/// response path. Mapped to ProblemDetail by the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverrideError {
    /// The request named an agent id that the store does not know about.
    UnknownAgent(String),
}

/// Thread-safe holder for the dashboard Capability Matrix snapshot.
#[derive(Debug)]
pub struct CapabilityStore {
    inner: RwLock<CapabilityMatrix>,
    /// Append-only log of all override operations applied since startup.
    overrides: RwLock<Vec<OverrideRecord>>,
}

impl CapabilityStore {
    /// Build a store seeded with the dashboard fixture data.
    pub fn new_seeded() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(seeded_matrix()),
            overrides: RwLock::new(vec![]),
        })
    }

    /// Return a cloned snapshot of the matrix.
    pub async fn snapshot(&self) -> CapabilityMatrix {
        self.inner.read().await.clone()
    }

    /// Return all recorded overrides, optionally filtered to those affecting
    /// a specific `agent_id`.
    pub async fn list_overrides(&self, agent_id: Option<&str>) -> Vec<OverrideRecord> {
        let log = self.overrides.read().await;
        match agent_id {
            None => log.clone(),
            Some(id) => log
                .iter()
                .filter(|r| r.agent_ids.iter().any(|a| a == id))
                .cloned()
                .collect(),
        }
    }

    /// Apply a single `(resource_id, verb, decision)` override across the
    /// requested agents and return the rows that changed.
    ///
    /// Rejects unknown `agent_id` values with `OverrideError::UnknownAgent`.
    /// An unknown `resource_id` is silently ignored for that agent (matches
    /// the dashboard mock at `capability.ts::applyOverrideToAgents`).
    ///
    /// On success, appends one [`OverrideRecord`] to the override log so that
    /// `GET /capability/override` can list applied overrides.
    pub async fn apply_override(&self, req: &CapabilityOverrideRequest) -> Result<Vec<CapabilityAgent>, OverrideError> {
        let mut matrix = self.inner.write().await;
        // Validate every requested agent_id up front so a single unknown id
        // rejects the whole request without partial mutation.
        for id in &req.agent_ids {
            if !matrix.agents.iter().any(|a| &a.id == id) {
                return Err(OverrideError::UnknownAgent(id.clone()));
            }
        }
        let mut updated = Vec::with_capacity(req.agent_ids.len());
        for agent in matrix.agents.iter_mut() {
            if !req.agent_ids.contains(&agent.id) {
                continue;
            }
            if let Some(cell) = agent.caps.get_mut(&req.resource_id) {
                match req.verb {
                    Verb::Read => cell.read = req.decision,
                    Verb::Write => cell.write = req.decision,
                    Verb::Delete => cell.delete = req.decision,
                    Verb::Exec => cell.exec = req.decision,
                }
                updated.push(agent.clone());
            }
        }
        // Record the override in the append-only log regardless of whether
        // any cells changed (req may target an unknown resource_id, which is
        // silently skipped but still logged so callers can audit requests).
        drop(matrix);
        let record = OverrideRecord {
            id: uuid::Uuid::new_v4().to_string(),
            agent_ids: req.agent_ids.clone(),
            resource_id: req.resource_id.clone(),
            verb: req.verb,
            decision: req.decision,
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
        };
        self.overrides.write().await.push(record);
        Ok(updated)
    }
}

/// `GET /api/v1/capability/matrix` — return the full agent × resource ×
/// verb × decision matrix that backs the dashboard Capability Matrix page.
///
/// Returns the full snapshot — resources, agents (each with a `caps` map),
/// policies, and sample calls — in the exact shape the dashboard's
/// `CapabilityClient.getMatrix()` consumes.
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

/// `POST /api/v1/capability/override` — apply a capability override across
/// one or more agents. Mutating capability state is treated as a
/// `Global`-scope policy update, so the caller must hold the `OrgAdmin`
/// role (Admin API scope).
///
/// Returns the subset of agent rows that actually changed — the dashboard
/// uses this to drive an optimistic-UI rollback when an override fails.
/// An unknown `agentId` rejects the request with 400 and leaves the store
/// untouched; an unknown `resourceId` on an agent is silently skipped.
#[utoipa::path(
    post,
    path = "/api/v1/capability/override",
    request_body = CapabilityOverrideRequest,
    responses(
        (status = 200, description = "Updated agent rows", body = CapabilityOverrideResponse),
        (status = 400, description = "Unknown agent id"),
        (status = 403, description = "Caller lacks the role required to mutate capability state")
    ),
    tag = "capability"
)]
pub async fn apply_override(
    policy_auth: PolicyWriteAuth,
    Extension(state): Extension<AppState>,
    Json(body): Json<CapabilityOverrideRequest>,
) -> Result<(StatusCode, Json<CapabilityOverrideResponse>), OverrideHandlerError> {
    policy_auth
        .check_mutation(&PolicyScope::Global, MutationKind::Update)
        .map_err(OverrideHandlerError::Forbidden)?;

    let updated = state
        .capability_store
        .apply_override(&body)
        .await
        .map_err(|e| match e {
            OverrideError::UnknownAgent(id) => OverrideHandlerError::BadRequest(
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Unknown agent id: {id}")),
            ),
        })?;

    Ok((StatusCode::OK, Json(CapabilityOverrideResponse { updated })))
}

/// Unified error type for the override handler so 400 and 403 paths render
/// through their respective ProblemDetail / PolicyAuthorizationDenied
/// `IntoResponse` impls.
#[derive(Debug)]
pub enum OverrideHandlerError {
    BadRequest(ProblemDetail),
    Forbidden(PolicyAuthorizationDenied),
}

impl IntoResponse for OverrideHandlerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::BadRequest(p) => p.into_response(),
            Self::Forbidden(d) => d.into_response(),
        }
    }
}

/// Query parameters accepted by `GET /api/v1/capability/override`.
#[derive(serde::Deserialize)]
pub struct ListOverridesParams {
    agent_id: Option<String>,
}

/// `GET /api/v1/capability/override` — list all active capability overrides
/// recorded since the server started, optionally filtered to a single agent.
///
/// The response is an array of [`OverrideRecord`] objects. Each record
/// corresponds to one successful `POST /capability/override` call and carries
/// the agents, resource, verb, decision, and ISO 8601 timestamp of when the
/// override was applied.
#[utoipa::path(
    get,
    path = "/api/v1/capability/override",
    params(("agent_id" = Option<String>, Query, description = "Filter results to overrides that affect this agent id")),
    responses(
        (status = 200, description = "Active override records", body = Vec<OverrideRecord>)
    ),
    tag = "capability"
)]
pub async fn list_overrides(
    Query(params): Query<ListOverridesParams>,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<Vec<OverrideRecord>>) {
    let overrides = state.capability_store.list_overrides(params.agent_id.as_deref()).await;
    (StatusCode::OK, Json(overrides))
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
    async fn apply_override_mutates_targeted_cells_only() {
        let store = CapabilityStore::new_seeded();
        let before = store.snapshot().await;
        let target_agent = before.agents[0].id.clone();
        let untouched_agent = before.agents[1].id.clone();

        let req = CapabilityOverrideRequest {
            agent_ids: vec![target_agent.clone()],
            resource_id: "pg".into(),
            verb: Verb::Write,
            decision: Decision::Deny,
            ttl_seconds: None,
        };
        let updated = store.apply_override(&req).await.unwrap();
        assert_eq!(updated.len(), 1);
        assert_eq!(updated[0].id, target_agent);
        assert_eq!(updated[0].caps.get("pg").unwrap().write, Decision::Deny);

        let after = store.snapshot().await;
        let other_after = after.agents.iter().find(|a| a.id == untouched_agent).unwrap();
        let other_before = before.agents.iter().find(|a| a.id == untouched_agent).unwrap();
        assert_eq!(
            other_after.caps.get("pg").unwrap().write,
            other_before.caps.get("pg").unwrap().write,
            "untouched agent's `pg.write` must be unchanged"
        );
    }

    #[tokio::test]
    async fn apply_override_rejects_unknown_agent() {
        let store = CapabilityStore::new_seeded();
        let err = store
            .apply_override(&CapabilityOverrideRequest {
                agent_ids: vec!["does-not-exist".into()],
                resource_id: "pg".into(),
                verb: Verb::Read,
                decision: Decision::Allow,
                ttl_seconds: None,
            })
            .await
            .unwrap_err();
        assert_eq!(err, OverrideError::UnknownAgent("does-not-exist".into()));
    }

    #[tokio::test]
    async fn apply_override_skips_unknown_resource_silently() {
        let store = CapabilityStore::new_seeded();
        let target = store.snapshot().await.agents[0].id.clone();
        let updated = store
            .apply_override(&CapabilityOverrideRequest {
                agent_ids: vec![target],
                resource_id: "nonexistent-resource".into(),
                verb: Verb::Read,
                decision: Decision::Deny,
                ttl_seconds: None,
            })
            .await
            .unwrap();
        assert!(updated.is_empty(), "agent without that resource cell yields no row");
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
