//! Capability matrix endpoints (AAASM-1366).
//!
//! The store holds an in-memory `CapabilityMatrix` seeded to mirror the
//! dashboard's typed mock client (`dashboard/src/api/capability.ts`). This
//! lets the dashboard swap the mock for the generated `openapi-fetch`
//! client without a shape change; a follow-up Story can replace the seed
//! with a live projection from the policy engine.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Path;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::{Extension, Json};
use serde::Deserialize;
use tokio::sync::RwLock;
use utoipa::IntoParams;
use uuid::Uuid;

use aa_gateway::policy::rbac::MutationKind;
use aa_gateway::policy::scope::PolicyScope;

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

/// Pre-mutation snapshot of a single (agent, resource, verb) cell, used to
/// restore the original decision when a TTL expires.
#[derive(Debug, Clone)]
struct CellSnapshot {
    agent_id: String,
    resource_id: String,
    verb: Verb,
    original: Decision,
}

/// Reasons a revoke request can fail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeOverrideError {
    /// No active override with the supplied id exists.
    NotFound,
}

/// Per-agent revert record — tracks the pre-override cell value so
/// `DELETE /capability/override/{id}` can restore each cell individually.
#[derive(Debug, Clone)]
struct RevertRecord {
    override_id: String,
    agent_id: String,
    resource_id: String,
    verb: Verb,
    prev_decision: Decision,
}

/// Thread-safe holder for the dashboard Capability Matrix snapshot, the
/// append-only override log (for `GET /capability/override`), and the
/// per-agent revert records (for `DELETE /capability/override/{id}`).
#[derive(Debug)]
pub struct CapabilityStore {
    inner: RwLock<CapabilityMatrix>,
    /// Append-only log of all override operations applied since startup.
    overrides: RwLock<Vec<OverrideRecord>>,
    /// Per-agent pre-override cell values used to revert on DELETE.
    revert_records: RwLock<Vec<RevertRecord>>,
}

impl CapabilityStore {
    /// Build a store seeded with the dashboard fixture data.
    pub fn new_seeded() -> Arc<Self> {
        Arc::new(Self {
            inner: RwLock::new(seeded_matrix()),
            overrides: RwLock::new(vec![]),
            revert_records: RwLock::new(Vec::new()),
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
    /// requested agents.  Returns a stable UUID for the override plus the
    /// agent rows that actually changed.
    ///
    /// Rejects unknown `agent_id` values with `OverrideError::UnknownAgent`.
    /// An unknown `resource_id` is silently ignored for that agent (matches
    /// the dashboard mock at `capability.ts::applyOverrideToAgents`).
    ///
    /// On success, appends one [`OverrideRecord`] to the override log so
    /// `GET /capability/override` can list applied overrides, and records
    /// per-agent revert data so `DELETE /capability/override/{id}` can undo.
    ///
    /// When `req.ttl_seconds` is `Some(n)`, a background Tokio task is spawned
    /// that sleeps for `n` seconds then reverts the affected cells to their
    /// pre-override decisions. The `Arc<Self>` receiver is required so the
    /// background task can hold a reference to the store beyond the call.
    pub async fn apply_override(
        self: Arc<Self>,
        req: &CapabilityOverrideRequest,
    ) -> Result<(String, Vec<CapabilityAgent>), OverrideError> {
        let override_id = Uuid::new_v4().to_string();
        let (updated, revert_items, snapshots) = {
            let mut matrix = self.inner.write().await;
            // Validate every requested agent_id up front so a single unknown id
            // rejects the whole request without partial mutation.
            for id in &req.agent_ids {
                if !matrix.agents.iter().any(|a| &a.id == id) {
                    return Err(OverrideError::UnknownAgent(id.clone()));
                }
            }

            let mut updated = Vec::with_capacity(req.agent_ids.len());
            let mut revert_items: Vec<RevertRecord> = Vec::new();
            let mut snapshots: Vec<CellSnapshot> = Vec::new();
            for agent in matrix.agents.iter_mut() {
                if !req.agent_ids.contains(&agent.id) {
                    continue;
                }
                if let Some(cell) = agent.caps.get_mut(&req.resource_id) {
                    let prev_decision = match req.verb {
                        Verb::Read => cell.read,
                        Verb::Write => cell.write,
                        Verb::Delete => cell.delete,
                        Verb::Exec => cell.exec,
                    };
                    revert_items.push(RevertRecord {
                        override_id: override_id.clone(),
                        agent_id: agent.id.clone(),
                        resource_id: req.resource_id.clone(),
                        verb: req.verb,
                        prev_decision,
                    });
                    snapshots.push(CellSnapshot {
                        agent_id: agent.id.clone(),
                        resource_id: req.resource_id.clone(),
                        verb: req.verb,
                        original: prev_decision,
                    });
                    match req.verb {
                        Verb::Read => cell.read = req.decision,
                        Verb::Write => cell.write = req.decision,
                        Verb::Delete => cell.delete = req.decision,
                        Verb::Exec => cell.exec = req.decision,
                    }
                    updated.push(agent.clone());
                }
            }
            (updated, revert_items, snapshots)
        };
        // Persist revert records for DELETE support.
        self.revert_records.write().await.extend(revert_items);
        // Append to the override log regardless of whether any cells changed
        // (unknown resource_id is silently skipped but still logged).
        let log_entry = OverrideRecord {
            id: override_id.clone(),
            agent_ids: req.agent_ids.clone(),
            resource_id: req.resource_id.clone(),
            verb: req.verb,
            decision: req.decision,
            created_at: chrono::Utc::now().to_rfc3339(),
            active: true,
        };
        self.overrides.write().await.push(log_entry);

        if let Some(ttl_secs) = req.ttl_seconds {
            let store = Arc::clone(&self);
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(ttl_secs)).await;
                store.revert_override(snapshots).await;
            });
        }

        Ok((override_id, updated))
    }

    /// Revert all cell changes made by the override identified by `id`,
    /// remove its revert records, and mark the log entry as inactive.
    ///
    /// Returns `RevokeOverrideError::NotFound` when no active override with
    /// that id exists.
    pub async fn revoke_override(&self, id: &str) -> Result<(), RevokeOverrideError> {
        let records: Vec<RevertRecord> = self
            .revert_records
            .read()
            .await
            .iter()
            .filter(|r| r.override_id == id)
            .cloned()
            .collect();
        if records.is_empty() {
            return Err(RevokeOverrideError::NotFound);
        }
        {
            let mut matrix = self.inner.write().await;
            for record in &records {
                if let Some(agent) = matrix.agents.iter_mut().find(|a| a.id == record.agent_id) {
                    if let Some(cell) = agent.caps.get_mut(&record.resource_id) {
                        match record.verb {
                            Verb::Read => cell.read = record.prev_decision,
                            Verb::Write => cell.write = record.prev_decision,
                            Verb::Delete => cell.delete = record.prev_decision,
                            Verb::Exec => cell.exec = record.prev_decision,
                        }
                    }
                }
            }
        }
        self.revert_records.write().await.retain(|r| r.override_id != id);
        // Mark the log entry inactive so GET /capability/override reflects the revocation.
        for entry in self.overrides.write().await.iter_mut() {
            if entry.id == id {
                entry.active = false;
            }
        }
        Ok(())
    }

    /// Restore cell decisions to their pre-override values. Called by the
    /// background TTL expiry task spawned in `apply_override`.
    async fn revert_override(&self, snapshots: Vec<CellSnapshot>) {
        let mut matrix = self.inner.write().await;
        for snap in snapshots {
            if let Some(agent) = matrix.agents.iter_mut().find(|a| a.id == snap.agent_id) {
                if let Some(cell) = agent.caps.get_mut(&snap.resource_id) {
                    match snap.verb {
                        Verb::Read => cell.read = snap.original,
                        Verb::Write => cell.write = snap.original,
                        Verb::Delete => cell.delete = snap.original,
                        Verb::Exec => cell.exec = snap.original,
                    }
                }
            }
        }
    }
}

/// Query parameters for `GET /api/v1/capability/matrix`.
#[derive(Debug, Default, Deserialize, IntoParams)]
pub struct MatrixQueryParams {
    /// Return only the agent row whose `id` matches this value.
    #[param(example = "research-bot-04")]
    pub team_id: Option<String>,
    /// Return only the resource column whose `id` matches this value, and
    /// filter each agent's caps map to that single resource key.
    #[param(example = "gmail")]
    pub tool: Option<String>,
    /// When `true`, exclude capability cells where all four verb decisions are `na`.
    #[param(example = true)]
    pub effective_only: Option<bool>,
}

/// `GET /api/v1/capability/matrix` — return the agent × resource × verb ×
/// decision matrix that backs the dashboard Capability Matrix page.
///
/// Optional filters:
/// - `team_id` — return only the agent row whose `id` matches.
/// - `tool` — return only the resource column whose `id` matches and filter
///   each agent's `caps` map to that single key.
/// - `effective_only=true` — exclude cells where all four verb decisions are `na`.
#[utoipa::path(
    get,
    path = "/api/v1/capability/matrix",
    params(MatrixQueryParams),
    responses(
        (status = 200, description = "Capability matrix snapshot (filtered)", body = CapabilityMatrix)
    ),
    tag = "capability"
)]
pub async fn get_matrix(
    Query(params): Query<MatrixQueryParams>,
    Extension(state): Extension<AppState>,
) -> (StatusCode, Json<CapabilityMatrix>) {
    let mut matrix = state.capability_store.snapshot().await;

    if let Some(ref tid) = params.team_id {
        matrix.agents.retain(|a| &a.id == tid);
    }

    if let Some(ref tool) = params.tool {
        matrix.resources.retain(|r| &r.id == tool);
        for agent in &mut matrix.agents {
            agent.caps.retain(|k, _| k == tool);
        }
    }

    if params.effective_only == Some(true) {
        use Decision::Na;
        for agent in &mut matrix.agents {
            agent
                .caps
                .retain(|_, cell| !(cell.read == Na && cell.write == Na && cell.delete == Na && cell.exec == Na));
        }
    }

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
///
/// When `ttlSeconds` is present the override is automatically reverted after
/// that many seconds and the response status is **201 Created**. Without a
/// TTL the response is **200 OK** (unchanged behaviour).
#[utoipa::path(
    post,
    path = "/api/v1/capability/override",
    request_body = CapabilityOverrideRequest,
    responses(
        (status = 200, description = "Updated agent rows (no TTL)", body = CapabilityOverrideResponse),
        (status = 201, description = "Updated agent rows with TTL scheduled", body = CapabilityOverrideResponse),
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

    let has_ttl = body.ttl_seconds.is_some();
    let (override_id, updated) = Arc::clone(&state.capability_store)
        .apply_override(&body)
        .await
        .map_err(|e| match e {
            OverrideError::UnknownAgent(id) => OverrideHandlerError::BadRequest(
                ProblemDetail::from_status(StatusCode::BAD_REQUEST).with_detail(format!("Unknown agent id: {id}")),
            ),
        })?;

    let status = if has_ttl { StatusCode::CREATED } else { StatusCode::OK };
    Ok((status, Json(CapabilityOverrideResponse { override_id, updated })))
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

/// `DELETE /api/v1/capability/override/{id}` — revert a previously applied
/// capability override, restoring each affected cell to its pre-override value.
///
/// Returns 204 No Content on success.  Returns 404 when no active override
/// with the supplied `id` exists (either it was never created or has already
/// been revoked).
#[utoipa::path(
    delete,
    path = "/api/v1/capability/override/{id}",
    params(
        ("id" = String, Path, description = "UUID of the override to revoke")
    ),
    responses(
        (status = 204, description = "Override revoked; cells restored to base policy"),
        (status = 404, description = "No active override with this id", body = ProblemDetail)
    ),
    tag = "capability"
)]
pub async fn revoke_override(Extension(state): Extension<AppState>, Path(id): Path<String>) -> impl IntoResponse {
    match state.capability_store.revoke_override(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(RevokeOverrideError::NotFound) => ProblemDetail::from_status(StatusCode::NOT_FOUND)
            .with_detail(format!("No active override with id: {id}"))
            .with_instance(format!("/api/v1/capability/override/{id}"))
            .into_response(),
    }
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
        let (_override_id, updated) = Arc::clone(&store).apply_override(&req).await.unwrap();
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
        let err = Arc::clone(&store)
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
        let (_override_id, updated) = Arc::clone(&store)
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
