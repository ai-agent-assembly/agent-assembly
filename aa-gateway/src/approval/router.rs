//! Routes an approval request to the appropriate team approver queue.

use std::sync::Arc;

use aa_core::{AgentContext, AuditEventType};
use aa_runtime::approval::ApprovalRequest;

use super::audit_sink::AuditEventSink;
use super::clock::Clock;
use super::repo::{ApprovalRoutingRepo, RepoError};

// ---------------------------------------------------------------------------
// RoutingDecision
// ---------------------------------------------------------------------------

/// The outcome of routing an [`ApprovalRequest`] through the team config.
#[derive(Debug, Clone, PartialEq)]
pub struct RoutingDecision {
    /// Team identifier, or `None` for orphan / root agents.
    pub team_id: Option<String>,
    /// Role of the initial approval target (`"TeamAdmin"` or `"OrgAdmin"`).
    pub target_role: String,
    /// Role to escalate to when the escalation timer fires.
    pub escalation_role: String,
    /// Unix timestamp (seconds) at which escalation should fire.
    pub escalate_at: u64,
}

// ---------------------------------------------------------------------------
// RouterError
// ---------------------------------------------------------------------------

/// Error returned by [`ApprovalRouter::route`].
#[derive(Debug, thiserror::Error)]
pub enum RouterError {
    #[error("approval routing repo error: {0}")]
    Repo(#[from] RepoError),
}

// ---------------------------------------------------------------------------
// ApprovalRouter
// ---------------------------------------------------------------------------

/// Routes approval requests to team-specific approvers.
///
/// Resolution order:
/// 1. If `ctx.team_id` is `None` (orphan agent), routes directly to `OrgAdmin`.
/// 2. Otherwise looks up the team config via the injected [`ApprovalRoutingRepo`]
///    (which always falls back to the global default when no explicit row exists).
/// 3. Per-policy overrides on the request take priority over team-level values.
///
/// Emits an [`AuditEventType::ApprovalRouted`] event for every call.
pub struct ApprovalRouter {
    repo: Arc<dyn ApprovalRoutingRepo>,
    audit_sink: Arc<dyn AuditEventSink>,
    clock: Arc<dyn Clock>,
}

impl ApprovalRouter {
    pub fn new(
        repo: Arc<dyn ApprovalRoutingRepo>,
        audit_sink: Arc<dyn AuditEventSink>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { repo, audit_sink, clock }
    }

    /// Route `approval` based on the agent's execution context.
    ///
    /// The caller is responsible for persisting the returned `RoutingDecision`
    /// (e.g. writing `routing_status = "routed_to_team_admin"` to the approval
    /// row and inserting a `pending_escalations` entry at `escalate_at`).
    pub async fn route(
        &self,
        approval: &ApprovalRequest,
        ctx: &AgentContext,
    ) -> Result<RoutingDecision, RouterError> {
        let now = self.clock.now_secs();

        let decision = match ctx.team_id.as_deref() {
            None => {
                // Orphan / root agent: no team → route directly to OrgAdmin.
                let timeout = approval.timeout_override_secs.unwrap_or(approval.timeout_secs);
                RoutingDecision {
                    team_id: None,
                    target_role: "OrgAdmin".to_string(),
                    escalation_role: "OrgAdmin".to_string(),
                    escalate_at: now + timeout,
                }
            }
            Some(team_id) => {
                let config = self.repo.get(team_id, None).await?;
                let effective_timeout = approval
                    .timeout_override_secs
                    .unwrap_or(config.escalation_timeout_secs);
                let effective_escalation_role = approval
                    .escalation_role_override
                    .clone()
                    .or_else(|| config.escalation_approvers.into_iter().next())
                    .unwrap_or_else(|| "OrgAdmin".to_string());

                RoutingDecision {
                    team_id: Some(team_id.to_string()),
                    target_role: "TeamAdmin".to_string(),
                    escalation_role: effective_escalation_role,
                    escalate_at: now + effective_timeout,
                }
            }
        };

        let payload = serde_json::json!({
            "approval_id": approval.request_id.to_string(),
            "team_id": decision.team_id,
            "target_role": decision.target_role,
        })
        .to_string();
        self.audit_sink.emit(AuditEventType::ApprovalRouted, payload);

        Ok(decision)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use aa_core::identity::{AgentId, SessionId};
    use aa_core::time::Timestamp;
    use aa_core::{AgentContext, GovernanceLevel};
    use aa_runtime::approval::ApprovalRequest;
    use sqlx::SqlitePool;
    use uuid::Uuid;

    use super::*;
    use crate::approval::audit_sink::NoopAuditSink;
    use crate::approval::clock::FakeClock;
    use crate::approval::routing_config::TeamRoutingConfig;
    use crate::approval::sqlite_repo::SqliteApprovalRoutingRepo;

    async fn in_memory_repo() -> SqliteApprovalRoutingRepo {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        SqliteApprovalRoutingRepo::new(pool).await.unwrap()
    }

    fn make_ctx(team_id: Option<&str>) -> AgentContext {
        AgentContext {
            agent_id: AgentId::from_bytes([0u8; 16]),
            session_id: SessionId::from_bytes([0u8; 16]),
            pid: 1,
            started_at: Timestamp::from_nanos(0),
            metadata: BTreeMap::new(),
            governance_level: GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: team_id.map(str::to_string),
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        }
    }

    fn make_approval(timeout_secs: u64) -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "delete_db".to_string(),
            condition_triggered: "requires_approval".to_string(),
            submitted_at: 0,
            timeout_secs,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: None,
            timeout_override_secs: None,
            escalation_role_override: None,
        }
    }

    fn make_router(repo: SqliteApprovalRoutingRepo, now_secs: u64) -> ApprovalRouter {
        ApprovalRouter::new(
            Arc::new(repo),
            Arc::new(NoopAuditSink),
            Arc::new(FakeClock::new(now_secs)),
        )
    }

    #[tokio::test]
    async fn team_routed_path_returns_team_admin_decision() {
        let repo = in_memory_repo().await;
        repo.upsert(TeamRoutingConfig {
            team_id: "team-alpha".to_string(),
            approval_kind: None,
            approvers: vec!["alice".to_string()],
            escalation_timeout_secs: 300,
            escalation_approvers: vec!["manager".to_string()],
        })
        .await
        .unwrap();

        let router = make_router(repo, 1000);
        let ctx = make_ctx(Some("team-alpha"));
        let approval = make_approval(60);

        let decision = router.route(&approval, &ctx).await.unwrap();

        assert_eq!(decision.team_id, Some("team-alpha".to_string()));
        assert_eq!(decision.target_role, "TeamAdmin");
        assert_eq!(decision.escalation_role, "manager");
        assert_eq!(decision.escalate_at, 1000 + 300);
    }

    #[tokio::test]
    async fn orphan_path_routes_to_org_admin() {
        let repo = in_memory_repo().await;
        let router = make_router(repo, 2000);
        let ctx = make_ctx(None);
        let approval = make_approval(120);

        let decision = router.route(&approval, &ctx).await.unwrap();

        assert_eq!(decision.team_id, None);
        assert_eq!(decision.target_role, "OrgAdmin");
        assert_eq!(decision.escalation_role, "OrgAdmin");
        assert_eq!(decision.escalate_at, 2000 + 120);
    }

    #[tokio::test]
    async fn per_policy_override_takes_priority_over_team_config() {
        let repo = in_memory_repo().await;
        repo.upsert(TeamRoutingConfig {
            team_id: "team-beta".to_string(),
            approval_kind: None,
            approvers: vec!["bob".to_string()],
            escalation_timeout_secs: 1800,
            escalation_approvers: vec!["team-lead".to_string()],
        })
        .await
        .unwrap();

        let router = make_router(repo, 3000);
        let ctx = make_ctx(Some("team-beta"));
        let approval = ApprovalRequest {
            timeout_override_secs: Some(60),
            escalation_role_override: Some("SecurityTeam".to_string()),
            ..make_approval(300)
        };

        let decision = router.route(&approval, &ctx).await.unwrap();

        assert_eq!(decision.team_id, Some("team-beta".to_string()));
        assert_eq!(decision.target_role, "TeamAdmin");
        assert_eq!(decision.escalation_role, "SecurityTeam");
        assert_eq!(decision.escalate_at, 3000 + 60);
    }

    #[tokio::test]
    async fn unknown_team_uses_global_default_config() {
        let repo = in_memory_repo().await;
        let router = make_router(repo, 4000);
        let ctx = make_ctx(Some("ghost-team"));
        let approval = make_approval(60);

        let decision = router.route(&approval, &ctx).await.unwrap();

        assert_eq!(decision.team_id, Some("ghost-team".to_string()));
        assert_eq!(decision.target_role, "TeamAdmin");
        assert_eq!(decision.escalation_role, "OrgAdmin"); // global default
        assert_eq!(decision.escalate_at, 4000 + 1800); // DEFAULT_ESCALATION_TIMEOUT_SECS
    }
}
