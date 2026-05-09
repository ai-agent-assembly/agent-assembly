//! Repository trait for team-level approval routing configuration.

use async_trait::async_trait;

use aa_core::ApprovalKind;

use super::routing_config::TeamRoutingConfig;

/// Global default timeout (seconds) applied when no team config row exists.
pub const DEFAULT_ESCALATION_TIMEOUT_SECS: u64 = 1800;

/// Global default escalation role applied when no team config row exists.
pub const DEFAULT_ESCALATION_ROLE: &str = "OrgAdmin";

/// Error type returned by all repository operations.
#[derive(Debug, thiserror::Error)]
pub enum RepoError {
    #[error("approval routing repo database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("approval routing repo migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),
    #[error("approval routing repo serialisation error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Build the global-default [`TeamRoutingConfig`] for a team that has no
/// explicit routing configuration row.
///
/// Defaults: 1800 s timeout, `OrgAdmin` as both primary and escalation approver.
pub fn global_default(team_id: &str, approval_kind: Option<ApprovalKind>) -> TeamRoutingConfig {
    TeamRoutingConfig {
        team_id: team_id.to_string(),
        approval_kind,
        approvers: vec![DEFAULT_ESCALATION_ROLE.to_string()],
        escalation_timeout_secs: DEFAULT_ESCALATION_TIMEOUT_SECS,
        escalation_approvers: vec![DEFAULT_ESCALATION_ROLE.to_string()],
    }
}

/// Persistent store for team-level approval routing configuration.
///
/// [`get`] always returns a config: it resolves in order
/// (exact kind → team-wide → global default), so callers never receive `None`.
///
/// [`get`]: ApprovalRoutingRepo::get
#[async_trait]
pub trait ApprovalRoutingRepo: Send + Sync {
    /// Return the most-specific routing config for `(team_id, approval_kind)`.
    ///
    /// Resolution order:
    /// 1. `(team_id, Some(approval_kind))` — exact kind match
    /// 2. `(team_id, None)` — team-wide fallback
    /// 3. Global default `(1800 s, OrgAdmin)` — when no row exists for the team
    async fn get(&self, team_id: &str, approval_kind: Option<&ApprovalKind>) -> Result<TeamRoutingConfig, RepoError>;

    /// Insert or replace the routing config for `(team_id, approval_kind)`.
    async fn upsert(&self, config: TeamRoutingConfig) -> Result<(), RepoError>;

    /// Return all routing configs registered for `team_id`.
    ///
    /// Includes both the team-wide fallback (if present) and all kind-specific
    /// overrides. Returns an empty `Vec` when no config exists for the team;
    /// this is distinct from [`get`] which always falls back to the global default.
    ///
    /// [`get`]: ApprovalRoutingRepo::get
    async fn list_for_team(&self, team_id: &str) -> Result<Vec<TeamRoutingConfig>, RepoError>;
}
