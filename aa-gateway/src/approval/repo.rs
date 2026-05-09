//! Repository trait for team-level approval routing configuration.

use async_trait::async_trait;

use aa_core::ApprovalKind;

use super::routing_config::TeamRoutingConfig;

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

/// Persistent store for team-level approval routing configuration.
///
/// Look up with [`get`] using the narrowest match first
/// (`team_id` + `approval_kind`), then fall back to the team-wide config
/// (`team_id` + `None`).
///
/// [`get`]: ApprovalRoutingRepo::get
#[async_trait]
pub trait ApprovalRoutingRepo: Send + Sync {
    /// Return the most-specific routing config for `(team_id, approval_kind)`.
    ///
    /// Resolution order:
    /// 1. `(team_id, Some(approval_kind))` — exact kind match
    /// 2. `(team_id, None)` — team-wide fallback
    ///
    /// Returns `None` when no config exists for the team.
    async fn get(
        &self,
        team_id: &str,
        approval_kind: Option<&ApprovalKind>,
    ) -> Result<Option<TeamRoutingConfig>, RepoError>;

    /// Insert or replace the routing config for `(team_id, approval_kind)`.
    async fn upsert(&self, config: TeamRoutingConfig) -> Result<(), RepoError>;

    /// Return all routing configs registered for `team_id`.
    ///
    /// Includes both the team-wide fallback (if present) and all kind-specific
    /// overrides.
    async fn list_for_team(&self, team_id: &str) -> Result<Vec<TeamRoutingConfig>, RepoError>;
}
