//! SQLite-backed implementation of [`ApprovalRoutingRepo`].

use async_trait::async_trait;
use sqlx::SqlitePool;

use aa_core::ApprovalKind;

use super::repo::{ApprovalRoutingRepo, RepoError};
use super::routing_config::TeamRoutingConfig;

/// SQLite-backed store for team-level approval routing configuration.
///
/// Runs all pending migrations on [`new`][Self::new] so the table is always
/// present before the first query.
pub struct SqliteApprovalRoutingRepo {
    pool: SqlitePool,
}

impl SqliteApprovalRoutingRepo {
    /// Create a new repo and run pending migrations against `pool`.
    pub async fn new(pool: SqlitePool) -> Result<Self, RepoError> {
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

#[async_trait]
impl ApprovalRoutingRepo for SqliteApprovalRoutingRepo {
    async fn get(
        &self,
        team_id: &str,
        approval_kind: Option<&ApprovalKind>,
    ) -> Result<Option<TeamRoutingConfig>, RepoError> {
        let kind_str = approval_kind.map(ApprovalKind::as_str);

        // Try exact (team_id, approval_kind) match first.
        if let Some(k) = kind_str {
            if let Some(cfg) = fetch_one(&self.pool, team_id, Some(k)).await? {
                return Ok(Some(cfg));
            }
        }

        // Fall back to team-wide config (approval_kind IS NULL).
        fetch_one(&self.pool, team_id, None).await
    }

    async fn upsert(&self, config: TeamRoutingConfig) -> Result<(), RepoError> {
        let approvers = serde_json::to_string(&config.approvers)?;
        let escalation_approvers = serde_json::to_string(&config.escalation_approvers)?;
        let kind_str = config.approval_kind.as_ref().map(ApprovalKind::as_str);
        let escalation_timeout = config.escalation_timeout_secs as i64;

        sqlx::query!(
            r#"
            INSERT INTO approval_routing_config
                (team_id, approval_kind, approvers, escalation_timeout_secs, escalation_approvers)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(team_id, approval_kind) DO UPDATE SET
                approvers                = excluded.approvers,
                escalation_timeout_secs  = excluded.escalation_timeout_secs,
                escalation_approvers     = excluded.escalation_approvers
            "#,
            config.team_id,
            kind_str,
            approvers,
            escalation_timeout,
            escalation_approvers,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    async fn list_for_team(&self, team_id: &str) -> Result<Vec<TeamRoutingConfig>, RepoError> {
        let rows = sqlx::query!(
            r#"
            SELECT team_id, approval_kind, approvers, escalation_timeout_secs, escalation_approvers
            FROM approval_routing_config
            WHERE team_id = ?
            "#,
            team_id,
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| {
                Ok(TeamRoutingConfig {
                    team_id: r.team_id,
                    approval_kind: r
                        .approval_kind
                        .map(|s| s.parse().expect("ApprovalKind::from_str is infallible")),
                    approvers: serde_json::from_str(&r.approvers)?,
                    escalation_timeout_secs: r.escalation_timeout_secs as u64,
                    escalation_approvers: serde_json::from_str(&r.escalation_approvers)?,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Fetch a single row matching `(team_id, approval_kind)`.
///
/// Uses SQLite's `IS` operator so a `NULL` binding correctly matches rows
/// where `approval_kind IS NULL` (the team-wide fallback).
async fn fetch_one(
    pool: &SqlitePool,
    team_id: &str,
    approval_kind: Option<&str>,
) -> Result<Option<TeamRoutingConfig>, RepoError> {
    let row = sqlx::query!(
        r#"
        SELECT team_id, approval_kind, approvers, escalation_timeout_secs, escalation_approvers
        FROM approval_routing_config
        WHERE team_id = ? AND approval_kind IS ?
        "#,
        team_id,
        approval_kind,
    )
    .fetch_optional(pool)
    .await?;

    row.map(|r| {
        Ok(TeamRoutingConfig {
            team_id: r.team_id,
            approval_kind: r
                .approval_kind
                .map(|s| s.parse().expect("ApprovalKind::from_str is infallible")),
            approvers: serde_json::from_str(&r.approvers)?,
            escalation_timeout_secs: r.escalation_timeout_secs as u64,
            escalation_approvers: serde_json::from_str(&r.escalation_approvers)?,
        })
    })
    .transpose()
}
