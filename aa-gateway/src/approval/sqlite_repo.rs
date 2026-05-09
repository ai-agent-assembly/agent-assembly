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

        // Fall back to team-wide config (approval_kind = '' sentinel).
        fetch_one(&self.pool, team_id, None).await
    }

    async fn upsert(&self, config: TeamRoutingConfig) -> Result<(), RepoError> {
        let approvers = serde_json::to_string(&config.approvers)?;
        let escalation_approvers = serde_json::to_string(&config.escalation_approvers)?;
        // Map None → "" sentinel (SQLite doesn't treat NULLs as equal in PRIMARY KEY).
        let kind_str = config
            .approval_kind
            .as_ref()
            .map(ApprovalKind::as_str)
            .unwrap_or("");
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
                    approval_kind: kind_from_db(&r.approval_kind),
                    approvers: serde_json::from_str(&r.approvers)?,
                    escalation_timeout_secs: r.escalation_timeout_secs as u64,
                    escalation_approvers: serde_json::from_str(&r.escalation_approvers)?,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    async fn in_memory_repo() -> SqliteApprovalRoutingRepo {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        SqliteApprovalRoutingRepo::new(pool).await.unwrap()
    }

    fn cfg(team_id: &str, kind: Option<ApprovalKind>) -> TeamRoutingConfig {
        TeamRoutingConfig {
            team_id: team_id.to_string(),
            approval_kind: kind,
            approvers: vec!["alice".to_string()],
            escalation_timeout_secs: 300,
            escalation_approvers: vec!["manager".to_string()],
        }
    }

    #[tokio::test]
    async fn upsert_and_get_team_wide_config() {
        let repo = in_memory_repo().await;
        repo.upsert(cfg("team-a", None)).await.unwrap();

        let got = repo.get("team-a", None).await.unwrap().unwrap();
        assert_eq!(got.team_id, "team-a");
        assert_eq!(got.approval_kind, None);
        assert_eq!(got.approvers, vec!["alice"]);
    }

    #[tokio::test]
    async fn get_falls_back_to_team_wide_when_no_kind_match() {
        let repo = in_memory_repo().await;
        repo.upsert(cfg("team-b", None)).await.unwrap();

        // Querying with a specific kind falls back to the team-wide config.
        let got = repo.get("team-b", Some(&ApprovalKind::ToolUse)).await.unwrap().unwrap();
        assert_eq!(got.approval_kind, None);
    }

    #[tokio::test]
    async fn kind_specific_config_overrides_team_wide() {
        let repo = in_memory_repo().await;
        repo.upsert(cfg("team-c", None)).await.unwrap();

        let override_cfg = TeamRoutingConfig {
            team_id: "team-c".to_string(),
            approval_kind: Some(ApprovalKind::ToolUse),
            approvers: vec!["bob".to_string()],
            escalation_timeout_secs: 60,
            escalation_approvers: vec![],
        };
        repo.upsert(override_cfg).await.unwrap();

        let got = repo.get("team-c", Some(&ApprovalKind::ToolUse)).await.unwrap().unwrap();
        assert_eq!(got.approvers, vec!["bob"]);
        assert_eq!(got.escalation_timeout_secs, 60);

        // Team-wide fallback is unaffected.
        let fallback = repo.get("team-c", None).await.unwrap().unwrap();
        assert_eq!(fallback.approvers, vec!["alice"]);
    }

    #[tokio::test]
    async fn get_unknown_team_returns_none() {
        let repo = in_memory_repo().await;
        assert!(repo.get("ghost", None).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn upsert_overwrites_existing_config() {
        let repo = in_memory_repo().await;
        repo.upsert(cfg("team-d", None)).await.unwrap();

        let updated = TeamRoutingConfig {
            team_id: "team-d".to_string(),
            approval_kind: None,
            approvers: vec!["carol".to_string()],
            escalation_timeout_secs: 600,
            escalation_approvers: vec![],
        };
        repo.upsert(updated).await.unwrap();

        let got = repo.get("team-d", None).await.unwrap().unwrap();
        assert_eq!(got.approvers, vec!["carol"]);
        assert_eq!(got.escalation_timeout_secs, 600);
    }

    #[tokio::test]
    async fn list_for_team_returns_all_configs() {
        let repo = in_memory_repo().await;
        repo.upsert(cfg("team-e", None)).await.unwrap();
        repo.upsert(cfg("team-e", Some(ApprovalKind::Spawn))).await.unwrap();
        repo.upsert(cfg("team-e", Some(ApprovalKind::ToolUse))).await.unwrap();

        let mut configs = repo.list_for_team("team-e").await.unwrap();
        configs.sort_by_key(|c| c.approval_kind.as_ref().map(|k| k.to_string()));
        assert_eq!(configs.len(), 3);
    }

    #[tokio::test]
    async fn list_for_unknown_team_returns_empty() {
        let repo = in_memory_repo().await;
        let configs = repo.list_for_team("nobody").await.unwrap();
        assert!(configs.is_empty());
    }
}

// ---------------------------------------------------------------------------
// Internal helper
// ---------------------------------------------------------------------------

/// Map a DB `approval_kind` string back to `Option<ApprovalKind>`.
/// The empty string `""` is the sentinel for "team-wide fallback" (None).
fn kind_from_db(s: &str) -> Option<ApprovalKind> {
    if s.is_empty() {
        None
    } else {
        Some(s.parse().expect("ApprovalKind::from_str is infallible"))
    }
}

/// Fetch a single row matching `(team_id, approval_kind)`.
///
/// `approval_kind = None` resolves to the team-wide fallback (stored as `''`).
async fn fetch_one(
    pool: &SqlitePool,
    team_id: &str,
    approval_kind: Option<&str>,
) -> Result<Option<TeamRoutingConfig>, RepoError> {
    let kind_db = approval_kind.unwrap_or("");
    let row = sqlx::query!(
        r#"
        SELECT team_id, approval_kind, approvers, escalation_timeout_secs, escalation_approvers
        FROM approval_routing_config
        WHERE team_id = ? AND approval_kind = ?
        "#,
        team_id,
        kind_db,
    )
    .fetch_optional(pool)
    .await?;

    row.map(|r| {
        Ok(TeamRoutingConfig {
            team_id: r.team_id,
            approval_kind: kind_from_db(&r.approval_kind),
            approvers: serde_json::from_str(&r.approvers)?,
            escalation_timeout_secs: r.escalation_timeout_secs as u64,
            escalation_approvers: serde_json::from_str(&r.escalation_approvers)?,
        })
    })
    .transpose()
}
