//! [`PgUserStore`] — native email/password account persistence (AAASM-5304).
//!
//! The Postgres-gated data layer for ADR 0031 native accounts: users, invites,
//! and refresh-token sessions. Every method is tenant-scoped through the same
//! `begin_for_tenant` RLS seam the other stores use, so a row is only ever read
//! or written under its verified `org_id` (never client input).
//!
//! This is the data layer only — no HTTP, no JWT minting, no request wiring
//! (that is AAASM-5305). Secrets are handled safely here: the password is stored
//! as the argon2id hash the caller passes in (minted by
//! `aa_auth::password::hash_password`), and invite/refresh tokens are stored only
//! as their SHA-256 hash — never the raw token.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use aa_storage::Result;

use crate::pool::PostgresPool;
use crate::support::backend_err;

/// The role of a native account, persisted as the `user_role` Postgres enum.
///
/// Kept storage-local (rather than importing `aa_auth::role::Role`) so this pure
/// data driver does not take a dependency on the axum-based HTTP auth crate. The
/// string values match `aa_auth::role::Role` one-for-one, so the presentation
/// layer maps between them by name (AAASM-5305).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserRole {
    /// Workspace owner (first bootstrapped account).
    Owner,
    /// Administrator.
    Admin,
    /// Developer.
    Developer,
    /// Viewer.
    Viewer,
}

impl UserRole {
    /// The lowercase `user_role` enum label for this role.
    pub fn as_str(self) -> &'static str {
        match self {
            UserRole::Owner => "owner",
            UserRole::Admin => "admin",
            UserRole::Developer => "developer",
            UserRole::Viewer => "viewer",
        }
    }

    /// Parse a `user_role` enum label read back from the database.
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "owner" => Some(UserRole::Owner),
            "admin" => Some(UserRole::Admin),
            "developer" => Some(UserRole::Developer),
            "viewer" => Some(UserRole::Viewer),
            _ => None,
        }
    }
}

/// The lifecycle status of a native account, persisted as the `user_status`
/// Postgres enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserStatus {
    /// The account is active and may authenticate.
    Active,
    /// The account was created by an invite that has not yet been accepted.
    Invited,
    /// The account is disabled and may not authenticate.
    Disabled,
}

impl UserStatus {
    /// The lowercase `user_status` enum label for this status.
    pub fn as_str(self) -> &'static str {
        match self {
            UserStatus::Active => "active",
            UserStatus::Invited => "invited",
            UserStatus::Disabled => "disabled",
        }
    }

    /// Parse a `user_status` enum label read back from the database.
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(UserStatus::Active),
            "invited" => Some(UserStatus::Invited),
            "disabled" => Some(UserStatus::Disabled),
            _ => None,
        }
    }
}

/// A native account as stored. `password_hash` is the argon2id PHC string; it is
/// carried here for the authentication path (verify) and must never be logged or
/// returned on any wire.
#[derive(Debug, Clone)]
pub struct UserRecord {
    /// Account id.
    pub id: Uuid,
    /// Case-insensitive email (as stored; comparison folds case).
    pub email: String,
    /// argon2id PHC-encoded password hash.
    pub password_hash: String,
    /// The tenant (org) this account belongs to.
    pub org_id: Uuid,
    /// The account's role.
    pub role: UserRole,
    /// The account's lifecycle status.
    pub status: UserStatus,
    /// When the account was created.
    pub created_at: DateTime<Utc>,
    /// When the account was last updated.
    pub updated_at: DateTime<Utc>,
    /// When the account last logged in, if ever.
    pub last_login_at: Option<DateTime<Utc>>,
}

/// The fields needed to create a native account.
#[derive(Debug, Clone)]
pub struct NewUser {
    /// Account id (caller-generated so the same id can be referenced elsewhere
    /// in the creating transaction later).
    pub id: Uuid,
    /// The account email (stored case-insensitively).
    pub email: String,
    /// The argon2id PHC-encoded password hash (from `aa_auth::password`).
    pub password_hash: String,
    /// The account's role.
    pub role: UserRole,
    /// The account's initial status.
    pub status: UserStatus,
}

/// A pending invite as stored. Only `token_hash` (a SHA-256 of the raw invite
/// token) is persisted — the raw token is never stored.
#[derive(Debug, Clone)]
pub struct InviteRecord {
    /// Invite id.
    pub id: Uuid,
    /// SHA-256 hash of the raw invite token.
    pub token_hash: String,
    /// The invited email.
    pub email: String,
    /// The tenant (org) the invite grants access to.
    pub org_id: Uuid,
    /// The role the accepted account will receive.
    pub role: UserRole,
    /// When the invite expires.
    pub expires_at: DateTime<Utc>,
    /// The user who issued the invite, if recorded.
    pub invited_by: Option<Uuid>,
    /// When the invite was consumed, if it has been.
    pub consumed_at: Option<DateTime<Utc>>,
}

/// The fields needed to create an invite.
#[derive(Debug, Clone)]
pub struct NewInvite {
    /// Invite id (caller-generated).
    pub id: Uuid,
    /// SHA-256 hash of the raw invite token (never the raw token).
    pub token_hash: String,
    /// The invited email.
    pub email: String,
    /// The role the accepted account will receive.
    pub role: UserRole,
    /// When the invite expires.
    pub expires_at: DateTime<Utc>,
    /// The user issuing the invite, if known.
    pub invited_by: Option<Uuid>,
}

/// Postgres-backed store for native accounts, invites, and refresh sessions.
///
/// Every method takes the verified tenant `org_id` and runs under the RLS GUC
/// for that tenant, so a caller can only touch its own tenant's rows.
#[derive(Clone)]
pub struct PgUserStore {
    pool: PostgresPool,
}

impl PgUserStore {
    /// Build a user store over an existing pool.
    pub fn new(pool: PostgresPool) -> Self {
        Self { pool }
    }

    /// Create a native account under the verified tenant `org_id`.
    ///
    /// The RLS `WITH CHECK` rejects any attempt to create the row for a tenant
    /// other than the connection's GUC. `email` uniqueness is case-insensitive
    /// (citext); a duplicate surfaces as [`aa_storage::StorageError::Backend`]
    /// from the unique-index violation.
    pub async fn create_user(&self, org_id: Uuid, user: &NewUser) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO users (id, email, password_hash, org_id, role, status) \
             VALUES ($1, $2, $3, $4, $5::user_role, $6::user_status)",
        )
        .bind(user.id)
        .bind(&user.email)
        .bind(&user.password_hash)
        .bind(org_id)
        .bind(user.role.as_str())
        .bind(user.status.as_str())
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    /// Find a native account by email within the verified tenant `org_id`.
    ///
    /// Email comparison is case-insensitive (citext). Returns `Ok(None)` when no
    /// account matches (or the row belongs to another RLS-invisible tenant).
    pub async fn find_by_email(&self, org_id: Uuid, email: &str) -> Result<Option<UserRecord>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        // `$1::citext` forces the case-insensitive citext comparison: a bound
        // `text` parameter otherwise resolves `email = $1` to case-sensitive
        // `text = text`, silently defeating the case-insensitive lookup.
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, org_id, role::text AS role, status::text AS status, \
                    created_at, updated_at, last_login_at \
             FROM users WHERE email = $1::citext",
        )
        .bind(email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        row.map(UserRow::into_record).transpose()
    }

    /// Create a pending invite under the verified tenant `org_id`.
    pub async fn create_invite(&self, org_id: Uuid, invite: &NewInvite) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO user_invites (id, token_hash, email, org_id, role, expires_at, invited_by) \
             VALUES ($1, $2, $3, $4, $5::user_role, $6, $7)",
        )
        .bind(invite.id)
        .bind(&invite.token_hash)
        .bind(&invite.email)
        .bind(org_id)
        .bind(invite.role.as_str())
        .bind(invite.expires_at)
        .bind(invite.invited_by)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    /// Atomically consume a single-use invite by its `token_hash` under the
    /// verified tenant `org_id`, returning the consumed invite.
    ///
    /// Single-use is enforced in the UPDATE: only an invite that is not yet
    /// consumed and not yet expired is stamped and returned. A missing, already
    /// consumed, expired, or RLS-invisible invite yields `Ok(None)` — so a replay
    /// of an accepted token gets nothing. The row is returned so the caller
    /// (AAASM-5305) can create the account against its role/email/org.
    pub async fn consume_invite(&self, org_id: Uuid, token_hash: &str) -> Result<Option<InviteRecord>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<InviteRow> = sqlx::query_as(
            "UPDATE user_invites \
                SET consumed_at = now() \
              WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
          RETURNING id, token_hash, email, org_id, role::text AS role, expires_at, invited_by, consumed_at",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        row.map(InviteRow::into_record).transpose()
    }

    /// Store a refresh-token session under the verified tenant `org_id`.
    ///
    /// Only `token_hash` (a SHA-256 of the opaque refresh token) is persisted.
    /// `user_id` must belong to the same tenant; the RLS `WITH CHECK` rejects a
    /// mismatched-tenant write.
    pub async fn store_refresh_token(
        &self,
        org_id: Uuid,
        id: Uuid,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "INSERT INTO refresh_tokens (id, token_hash, user_id, org_id, expires_at) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(token_hash)
        .bind(user_id)
        .bind(org_id)
        .bind(expires_at)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    /// Revoke a refresh token by its `token_hash` under the verified tenant
    /// `org_id`.
    ///
    /// Idempotent: stamps `revoked_at` on a live token; revoking a missing,
    /// already-revoked, or RLS-invisible token affects zero rows and still
    /// succeeds. Returns `true` when a live token was revoked by this call.
    pub async fn revoke_refresh_token(&self, org_id: Uuid, token_hash: &str) -> Result<bool> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let result = sqlx::query(
            "UPDATE refresh_tokens SET revoked_at = now() \
              WHERE token_hash = $1 AND revoked_at IS NULL",
        )
        .bind(token_hash)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(result.rows_affected() > 0)
    }
}

/// Raw `users` row as read from Postgres (role/status come back as `text` via the
/// `::text` cast in the SELECT). Converted to [`UserRecord`] by [`into_record`].
#[derive(sqlx::FromRow)]
struct UserRow {
    id: Uuid,
    email: String,
    password_hash: String,
    org_id: Uuid,
    role: String,
    status: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    last_login_at: Option<DateTime<Utc>>,
}

impl UserRow {
    fn into_record(self) -> Result<UserRecord> {
        let role = UserRole::from_str(&self.role)
            .ok_or_else(|| aa_storage::StorageError::Backend(format!("unknown user_role `{}`", self.role)))?;
        let status = UserStatus::from_str(&self.status)
            .ok_or_else(|| aa_storage::StorageError::Backend(format!("unknown user_status `{}`", self.status)))?;
        Ok(UserRecord {
            id: self.id,
            email: self.email,
            password_hash: self.password_hash,
            org_id: self.org_id,
            role,
            status,
            created_at: self.created_at,
            updated_at: self.updated_at,
            last_login_at: self.last_login_at,
        })
    }
}

/// Raw `user_invites` row as read from Postgres (role via `::text`).
#[derive(sqlx::FromRow)]
struct InviteRow {
    id: Uuid,
    token_hash: String,
    email: String,
    org_id: Uuid,
    role: String,
    expires_at: DateTime<Utc>,
    invited_by: Option<Uuid>,
    consumed_at: Option<DateTime<Utc>>,
}

impl InviteRow {
    fn into_record(self) -> Result<InviteRecord> {
        let role = UserRole::from_str(&self.role)
            .ok_or_else(|| aa_storage::StorageError::Backend(format!("unknown user_role `{}`", self.role)))?;
        Ok(InviteRecord {
            id: self.id,
            token_hash: self.token_hash,
            email: self.email,
            org_id: self.org_id,
            role,
            expires_at: self.expires_at,
            invited_by: self.invited_by,
            consumed_at: self.consumed_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_role_str_roundtrips() {
        for role in [UserRole::Owner, UserRole::Admin, UserRole::Developer, UserRole::Viewer] {
            assert_eq!(UserRole::from_str(role.as_str()), Some(role));
        }
        assert_eq!(UserRole::from_str("nope"), None);
    }

    #[test]
    fn user_status_str_roundtrips() {
        for status in [UserStatus::Active, UserStatus::Invited, UserStatus::Disabled] {
            assert_eq!(UserStatus::from_str(status.as_str()), Some(status));
        }
        assert_eq!(UserStatus::from_str("nope"), None);
    }

    #[test]
    fn user_role_labels_match_the_migration_enum() {
        assert_eq!(UserRole::Owner.as_str(), "owner");
        assert_eq!(UserRole::Admin.as_str(), "admin");
        assert_eq!(UserRole::Developer.as_str(), "developer");
        assert_eq!(UserRole::Viewer.as_str(), "viewer");
    }
}
