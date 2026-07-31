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

/// A refresh-token session as stored (AAASM-5305). Only the hash is persisted;
/// this is the record the refresh path reads to rotate a live token.
#[derive(Debug, Clone)]
pub struct RefreshTokenRecord {
    /// Session id.
    pub id: Uuid,
    /// The user this session belongs to.
    pub user_id: Uuid,
    /// The tenant (org) the session belongs to.
    pub org_id: Uuid,
    /// When the session expires.
    pub expires_at: DateTime<Utc>,
    /// When the session was revoked, if it has been.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl RefreshTokenRecord {
    /// Whether this session is currently usable: not revoked and not expired.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// A consumed password-reset token (AAASM-5306, ADR 0031 §Q4). Only the hash is
/// persisted; this is the record the confirm path reads back after atomically
/// spending a single-use token, so it can set the new password for the right
/// account. The raw token is never stored or returned.
#[derive(Debug, Clone)]
pub struct ResetTokenRecord {
    /// Reset-token id.
    pub id: Uuid,
    /// The account this reset targets.
    pub user_id: Uuid,
    /// The tenant (org) the reset belongs to.
    pub org_id: Uuid,
    /// When the token expires.
    pub expires_at: DateTime<Utc>,
}

/// The lockout state of an account (AAASM-5305, ADR 0031 brute-force control).
///
/// Returned by the failed-attempt counter methods so the login handler can map a
/// locked account to `423 Locked` + a `retry-after` without re-reading the row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockoutState {
    /// Consecutive failed attempts recorded for the account.
    pub failed_count: i32,
    /// When the account is locked until, if it is currently locked.
    pub locked_until: Option<DateTime<Utc>>,
}

impl LockoutState {
    /// Seconds remaining in the lockout window relative to `now`, or `None` when
    /// the account is not currently locked.
    pub fn retry_after_secs(&self, now: DateTime<Utc>) -> Option<u64> {
        self.locked_until.and_then(|until| {
            let remaining = (until - now).num_seconds();
            (remaining > 0).then_some(remaining as u64)
        })
    }
}

/// The outcome of an atomic first-user bootstrap attempt (AAASM-5305, ADR 0031
/// §4 / security "bootstrap race").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    /// This call created the first account as `owner` of the default workspace.
    /// Carries the tenant the account was created under so the caller can mint a
    /// tenant-scoped JWT.
    CreatedOwner {
        /// The default workspace (org) the owner now belongs to.
        org_id: Uuid,
    },
    /// A user already existed, so the bootstrap did not run. The caller decides
    /// between `403` (registration closed) and the open-registration path.
    AlreadyBootstrapped {
        /// The default workspace (org) open-registration accounts join.
        org_id: Uuid,
    },
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

    /// Look up a live-or-dead refresh session by its `token_hash` under the
    /// verified tenant `org_id` (AAASM-5305).
    ///
    /// Returns the row (including `revoked_at` / `expires_at`) so the refresh
    /// path can decide whether it may be rotated; a missing or RLS-invisible
    /// token yields `Ok(None)`. Liveness is [`RefreshTokenRecord::is_live`] — the
    /// caller checks it rather than the query, so an expired/revoked token is
    /// distinguishable from an absent one.
    pub async fn find_refresh_token(&self, org_id: Uuid, token_hash: &str) -> Result<Option<RefreshTokenRecord>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<RefreshTokenRow> = sqlx::query_as(
            "SELECT id, user_id, org_id, expires_at, revoked_at \
               FROM refresh_tokens WHERE token_hash = $1",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(row.map(RefreshTokenRow::into_record))
    }

    /// Find a native account by id within the verified tenant `org_id`
    /// (AAASM-5305).
    ///
    /// Used by the refresh path to reload the account behind a valid refresh
    /// session so the rotated access token carries the account's current role
    /// and status. Returns `Ok(None)` when no such account is visible.
    pub async fn find_by_id(&self, org_id: Uuid, user_id: Uuid) -> Result<Option<UserRecord>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<UserRow> = sqlx::query_as(
            "SELECT id, email, password_hash, org_id, role::text AS role, status::text AS status, \
                    created_at, updated_at, last_login_at \
             FROM users WHERE id = $1",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        row.map(UserRow::into_record).transpose()
    }

    /// Atomically bootstrap the first account as `owner`, or report that the
    /// workspace is already bootstrapped (AAASM-5305, ADR 0031 §4 + security
    /// "bootstrap race").
    ///
    /// The whole check-then-create runs in a single transaction guarded by a
    /// transaction-scoped advisory lock (`pg_advisory_xact_lock`), so two
    /// concurrent registrations cannot both observe an empty table and both
    /// claim `owner` — the second waits on the lock, then sees the row the first
    /// inserted and returns [`BootstrapOutcome::AlreadyBootstrapped`]. The
    /// default workspace org is created on demand (idempotently) so a fresh
    /// instance needs no seeding step. The new user is created `active`.
    pub async fn bootstrap_first_user(
        &self,
        default_org_id: Uuid,
        default_org_name: &str,
        new_user_id: Uuid,
        email: &str,
        password_hash: &str,
    ) -> Result<BootstrapOutcome> {
        let mut tx = self.pool.begin_for_tenant(default_org_id).await.map_err(backend_err)?;

        // Serialise every bootstrap attempt on one well-known advisory key so the
        // count-then-insert is race-free. The lock releases at transaction end.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(BOOTSTRAP_ADVISORY_KEY)
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;

        // Ensure the single default workspace exists. Idempotent: a second
        // bootstrap attempt (or a re-run after a crash) is a no-op.
        sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
            .bind(default_org_id)
            .bind(default_org_name)
            .execute(&mut *tx)
            .await
            .map_err(backend_err)?;

        // Count under the advisory lock AND the tenant GUC: the count only sees
        // this tenant's users (RLS), which is exactly the single-workspace scope.
        let existing: i64 = sqlx::query_scalar("SELECT count(*) FROM users")
            .fetch_one(&mut *tx)
            .await
            .map_err(backend_err)?;

        if existing > 0 {
            tx.commit().await.map_err(backend_err)?;
            return Ok(BootstrapOutcome::AlreadyBootstrapped { org_id: default_org_id });
        }

        sqlx::query(
            "INSERT INTO users (id, email, password_hash, org_id, role, status) \
             VALUES ($1, $2, $3, $4, 'owner'::user_role, 'active'::user_status)",
        )
        .bind(new_user_id)
        .bind(email)
        .bind(password_hash)
        .bind(default_org_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;

        tx.commit().await.map_err(backend_err)?;
        Ok(BootstrapOutcome::CreatedOwner { org_id: default_org_id })
    }

    /// Activate an invited account by setting its initial password hash and
    /// flipping its status to `active` (AAASM-5305).
    ///
    /// Only a row currently in `invited` status is activated; a missing, already
    /// active/disabled, or RLS-invisible user affects zero rows. Returns `true`
    /// when this call activated the account. The invite itself is consumed
    /// separately via [`consume_invite`](Self::consume_invite); this is the
    /// account-side half of accepting an invite.
    pub async fn activate_invited_user(&self, org_id: Uuid, user_id: Uuid, password_hash: &str) -> Result<bool> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let result = sqlx::query(
            "UPDATE users SET password_hash = $1, status = 'active'::user_status, updated_at = now() \
              WHERE id = $2 AND status = 'invited'::user_status",
        )
        .bind(password_hash)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(result.rows_affected() > 0)
    }

    /// Read the current lockout state of an account (AAASM-5305).
    ///
    /// Returns the zero state when no counter row exists yet (an account that has
    /// never failed a login). The login handler consults this *before* verifying
    /// the password so a locked account is refused with `423` regardless of
    /// whether the supplied password is correct.
    pub async fn lockout_state(&self, org_id: Uuid, user_id: Uuid) -> Result<LockoutState> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<(i32, Option<DateTime<Utc>>)> =
            sqlx::query_as("SELECT failed_count, locked_until FROM login_attempts WHERE user_id = $1")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(row.map_or(
            LockoutState {
                failed_count: 0,
                locked_until: None,
            },
            |(failed_count, locked_until)| LockoutState {
                failed_count,
                locked_until,
            },
        ))
    }

    /// Record a failed login attempt, locking the account for `lock_secs` once
    /// `threshold` consecutive failures are reached (AAASM-5305).
    ///
    /// Atomic upsert: the counter row is created or its `failed_count`
    /// incremented, and `locked_until` is set to `now() + lock_secs` when the new
    /// count meets or exceeds `threshold`. Returns the resulting
    /// [`LockoutState`]. The counter lives in Postgres (never memory) so it
    /// survives a restart and is shared across processes (ADR 0031).
    pub async fn record_login_failure(
        &self,
        org_id: Uuid,
        user_id: Uuid,
        threshold: i32,
        lock_secs: i64,
    ) -> Result<LockoutState> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: (i32, Option<DateTime<Utc>>) = sqlx::query_as(
            "INSERT INTO login_attempts (user_id, org_id, failed_count, locked_until, updated_at) \
             VALUES ($1, $2, 1, NULL, now()) \
             ON CONFLICT (user_id) DO UPDATE SET \
                 failed_count = login_attempts.failed_count + 1, \
                 locked_until = CASE WHEN login_attempts.failed_count + 1 >= $3 \
                                     THEN now() + make_interval(secs => $4) \
                                     ELSE login_attempts.locked_until END, \
                 updated_at = now() \
             RETURNING failed_count, locked_until",
        )
        .bind(user_id)
        .bind(org_id)
        .bind(threshold)
        .bind(lock_secs as f64)
        .fetch_one(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(LockoutState {
            failed_count: row.0,
            locked_until: row.1,
        })
    }

    /// Clear an account's failed-attempt counter after a successful login
    /// (AAASM-5305).
    ///
    /// Idempotent: resets `failed_count` to zero and clears `locked_until` for the
    /// account, affecting zero rows when no counter exists.
    pub async fn clear_login_failures(&self, org_id: Uuid, user_id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        sqlx::query(
            "UPDATE login_attempts SET failed_count = 0, locked_until = NULL, updated_at = now() \
              WHERE user_id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(())
    }

    /// Store a single-use, expiring password-reset token under the verified
    /// tenant `org_id` (AAASM-5306, ADR 0031 §Q4).
    ///
    /// Only `token_hash` (a SHA-256 of the opaque reset token) is persisted — the
    /// raw token is emailed to the account owner and never stored. `user_id` must
    /// belong to the same tenant; the RLS `WITH CHECK` rejects a mismatched-tenant
    /// write.
    pub async fn create_reset_token(
        &self,
        org_id: Uuid,
        id: Uuid,
        token_hash: &str,
        user_id: Uuid,
        expires_at: DateTime<Utc>,
    ) -> Result<()> {
        self.execute_in_tenant(
            org_id,
            sqlx::query(
                "INSERT INTO password_reset_tokens (id, token_hash, user_id, org_id, expires_at) \
                 VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(id)
            .bind(token_hash)
            .bind(user_id)
            .bind(org_id)
            .bind(expires_at),
        )
        .await
        .map(|_| ())
    }

    /// Atomically consume a single-use password-reset token by its `token_hash`
    /// under the verified tenant `org_id`, returning the token it spent
    /// (AAASM-5306, ADR 0031 §Q4).
    ///
    /// Single-use is enforced in the UPDATE: only a token that is not yet consumed
    /// and not yet expired is stamped and returned. A missing, already consumed,
    /// expired, or RLS-invisible token yields `Ok(None)` — so a replay of a spent
    /// token gets nothing, exactly like [`consume_invite`](Self::consume_invite).
    /// The record is returned so the caller can set the new password for the
    /// right account.
    pub async fn consume_reset_token(&self, org_id: Uuid, token_hash: &str) -> Result<Option<ResetTokenRecord>> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let row: Option<ResetTokenRow> = sqlx::query_as(
            "UPDATE password_reset_tokens \
                SET consumed_at = now() \
              WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now() \
          RETURNING id, user_id, org_id, expires_at",
        )
        .bind(token_hash)
        .fetch_optional(&mut *tx)
        .await
        .map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(row.map(ResetTokenRow::into_record))
    }

    /// Set an account's password hash under the verified tenant `org_id`
    /// (AAASM-5306).
    ///
    /// Used by the reset-confirm path to install the freshly argon2id-hashed
    /// password. Only an `active` account is updated — a reset must never
    /// resurrect a disabled account or clobber an invited (never-accepted) one.
    /// Returns `true` when this call updated the account; a missing, non-active,
    /// or RLS-invisible user affects zero rows and returns `false`.
    pub async fn set_password(&self, org_id: Uuid, user_id: Uuid, password_hash: &str) -> Result<bool> {
        let affected = self
            .execute_in_tenant(
                org_id,
                sqlx::query(
                    "UPDATE users SET password_hash = $1, updated_at = now() \
                      WHERE id = $2 AND status = 'active'::user_status",
                )
                .bind(password_hash)
                .bind(user_id),
            )
            .await?;
        Ok(affected > 0)
    }

    /// Revoke every outstanding (unrevoked) refresh session for an account under
    /// the verified tenant `org_id` (AAASM-5306).
    ///
    /// Called after a password reset so an attacker who already held a live
    /// session is forced back to the login screen (ADR 0031 §Q4: a reset
    /// invalidates outstanding sessions). Idempotent: stamps `revoked_at` on
    /// every live token for the user and returns how many it revoked; an account
    /// with no live sessions affects zero rows.
    pub async fn revoke_all_refresh_tokens(&self, org_id: Uuid, user_id: Uuid) -> Result<u64> {
        self.execute_in_tenant(
            org_id,
            sqlx::query(
                "UPDATE refresh_tokens SET revoked_at = now() \
                  WHERE user_id = $1 AND revoked_at IS NULL",
            )
            .bind(user_id),
        )
        .await
    }

    /// Run a single write `query` inside a tenant-scoped transaction and return
    /// the number of rows affected.
    ///
    /// Factors out the `begin_for_tenant` → `execute` → `commit` scaffolding that
    /// every single-statement write in this store repeats, so the RLS seam is
    /// applied identically in one place. Read/`RETURNING` queries keep their own
    /// bodies because they map a row back.
    async fn execute_in_tenant<'q>(
        &self,
        org_id: Uuid,
        query: sqlx::query::Query<'q, sqlx::Postgres, sqlx::postgres::PgArguments>,
    ) -> Result<u64> {
        let mut tx = self.pool.begin_for_tenant(org_id).await.map_err(backend_err)?;
        let result = query.execute(&mut *tx).await.map_err(backend_err)?;
        tx.commit().await.map_err(backend_err)?;
        Ok(result.rows_affected())
    }
}

/// Advisory-lock key serialising first-user bootstrap attempts. An arbitrary
/// fixed 64-bit constant unique to this concern.
const BOOTSTRAP_ADVISORY_KEY: i64 = 0x5305_0001_B007_57A9_u64 as i64;

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

/// Raw `refresh_tokens` row as read from Postgres (AAASM-5305).
#[derive(sqlx::FromRow)]
struct RefreshTokenRow {
    id: Uuid,
    user_id: Uuid,
    org_id: Uuid,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl RefreshTokenRow {
    fn into_record(self) -> RefreshTokenRecord {
        RefreshTokenRecord {
            id: self.id,
            user_id: self.user_id,
            org_id: self.org_id,
            expires_at: self.expires_at,
            revoked_at: self.revoked_at,
        }
    }
}

/// Raw `password_reset_tokens` row as read from Postgres (AAASM-5306).
#[derive(sqlx::FromRow)]
struct ResetTokenRow {
    id: Uuid,
    user_id: Uuid,
    org_id: Uuid,
    expires_at: DateTime<Utc>,
}

impl ResetTokenRow {
    fn into_record(self) -> ResetTokenRecord {
        ResetTokenRecord {
            id: self.id,
            user_id: self.user_id,
            org_id: self.org_id,
            expires_at: self.expires_at,
        }
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

    #[test]
    fn lockout_retry_after_is_none_when_not_locked() {
        let now = Utc::now();
        let unlocked = LockoutState {
            failed_count: 2,
            locked_until: None,
        };
        assert_eq!(unlocked.retry_after_secs(now), None);

        // A lock whose window has already elapsed is no longer a lock.
        let past = LockoutState {
            failed_count: 5,
            locked_until: Some(now - chrono::Duration::seconds(1)),
        };
        assert_eq!(past.retry_after_secs(now), None);
    }

    #[test]
    fn lockout_retry_after_reports_remaining_window() {
        let now = Utc::now();
        let locked = LockoutState {
            failed_count: 5,
            locked_until: Some(now + chrono::Duration::seconds(90)),
        };
        // Allow a 1s slack for the arithmetic crossing a second boundary.
        let remaining = locked.retry_after_secs(now).expect("still locked");
        assert!((89..=90).contains(&remaining), "expected ~90s, got {remaining}");
    }

    #[test]
    fn refresh_token_liveness_tracks_revocation_and_expiry() {
        let now = Utc::now();
        let base = RefreshTokenRecord {
            id: Uuid::nil(),
            user_id: Uuid::nil(),
            org_id: Uuid::nil(),
            expires_at: now + chrono::Duration::hours(1),
            revoked_at: None,
        };
        assert!(base.is_live(now), "a fresh unrevoked token is live");

        let revoked = RefreshTokenRecord {
            revoked_at: Some(now - chrono::Duration::minutes(1)),
            ..base.clone()
        };
        assert!(!revoked.is_live(now), "a revoked token is not live");

        let expired = RefreshTokenRecord {
            expires_at: now - chrono::Duration::minutes(1),
            ..base
        };
        assert!(!expired.is_live(now), "an expired token is not live");
    }
}
