//! Native-account store integration suite (AAASM-5304). Exercises the 0008
//! migration and [`PgUserStore`] against a real Postgres, proving the CRUD, the
//! case-insensitive email uniqueness, single-use invite consumption, refresh
//! revocation, and the tenant-isolation RLS backstop.
//!
//! Docker-gated: requires a working Docker daemon for the Postgres
//! testcontainer. When Docker is unavailable the container fails to start and
//! the test errors on setup — that is an environment gap, not a code failure;
//! the unit tests (argon2, role→scope, enum roundtrips) cover the non-DB logic.
//!
//! Harness note (mirrors `rls_isolation_pg.rs`): the container's bootstrap user
//! is a superuser, which BYPASSES RLS (FORCE RLS binds the table owner, never a
//! superuser). Migrations and role setup run as that superuser, but every store
//! assertion runs through a second pool connected as a restricted, RLS-bound
//! `app_user` role — exactly the privileged-migrator / unprivileged-row-access
//! split the production deployment uses. Otherwise the RLS assertions would
//! silently pass under a bypassing superuser.

use aa_storage_postgres::{
    BootstrapOutcome, NewInvite, NewUser, PgUserStore, PostgresPool, PostgresPoolConfig, UserRole, UserStatus,
};
use chrono::{Duration, Utc};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

const TENANT_A: Uuid = Uuid::from_u128(0x0a);
const TENANT_B: Uuid = Uuid::from_u128(0x0b);

/// Start a fresh Postgres 18 container, run migrations + role setup + org seed as
/// the superuser, and return the container guard plus the restricted `app_user`
/// pool every assertion reads/writes through (RLS-bound, the runtime role).
async fn setup() -> (ContainerAsync<Postgres>, PostgresPool) {
    let container = Postgres::default()
        .with_db_name("aasm")
        .with_user("aasm")
        .with_password("secret")
        .with_tag("18-alpine")
        .start()
        .await
        .expect("start postgres testcontainer (is Docker running?)");

    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");

    // Superuser pool: applies migrations, seeds orgs, creates the app role.
    let admin_url = format!("postgres://aasm:secret@{host}:{port}/aasm");
    let admin = PostgresPool::connect(&PostgresPoolConfig {
        url: admin_url,
        max_connections: 5,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect admin pool");
    admin.migrate().await.expect("run migrations");

    for org in [TENANT_A, TENANT_B] {
        sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
            .bind(org)
            .bind(format!("org-{org}"))
            .execute(admin.pool())
            .await
            .expect("seed org");
    }

    for stmt in [
        "CREATE ROLE app_user LOGIN PASSWORD 'app'",
        "GRANT USAGE ON SCHEMA public TO app_user",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user",
    ] {
        sqlx::query(stmt)
            .execute(admin.pool())
            .await
            .unwrap_or_else(|e| panic!("grant setup `{stmt}`: {e}"));
    }

    // Restricted, RLS-bound pool — the runtime row-access role.
    let app_url = format!("postgres://app_user:app@{host}:{port}/aasm");
    let app = PostgresPool::connect(&PostgresPoolConfig {
        url: app_url,
        // One connection makes any pooled-reuse behaviour deterministic.
        max_connections: 1,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect app_user pool");

    (container, app)
}

fn new_user(email: &str) -> NewUser {
    NewUser {
        id: Uuid::new_v4(),
        email: email.to_string(),
        // A fixed non-secret placeholder hash; the store treats it as opaque.
        password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".to_string(),
        role: UserRole::Developer,
        status: UserStatus::Active,
    }
}

#[tokio::test]
async fn create_then_find_by_email_roundtrips() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("alice@example.com");
    let id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    let found = store
        .find_by_email(TENANT_A, "alice@example.com")
        .await
        .expect("find")
        .expect("user present");
    assert_eq!(found.id, id);
    assert_eq!(found.org_id, TENANT_A);
    assert_eq!(found.role, UserRole::Developer);
    assert_eq!(found.status, UserStatus::Active);
    assert!(found.last_login_at.is_none());
}

#[tokio::test]
async fn find_by_email_is_case_insensitive() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    store
        .create_user(TENANT_A, &new_user("Bob@Example.com"))
        .await
        .expect("create user");

    // A differently-cased lookup must resolve the same citext row.
    let found = store.find_by_email(TENANT_A, "bob@example.COM").await.expect("find");
    assert!(found.is_some(), "citext email lookup must be case-insensitive");
}

#[tokio::test]
async fn duplicate_email_is_rejected_case_insensitively() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    store
        .create_user(TENANT_A, &new_user("carol@example.com"))
        .await
        .expect("first create");
    // Same email, different case → the citext unique index must reject it.
    let dup = store.create_user(TENANT_A, &new_user("CAROL@EXAMPLE.COM")).await;
    assert!(
        dup.is_err(),
        "a case-variant duplicate email must violate the unique index"
    );
}

#[tokio::test]
async fn consume_invite_is_single_use() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let invite = NewInvite {
        id: Uuid::new_v4(),
        token_hash: "sha256-of-raw-token".to_string(),
        email: "dave@example.com".to_string(),
        role: UserRole::Viewer,
        expires_at: Utc::now() + Duration::hours(1),
        invited_by: None,
    };
    store.create_invite(TENANT_A, &invite).await.expect("create invite");

    // First consume succeeds and returns the invite.
    let first = store
        .consume_invite(TENANT_A, "sha256-of-raw-token")
        .await
        .expect("consume")
        .expect("invite present");
    assert_eq!(first.email, "dave@example.com");
    assert_eq!(first.role, UserRole::Viewer);
    assert!(first.consumed_at.is_some());

    // Second consume (replay) must find nothing — the token is spent.
    let replay = store
        .consume_invite(TENANT_A, "sha256-of-raw-token")
        .await
        .expect("consume replay");
    assert!(replay.is_none(), "a consumed invite must not be consumable again");
}

#[tokio::test]
async fn expired_invite_cannot_be_consumed() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let invite = NewInvite {
        id: Uuid::new_v4(),
        token_hash: "expired-token-hash".to_string(),
        email: "erin@example.com".to_string(),
        role: UserRole::Viewer,
        expires_at: Utc::now() - Duration::hours(1),
        invited_by: None,
    };
    store.create_invite(TENANT_A, &invite).await.expect("create invite");

    let consumed = store
        .consume_invite(TENANT_A, "expired-token-hash")
        .await
        .expect("consume");
    assert!(consumed.is_none(), "an expired invite must not be consumable");
}

#[tokio::test]
async fn store_then_revoke_refresh_token() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("frank@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    store
        .store_refresh_token(
            TENANT_A,
            Uuid::new_v4(),
            "refresh-token-hash",
            user_id,
            Utc::now() + Duration::days(7),
        )
        .await
        .expect("store refresh token");

    // First revoke flips a live token → true.
    let revoked = store
        .revoke_refresh_token(TENANT_A, "refresh-token-hash")
        .await
        .expect("revoke");
    assert!(revoked, "revoking a live token reports true");

    // Second revoke is idempotent → false (already revoked, zero rows).
    let again = store
        .revoke_refresh_token(TENANT_A, "refresh-token-hash")
        .await
        .expect("revoke again");
    assert!(!again, "re-revoking an already-revoked token reports false");
}

#[tokio::test]
async fn find_by_email_is_tenant_scoped() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    // A user in tenant A must be invisible to a tenant-B-scoped lookup (RLS).
    store
        .create_user(TENANT_A, &new_user("grace@example.com"))
        .await
        .expect("create user in A");

    let via_b = store
        .find_by_email(TENANT_B, "grace@example.com")
        .await
        .expect("find via B");
    assert!(via_b.is_none(), "tenant B must not see tenant A's user (RLS)");
}

const DEFAULT_ORG: Uuid = Uuid::from_u128(0x0d);

#[tokio::test]
async fn bootstrap_first_user_creates_owner_then_reports_already_bootstrapped() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    // A fresh workspace: the first bootstrap creates the owner and the default org
    // (created on demand — no seeding step needed).
    let first = store
        .bootstrap_first_user(DEFAULT_ORG, "Default", Uuid::new_v4(), "ivan@example.com", "hash")
        .await
        .expect("first bootstrap");
    assert_eq!(first, BootstrapOutcome::CreatedOwner { org_id: DEFAULT_ORG });

    let created = store
        .find_by_email(DEFAULT_ORG, "ivan@example.com")
        .await
        .expect("find")
        .expect("owner present");
    assert_eq!(created.role, UserRole::Owner, "the first account becomes owner");
    assert_eq!(created.status, UserStatus::Active);

    // A second bootstrap must NOT create a second owner — it reports the workspace
    // is already bootstrapped, leaving the count-then-insert race-free.
    let second = store
        .bootstrap_first_user(DEFAULT_ORG, "Default", Uuid::new_v4(), "judy@example.com", "hash")
        .await
        .expect("second bootstrap");
    assert_eq!(second, BootstrapOutcome::AlreadyBootstrapped { org_id: DEFAULT_ORG });
    assert!(
        store
            .find_by_email(DEFAULT_ORG, "judy@example.com")
            .await
            .expect("find")
            .is_none(),
        "a second bootstrap must not create a user"
    );
}

#[tokio::test]
async fn lockout_counter_increments_locks_and_clears() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("kate@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    // No failures yet: zero state, no lock.
    let initial = store.lockout_state(TENANT_A, user_id).await.expect("state");
    assert_eq!(initial.failed_count, 0);
    assert!(initial.locked_until.is_none());

    // Below threshold: increments but does not lock.
    let one = store
        .record_login_failure(TENANT_A, user_id, 3, 900)
        .await
        .expect("fail 1");
    assert_eq!(one.failed_count, 1);
    assert!(one.locked_until.is_none(), "below threshold must not lock");

    store
        .record_login_failure(TENANT_A, user_id, 3, 900)
        .await
        .expect("fail 2");
    // Reaching the threshold locks the account.
    let three = store
        .record_login_failure(TENANT_A, user_id, 3, 900)
        .await
        .expect("fail 3");
    assert_eq!(three.failed_count, 3);
    assert!(three.locked_until.is_some(), "reaching threshold must lock");
    assert!(
        three.retry_after_secs(Utc::now()).is_some(),
        "a locked account reports a retry-after"
    );

    // A successful login clears the counter.
    store.clear_login_failures(TENANT_A, user_id).await.expect("clear");
    let cleared = store.lockout_state(TENANT_A, user_id).await.expect("state");
    assert_eq!(cleared.failed_count, 0);
    assert!(cleared.locked_until.is_none(), "clear must lift the lock");
}

#[tokio::test]
async fn find_refresh_token_reads_liveness() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("leo@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");
    store
        .store_refresh_token(
            TENANT_A,
            Uuid::new_v4(),
            "live-refresh-hash",
            user_id,
            Utc::now() + Duration::days(7),
        )
        .await
        .expect("store");

    let found = store
        .find_refresh_token(TENANT_A, "live-refresh-hash")
        .await
        .expect("find")
        .expect("token present");
    assert_eq!(found.user_id, user_id);
    assert!(found.is_live(Utc::now()), "a stored unrevoked token is live");

    // After revocation the same lookup shows it dead (so refresh can reject it).
    store
        .revoke_refresh_token(TENANT_A, "live-refresh-hash")
        .await
        .expect("revoke");
    let after = store
        .find_refresh_token(TENANT_A, "live-refresh-hash")
        .await
        .expect("find")
        .expect("token still present");
    assert!(!after.is_live(Utc::now()), "a revoked token reads as not live");

    // A missing token is None (not an error).
    assert!(store
        .find_refresh_token(TENANT_A, "no-such-hash")
        .await
        .expect("find")
        .is_none());
}

#[tokio::test]
async fn activate_invited_user_sets_password_and_status() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let mut invited = new_user("mia@example.com");
    invited.status = UserStatus::Invited;
    let user_id = invited.id;
    store.create_user(TENANT_A, &invited).await.expect("create invited");

    let activated = store
        .activate_invited_user(TENANT_A, user_id, "new-hash")
        .await
        .expect("activate");
    assert!(activated, "activating an invited account reports true");

    let record = store
        .find_by_id(TENANT_A, user_id)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(record.status, UserStatus::Active);
    assert_eq!(record.password_hash, "new-hash");

    // Re-activating an already-active account is a no-op (zero rows → false).
    let again = store
        .activate_invited_user(TENANT_A, user_id, "another-hash")
        .await
        .expect("activate again");
    assert!(!again, "an already-active account cannot be re-activated");
}

#[tokio::test]
async fn consume_reset_token_is_single_use() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("nina@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    store
        .create_reset_token(
            TENANT_A,
            Uuid::new_v4(),
            "reset-token-hash",
            user_id,
            Utc::now() + Duration::hours(1),
        )
        .await
        .expect("create reset token");

    // First consume spends the token and returns the target account.
    let first = store
        .consume_reset_token(TENANT_A, "reset-token-hash")
        .await
        .expect("consume")
        .expect("token present");
    assert_eq!(first.user_id, user_id);

    // Replay must find nothing — a spent single-use token is dead.
    let replay = store
        .consume_reset_token(TENANT_A, "reset-token-hash")
        .await
        .expect("consume replay");
    assert!(replay.is_none(), "a consumed reset token must not be consumable again");
}

#[tokio::test]
async fn expired_reset_token_cannot_be_consumed() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("omar@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    store
        .create_reset_token(
            TENANT_A,
            Uuid::new_v4(),
            "expired-reset-hash",
            user_id,
            Utc::now() - Duration::hours(1),
        )
        .await
        .expect("create reset token");

    let consumed = store
        .consume_reset_token(TENANT_A, "expired-reset-hash")
        .await
        .expect("consume");
    assert!(consumed.is_none(), "an expired reset token must not be consumable");
}

#[tokio::test]
async fn set_password_only_touches_active_accounts() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let active = new_user("pat@example.com");
    let active_id = active.id;
    store.create_user(TENANT_A, &active).await.expect("create active");

    // A fixed non-secret placeholder replacement hash; the store treats it as opaque.
    let new_hash = "$argon2id$v=19$m=19456,t=2,p=1$bmV3c2FsdA$bmV3aGFzaA";
    let updated = store
        .set_password(TENANT_A, active_id, new_hash)
        .await
        .expect("set password");
    assert!(updated, "setting the password of an active account reports true");

    let record = store
        .find_by_id(TENANT_A, active_id)
        .await
        .expect("find")
        .expect("present");
    assert_eq!(record.password_hash, new_hash);

    // An invited (never-accepted) account must not be resettable.
    let mut invited = new_user("quinn@example.com");
    invited.status = UserStatus::Invited;
    let invited_id = invited.id;
    store.create_user(TENANT_A, &invited).await.expect("create invited");

    let touched = store
        .set_password(TENANT_A, invited_id, new_hash)
        .await
        .expect("set password on invited");
    assert!(!touched, "an invited (non-active) account must not be password-resettable");
}

#[tokio::test]
async fn revoke_all_refresh_tokens_revokes_every_live_session() {
    let (_pg, pool) = setup().await;
    let store = PgUserStore::new(pool);

    let user = new_user("ruth@example.com");
    let user_id = user.id;
    store.create_user(TENANT_A, &user).await.expect("create user");

    // Two live sessions for the user.
    for hash in ["revoke-all-hash-1", "revoke-all-hash-2"] {
        store
            .store_refresh_token(TENANT_A, Uuid::new_v4(), hash, user_id, Utc::now() + Duration::days(7))
            .await
            .expect("store refresh token");
    }

    // A reset revokes every outstanding session at once.
    let revoked = store
        .revoke_all_refresh_tokens(TENANT_A, user_id)
        .await
        .expect("revoke all");
    assert_eq!(revoked, 2, "both live sessions must be revoked");

    // Each is now dead, so a subsequent refresh with either is rejected.
    for hash in ["revoke-all-hash-1", "revoke-all-hash-2"] {
        let record = store
            .find_refresh_token(TENANT_A, hash)
            .await
            .expect("find")
            .expect("token present");
        assert!(!record.is_live(Utc::now()), "revoke_all must kill the session");
    }

    // Idempotent: a second revoke-all finds nothing live → zero rows.
    let again = store
        .revoke_all_refresh_tokens(TENANT_A, user_id)
        .await
        .expect("revoke all again");
    assert_eq!(again, 0, "re-revoking with no live sessions affects zero rows");
}

#[tokio::test]
async fn create_is_rejected_for_mismatched_tenant() {
    let (_pg, pool) = setup().await;

    // Directly attempt to write a users row stamped for tenant B while running
    // under tenant A's GUC — the RLS WITH CHECK must reject it. Runs through the
    // RLS-bound app_user pool (a superuser would bypass the policy). The store's
    // create_user always stamps org_id = the GUC tenant, so this raw INSERT
    // exercises the policy the store relies on.
    let mut tx = pool.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
    let result = sqlx::query(
        "INSERT INTO users (id, email, password_hash, org_id, role, status) \
         VALUES ($1, $2, $3, $4, 'developer'::user_role, 'active'::user_status)",
    )
    .bind(Uuid::new_v4())
    .bind("heidi@example.com")
    .bind("hash")
    .bind(TENANT_B)
    .execute(&mut *tx)
    .await;
    assert!(
        result.is_err(),
        "WITH CHECK must reject inserting a user for a tenant other than the GUC"
    );
}
