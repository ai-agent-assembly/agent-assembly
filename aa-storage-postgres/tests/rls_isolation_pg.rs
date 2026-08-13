//! RLS regression suite (AAASM-3598) — the executable contract for AAASM-3564.
//!
//! Proves the DB backstop holds even when the application layer misbehaves:
//!   1. A raw query with the app-layer tenant predicate REMOVED still returns
//!      zero of another tenant's rows (RLS filters them).
//!   2. A connection with no `app.tenant_id` set returns zero rows (fail-closed),
//!      and an empty-string GUC residue is treated the same (NULLIF guard).
//!   3. A pooled connection reused across tenants carries no stale GUC
//!      (`set_config(..., is_local = true)` correctness).
//!   4. A client-supplied org differing from the GUC cannot widen results.
//!
//! Critical harness note: the container's bootstrap superuser BYPASSES RLS
//! (FORCE RLS binds the table *owner*, never a superuser). So the migrations are
//! applied as the superuser, but the RLS assertions run through a second pool
//! connected as a restricted, non-superuser, RLS-bound `app_user` role — exactly
//! the role split the production deployment uses (privileged migrator vs.
//! unprivileged row-access). Requires a working Docker daemon.

use aa_storage_postgres::{PostgresPool, PostgresPoolConfig};
use sqlx::Row;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

const TENANT_A: Uuid = Uuid::from_u128(0x0a);
const TENANT_B: Uuid = Uuid::from_u128(0x0b);

/// Start a fresh Postgres 18 container. Returns the container guard, the
/// superuser pool (migrations + seeding, bypasses RLS), and an `app_user` pool
/// (restricted, RLS-bound — the pool every assertion reads through).
async fn setup_pg() -> (ContainerAsync<Postgres>, PostgresPool, PostgresPool) {
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

    // Superuser pool: applies migrations and seeds rows (RLS does not bind it).
    let admin_url = format!("postgres://aasm:secret@{host}:{port}/aasm");
    let admin = PostgresPool::connect(&PostgresPoolConfig {
        url: admin_url,
        max_connections: 5,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect admin pool");
    admin.migrate().await.expect("run migrations");

    // Create the restricted row-access role and grant it table DML.
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

    // app_user pool: non-superuser, so FORCE RLS applies — every assertion below
    // runs through this pool, the way the runtime row-access role would.
    let app_url = format!("postgres://app_user:app@{host}:{port}/aasm");
    let app = PostgresPool::connect(&PostgresPoolConfig {
        url: app_url,
        // One connection makes the pooled-reuse test deterministic.
        max_connections: 1,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect app_user pool");

    (container, admin, app)
}

/// Seed an org + one audit row stamped with that org, AS the superuser (bypasses
/// RLS, so the cross-tenant seed needs no per-row GUC dance).
async fn seed_tenant_audit(admin: &PostgresPool, org: Uuid, agent: &str, event_id: Uuid) {
    sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(org)
        .bind(format!("tenant-{org}"))
        .execute(admin.pool())
        .await
        .expect("seed org");
    sqlx::query(
        "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, ts, org_id) \
         VALUES ($1, $2, 'fs.read', 'allow', now(), $3)",
    )
    .bind(event_id)
    .bind(agent)
    .bind(org)
    .execute(admin.pool())
    .await
    .expect("seed audit row");
}

async fn seed_two_tenants(admin: &PostgresPool) {
    seed_tenant_audit(admin, TENANT_A, "agent-a", Uuid::from_u128(0xa1)).await;
    seed_tenant_audit(admin, TENANT_B, "agent-b", Uuid::from_u128(0xb1)).await;
}

/// AC#1: a query with NO tenant predicate, run under tenant A's GUC, returns
/// only A's rows — RLS filters B's even though the app forgot the WHERE.
#[tokio::test]
async fn dropped_filter_still_excludes_other_tenant_rows() {
    let (_pg, admin, app) = setup_pg().await;
    seed_two_tenants(&admin).await;

    let mut tx = app.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
    // Deliberately NO `WHERE org_id = …` — the app-layer filter is dropped.
    let rows = sqlx::query("SELECT org_id, agent_id FROM audit_logs")
        .fetch_all(&mut *tx)
        .await
        .expect("select without predicate");
    tx.commit().await.expect("commit");

    assert_eq!(rows.len(), 1, "RLS must hide tenant B's rows even with no predicate");
    let org: Uuid = rows[0].get("org_id");
    assert_eq!(org, TENANT_A, "the only visible row must belong to tenant A");
}

/// AC#1 (fail-closed): the restricted role with no `app.tenant_id` set sees zero
/// rows; an empty-string GUC residue is treated identically (NULLIF guard).
#[tokio::test]
async fn unset_or_empty_guc_returns_zero_rows() {
    let (_pg, admin, app) = setup_pg().await;
    seed_two_tenants(&admin).await;

    // Never-set GUC, via the bare app_user pool.
    for table in ["audit_logs", "agents", "policies", "credentials"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(app.pool())
            .await
            .unwrap_or_else(|e| panic!("count {table}: {e}"));
        assert_eq!(count, 0, "unset app.tenant_id must see zero rows from {table}");
    }

    // Empty-string GUC must also deny (the NULLIF(…, '') guard), not error on
    // the `::uuid` cast.
    let mut tx = app.pool().begin().await.expect("begin");
    sqlx::query("SELECT set_config('app.tenant_id', '', true)")
        .execute(&mut *tx)
        .await
        .expect("set empty guc");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(&mut *tx)
        .await
        .expect("count under empty guc");
    tx.commit().await.expect("commit");
    assert_eq!(count, 0, "empty-string app.tenant_id must see zero rows (fail-closed)");
}

/// Reusing a pooled connection across tenants must not carry tenant A's GUC into
/// tenant B's checkout. With max_connections = 1 the second `begin_for_tenant`
/// reuses the same physical connection, so an `is_local = false` leak would show
/// A's row under B's scope.
#[tokio::test]
async fn pooled_connection_reuse_does_not_bleed_guc() {
    let (_pg, admin, app) = setup_pg().await;
    seed_two_tenants(&admin).await;

    {
        let mut tx = app.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&mut *tx)
            .await
            .expect("count under A");
        assert_eq!(n, 1, "A sees exactly its own row");
        tx.commit().await.expect("commit A");
    }

    let mut tx = app.begin_for_tenant(TENANT_B).await.expect("tenant B tx");
    let rows = sqlx::query("SELECT org_id FROM audit_logs")
        .fetch_all(&mut *tx)
        .await
        .expect("count under B");
    tx.commit().await.expect("commit B");
    assert_eq!(rows.len(), 1, "B must see exactly one row (no GUC bleed from A)");
    let org: Uuid = rows[0].get("org_id");
    assert_eq!(org, TENANT_B, "the visible row must belong to tenant B, not A");
}

/// AC#2: a "spoof" — a query that hard-codes another tenant's id in its WHERE —
/// cannot widen results past the connection's GUC. Tenant A asks for B's rows by
/// id; RLS still returns nothing because the row is invisible under A's scope.
#[tokio::test]
async fn client_supplied_org_cannot_widen_past_guc() {
    let (_pg, admin, app) = setup_pg().await;
    seed_two_tenants(&admin).await;

    let mut tx = app.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE org_id = $1")
        .bind(TENANT_B)
        .fetch_one(&mut *tx)
        .await
        .expect("spoof query");
    tx.commit().await.expect("commit");
    assert_eq!(count, 0, "a client-chosen org cannot reach past the connection's GUC");
}

/// The RLS WITH CHECK rejects a write that would stamp a row with a tenant other
/// than the connection's GUC — a forged-tenant INSERT cannot land.
#[tokio::test]
async fn write_with_mismatched_tenant_is_rejected() {
    let (_pg, _admin, app) = setup_pg().await;

    // orgs carries no RLS, so the app_user pool can seed tenant B's org row
    // directly to satisfy any FK; audit_logs itself has no FK to orgs but this
    // keeps the fixture honest for the cross-tenant write attempt.
    sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, 'B') ON CONFLICT (id) DO NOTHING")
        .bind(TENANT_B)
        .execute(app.pool())
        .await
        .expect("seed org B");

    // Under tenant A's GUC, try to write a row tagged for tenant B.
    let mut tx = app.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
    let result = sqlx::query(
        "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, ts, org_id) \
         VALUES ($1, 'x', 'y', 'allow', now(), $2)",
    )
    .bind(Uuid::from_u128(0xc1))
    .bind(TENANT_B)
    .execute(&mut *tx)
    .await;
    assert!(
        result.is_err(),
        "WITH CHECK must reject inserting a row for a tenant other than the GUC"
    );
}
