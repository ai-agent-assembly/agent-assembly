//! RLS regression suite (AAASM-3598) — the executable contract for AAASM-3564.
//!
//! Proves the DB backstop holds even when the application layer misbehaves:
//!   1. A raw query with the app-layer tenant predicate REMOVED still returns
//!      zero of another tenant's rows (RLS filters them).
//!   2. A connection with no `app.tenant_id` set returns zero rows (fail-closed).
//!   3. A pooled connection reused across tenants carries no stale GUC
//!      (`set_config(..., is_local = true)` correctness).
//!   4. A client-supplied org differing from the GUC cannot widen results.
//!
//! Each case runs against a real Postgres via `testcontainers-modules`, mirroring
//! `conformance_pg.rs`. Requires a working Docker daemon.

use aa_storage_postgres::{PostgresPool, PostgresPoolConfig};
use sqlx::Row;
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};
use uuid::Uuid;

const TENANT_A: Uuid = Uuid::from_u128(0x0a);
const TENANT_B: Uuid = Uuid::from_u128(0x0b);

/// Start a fresh Postgres 18 container, connect a pool, and run migrations.
async fn setup_pg() -> (ContainerAsync<Postgres>, PostgresPool) {
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
    let url = format!("postgres://aasm:secret@{host}:{port}/aasm");

    let pool = PostgresPool::connect(&PostgresPoolConfig {
        url,
        // A single connection makes the pooled-reuse test deterministic: the
        // second checkout is guaranteed to be the same physical connection.
        max_connections: 1,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect pool");
    pool.migrate().await.expect("run migrations");

    (container, pool)
}

/// Seed one org row plus one audit_logs row stamped with that org, under a
/// tenant-scoped transaction so the RLS WITH CHECK admits the write.
async fn seed_tenant_audit(pool: &PostgresPool, org: Uuid, agent: &str) {
    // The org FK lives only on policies/credentials, not audit_logs, but seed the
    // org so any future FK-bearing seed reuses the same helper. Insert it under a
    // bypass path: orgs has no RLS, so the bare pool can write it.
    sqlx::query("INSERT INTO orgs (id, name) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING")
        .bind(org)
        .bind(format!("tenant-{org}"))
        .execute(pool.pool())
        .await
        .expect("seed org");

    let mut tx = pool.begin_for_tenant(org).await.expect("begin tenant tx");
    sqlx::query(
        "INSERT INTO audit_logs (event_id, agent_id, tool_name, decision, ts, org_id) \
         VALUES ($1, $2, 'fs.read', 'allow', now(), $3)",
    )
    .bind(Uuid::new_v4())
    .bind(agent)
    .bind(org)
    .execute(&mut *tx)
    .await
    .expect("seed audit row");
    tx.commit().await.expect("commit seed");
}

/// AC#1: a query with NO tenant predicate, run under tenant A's GUC, returns
/// only A's rows — RLS filters B's even though the app forgot the WHERE.
#[tokio::test]
async fn dropped_filter_still_excludes_other_tenant_rows() {
    let (_pg, pool) = setup_pg().await;
    seed_tenant_audit(&pool, TENANT_A, "agent-a").await;
    seed_tenant_audit(&pool, TENANT_B, "agent-b").await;

    let mut tx = pool.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
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

/// AC#1 (fail-closed): a connection with no `app.tenant_id` set sees zero rows
/// from every tenant table — an unset tenant denies all, never dumps all.
#[tokio::test]
async fn unset_guc_returns_zero_rows() {
    let (_pg, pool) = setup_pg().await;
    seed_tenant_audit(&pool, TENANT_A, "agent-a").await;
    seed_tenant_audit(&pool, TENANT_B, "agent-b").await;

    // The bare pool sets no app.tenant_id; FORCE RLS + missing_ok current_setting
    // makes the policy predicate NULL → no row matches.
    for table in ["audit_logs", "agents", "policies", "credentials"] {
        let count: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(pool.pool())
            .await
            .unwrap_or_else(|e| panic!("count {table}: {e}"));
        assert_eq!(count, 0, "unset app.tenant_id must see zero rows from {table}");
    }
}

/// AC#3 of the test plan: reusing a pooled connection across tenants must not
/// carry tenant A's GUC into tenant B's checkout. With max_connections = 1 the
/// second `begin_for_tenant` reuses the same physical connection, so a leak of
/// `is_local = false` semantics would show A's row under B's scope.
#[tokio::test]
async fn pooled_connection_reuse_does_not_bleed_guc() {
    let (_pg, pool) = setup_pg().await;
    seed_tenant_audit(&pool, TENANT_A, "agent-a").await;
    seed_tenant_audit(&pool, TENANT_B, "agent-b").await;

    // First checkout: tenant A, then return the connection to the pool.
    {
        let mut tx = pool.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&mut *tx)
            .await
            .expect("count under A");
        assert_eq!(n, 1, "A sees exactly its own row");
        tx.commit().await.expect("commit A");
    }

    // Second checkout: same physical connection, tenant B. It must see only B's
    // row — never A's leftover GUC — and the count must be B's, not A's+B's.
    let mut tx = pool.begin_for_tenant(TENANT_B).await.expect("tenant B tx");
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
    let (_pg, pool) = setup_pg().await;
    seed_tenant_audit(&pool, TENANT_A, "agent-a").await;
    seed_tenant_audit(&pool, TENANT_B, "agent-b").await;

    let mut tx = pool.begin_for_tenant(TENANT_A).await.expect("tenant A tx");
    // Tenant A explicitly asks for tenant B's rows (the spoof attempt).
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE org_id = $1")
        .bind(TENANT_B)
        .fetch_one(&mut *tx)
        .await
        .expect("spoof query");
    tx.commit().await.expect("commit");
    assert_eq!(count, 0, "a client-chosen org cannot reach past the connection's GUC");
}
