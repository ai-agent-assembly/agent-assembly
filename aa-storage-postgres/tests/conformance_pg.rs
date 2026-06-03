//! Trait-conformance tests for the Postgres driver, run against a real Postgres
//! via `testcontainers-modules`. Each test spins up its own fresh Postgres 18
//! container, so the cases are isolated and require Docker to run.

use aa_storage_postgres::{PostgresPool, PostgresPoolConfig};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::{ContainerAsync, ImageExt};

/// Start a fresh Postgres 18 container, connect a pool, and run migrations.
///
/// Returns the container guard (kept alive for the test's duration) alongside
/// the migrated pool.
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
        max_connections: 5,
        statement_timeout_ms: 0,
    })
    .await
    .expect("connect pool");
    pool.migrate().await.expect("run migrations");

    (container, pool)
}

#[tokio::test]
async fn migrations_apply_cleanly_and_audit_logs_is_metadata_only() {
    let (_pg, pool) = setup_pg().await;

    // Every migrated table exists after a fresh migrate().
    for table in ["orgs", "agents", "policies", "audit_logs", "credentials"] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)")
                .bind(table)
                .fetch_one(pool.pool())
                .await
                .expect("query table existence");
        assert!(exists, "table {table} should exist after migrations");
    }

    // audit_logs must carry no payload/prompt/body column (spec line 7551).
    let columns: Vec<String> =
        sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_logs'")
            .fetch_all(pool.pool())
            .await
            .expect("query audit_logs columns");
    for forbidden in ["payload", "prompt", "body"] {
        assert!(
            !columns.iter().any(|c| c == forbidden),
            "audit_logs must not contain a {forbidden} column"
        );
    }
}
