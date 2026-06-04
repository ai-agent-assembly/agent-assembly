//! Migration drift gate (AAASM-2389).
//!
//! The async Gateway consumer and the OSS Postgres driver must agree on the MVP
//! schema. Rather than copy migration files, the gateway boots the **driver's**
//! embedded [`aa_storage_postgres::MIGRATOR`] against a fresh Postgres 18 and
//! asserts the canonical four-table shape. If a migration file changes such that
//! it no longer applies cleanly — or the `audit_logs` contract drifts — this
//! test (and the `migration-drift-check` CI job that runs it) fails.
//!
//! Requires Docker: each run spins its own throwaway Postgres container.

use aa_storage_postgres::{PostgresPool, PostgresPoolConfig};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;

/// Boot a fresh Postgres 18 and apply the driver's embedded migrations through
/// the same `PostgresPool::migrate` path a gateway uses at startup.
#[tokio::test]
async fn gateway_boots_driver_migrations_on_fresh_postgres() {
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

    // The drift gate: applying the driver's MIGRATOR must succeed.
    pool.migrate().await.expect("driver migrations apply cleanly");

    // The canonical MVP four tables (+ credentials) all exist.
    for table in ["orgs", "agents", "policies", "audit_logs", "credentials"] {
        let exists: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)")
                .bind(table)
                .fetch_one(pool.pool())
                .await
                .expect("query table existence");
        assert!(exists, "table {table} must exist after the driver migrations");
    }

    // audit_logs.event_id is the idempotency key: present and NOT NULL.
    let event_id_nullable: Option<String> = sqlx::query_scalar(
        "SELECT is_nullable FROM information_schema.columns \
         WHERE table_name = 'audit_logs' AND column_name = 'event_id'",
    )
    .fetch_optional(pool.pool())
    .await
    .expect("query audit_logs.event_id");
    assert_eq!(
        event_id_nullable.as_deref(),
        Some("NO"),
        "audit_logs.event_id must exist and be NOT NULL"
    );

    // Metadata-only: no payload/body/prompt/completion column ever lands.
    let columns: Vec<String> =
        sqlx::query_scalar("SELECT column_name FROM information_schema.columns WHERE table_name = 'audit_logs'")
            .fetch_all(pool.pool())
            .await
            .expect("query audit_logs columns");
    for forbidden in ["payload", "body", "prompt", "completion"] {
        assert!(
            !columns.iter().any(|c| c == forbidden),
            "audit_logs must not contain a {forbidden} column"
        );
    }

    // The dashboard query index survives migration.
    let has_index: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes \
         WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_agent_ts')",
    )
    .fetch_one(pool.pool())
    .await
    .expect("query audit_logs indexes");
    assert!(has_index, "idx_audit_logs_agent_ts must exist after migrations");
}
