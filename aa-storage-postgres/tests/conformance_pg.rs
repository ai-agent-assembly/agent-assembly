//! Trait-conformance tests for the Postgres driver, run against a real Postgres
//! via `testcontainers-modules`. Each test spins up its own fresh Postgres 18
//! container, so the cases are isolated and require Docker to run.

use aa_core::EnforcementMode;
use aa_storage::conformance::assert_policy_store_conformance;
use aa_storage::{AgentId, CredentialStore, LifecycleStore, PolicyDocument, StorageError};
use aa_storage_postgres::{
    PgAuditSink, PgCredentialStore, PgLifecycleStore, PgPolicyStore, PostgresPool, PostgresPoolConfig,
};
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

#[tokio::test]
async fn lifecycle_register_heartbeat_deregister() {
    let (_pg, pool) = setup_pg().await;
    let store = PgLifecycleStore::new(pool.clone());

    let present = AgentId::from_bytes([7u8; 16]);
    let absent = AgentId::from_bytes([9u8; 16]);

    store.register(&present).await.expect("register");
    // Re-registration overwrites the stale row without error.
    store.register(&present).await.expect("re-register is idempotent");
    store.heartbeat(&present).await.expect("heartbeat present");

    match store.heartbeat(&absent).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("heartbeat(absent) should be NotFound, got {other:?}"),
    }

    store.deregister(&present).await.expect("deregister");
    store
        .deregister(&absent)
        .await
        .expect("deregister(absent) is idempotent");
}

#[tokio::test]
async fn policy_store_satisfies_conformance() {
    let (_pg, pool) = setup_pg().await;

    let present = AgentId::from_bytes([1u8; 16]);
    let absent = AgentId::from_bytes([2u8; 16]);

    // Seed: the policies FK requires the agent row, so register it first, then
    // insert one policy version for the present agent.
    PgLifecycleStore::new(pool.clone())
        .register(&present)
        .await
        .expect("register present agent");

    let doc = PolicyDocument {
        version: 1,
        name: "test".to_owned(),
        rules: Vec::new(),
        enforcement_mode: EnforcementMode::default(),
    };
    let body = serde_json::to_value(&doc).expect("serialize policy");
    let agent_text = uuid::Uuid::from_bytes(*present.as_bytes()).to_string();
    sqlx::query("INSERT INTO policies (agent_id, policy_version, body) VALUES ($1, $2, $3)")
        .bind(&agent_text)
        .bind(1_i64)
        .bind(body)
        .execute(pool.pool())
        .await
        .expect("seed policy row");

    let store = PgPolicyStore::new(pool.clone());
    // Coerces to `&dyn PolicyStore`, exercising object-safety too.
    assert_policy_store_conformance(&store, &present, &absent).await;
}

#[tokio::test]
async fn credential_store_secret_roundtrip() {
    let (_pg, pool) = setup_pg().await;
    let store = PgCredentialStore::new(pool.clone());

    let key = "openai/api_key";
    match store.get_secret(key).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("get_secret(absent) should be NotFound, got {other:?}"),
    }

    store.put_secret(key, b"ciphertext-bytes".to_vec()).await.expect("put");
    assert_eq!(store.get_secret(key).await.expect("get"), b"ciphertext-bytes");

    // put overwrites.
    store.put_secret(key, b"rotated".to_vec()).await.expect("overwrite");
    assert_eq!(store.get_secret(key).await.expect("get rotated"), b"rotated");

    store.delete_secret(key).await.expect("delete");
    store.delete_secret(key).await.expect("delete(absent) is idempotent");
    match store.get_secret(key).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("get_secret after delete should be NotFound, got {other:?}"),
    }
}

#[tokio::test]
async fn audit_sink_writes_metadata_only_row() {
    use aa_core::audit::{AuditEntry, AuditEventType};
    use aa_storage::{AuditSink, SessionId};

    let (_pg, pool) = setup_pg().await;
    let sink = PgAuditSink::new(pool.clone());

    let agent = AgentId::from_bytes([3u8; 16]);
    let session = SessionId::from_bytes([4u8; 16]);
    let entry = AuditEntry::new(
        0,
        1_700_000_000_000_000_000,
        AuditEventType::ToolDispatched,
        agent,
        session,
        // A payload carrying a secret — the sink must NOT persist it.
        r#"{"tool":"shell","secret":"should-not-be-stored"}"#.to_owned(),
        [0u8; 32],
    );

    sink.emit(entry).await.expect("emit");

    let agent_text = uuid::Uuid::from_bytes(*agent.as_bytes()).to_string();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE agent_id = $1")
        .bind(&agent_text)
        .fetch_one(pool.pool())
        .await
        .expect("count audit rows");
    assert_eq!(count, 1, "emit should write exactly one audit row");

    let (tool_name, decision): (String, String) =
        sqlx::query_as("SELECT tool_name, decision FROM audit_logs WHERE agent_id = $1")
            .bind(&agent_text)
            .fetch_one(pool.pool())
            .await
            .expect("fetch audit row");
    assert_eq!(tool_name, "ToolDispatched");
    assert_eq!(decision, "allow");
}
