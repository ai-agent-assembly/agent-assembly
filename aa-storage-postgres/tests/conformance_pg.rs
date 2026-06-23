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

    // audit_logs must carry no payload/body/prompt/completion column (spec line 7551).
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

    // The dashboard reads audit_logs by (agent_id, ts DESC); that covering
    // index must survive a fresh migrate() (AAASM-2389 AC).
    let has_index: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM pg_indexes \
         WHERE tablename = 'audit_logs' AND indexname = 'idx_audit_logs_agent_ts')",
    )
    .fetch_one(pool.pool())
    .await
    .expect("query audit_logs indexes");
    assert!(has_index, "idx_audit_logs_agent_ts must exist after migrations");
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
    // Under FORCE RLS (0007) a bare-pool insert with no app.tenant_id is denied,
    // so seed the policy under the reserved system org the trait-impl read path
    // (PgPolicyStore::get_policy) scopes to. The org_id column defaults to the
    // system org, so this matches the GUC the read uses.
    let mut tx = pool
        .begin_for_tenant(uuid::Uuid::nil())
        .await
        .expect("begin system-org tx");
    sqlx::query("INSERT INTO policies (agent_id, policy_version, body) VALUES ($1, $2, $3)")
        .bind(&agent_text)
        .bind(1_i64)
        .bind(body)
        .execute(&mut *tx)
        .await
        .expect("seed policy row");
    tx.commit().await.expect("commit seed");

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

#[tokio::test]
async fn audit_sink_dedups_repeated_emit_on_event_id() {
    use aa_core::audit::{AuditEntry, AuditEventType};
    use aa_storage::{AuditSink, SessionId};

    let (_pg, pool) = setup_pg().await;
    let sink = PgAuditSink::new(pool.clone());

    let agent = AgentId::from_bytes([5u8; 16]);
    let session = SessionId::from_bytes([6u8; 16]);
    // Re-emitting an identical entry yields the same content hash → same
    // event_id → the UNIQUE key collapses the retry to one row.
    let make_entry = || {
        AuditEntry::new(
            0,
            1_700_000_000_000_000_000,
            AuditEventType::ToolDispatched,
            agent,
            session,
            r#"{"tool":"shell"}"#.to_owned(),
            [0u8; 32],
        )
    };

    sink.emit(make_entry()).await.expect("first emit");
    sink.emit(make_entry()).await.expect("retried emit is idempotent");

    let agent_text = uuid::Uuid::from_bytes(*agent.as_bytes()).to_string();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE agent_id = $1")
        .bind(&agent_text)
        .fetch_one(pool.pool())
        .await
        .expect("count audit rows");
    assert_eq!(count, 1, "duplicate event_id must not double-insert");
}

#[tokio::test]
async fn insert_audit_logs_batches_and_counts_duplicates() {
    use aa_storage_postgres::AuditLogRecord;
    use chrono::Utc;
    use uuid::Uuid;

    let (_pg, pool) = setup_pg().await;
    let sink = PgAuditSink::new(pool.clone());

    let rec = |id: Uuid| AuditLogRecord {
        event_id: id,
        agent_id: "acme/bot".to_owned(),
        tool_name: "fs.read".to_owned(),
        decision: "allow".to_owned(),
        latency_ms: None,
        ts: Utc::now(),
    };
    let (a, b, c, d) = (
        Uuid::from_u128(0xA),
        Uuid::from_u128(0xB),
        Uuid::from_u128(0xC),
        Uuid::from_u128(0xD),
    );

    // Batch of 5 with 2 intra-batch duplicates (A, B repeated) → 3 new rows.
    let batch = vec![rec(a), rec(b), rec(c), rec(a), rec(b)];
    let inserted = sink.insert_audit_logs(&batch).await.expect("batch insert");
    assert_eq!(inserted, 3, "intra-batch duplicate event_ids must not double-insert");
    assert_eq!(batch.len() as u64 - inserted, 2, "caller derives duplicate count");

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(pool.pool())
        .await
        .expect("count after first batch");
    assert_eq!(count, 3);

    // Second batch: A already exists (cross-batch dup), D is new → 1 new row.
    let inserted2 = sink.insert_audit_logs(&[rec(a), rec(d)]).await.expect("second batch");
    assert_eq!(inserted2, 1, "only the previously-unseen event_id is inserted");

    let count2: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
        .fetch_one(pool.pool())
        .await
        .expect("count after second batch");
    assert_eq!(count2, 4);

    // An empty batch is a no-op.
    assert_eq!(sink.insert_audit_logs(&[]).await.expect("empty batch"), 0);
}
