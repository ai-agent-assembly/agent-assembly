//! The sensitive-data projection's contract, on PostgreSQL (AAASM-5357).
//!
//! The *same* assertions the SQLite suite runs, from `sensitive_data_contract`.
//! The first cut of this file checked a handful of properties by hand, which
//! left the exact column set, the per-category aggregate, the prevention truth
//! table, the flag and the count-mismatch refusal asserted on one backend only —
//! so a mutation to the PostgreSQL copy of the same SQL would not have failed
//! anything. Two backends, one contract, executed on both.
//!
//! Driven by `testcontainers-modules` per the repo pattern, so it needs Docker.
//! One container for the whole file: each contract assertion uses its own
//! tenant, so they compose on a single database, and a container per assertion
//! would be minutes of startup for no extra coverage.
//!
//! It calls only the projection's own migration and never
//! `StorageBackend::migrate` — the projection owns separate up and down
//! statements precisely so it can be applied and rolled back on its own.

use std::sync::Arc;

use aa_core::time::Timestamp;
use aa_gateway::storage::sensitive_data::SensitiveDataProjection;
use aa_gateway::storage::{PostgresBackend, PostgresConfig};

#[path = "sensitive_data_contract/mod.rs"]
mod contract;

/// The whole contract on a real PostgreSQL cluster.
#[tokio::test]
async fn the_projection_contract_holds_on_postgres() {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    let container = Postgres::default()
        .start()
        .await
        .expect("failed to start postgres testcontainer (is Docker running?)");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let store = Arc::new(
        PostgresBackend::connect(&PostgresConfig {
            database_url: Some(url.clone()),
            max_connections: 4,
            min_connections: 1,
            ..PostgresConfig::default()
        })
        .await
        .expect("connect to postgres container"),
    );

    // Before the migration: a disabled writer must create nothing.
    contract::a_disabled_projection_writes_nothing(&store).await;

    store
        .migrate_sensitive_data_projection()
        .await
        .expect("projection migration applies to a fresh cluster");
    store
        .migrate_sensitive_data_projection()
        .await
        .expect("re-migrating must be a no-op");

    contract::columns_are_exactly_the_reviewed_set(&store).await;
    a_same_named_table_in_another_schema_is_not_reported(&store, &url).await;
    contract::a_byte_span_reaches_no_part_of_the_projection(&store).await;
    contract::every_projected_value_round_trips(&store).await;
    contract::one_blocked_action_with_three_findings_stays_one_event(&store).await;
    contract::a_row_count_disagreeing_with_the_tally_is_refused(&store).await;
    contract::a_neighbouring_tenant_sees_none_of_it(&store).await;
    contract::two_tenants_sharing_an_event_id_keep_their_own_rows(&store).await;
    contract::a_replayed_event_does_not_double_count(&store).await;
    contract::a_divergent_replay_cannot_desynchronise_parent_from_children(&store).await;
    contract::a_late_duplicate_cannot_rewrite_stored_tallies(&store).await;
    contract::the_filters_narrowings_are_honoured_on_every_read(&store).await;
    contract::prevention_is_claimed_only_where_evidence_supports_it(&store).await;
    contract::an_unresolvable_category_is_stored_but_never_labelled(&store).await;

    unreadable_schema_major_is_refused(&store, &url).await;

    // The rollback is executed, not merely written, and re-applying works.
    store
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback applies");
    assert!(
        store
            .sensitive_data_projection_columns()
            .await
            .expect("read information_schema")
            .is_empty(),
        "rollback must remove the projection's tables"
    );
    store
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback must itself be idempotent");
    store
        .migrate_sensitive_data_projection()
        .await
        .expect("re-applying after a rollback must work");
}

/// A same-named table in another schema must not be reported as ours.
///
/// `sensitive_data_projection_columns` is the mechanism the entire "no offset
/// column" claim rests on, and on PostgreSQL it reads a catalogue view rather
/// than a per-table pragma. Without `table_schema = current_schema()` that view
/// answers for every schema on the search path, so a `decoy.sensitive_data_findings`
/// carrying a `span_start` column would be reported under the projection's own
/// name — the exact-set assertion would then either fail for the wrong reason
/// or, if the decoy happened to match, pass while describing the wrong table.
///
/// The decoy is planted and removed here so the filter is proved load-bearing
/// rather than assumed. This closes the over-reporting half only; the
/// under-reporting half — `information_schema` hides columns the connecting
/// role lacks privilege on — is named in the implementation and stays open.
async fn a_same_named_table_in_another_schema_is_not_reported(store: &Arc<PostgresBackend>, url: &str) {
    let pool = sqlx::PgPool::connect(url).await.expect("second connection");
    sqlx::query("CREATE SCHEMA IF NOT EXISTS decoy")
        .execute(&pool)
        .await
        .expect("create decoy schema");
    sqlx::query("CREATE TABLE IF NOT EXISTS decoy.sensitive_data_findings (span_start INTEGER NOT NULL)")
        .execute(&pool)
        .await
        .expect("create decoy table");

    let columns = store
        .sensitive_data_projection_columns()
        .await
        .expect("read information_schema");
    assert!(
        !columns.iter().any(|(_, name)| name == "span_start"),
        "a same-named table in another schema was reported as the projection's own; \
         ADR 0032 §9 evidence must describe the tables this backend created"
    );
    // And the reviewed set is still exactly right with the decoy in place.
    contract::columns_are_exactly_the_reviewed_set(store).await;

    sqlx::query("DROP SCHEMA decoy CASCADE")
        .execute(&pool)
        .await
        .expect("drop decoy schema");
}

/// The PostgreSQL decoder refuses a foreign schema major, as the SQLite one
/// does. Driven through a second connection because no in-crate path can
/// produce one — which is why the read path has to defend against it.
async fn unreadable_schema_major_is_refused(store: &Arc<PostgresBackend>, url: &str) {
    let tenant = "t-schema";
    let (event, findings) = contract::blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNSCHM01", tenant);
    contract::writer(store)
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    store
        .query_sensitive_data_events(&contract::filter(tenant))
        .await
        .expect("readable at the current major");

    let pool = sqlx::PgPool::connect(url).await.expect("second connection");
    for table in ["sensitive_data_events", "sensitive_data_findings"] {
        sqlx::query(&format!(
            "UPDATE {table} SET schema_version_major = 99 WHERE tenant_id = $1"
        ))
        .bind(tenant)
        .execute(&pool)
        .await
        .expect("bump major");
    }

    for err in [
        store
            .query_sensitive_data_events(&contract::filter(tenant))
            .await
            .expect_err("a foreign major must be refused, not decoded"),
        store
            .query_sensitive_data_findings(&contract::filter(tenant))
            .await
            .expect_err("the finding decoder must refuse it too"),
    ] {
        assert!(
            err.to_string().contains("schema major 99"),
            "expected an unreadable-schema error, got: {err}"
        );
    }
}
