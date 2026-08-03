//! The sensitive-data projection's contract, on SQLite (AAASM-5357).
//!
//! The assertions themselves live in `sensitive_data_contract`, shared with the
//! PostgreSQL suite, because they are properties of the *projection* rather than
//! of a backend — see that module's header for why sharing them is not
//! optional. This file supplies a SQLite store, plus the checks that are about
//! schema lifecycle and so cannot share a database with anything else.
//!
//! They are in `tests/` rather than in the module because every claim is about
//! what a *consumer* can observe, and a unit test sharing
//! `storage::sensitive_data`'s privacy could satisfy the claim by inspecting
//! things no consumer can reach.
//!
//! ADR 0032 §9 is the source of the tiering rules; §8 of the counting rules.

use std::path::Path;
use std::sync::Arc;

use aa_core::time::Timestamp;
use aa_gateway::storage::sensitive_data::{ProjectionError, SensitiveDataProjection, TenantScope};
use aa_gateway::storage::{SqliteBackend, SqliteConfig, StorageBackend};

#[path = "sensitive_data_contract/mod.rs"]
mod contract;

/// A store with the base schema only — no projection tables.
async fn bare() -> (tempfile::TempDir, Arc<SqliteBackend>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: dir.path().join("projection.db"),
    })
    .await
    .expect("open sqlite");
    backend.migrate().await.expect("base migrate");
    (dir, Arc::new(backend))
}

/// A store with the base schema and the projection applied.
async fn migrated() -> (tempfile::TempDir, Arc<SqliteBackend>) {
    let (dir, backend) = bare().await;
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("projection migrate");
    (dir, backend)
}

/// Bind one shared contract assertion to a fresh SQLite database.
macro_rules! contract_test {
    ($name:ident) => {
        #[tokio::test]
        async fn $name() {
            let (_dir, store) = migrated().await;
            contract::$name(&store).await;
        }
    };
}

contract_test!(columns_are_exactly_the_reviewed_set);
contract_test!(a_byte_span_reaches_no_part_of_the_projection);
contract_test!(every_projected_value_round_trips);
contract_test!(one_blocked_action_with_three_findings_stays_one_event);
contract_test!(a_row_count_disagreeing_with_the_tally_is_refused);
contract_test!(a_neighbouring_tenant_sees_none_of_it);
contract_test!(a_replayed_event_does_not_double_count);
contract_test!(a_divergent_replay_cannot_desynchronise_parent_from_children);
contract_test!(a_late_duplicate_cannot_rewrite_stored_tallies);
contract_test!(the_filters_narrowings_are_honoured_on_every_read);
contract_test!(prevention_is_claimed_only_where_evidence_supports_it);
contract_test!(an_unresolvable_category_is_stored_but_never_labelled);

/// The flag test needs a store whose projection has *not* been migrated, since
/// what it asserts is that a disabled writer creates nothing.
#[tokio::test]
async fn a_disabled_projection_writes_nothing_and_leaves_the_audit_path_alone() {
    let (_dir, store) = bare().await;
    contract::a_disabled_projection_writes_nothing(&store).await;

    // The audit path still works with the projection off, which is what
    // "turned off without affecting existing audit behaviour" means.
    store
        .count_audit_events(Default::default())
        .await
        .expect("audit path unaffected");
}

/// A blank tenant is not a narrower scope, so it cannot be constructed — and a
/// scope stores what it validated, so a padded identifier cannot become one
/// that silently matches nothing.
#[test]
fn an_empty_tenancy_cannot_be_scoped_and_a_padded_one_is_normalised() {
    assert!(matches!(
        TenantScope::new("", "acme-prod"),
        Err(ProjectionError::EmptyTenancy("org_id"))
    ));
    assert!(matches!(
        TenantScope::new("acme", "   "),
        Err(ProjectionError::EmptyTenancy("tenant_id"))
    ));

    let padded = TenantScope::new("  acme  ", " acme-prod ").expect("padded identifiers are accepted");
    assert_eq!(
        padded,
        TenantScope::new("acme", "acme-prod").expect("scope"),
        "validating the trimmed form and storing the untrimmed one would make this a \
         scope that passes construction and then matches no row"
    );
}

/// The migration is idempotent and the rollback is executed, not merely written
/// — and running it leaves the audit tables intact.
#[tokio::test]
async fn the_migration_is_idempotent_and_the_rollback_is_a_real_inverse() {
    let (_dir, store) = migrated().await;
    let expected = contract::expected_qualified_columns().len();

    store
        .migrate_sensitive_data_projection()
        .await
        .expect("re-migrating must be a no-op");
    assert_eq!(
        store.sensitive_data_projection_columns().await.expect("columns").len(),
        expected
    );

    store
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback must apply");
    assert!(
        store
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .is_empty(),
        "rollback must remove the projection's tables"
    );

    // Unaffected by the rollback — the whole reason the projection owns its own
    // up and down statements rather than joining the shared migrator.
    store
        .count_audit_events(Default::default())
        .await
        .expect("the audit tables must survive a projection rollback");

    store
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback must itself be idempotent");
    store
        .migrate_sensitive_data_projection()
        .await
        .expect("re-applying after a rollback must work");
    assert_eq!(
        store.sensitive_data_projection_columns().await.expect("columns").len(),
        expected
    );
}

/// A row written against a schema major this build does not read is refused on
/// the way out, not silently decoded.
///
/// `SchemaVersion` documents this as mandatory — "a reader of a different major
/// **must** refuse the record" — and the first cut shipped an `is_readable`
/// helper with no callers, which is a comment rather than a rule. Driven
/// through raw SQL against the same file because no in-crate path can produce a
/// foreign major, which is precisely why the read path has to defend against
/// one.
#[tokio::test]
async fn a_row_from_an_unreadable_schema_major_is_refused_not_decoded() {
    let (dir, store) = migrated().await;
    let tenant = "t-schema";
    let (event, findings) = contract::blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNSCHM01", tenant);
    contract::writer(&store)
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    // Readable before the bump, so the refusal below is the bump's doing and
    // not a query that was broken all along.
    store
        .query_sensitive_data_events(&contract::filter(tenant))
        .await
        .expect("readable at the current major");
    store
        .query_sensitive_data_findings(&contract::filter(tenant))
        .await
        .expect("readable at the current major");

    bump_schema_major(&dir.path().join("projection.db"), 99).await;

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

/// Rewrite the stored schema major through a second connection, bypassing every
/// in-crate write path.
async fn bump_schema_major(path: &Path, major: i64) {
    let pool = sqlx::SqlitePool::connect(&format!("sqlite://{}", path.display()))
        .await
        .expect("second connection to the same file");
    for table in ["sensitive_data_events", "sensitive_data_findings"] {
        sqlx::query(&format!("UPDATE {table} SET schema_version_major = ?"))
            .bind(major)
            .execute(&pool)
            .await
            .expect("bump major");
    }
}
