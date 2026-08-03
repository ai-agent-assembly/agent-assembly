//! PostgreSQL integration test for the sensitive-data projection (AAASM-5357).
//!
//! Same properties as the SQLite suite, against the backend that actually
//! serves production: the migration applies and is idempotent, the rollback is
//! executed rather than merely written, the schema carries no offset or length
//! column, tenant scoping holds, and a replayed event does not double-count.
//!
//! Driven by `testcontainers-modules` per the repo pattern, so it needs Docker
//! on the host. It deliberately calls only the projection's own migration and
//! not `StorageBackend::migrate`: the projection owns its up and down
//! statements precisely so it can be applied and rolled back on its own.

use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    AgentLineage, AuditLabel, Endpoint, EndpointKind, EnforcementPoint, ExecutionEvidence, FieldPath, FindingCounts,
    InspectedAction, OperationKind, RequestDirection, RuntimeVerdictLabel, SensitiveDataDecisionEvent,
    SensitiveDataFindingRecord, Tenancy, TransmissionEvidence, TrustZone,
};
use aa_core::types::AgentId;
use aa_security::canonical::{
    ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus,
    Provenance, Recognizer, Severity,
};

use aa_gateway::storage::sensitive_data::{
    SensitiveDataEventFilter, SensitiveDataProjection, SensitiveDataProjectionConfig, SensitiveDataProjectionWriter,
    TenantScope,
};
use aa_gateway::storage::{PostgresBackend, PostgresConfig};

const SPAN_START: usize = 760_913;
const SPAN_END: usize = 760_931;

fn record(event_id: &str, category: CanonicalCategory, path: &str) -> SensitiveDataFindingRecord {
    let finding = CanonicalFinding::new(
        category,
        Severity::Critical,
        ConfidenceBand::High,
        ByteSpan::new(SPAN_START, SPAN_END),
        DetectionMethod::Deterministic,
        Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
        FindingStatus::Confirmed,
    )
    .expect("well-formed span");
    SensitiveDataFindingRecord::from_finding(
        AuditLabel::new(event_id).expect("event id"),
        &finding,
        FieldPath::parse(path).expect("field path"),
    )
    .expect("record projects")
}

/// ADR 0032 §8's worked example: three findings, one blocked action.
fn blocked_action_with_three_findings(
    event_id: &str,
    org: &str,
    tenant: &str,
) -> (SensitiveDataDecisionEvent, Vec<SensitiveDataFindingRecord>) {
    let email = CanonicalCategory::unqualified(CategoryBase::EmailAddress);
    let token = CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access");
    let records = vec![
        record(event_id, email, "body.customer.email"),
        record(event_id, email, "body.contact.email"),
        record(event_id, token, "headers.authorization"),
    ];
    let counts = FindingCounts::tally(&records, 0, 3).expect("tally");

    let event = SensitiveDataDecisionEvent::builder(
        AuditLabel::new(event_id).expect("event id"),
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        Tenancy {
            org_id: AuditLabel::new(org).expect("org"),
            tenant_id: AuditLabel::new(tenant).expect("tenant"),
            team_id: Some(AuditLabel::new("billing").expect("team")),
        },
        AgentLineage {
            acting_agent: AgentId::parse("acme/billing-bot").expect("agent"),
            root_agent: AgentId::parse("acme/orchestrator").expect("agent"),
            parent_agent: None,
            delegation_depth: 0,
        },
        InspectedAction {
            operation: OperationKind::ToolCall,
            source: None,
            destination: Endpoint::new(EndpointKind::HttpHost, "api.example.com").expect("endpoint"),
            trust_zone: TrustZone::Public,
            direction: RequestDirection::Outbound,
        },
        RuntimeVerdictLabel::DENY,
        ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        ),
    )
    .finding_counts(counts)
    .build();

    (event, records)
}

fn filter(org: &str, tenant: &str) -> SensitiveDataEventFilter {
    SensitiveDataEventFilter::new(TenantScope::new(org, tenant).expect("scope"))
}

/// The whole projection lifecycle on a real PostgreSQL cluster.
///
/// One test rather than several because each would otherwise pay for its own
/// container start; the assertions are independent and each names what it
/// checks.
#[tokio::test]
async fn projection_migrates_persists_isolates_and_rolls_back_on_postgres() {
    use testcontainers_modules::postgres::Postgres;
    use testcontainers_modules::testcontainers::runners::AsyncRunner;

    let container = Postgres::default()
        .start()
        .await
        .expect("failed to start postgres testcontainer (is Docker running?)");
    let host = container.get_host().await.expect("container host");
    let port = container.get_host_port_ipv4(5432).await.expect("container port");

    let backend = PostgresBackend::connect(&PostgresConfig {
        database_url: Some(format!("postgres://postgres:postgres@{host}:{port}/postgres")),
        max_connections: 4,
        min_connections: 1,
        ..PostgresConfig::default()
    })
    .await
    .expect("connect to postgres container");

    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("projection migration applies to a fresh cluster");
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("re-migrating must be a no-op");

    // ADR 0032 §9: no offset, length, span or payload column reaches this tier.
    let columns = backend
        .sensitive_data_projection_columns()
        .await
        .expect("read information_schema");
    assert!(!columns.is_empty(), "the migration created no columns");
    for (table, name) in &columns {
        for banned in ["offset", "length", "span", "byte", "payload", "raw"] {
            assert!(
                !name.contains(banned),
                "{table}.{name} contains `{banned}` — audit-tier only (ADR 0032 §9)"
            );
        }
    }

    let writer = SensitiveDataProjectionWriter::new(backend, SensitiveDataProjectionConfig::enabled());
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    for attempt in 0..2 {
        writer
            .write(
                &event,
                &findings,
                Timestamp::from_nanos(1_700_000_000_100_000_000 + attempt),
            )
            .await
            .expect("write (and replay) must be accepted");
    }

    let owner = filter("acme", "acme-prod");
    let store = writer.store();
    assert_eq!(
        store.count_sensitive_data_events(&owner).await.expect("count"),
        1,
        "a replayed event must not double-count"
    );
    assert_eq!(
        store.count_sensitive_data_findings(&owner).await.expect("count"),
        3,
        "finding rows are a different count from event rows and must survive the replay"
    );

    let row = &store.query_sensitive_data_events(&owner).await.expect("events")[0];
    assert_eq!(row.blocked_event_count, 1);
    assert_eq!(row.blocked_finding_count, 3);
    assert!(
        row.counts_as_prevented_transmission(),
        "denied pre-transmission with the bytes observed not to have gone"
    );

    let intruder = filter("acme", "acme-staging");
    assert_eq!(store.count_sensitive_data_events(&intruder).await.expect("count"), 0);
    assert_eq!(store.count_sensitive_data_findings(&intruder).await.expect("count"), 0);
    assert!(store
        .aggregate_sensitive_data_by_category(&intruder)
        .await
        .expect("aggregate")
        .is_empty());

    // The rollback is executed, not merely written.
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
        .migrate_sensitive_data_projection()
        .await
        .expect("re-applying after a rollback must work");
}
