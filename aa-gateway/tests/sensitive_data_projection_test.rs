//! Adversarial tests for the durable sensitive-data projection (AAASM-5357).
//!
//! These live in `tests/` on purpose. Every claim this file makes is about
//! something a *consumer* of the projection can or cannot observe — an offset
//! in a column, a span in a serialized row, one tenant's rows under another
//! tenant's scope — and a unit test inside `storage::sensitive_data` would
//! share that module's privacy and could therefore assert the claim by
//! inspecting things no consumer can reach. From out here the only available
//! surface is the public one, which is the surface the claim is about.
//!
//! ADR 0032 §9 is the source of the tiering rules; §8 of the counting rules.

use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    AgentLineage, AuditLabel, CategoryLabel, EndpointKind, EnforcementPoint, ExecutionEvidence, FieldPath,
    FindingClassification, FindingCounts, InspectedAction, InspectionLatency, OperationKind, PolicyAttribution,
    PolicyReasonCode, RequestDirection, RuntimeVerdictLabel, SensitiveDataDecisionEvent, SensitiveDataFindingRecord,
    SensitiveDataMetricLabels, Tenancy, TransmissionEvidence, TrustZone,
};
use aa_core::types::AgentId;
use aa_security::canonical::{
    ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus,
    Provenance, Recognizer, Severity,
};

use aa_gateway::storage::sensitive_data::{
    CategoryFindingAggregate, ProjectionError, SensitiveDataEventFilter, SensitiveDataProjection,
    SensitiveDataProjectionConfig, SensitiveDataProjectionWriter, TenantScope, WriteOutcome,
};
use aa_gateway::storage::{SqliteBackend, SqliteConfig, StorageBackend};

/// A byte span whose numbers appear nowhere else in this file, in the schema,
/// or in any vocabulary the projection stores.
///
/// The point of picking odd six-digit values rather than the `(4, 44)` the
/// `aa-core` fixtures use: a search for "4" in a serialized row finds a schema
/// version, a delegation depth and a latency. A search for `760913` finds a
/// leak or nothing.
const SPAN_START: usize = 760_913;
const SPAN_END: usize = 760_931;

/// A marker standing in for the sensitive value itself.
///
/// No real credential is constructed anywhere here. The projection's write path
/// never receives a payload at all, so this is a regression guard rather than a
/// live risk: if a payload column is ever added, this marker is what proves it.
const SECRET_MARKER: &str = "ZZ-synthetic-secret-value-do-not-store-ZZ";

fn synthetic_finding(category: CanonicalCategory) -> CanonicalFinding {
    CanonicalFinding::new(
        category,
        Severity::Critical,
        ConfidenceBand::High,
        ByteSpan::new(SPAN_START, SPAN_END),
        DetectionMethod::Deterministic,
        Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
        FindingStatus::Confirmed,
    )
    .expect("well-formed span")
}

fn record(event_id: &str, category: CanonicalCategory, path: &str) -> SensitiveDataFindingRecord {
    SensitiveDataFindingRecord::from_finding(
        AuditLabel::new(event_id).expect("well-formed event id"),
        &synthetic_finding(category),
        FieldPath::parse(path).expect("well-formed field path"),
    )
    .expect("record projects")
}

fn tenancy(org: &str, tenant: &str) -> Tenancy {
    Tenancy {
        org_id: AuditLabel::new(org).expect("org label"),
        tenant_id: AuditLabel::new(tenant).expect("tenant label"),
        team_id: Some(AuditLabel::new("billing").expect("team label")),
    }
}

fn lineage() -> AgentLineage {
    AgentLineage {
        acting_agent: AgentId::parse("acme/billing-bot").expect("agent id"),
        root_agent: AgentId::parse("acme/orchestrator").expect("agent id"),
        parent_agent: Some(AgentId::parse("acme/orchestrator").expect("agent id")),
        delegation_depth: 1,
    }
}

fn action() -> InspectedAction {
    InspectedAction {
        operation: OperationKind::ToolCall,
        source: None,
        destination: aa_core::types::sensitive_data::Endpoint::new(EndpointKind::HttpHost, "api.example.com")
            .expect("endpoint"),
        trust_zone: TrustZone::Public,
        direction: RequestDirection::Outbound,
    }
}

/// ADR 0032 §8's worked example: three findings in one action, blocked before
/// transmission while enforcing. Two of the findings share a category, so the
/// per-category event count and finding count differ as well.
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
        tenancy(org, tenant),
        lineage(),
        action(),
        RuntimeVerdictLabel::DENY,
        ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        ),
    )
    .finding_counts(counts)
    .classification(FindingClassification {
        severity: Severity::Critical,
        confidence: ConfidenceBand::High,
        method: DetectionMethod::Deterministic,
        status: FindingStatus::Confirmed,
    })
    .inspected_fields(vec![
        FieldPath::parse("body.customer.email").expect("path"),
        FieldPath::parse("body.contact.email").expect("path"),
        FieldPath::parse("headers.authorization").expect("path"),
    ])
    .policy(PolicyAttribution {
        document_id: Some(AuditLabel::new("sha256:abc123").expect("doc id")),
        version: Some(7),
        matched_rule_ids: vec![AuditLabel::new("no-pii-to-public-hosts").expect("rule id")],
    })
    .reason_codes(vec![PolicyReasonCode::SensitiveDataDetected])
    .latency(InspectionLatency {
        provider_us: None,
        total_us: 6,
    })
    .build();

    (event, records)
}

async fn migrated_backend() -> (tempfile::TempDir, SqliteBackend) {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: dir.path().join("projection.db"),
    })
    .await
    .expect("open sqlite");
    backend.migrate().await.expect("base migrate");
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("projection migrate");
    (dir, backend)
}

fn scope(org: &str, tenant: &str) -> TenantScope {
    TenantScope::new(org, tenant).expect("scope")
}

fn filter(org: &str, tenant: &str) -> SensitiveDataEventFilter {
    SensitiveDataEventFilter::new(scope(org, tenant))
}

fn writer(backend: SqliteBackend) -> SensitiveDataProjectionWriter<SqliteBackend> {
    SensitiveDataProjectionWriter::new(backend, SensitiveDataProjectionConfig::enabled())
}

// ---------------------------------------------------------------------------
// ADR 0032 §9 — offsets and lengths belong to the audit tier only
// ---------------------------------------------------------------------------

/// The exact column set of both tables, read from the live SQLite catalogue.
///
/// Pinned exactly rather than checked for the absence of a list of bad names:
/// a substring check knows only the leaks someone thought of, whereas an exact
/// set fails on any column at all that is not on the reviewed list — which is
/// the property ADR 0032 §9 actually needs.
#[tokio::test]
async fn projection_tables_have_exactly_the_reviewed_columns_and_no_offset() {
    let (_dir, backend) = migrated_backend().await;

    let mut actual = backend
        .sensitive_data_projection_columns()
        .await
        .expect("read catalogue")
        .into_iter()
        .map(|(table, column)| format!("{table}.{column}"))
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = EXPECTED_EVENT_COLUMNS
        .iter()
        .map(|c| format!("sensitive_data_events.{c}"))
        .chain(
            EXPECTED_FINDING_COLUMNS
                .iter()
                .map(|c| format!("sensitive_data_findings.{c}")),
        )
        .collect::<Vec<_>>();
    expected.sort();

    assert_eq!(
        actual, expected,
        "the projection's persisted columns changed; ADR 0032 §9 confines offsets and \
         lengths to the tamper-evident tier, so any new column here needs review"
    );

    // Belt as well as braces: the exact-set assertion above is the real guard,
    // but naming the forbidden shapes documents *why* the list is closed.
    for entry in &actual {
        let name = entry.split('.').next_back().expect("qualified name");
        for banned in ["offset", "length", "span", "byte", "payload", "raw"] {
            assert!(
                !name.contains(banned),
                "column `{entry}` contains `{banned}` — offsets, lengths and payloads are \
                 audit-tier only (ADR 0032 §9)"
            );
        }
    }
}

/// The serialized shape a consumer receives, pinned the same way.
///
/// Separate from the column test because they can diverge: a struct field with
/// no column would still be published to any consumer that serializes a row.
#[tokio::test]
async fn serialized_rows_expose_exactly_the_reviewed_keys_and_no_span() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);
    writer
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    let events = writer
        .store()
        .query_sensitive_data_events(&filter("acme", "acme-prod"))
        .await
        .expect("query events");
    let rows = writer
        .store()
        .query_sensitive_data_findings(&filter("acme", "acme-prod"))
        .await
        .expect("query findings");

    let event_json = serde_json::to_value(&events[0]).expect("serialize event row");
    let finding_json = serde_json::to_value(&rows[0]).expect("serialize finding row");

    let mut event_keys = event_json
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    event_keys.sort();
    let mut expected_event = EXPECTED_EVENT_COLUMNS
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    expected_event.sort();
    assert_eq!(
        event_keys, expected_event,
        "the event row's serialized keys must match its columns exactly"
    );

    let mut finding_keys = finding_json
        .as_object()
        .expect("object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    finding_keys.sort();
    let mut expected_finding = EXPECTED_FINDING_COLUMNS
        .iter()
        .map(|s| (*s).to_string())
        .collect::<Vec<_>>();
    expected_finding.sort();
    assert_eq!(
        finding_keys, expected_finding,
        "the finding row's serialized keys must match its columns exactly"
    );
}

/// The end-to-end attack: a finding carrying a distinctive span goes in, and
/// neither of its numbers comes back out of storage in any form.
///
/// This is the assertion the type-level argument is supposed to make
/// unnecessary — and the reason it is written anyway. "Span-free by
/// construction" is a claim about construction paths, not an unrepresentable
/// state; the fields are `pub` and `Deserialize` rebuilds a record from bytes.
/// So the claim is checked against what is actually durable.
#[tokio::test]
async fn a_findings_byte_span_reaches_no_part_of_the_persisted_projection() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");

    // The span really is on the finding that was scanned — otherwise this test
    // would pass by testing nothing, which is how a span-leak test fails.
    let scanned = synthetic_finding(CanonicalCategory::unqualified(CategoryBase::EmailAddress));
    assert_eq!(scanned.span().start(), SPAN_START, "fixture must carry the span");

    let writer = writer(backend);
    writer
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    let f = filter("acme", "acme-prod");
    let events = writer.store().query_sensitive_data_events(&f).await.expect("events");
    let rows = writer
        .store()
        .query_sensitive_data_findings(&f)
        .await
        .expect("findings");

    let dump = format!(
        "{}{}",
        serde_json::to_string(&events).expect("serialize events"),
        serde_json::to_string(&rows).expect("serialize findings"),
    );

    for needle in [SPAN_START.to_string(), SPAN_END.to_string()] {
        assert!(
            !dump.contains(&needle),
            "byte offset {needle} reached the non-audit projection; ADR 0032 §9 permits \
             offsets only in the tamper-evident tier"
        );
    }
    assert!(
        !dump.contains(SECRET_MARKER),
        "a sensitive value reached the projection; it stores redacted and derived data only"
    );
    // The drill-down granularity §9 grants *in place of* offsets did survive —
    // otherwise the absence above would just mean nothing was stored.
    assert!(
        dump.contains("headers.authorization"),
        "field paths are the drill-down granularity and must be persisted"
    );
}

// ---------------------------------------------------------------------------
// ADR 0032 §8 — event counts and finding counts are different numbers
// ---------------------------------------------------------------------------

/// The §8 worked example, carried all the way through storage.
///
/// Three findings in one blocked action: one blocked *event*, three blocked
/// *findings*. Both numbers are read back from the database rather than from
/// the in-memory event, because the collapse this guards against is a writer
/// putting one of them in the other's column.
#[tokio::test]
async fn one_blocked_action_with_three_findings_persists_as_one_event_and_three_findings() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);
    writer
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    let f = filter("acme", "acme-prod");
    let store = writer.store();

    assert_eq!(store.count_sensitive_data_events(&f).await.expect("count"), 1);
    assert_eq!(store.count_sensitive_data_findings(&f).await.expect("count"), 3);

    let row = &store.query_sensitive_data_events(&f).await.expect("events")[0];
    assert_eq!(row.event_count, 1, "one action is one event");
    assert_eq!(row.blocked_event_count, 1, "the action was refused");
    assert_eq!(row.finding_count, 3);
    assert_eq!(row.blocked_finding_count, 3);
    assert_ne!(
        row.blocked_event_count, row.blocked_finding_count,
        "the two are different measures and must not be interchangeable"
    );

    // The per-category aggregate reports both, and for the doubled category
    // they differ — two email findings inside a single event.
    let aggregates = store
        .aggregate_sensitive_data_by_category(&f)
        .await
        .expect("aggregate by category");
    // Rendered from the catalogue rather than spelled out, so a renamed
    // category is a compile-or-lookup failure here instead of a silently
    // never-matching `find` that makes the assertions below unreachable.
    let email_label = CategoryLabel::from(CanonicalCategory::unqualified(CategoryBase::EmailAddress));
    let email = aggregates
        .iter()
        .find(|a| a.category == email_label.as_str())
        .unwrap_or_else(|| panic!("email category present; got {aggregates:?}"));
    assert_eq!(email.finding_count, 2, "two email findings");
    assert_eq!(email.event_count, 1, "in one event");
    assert_ne!(
        email.finding_count, email.event_count,
        "an aggregate that reported one of these as the other would be wrong by a \
         factor that varies per action (forbidden design #11)"
    );

    // A structural guard as well as a numeric one: adding a grouping dimension
    // to this aggregate stops the suite compiling, which is what keeps an
    // unbounded label — a destination, an agent id — out of it.
    let CategoryFindingAggregate {
        category: _,
        finding_count: _,
        event_count: _,
    } = aggregates[0].clone();
}

/// A producer whose finding rows disagree with its own tallies is refused
/// before anything becomes durable.
#[tokio::test]
async fn a_row_count_that_disagrees_with_the_events_tally_is_refused() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);

    let err = writer
        .write(&event, &findings[..2], Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect_err("two rows against a three-finding tally must be refused");
    assert!(
        matches!(
            err,
            ProjectionError::FindingCountMismatch {
                declared: 3,
                supplied: 2,
                ..
            }
        ),
        "expected FindingCountMismatch, got {err:?}"
    );

    let f = filter("acme", "acme-prod");
    assert_eq!(
        writer.store().count_sensitive_data_events(&f).await.expect("count"),
        0,
        "a refused projection must leave nothing behind"
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

/// One tenant's rows are invisible under another tenant's scope, on every read
/// path — including the findings table, which is scoped by its own columns
/// rather than by joining the events table.
#[tokio::test]
async fn a_neighbouring_tenant_sees_none_of_it() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);
    writer
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    let store = writer.store();
    let owner = filter("acme", "acme-prod");
    let same_org_other_tenant = filter("acme", "acme-staging");
    let other_org_same_tenant_name = filter("globex", "acme-prod");

    assert_eq!(store.count_sensitive_data_events(&owner).await.expect("count"), 1);

    for intruder in [&same_org_other_tenant, &other_org_same_tenant_name] {
        assert_eq!(
            store.count_sensitive_data_events(intruder).await.expect("count"),
            0,
            "events leaked across a tenant boundary"
        );
        assert_eq!(
            store.count_sensitive_data_findings(intruder).await.expect("count"),
            0,
            "findings leaked across a tenant boundary"
        );
        assert!(
            store
                .query_sensitive_data_events(intruder)
                .await
                .expect("query")
                .is_empty(),
            "event rows leaked across a tenant boundary"
        );
        assert!(
            store
                .query_sensitive_data_findings(intruder)
                .await
                .expect("query")
                .is_empty(),
            "finding rows leaked across a tenant boundary"
        );
        assert!(
            store
                .aggregate_sensitive_data_by_category(intruder)
                .await
                .expect("aggregate")
                .is_empty(),
            "an aggregate leaked across a tenant boundary — the failure mode that is a \
             smaller-looking answer rather than an error"
        );
    }
}

/// A blank tenant is not a narrower scope, so it cannot be constructed.
#[test]
fn an_empty_tenancy_cannot_be_scoped() {
    assert!(matches!(
        TenantScope::new("", "acme-prod"),
        Err(ProjectionError::EmptyTenancy("org_id"))
    ));
    assert!(matches!(
        TenantScope::new("acme", "   "),
        Err(ProjectionError::EmptyTenancy("tenant_id"))
    ));
    assert!(TenantScope::new("acme", "acme-prod").is_ok());
}

// ---------------------------------------------------------------------------
// Idempotency and late arrivals
// ---------------------------------------------------------------------------

/// A replayed event does not double-count, on either table.
#[tokio::test]
async fn a_replayed_event_does_not_double_count() {
    let (_dir, backend) = migrated_backend().await;
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);

    for attempt in 0..3 {
        writer
            .write(
                &event,
                &findings,
                Timestamp::from_nanos(1_700_000_000_100_000_000 + attempt),
            )
            .await
            .expect("replay must be accepted, not rejected");
    }

    let f = filter("acme", "acme-prod");
    assert_eq!(writer.store().count_sensitive_data_events(&f).await.expect("count"), 1);
    assert_eq!(
        writer.store().count_sensitive_data_findings(&f).await.expect("count"),
        3,
        "three replays of a three-finding event is still three findings"
    );
}

/// The documented late-arrival rule: first write wins.
///
/// A duplicate arriving after the fact cannot rewrite tallies a reader may
/// already have acted on, so a dashboard's numbers do not move under it.
#[tokio::test]
async fn a_late_duplicate_cannot_rewrite_the_stored_tallies() {
    let (_dir, backend) = migrated_backend().await;
    let (first, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    let writer = writer(backend);
    writer
        .write(&first, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("first write");

    // Same event id, a different verdict and different tallies — the shape a
    // corrupted or re-decided replay would have.
    let single = vec![record(
        "01HZX9V8ABCDEFGHJKMNPQRSTV",
        CanonicalCategory::unqualified(CategoryBase::EmailAddress),
        "body.customer.email",
    )];
    let contradicting = SensitiveDataDecisionEvent::builder(
        AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").expect("event id"),
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        tenancy("acme", "acme-prod"),
        lineage(),
        action(),
        RuntimeVerdictLabel::ALLOW,
        ExecutionEvidence::unrecorded(EnforcementMode::Observe),
    )
    .finding_counts(FindingCounts::tally(&single, 0, 0).expect("tally"))
    .build();

    writer
        .write(
            &contradicting,
            &single,
            Timestamp::from_nanos(1_700_000_999_000_000_000),
        )
        .await
        .expect("a late duplicate is ignored, not an error");

    let f = filter("acme", "acme-prod");
    let row = &writer.store().query_sensitive_data_events(&f).await.expect("events")[0];
    assert_eq!(row.verdict, "deny", "first write wins");
    assert_eq!(row.blocked_finding_count, 3, "the stored tallies did not move");
    assert_eq!(
        writer.store().count_sensitive_data_findings(&f).await.expect("count"),
        3,
        "the late duplicate added no finding rows"
    );
}

// ---------------------------------------------------------------------------
// Migration and rollback
// ---------------------------------------------------------------------------

/// The migration is idempotent and the rollback is executed, not merely
/// written — and running it leaves the audit tables untouched.
#[tokio::test]
async fn the_migration_is_idempotent_and_the_rollback_is_a_real_inverse() {
    let (_dir, backend) = migrated_backend().await;

    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("re-migrating must be a no-op");
    assert_eq!(
        backend
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .len(),
        EXPECTED_EVENT_COLUMNS.len() + EXPECTED_FINDING_COLUMNS.len()
    );

    backend
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback must apply");
    assert!(
        backend
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .is_empty(),
        "rollback must remove the projection's tables"
    );

    // The audit path is unaffected by the rollback — which is the whole reason
    // the projection owns its own up/down rather than joining the shared
    // migrator.
    backend
        .count_audit_events(Default::default())
        .await
        .expect("the audit tables must survive a projection rollback");

    backend
        .rollback_sensitive_data_projection()
        .await
        .expect("rollback must itself be idempotent");
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("re-applying after a rollback must work");
    assert_eq!(
        backend
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .len(),
        EXPECTED_EVENT_COLUMNS.len() + EXPECTED_FINDING_COLUMNS.len()
    );
}

// ---------------------------------------------------------------------------
// The flag
// ---------------------------------------------------------------------------

/// With the flag off nothing is written, no tables are created, and the
/// existing audit path is unaffected.
#[tokio::test]
async fn a_disabled_projection_writes_nothing_and_leaves_the_audit_path_alone() {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: dir.path().join("projection.db"),
    })
    .await
    .expect("open sqlite");
    backend.migrate().await.expect("base migrate");

    let writer = SensitiveDataProjectionWriter::new(backend, SensitiveDataProjectionConfig::disabled());
    assert!(!writer.is_enabled());
    assert_eq!(writer.migrate().await.expect("migrate"), WriteOutcome::Disabled);

    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    assert_eq!(
        writer
            .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
            .await
            .expect("a disabled write is a no-op, not an error"),
        WriteOutcome::Disabled
    );

    assert!(
        writer
            .store()
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .is_empty(),
        "a disabled projection must not create its tables"
    );
    // The audit path still works with the projection off, which is what
    // "turned off without affecting existing audit behaviour" means.
    writer
        .store()
        .count_audit_events(Default::default())
        .await
        .expect("audit path unaffected");
}

// ---------------------------------------------------------------------------
// Prevention requires evidence
// ---------------------------------------------------------------------------

/// Only a deny-or-transforming verdict, applied pre-transmission, while
/// enforcing, with the bytes observed not to have gone, counts as prevention.
///
/// The negative cases are the point. `scrub` with `forwarded_clean` is what a
/// successful redaction looks like — a *transformed transmission* — and it is
/// the case the `CredentialLeakBlocked` event name already got wrong once.
#[tokio::test]
async fn prevention_is_claimed_only_where_the_evidence_supports_it() {
    let (_dir, backend) = migrated_backend().await;
    let writer = writer(backend);

    let cases: [(
        &str,
        RuntimeVerdictLabel,
        EnforcementPoint,
        TransmissionEvidence,
        EnforcementMode,
        bool,
    ); 7] = [
        (
            "01HZX9V8ABCDEFGHJKMNPQRS01",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            true,
        ),
        (
            // Redaction forwards the scrubbed bytes. Detected, not prevented.
            "01HZX9V8ABCDEFGHJKMNPQRS02",
            RuntimeVerdictLabel::SCRUB,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::ForwardedClean,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // `narrow` scopes the action without transforming the payload.
            "01HZX9V8ABCDEFGHJKMNPQRS03",
            RuntimeVerdictLabel::NARROW,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // Observe mode computed the decision and applied nothing.
            "01HZX9V8ABCDEFGHJKMNPQRS04",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Observe,
            false,
        ),
        (
            // Decided after the bytes left.
            "01HZX9V8ABCDEFGHJKMNPQRS05",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PostTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // An unwired producer must not claim prevention by saying nothing.
            "01HZX9V8ABCDEFGHJKMNPQRS06",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::NotRecorded,
            TransmissionEvidence::NotRecorded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // The layer decided to redact and emitted the credential anyway.
            "01HZX9V8ABCDEFGHJKMNPQRS07",
            RuntimeVerdictLabel::SCRUB,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::ForwardedCarryingSensitiveValue,
            EnforcementMode::Enforce,
            false,
        ),
    ];

    for (event_id, verdict, point, transmission, mode, _expected) in cases {
        let event = SensitiveDataDecisionEvent::builder(
            AuditLabel::new(event_id).expect("event id"),
            Timestamp::from_nanos(1_700_000_000_000_000_000),
            tenancy("acme", "acme-prod"),
            lineage(),
            action(),
            verdict,
            ExecutionEvidence::new(point, transmission, mode),
        )
        .build();
        writer
            .write(&event, &[], Timestamp::from_nanos(1_700_000_000_100_000_000))
            .await
            .expect("write");
    }

    let rows = writer
        .store()
        .query_sensitive_data_events(&filter("acme", "acme-prod"))
        .await
        .expect("events");

    for (event_id, _, _, _, _, expected) in cases {
        let row = rows.iter().find(|r| r.event_id == event_id).expect("row present");
        assert_eq!(
            row.counts_as_prevented_transmission(),
            expected,
            "prevention verdict wrong for {event_id} \
             (verdict={}, point={}, transmission={}, mode={})",
            row.verdict,
            row.enforcement_point,
            row.transmission_evidence,
            row.enforcement_mode
        );
    }
}

// ---------------------------------------------------------------------------
// Metric labels stay bounded
// ---------------------------------------------------------------------------

/// A category this build cannot resolve is stored for drill-down but refused as
/// a metric label.
///
/// Both directions are asserted in one test on purpose. A test that only walked
/// the catalogue's own members could never reach the unbounded case and would
/// pass while the guard did nothing — the precedent this is written against.
/// The positive control is what proves the negative is not vacuous.
#[tokio::test]
async fn an_unresolvable_category_is_stored_for_drill_down_but_refused_as_a_label() {
    let mut arbitrary = record(
        "01HZX9V8ABCDEFGHJKMNPQRSTV",
        CanonicalCategory::unqualified(CategoryBase::EmailAddress),
        "body.customer.email",
    );
    // The shape an attacker-influenced or newer-build category would have:
    // well-formed, unbounded, and not in this build's catalogue.
    arbitrary.category = CategoryLabel::new("acme_internal_customer_ssn_v3_9f2c1b").expect("well-formed label");

    assert!(
        SensitiveDataMetricLabels::from_finding(&arbitrary, RuntimeVerdictLabel::DENY).is_none(),
        "an unresolvable category must not become a metric label — it is an unbounded \
         series, which ADR 0032 §9 forbids"
    );

    let catalogued = record(
        "01HZX9V8ABCDEFGHJKMNPQRSTV",
        CanonicalCategory::unqualified(CategoryBase::EmailAddress),
        "body.customer.email",
    );
    let labels = SensitiveDataMetricLabels::from_finding(&catalogued, RuntimeVerdictLabel::DENY)
        .expect("a catalogue category must resolve — otherwise the None above proves nothing");

    let names = labels.as_pairs().map(|(name, _)| name);
    assert_eq!(names, SensitiveDataMetricLabels::LABEL_NAMES);
    for banned in ["destination", "tenant", "org", "agent", "field_path", "event_id"] {
        assert!(
            !names.contains(&banned),
            "`{banned}` is unbounded cardinality and must never be a metric label"
        );
    }

    // The unresolvable category is still durable, so the drill-down that
    // replaces the offset is not lost by refusing the label.
    let (_dir, backend) = migrated_backend().await;
    let (event, mut findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNPQRSTV", "acme", "acme-prod");
    findings[0].category = CategoryLabel::new("acme_internal_customer_ssn_v3_9f2c1b").expect("label");
    let counts = FindingCounts::tally(&findings, 0, 3).expect("tally");
    let event = SensitiveDataDecisionEvent::builder(
        AuditLabel::new("01HZX9V8ABCDEFGHJKMNPQRSTV").expect("event id"),
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        tenancy("acme", "acme-prod"),
        lineage(),
        action(),
        event.verdict,
        ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        ),
    )
    .finding_counts(counts)
    .build();

    let writer = writer(backend);
    writer
        .write(&event, &findings, Timestamp::from_nanos(1_700_000_000_100_000_000))
        .await
        .expect("write");

    let stored = writer
        .store()
        .query_sensitive_data_findings(&filter("acme", "acme-prod"))
        .await
        .expect("findings");
    assert!(
        stored
            .iter()
            .any(|r| r.category == "acme_internal_customer_ssn_v3_9f2c1b"),
        "an unresolvable category must still be persisted for drill-down"
    );
}

// ---------------------------------------------------------------------------
// The reviewed column lists
// ---------------------------------------------------------------------------

/// Every column of `sensitive_data_events`, reviewed against ADR 0032 §9.
const EXPECTED_EVENT_COLUMNS: &[&str] = &[
    "schema_version_major",
    "schema_version_minor",
    "event_id",
    "occurred_at_ns",
    "ingested_at_ns",
    "org_id",
    "tenant_id",
    "team_id",
    "acting_agent_id",
    "root_agent_id",
    "parent_agent_id",
    "delegation_depth",
    "session_id",
    "trace_id",
    "request_id",
    "correlation_id",
    "operation",
    "destination_kind",
    "destination_id",
    "trust_zone",
    "direction",
    "policy_document_id",
    "policy_version",
    "matched_rule_ids",
    "inspected_field_paths",
    "verdict",
    "enforcement_point",
    "transmission_evidence",
    "enforcement_mode",
    "inspection_failure_path",
    "severity",
    "confidence",
    "method",
    "status",
    "event_count",
    "blocked_event_count",
    "finding_count",
    "blocked_finding_count",
    "transformed_finding_count",
    "finding_count_by_category",
    "reason_codes",
];

/// Every column of `sensitive_data_findings`, reviewed the same way.
const EXPECTED_FINDING_COLUMNS: &[&str] = &[
    "schema_version_major",
    "schema_version_minor",
    "event_id",
    "finding_ordinal",
    "org_id",
    "tenant_id",
    "occurred_at_ns",
    "category",
    "severity",
    "confidence",
    "method",
    "status",
    "recognizer",
    "recognizer_version",
    "field_path",
    "redaction_label",
    "aggregate_key",
];
