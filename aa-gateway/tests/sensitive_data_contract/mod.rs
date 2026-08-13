//! The backend-independent contract of the sensitive-data projection.
//!
//! Every assertion in here is about the *projection*, not about SQLite or
//! PostgreSQL, so it belongs to both. It lives in a shared module because the
//! first cut asserted the exact column set, the per-category aggregate, the
//! prevention truth table, the flag and the count-mismatch refusal on SQLite
//! only — which meant a mutation to the PostgreSQL copy of the same SQL would
//! not have failed anything. "Two backends, one contract" has to be executed on
//! both backends or it is a comment.
//!
//! Each function takes an `Arc<S>` and uses its own tenant, so the whole set
//! can run sequentially against one database — which is what the PostgreSQL
//! test does, since a container per assertion would be minutes of startup for
//! no extra coverage.
//!
//! ADR 0032 §9 is the source of the tiering rules; §8 of the counting rules.

#![allow(dead_code)] // each backend's test file uses a subset; the module is shared

use std::sync::Arc;

use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    AgentLineage, AuditLabel, CategoryLabel, Endpoint, EndpointKind, EnforcementPoint, ExecutionEvidence, FieldPath,
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

/// A byte span whose numbers appear nowhere else in this repository, in the
/// schema, or in any vocabulary the projection stores.
///
/// The point of six odd digits rather than the `(4, 44)` the `aa-core` fixtures
/// use: searching a serialized row for "4" finds a schema version, a delegation
/// depth and a latency. Searching for `760913` finds a leak or nothing.
pub const SPAN_START: usize = 760_913;
pub const SPAN_END: usize = 760_931;

/// A marker standing in for the sensitive value itself. No real credential is
/// constructed anywhere in these tests.
pub const SECRET_MARKER: &str = "ZZ-synthetic-secret-value-do-not-store-ZZ";

/// A well-formed category that this build's catalogue does not contain — the
/// shape an attacker-influenced or newer-build category would have.
pub const UNRESOLVABLE_CATEGORY: &str = "acme_internal_customer_ssn_v3_9f2c1b";

pub const ORG: &str = "acme";

pub fn synthetic_finding(category: CanonicalCategory) -> CanonicalFinding {
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

pub fn record(event_id: &str, category: CanonicalCategory, path: &str) -> SensitiveDataFindingRecord {
    SensitiveDataFindingRecord::from_finding(
        AuditLabel::new(event_id).expect("well-formed event id"),
        &synthetic_finding(category),
        FieldPath::parse(path).expect("well-formed field path"),
    )
    .expect("record projects")
}

pub fn email() -> CanonicalCategory {
    CanonicalCategory::unqualified(CategoryBase::EmailAddress)
}

pub fn token() -> CanonicalCategory {
    CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access")
}

/// The rendered form of a category, taken from the catalogue rather than spelled
/// out, so a rename is a lookup failure here instead of a silently
/// never-matching `find` that makes the assertions after it unreachable.
pub fn rendered(category: CanonicalCategory) -> String {
    CategoryLabel::from(category).as_str().to_string()
}

pub fn tenancy(tenant: &str) -> Tenancy {
    Tenancy {
        org_id: AuditLabel::new(ORG).expect("org label"),
        tenant_id: AuditLabel::new(tenant).expect("tenant label"),
        team_id: Some(AuditLabel::new("billing").expect("team label")),
    }
}

pub fn lineage() -> AgentLineage {
    AgentLineage {
        acting_agent: AgentId::parse("acme/billing-bot").expect("agent id"),
        root_agent: AgentId::parse("acme/orchestrator").expect("agent id"),
        parent_agent: Some(AgentId::parse("acme/orchestrator").expect("agent id")),
        delegation_depth: 1,
    }
}

pub fn action() -> InspectedAction {
    InspectedAction {
        operation: OperationKind::ToolCall,
        source: None,
        destination: Endpoint::new(EndpointKind::HttpHost, "api.example.com").expect("endpoint"),
        trust_zone: TrustZone::Public,
        direction: RequestDirection::Outbound,
    }
}

/// ADR 0032 §8's worked example: three findings in one action, blocked before
/// transmission while enforcing. Two share a category, so the per-category event
/// count and finding count differ as well.
pub fn blocked_action_with_three_findings(
    event_id: &str,
    tenant: &str,
) -> (SensitiveDataDecisionEvent, Vec<SensitiveDataFindingRecord>) {
    let records = vec![
        record(event_id, email(), "body.customer.email"),
        record(event_id, email(), "body.contact.email"),
        record(event_id, token(), "headers.authorization"),
    ];
    let counts = FindingCounts::tally(&records, 0, 3).expect("tally");

    let event = SensitiveDataDecisionEvent::builder(
        AuditLabel::new(event_id).expect("event id"),
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        tenancy(tenant),
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

/// A one-finding allowed action, for filter tests that need a second verdict.
pub fn allowed_action_with_one_finding(
    event_id: &str,
    tenant: &str,
    occurred_at_ns: u64,
) -> (SensitiveDataDecisionEvent, Vec<SensitiveDataFindingRecord>) {
    let records = vec![record(event_id, email(), "body.customer.email")];
    let counts = FindingCounts::tally(&records, 0, 0).expect("tally");
    let event = SensitiveDataDecisionEvent::builder(
        AuditLabel::new(event_id).expect("event id"),
        Timestamp::from_nanos(occurred_at_ns),
        tenancy(tenant),
        lineage(),
        action(),
        RuntimeVerdictLabel::ALLOW,
        ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
    )
    .finding_counts(counts)
    .build();
    (event, records)
}

pub fn scope(tenant: &str) -> TenantScope {
    TenantScope::new(ORG, tenant).expect("scope")
}

pub fn filter(tenant: &str) -> SensitiveDataEventFilter {
    SensitiveDataEventFilter::new(scope(tenant))
}

pub fn writer<S: SensitiveDataProjection>(store: &Arc<S>) -> SensitiveDataProjectionWriter<Arc<S>> {
    SensitiveDataProjectionWriter::new(Arc::clone(store), SensitiveDataProjectionConfig::enabled())
}

const INGESTED: u64 = 1_700_000_000_100_000_000;

// ---------------------------------------------------------------------------
// ADR 0032 §9 — offsets and lengths belong to the audit tier only
// ---------------------------------------------------------------------------

/// The exact column set of both tables, read from the live database catalogue.
///
/// Pinned exactly rather than checked against a list of bad names: a substring
/// check knows only the leaks someone thought of, whereas an exact set fails on
/// any column at all that is not on the reviewed list.
pub async fn columns_are_exactly_the_reviewed_set<S: SensitiveDataProjection>(store: &Arc<S>) {
    let mut actual = store
        .sensitive_data_projection_columns()
        .await
        .expect("read catalogue")
        .into_iter()
        .map(|(table, column)| format!("{table}.{column}"))
        .collect::<Vec<_>>();
    actual.sort();

    let mut expected = expected_qualified_columns();
    expected.sort();

    assert_eq!(
        actual, expected,
        "the projection's persisted columns changed; ADR 0032 §9 confines offsets and \
         lengths to the tamper-evident tier, so any new column here needs review"
    );

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

/// The end-to-end attack: a finding carrying a distinctive span goes in, and
/// neither of its numbers comes back out of storage in any form.
///
/// The assertion the type-level argument is meant to make unnecessary, written
/// anyway — "span-free by construction" is a property of construction paths,
/// not an unrepresentable state.
pub async fn a_byte_span_reaches_no_part_of_the_projection<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-span";
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNSPAN01", tenant);

    // The span really is on the finding that was scanned — otherwise this would
    // pass by testing nothing, which is how a span-leak test fails.
    assert_eq!(
        synthetic_finding(email()).span().start(),
        SPAN_START,
        "fixture must carry the span"
    );

    writer(store)
        .write(&event, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write");

    let f = filter(tenant);
    let events = store.query_sensitive_data_events(&f).await.expect("events");
    let rows = store.query_sensitive_data_findings(&f).await.expect("findings");

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

/// Every column of a fully-populated event row and finding row, asserted against
/// literals.
///
/// The gap this closes: pinning column *names* cannot detect a wrong *value*.
/// Five simultaneous mutations — blanking `destination_id`, blanking
/// `matched_rule_ids` back to the audit bridge's hardcoded `None`, blanking
/// `acting_agent_id`, collapsing `transformed_finding_count` into
/// `blocked_finding_count`, and backdating `ingested_at_ns` to `occurred_at_ns`
/// — passed the entire suite before this existed. Those five are the point of
/// the whole ticket, so they are asserted one by one.
pub async fn every_projected_value_round_trips<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-roundtrip";
    let event_id = "01HZX9V8ABCDEFGHJKMNROUND1";
    let (event, findings) = blocked_action_with_three_findings(event_id, tenant);
    writer(store)
        .write(&event, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write");

    let rows = store
        .query_sensitive_data_events(&filter(tenant))
        .await
        .expect("events");
    assert_eq!(rows.len(), 1);
    let row = &rows[0];

    assert_eq!(row.schema_version_major, 1);
    assert_eq!(row.schema_version_minor, 0);
    assert_eq!(row.event_id, event_id);
    assert_eq!(row.occurred_at_ns, 1_700_000_000_000_000_000);
    assert_eq!(
        row.ingested_at_ns, INGESTED,
        "ingested_at is stored, not inferred — backdating it to occurred_at kills late-arrival visibility"
    );
    assert_eq!(row.org_id, ORG);
    assert_eq!(row.tenant_id, tenant);
    assert_eq!(row.team_id.as_deref(), Some("billing"));
    assert_eq!(
        row.acting_agent_id, "acme/billing-bot",
        "lineage is loss #3 of the audit bridge's fourteen"
    );
    assert_eq!(row.root_agent_id, "acme/orchestrator");
    assert_eq!(row.parent_agent_id.as_deref(), Some("acme/orchestrator"));
    assert_eq!(row.delegation_depth, 1);
    assert_eq!(row.session_id, None);
    assert_eq!(row.trace_id, None);
    assert_eq!(row.request_id, None);
    assert_eq!(row.correlation_id, None);
    assert_eq!(row.operation, "tool_call");
    assert_eq!(row.destination_kind, "http_host");
    assert_eq!(
        row.destination_id, "api.example.com",
        "the destination is not a dimension of the audit event at all — it is why this Epic exists"
    );
    assert_eq!(row.trust_zone, "public");
    assert_eq!(row.direction, "outbound");
    assert_eq!(row.policy_document_id.as_deref(), Some("sha256:abc123"));
    assert_eq!(row.policy_version, Some(7));
    assert_eq!(
        row.matched_rule_ids,
        vec!["no-pii-to-public-hosts".to_string()],
        "the audit bridge hardcodes matched_rule_id to None; this is the field that fixes it"
    );
    assert_eq!(
        row.inspected_field_paths,
        vec![
            "body.customer.email".to_string(),
            "body.contact.email".to_string(),
            "headers.authorization".to_string(),
        ]
    );
    assert_eq!(row.verdict, "deny");
    assert_eq!(row.enforcement_point, "pre_transmission");
    assert_eq!(row.transmission_evidence, "not_forwarded");
    assert_eq!(
        row.enforcement_mode, "enforce",
        "the honest replacement for the bridge's hardcoded dry_run: false"
    );
    assert_eq!(row.inspection_failure_path, "completed");
    assert_eq!(row.severity.as_deref(), Some("critical"));
    assert_eq!(row.confidence.as_deref(), Some("high"));
    assert_eq!(row.method.as_deref(), Some("deterministic"));
    assert_eq!(row.status.as_deref(), Some("confirmed"));
    assert_eq!(row.event_count, 1);
    assert_eq!(row.blocked_event_count, 1);
    assert_eq!(row.finding_count, 3);
    assert_eq!(row.blocked_finding_count, 3);
    assert_eq!(
        row.transformed_finding_count, 0,
        "nothing was redacted; collapsing this into blocked_finding_count is forbidden design #11"
    );
    let by_category = row
        .finding_count_by_category
        .iter()
        .map(|t| (t.category.clone(), t.count))
        .collect::<Vec<_>>();
    assert_eq!(by_category, vec![(rendered(email()), 2), (rendered(token()), 1)]);
    assert_eq!(row.reason_codes, vec!["sensitive_data_detected".to_string()]);

    // The child rows, in ordinal order.
    let mut children = store
        .query_sensitive_data_findings(&filter(tenant))
        .await
        .expect("findings");
    children.sort_by_key(|r| r.finding_ordinal);
    assert_eq!(children.len(), 3);

    let first = &children[0];
    assert_eq!(first.schema_version_major, 1);
    assert_eq!(first.schema_version_minor, 0);
    assert_eq!(first.event_id, event_id);
    assert_eq!(first.finding_ordinal, 0);
    assert_eq!(first.org_id, ORG);
    assert_eq!(first.tenant_id, tenant);
    assert_eq!(first.occurred_at_ns, 1_700_000_000_000_000_000);
    assert_eq!(
        first.verdict, "deny",
        "replicated from the parent so it can be filtered on"
    );
    assert_eq!(first.category, rendered(email()));
    assert_eq!(first.severity, "critical");
    assert_eq!(first.confidence, "high");
    assert_eq!(first.method, "deterministic");
    assert_eq!(first.status, "confirmed");
    assert_eq!(first.recognizer, "aa-security::scanner");
    assert_eq!(first.recognizer_version, "0.0.0-test");
    assert_eq!(first.field_path, "body.customer.email");
    // Pinned as a literal, not as `email().redaction_label()` — both sides of
    // that comparison resolve through the same function, so it would hold
    // however wrong the function was. Worth doing: the literal caught an
    // assumption that `EmailAddress` had no `CredentialKind` and so redacted to
    // the opaque `[REDACTED]` sentinel. It does have one, so the writing build
    // emits the qualified form, and this is the value a reader will actually
    // see in the column.
    assert_eq!(first.redaction_label, "[REDACTED:EmailAddress]");
    assert_eq!(
        first.aggregate_key,
        format!(
            "{}|body.customer.email|deterministic|aa-security::scanner",
            rendered(email())
        )
    );

    assert_eq!(children[1].field_path, "body.contact.email");
    assert_eq!(children[1].category, rendered(email()));
    assert_eq!(children[2].field_path, "headers.authorization");
    assert_eq!(children[2].category, rendered(token()));

    // The serialized shape a consumer receives, pinned the same way as the
    // columns — a struct field with no column would still be published.
    let mut event_keys = serde_json::to_value(row)
        .expect("serialize event row")
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
    assert_eq!(event_keys, expected_event);

    let mut finding_keys = serde_json::to_value(first)
        .expect("serialize finding row")
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
    assert_eq!(finding_keys, expected_finding);
}

// ---------------------------------------------------------------------------
// ADR 0032 §8 — event counts and finding counts are different numbers
// ---------------------------------------------------------------------------

/// The §8 worked example, read back from the database rather than from the
/// in-memory event, because the collapse this guards against is a writer
/// putting one number in the other's column.
pub async fn one_blocked_action_with_three_findings_stays_one_event<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-counts";
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNCOUNT1", tenant);
    writer(store)
        .write(&event, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write");

    let f = filter(tenant);
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

    let aggregates = store
        .aggregate_sensitive_data_by_category(&f)
        .await
        .expect("aggregate by category");
    let email_label = rendered(email());
    let agg = aggregates
        .iter()
        .find(|a| a.category == email_label)
        .unwrap_or_else(|| panic!("email category present; got {aggregates:?}"));
    assert_eq!(agg.finding_count, 2, "two email findings");
    assert_eq!(agg.event_count, 1, "in one event");
    assert_ne!(
        agg.finding_count, agg.event_count,
        "an aggregate reporting one of these as the other would be wrong by a factor \
         that varies per action (forbidden design #11)"
    );

    // Structural as well as numeric: adding a grouping dimension stops the
    // suite compiling, which is what keeps an unbounded label out of it.
    let CategoryFindingAggregate {
        category: _,
        finding_count: _,
        event_count: _,
    } = aggregates[0].clone();
}

/// A producer whose finding rows disagree with its own tallies is refused before
/// anything becomes durable.
pub async fn a_row_count_disagreeing_with_the_tally_is_refused<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-mismatch";
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNMISM01", tenant);

    let err = writer(store)
        .write(&event, &findings[..2], Timestamp::from_nanos(INGESTED))
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
    assert_eq!(
        store.count_sensitive_data_events(&filter(tenant)).await.expect("count"),
        0,
        "a refused projection must leave nothing behind"
    );
}

// ---------------------------------------------------------------------------
// Tenant isolation
// ---------------------------------------------------------------------------

/// One tenant's rows are invisible under another tenant's scope on every read
/// path — including the findings table, scoped by its own columns rather than by
/// joining the events table.
pub async fn a_neighbouring_tenant_sees_none_of_it<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-isolation";
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNISOL01", tenant);
    writer(store)
        .write(&event, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write");

    let owner = filter(tenant);
    let same_org_other_tenant = filter("t-isolation-staging");
    let other_org_same_tenant_name = SensitiveDataEventFilter::new(TenantScope::new("globex", tenant).expect("scope"));

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

// ---------------------------------------------------------------------------
// Idempotency and late arrivals
// ---------------------------------------------------------------------------

/// A replayed event does not double-count, on either table.
pub async fn a_replayed_event_does_not_double_count<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-replay";
    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNREPL01", tenant);
    let w = writer(store);
    for attempt in 0..3 {
        w.write(&event, &findings, Timestamp::from_nanos(INGESTED + attempt))
            .await
            .expect("replay must be accepted, not rejected");
    }

    let f = filter(tenant);
    assert_eq!(store.count_sensitive_data_events(&f).await.expect("count"), 1);
    assert_eq!(
        store.count_sensitive_data_findings(&f).await.expect("count"),
        3,
        "three replays of a three-finding event is still three findings"
    );
}

/// A replay carrying **more** findings must not add child rows beneath a frozen
/// parent tally.
///
/// The case the smaller-replay test could not reach: `OR IGNORE` /
/// `DO NOTHING` is first-write-wins for the parent but purely *additive* for the
/// children, so without gating the child inserts on the parent insert actually
/// happening, `finding_count = 1` would sit above three rows and the
/// per-category aggregate — which reads the child table — would over-report
/// against the event's own number.
pub async fn a_divergent_replay_cannot_desynchronise_parent_from_children<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-divergent";
    let event_id = "01HZX9V8ABCDEFGHJKMNDIVG01";
    let w = writer(store);

    // First: a one-finding event.
    let (small, small_findings) = allowed_action_with_one_finding(event_id, tenant, 1_700_000_000_000_000_000);
    w.write(&small, &small_findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("first write");

    // Then a replay of the same id carrying three.
    let (big, big_findings) = blocked_action_with_three_findings(event_id, tenant);
    w.write(&big, &big_findings, Timestamp::from_nanos(INGESTED + 5))
        .await
        .expect("a divergent replay is ignored, not an error");

    let f = filter(tenant);
    let row = &store.query_sensitive_data_events(&f).await.expect("events")[0];
    assert_eq!(row.finding_count, 1, "first write wins for the parent");
    assert_eq!(row.verdict, "allow", "first write wins for the verdict too");
    assert_eq!(
        store.count_sensitive_data_findings(&f).await.expect("count"),
        u64::from(row.finding_count),
        "the child rows must agree with the parent's own tally; an additive child insert \
         leaves finding_count describing rows that are no longer there"
    );

    let total_in_aggregate: u64 = store
        .aggregate_sensitive_data_by_category(&f)
        .await
        .expect("aggregate")
        .iter()
        .map(|a| a.finding_count)
        .sum();
    assert_eq!(
        total_in_aggregate,
        u64::from(row.finding_count),
        "the per-category aggregate reads the child table and must not over-report \
         against the event it belongs to"
    );
}

/// The documented late-arrival rule: first write wins, so a duplicate arriving
/// after the fact cannot move numbers a reader has already acted on.
pub async fn a_late_duplicate_cannot_rewrite_stored_tallies<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-late";
    let event_id = "01HZX9V8ABCDEFGHJKMNLATE01";
    let w = writer(store);
    let (first, findings) = blocked_action_with_three_findings(event_id, tenant);
    w.write(&first, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("first write");

    let (contradicting, single) = allowed_action_with_one_finding(event_id, tenant, 1_700_000_000_000_000_000);
    w.write(
        &contradicting,
        &single,
        Timestamp::from_nanos(1_700_000_999_000_000_000),
    )
    .await
    .expect("a late duplicate is ignored, not an error");

    let f = filter(tenant);
    let row = &store.query_sensitive_data_events(&f).await.expect("events")[0];
    assert_eq!(row.verdict, "deny", "first write wins");
    assert_eq!(row.blocked_finding_count, 3, "the stored tallies did not move");
    assert_eq!(
        store.count_sensitive_data_findings(&f).await.expect("count"),
        3,
        "the late duplicate added no finding rows"
    );
}

// ---------------------------------------------------------------------------
// The filter's narrowings
// ---------------------------------------------------------------------------

/// `verdict`, `between` and `limit` are honoured on every read path.
///
/// The gap this closes: no test called any of the three builder methods, and
/// `verdict` was silently dropped on the findings query, the findings count and
/// the aggregate — so a "blocked findings by category" dashboard returned every
/// finding under a "denied" label.
pub async fn the_filters_narrowings_are_honoured_on_every_read<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-filters";
    let w = writer(store);

    let (denied, denied_findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNFILT01", tenant);
    w.write(&denied, &denied_findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write denied");

    // Two allowed events, one of them outside the window used below.
    for (id, occurred) in [
        ("01HZX9V8ABCDEFGHJKMNFILT02", 1_700_000_000_000_000_001_u64),
        ("01HZX9V8ABCDEFGHJKMNFILT03", 1_900_000_000_000_000_000_u64),
    ] {
        let (allowed, allowed_findings) = allowed_action_with_one_finding(id, tenant, occurred);
        w.write(&allowed, &allowed_findings, Timestamp::from_nanos(INGESTED))
            .await
            .expect("write allowed");
    }

    let all = filter(tenant);
    assert_eq!(store.count_sensitive_data_events(&all).await.expect("count"), 3);
    assert_eq!(store.count_sensitive_data_findings(&all).await.expect("count"), 5);

    // --- verdict, on all four data reads ---
    let denied_only = filter(tenant).with_verdict("deny");
    assert_eq!(store.count_sensitive_data_events(&denied_only).await.expect("count"), 1);
    assert_eq!(
        store.count_sensitive_data_findings(&denied_only).await.expect("count"),
        3,
        "the verdict predicate must reach the findings table, not be silently dropped"
    );
    assert!(store
        .query_sensitive_data_findings(&denied_only)
        .await
        .expect("query")
        .iter()
        .all(|r| r.verdict == "deny"));
    let denied_total: u64 = store
        .aggregate_sensitive_data_by_category(&denied_only)
        .await
        .expect("aggregate")
        .iter()
        .map(|a| a.finding_count)
        .sum();
    assert_eq!(
        denied_total, 3,
        "an aggregate that ignores the verdict over-reports a 'blocked by category' read"
    );

    // --- between ---
    let window = filter(tenant).between(
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        Timestamp::from_nanos(1_700_000_000_000_000_002),
    );
    assert_eq!(
        store.count_sensitive_data_events(&window).await.expect("count"),
        2,
        "the half-open window excludes the far-future event"
    );
    assert_eq!(store.count_sensitive_data_findings(&window).await.expect("count"), 4);

    // --- limit, including on the aggregate, whose groups are not a closed set ---
    assert_eq!(
        store
            .query_sensitive_data_events(&filter(tenant).with_limit(1))
            .await
            .expect("query")
            .len(),
        1
    );
    assert_eq!(
        store
            .query_sensitive_data_findings(&filter(tenant).with_limit(2))
            .await
            .expect("query")
            .len(),
        2
    );
    let capped = store
        .aggregate_sensitive_data_by_category(&filter(tenant).with_limit(1))
        .await
        .expect("aggregate");
    assert_eq!(
        capped.len(),
        1,
        "the aggregate must honour the limit — it is the only bound available against a \
         category vocabulary that is not closed"
    );

    // The two counts deliberately ignore the cap and report the true total.
    // Asserted rather than left to the docstring, because the pairing a UI
    // will actually build — a capped list beside its count — then shows 1 row
    // against a count of 3, and that has to be a documented, tested choice
    // rather than a surprise. An earlier docstring claimed `limit` applied to
    // every read, which was false for exactly these two.
    let capped_filter = filter(tenant).with_limit(1);
    assert_eq!(
        store.count_sensitive_data_events(&capped_filter).await.expect("count"),
        3,
        "a count reports the total for the filter, not the length of a capped page"
    );
    assert_eq!(
        store
            .count_sensitive_data_findings(&capped_filter)
            .await
            .expect("count"),
        5,
        "a count reports the total for the filter, not the length of a capped page"
    );
}

// ---------------------------------------------------------------------------
// Prevention requires evidence
// ---------------------------------------------------------------------------

type PreventionCase = (
    &'static str,
    RuntimeVerdictLabel,
    EnforcementPoint,
    TransmissionEvidence,
    EnforcementMode,
    bool,
);

/// Only a deny-or-transforming verdict, applied pre-transmission, while
/// enforcing, with the bytes observed not to have gone, counts as prevention.
///
/// The negative cases are the point. `scrub` with `forwarded_clean` is what a
/// successful redaction looks like — a *transformed transmission* — and it is
/// the case the `CredentialLeakBlocked` event name already got wrong once.
pub async fn prevention_is_claimed_only_where_evidence_supports_it<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-prevention";
    let cases: [PreventionCase; 7] = [
        (
            "01HZX9V8ABCDEFGHJKMNPREV01",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            true,
        ),
        (
            // Redaction forwards the scrubbed bytes. Detected, not prevented.
            "01HZX9V8ABCDEFGHJKMNPREV02",
            RuntimeVerdictLabel::SCRUB,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::ForwardedClean,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // `narrow` scopes the action without transforming the payload.
            "01HZX9V8ABCDEFGHJKMNPREV03",
            RuntimeVerdictLabel::NARROW,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // Observe mode computed the decision and applied nothing.
            "01HZX9V8ABCDEFGHJKMNPREV04",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Observe,
            false,
        ),
        (
            // Decided after the bytes left.
            "01HZX9V8ABCDEFGHJKMNPREV05",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::PostTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // An unwired producer must not claim prevention by saying nothing.
            "01HZX9V8ABCDEFGHJKMNPREV06",
            RuntimeVerdictLabel::DENY,
            EnforcementPoint::NotRecorded,
            TransmissionEvidence::NotRecorded,
            EnforcementMode::Enforce,
            false,
        ),
        (
            // The layer decided to redact and emitted the credential anyway.
            "01HZX9V8ABCDEFGHJKMNPREV07",
            RuntimeVerdictLabel::SCRUB,
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::ForwardedCarryingSensitiveValue,
            EnforcementMode::Enforce,
            false,
        ),
    ];

    let w = writer(store);
    for (event_id, verdict, point, transmission, mode, _) in cases {
        let event = SensitiveDataDecisionEvent::builder(
            AuditLabel::new(event_id).expect("event id"),
            Timestamp::from_nanos(1_700_000_000_000_000_000),
            tenancy(tenant),
            lineage(),
            action(),
            verdict,
            ExecutionEvidence::new(point, transmission, mode),
        )
        .build();
        w.write(&event, &[], Timestamp::from_nanos(INGESTED))
            .await
            .expect("write");
    }

    let rows = store
        .query_sensitive_data_events(&filter(tenant))
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

/// A category this build cannot resolve is stored for drill-down and refused as
/// a metric label.
///
/// Both directions in one function on purpose: a test that only walked the
/// catalogue's own members could never reach the unbounded case and would pass
/// while the guard did nothing.
pub async fn an_unresolvable_category_is_stored_but_never_labelled<S: SensitiveDataProjection>(store: &Arc<S>) {
    let tenant = "t-unbounded";
    let event_id = "01HZX9V8ABCDEFGHJKMNUNBD01";

    let mut arbitrary = record(event_id, email(), "body.customer.email");
    arbitrary.category = CategoryLabel::new(UNRESOLVABLE_CATEGORY).expect("well-formed label");
    assert!(
        SensitiveDataMetricLabels::from_finding(&arbitrary, RuntimeVerdictLabel::DENY).is_none(),
        "an unresolvable category must not become a metric label — it is an unbounded \
         series, which ADR 0032 §9 forbids"
    );

    let catalogued = record(event_id, email(), "body.customer.email");
    let labels = SensitiveDataMetricLabels::from_finding(&catalogued, RuntimeVerdictLabel::DENY)
        .expect("a catalogue category must resolve — otherwise the None above proves nothing");
    let names = labels.as_pairs().map(|(name, _)| name);
    for banned in ["destination", "tenant", "org", "agent", "field_path", "event_id"] {
        assert!(
            !names.contains(&banned),
            "`{banned}` is unbounded cardinality and must never be a metric label"
        );
    }

    // Stored anyway, so refusing the label does not lose the drill-down that
    // ADR 0032 §9 grants in place of the offset.
    let mut findings = vec![arbitrary];
    findings[0].event_id = AuditLabel::new(event_id).expect("event id");
    let event = SensitiveDataDecisionEvent::builder(
        AuditLabel::new(event_id).expect("event id"),
        Timestamp::from_nanos(1_700_000_000_000_000_000),
        tenancy(tenant),
        lineage(),
        action(),
        RuntimeVerdictLabel::DENY,
        ExecutionEvidence::new(
            EnforcementPoint::PreTransmission,
            TransmissionEvidence::NotForwarded,
            EnforcementMode::Enforce,
        ),
    )
    .finding_counts(FindingCounts::tally(&findings, 0, 1).expect("tally"))
    .build();

    writer(store)
        .write(&event, &findings, Timestamp::from_nanos(INGESTED))
        .await
        .expect("write");

    let stored = store
        .query_sensitive_data_findings(&filter(tenant))
        .await
        .expect("findings");
    assert!(
        stored.iter().any(|r| r.category == UNRESOLVABLE_CATEGORY),
        "an unresolvable category must still be persisted for drill-down"
    );

    // And it is its own aggregate group — the unboundedness the docstring now
    // admits to, bounded only by the limit.
    let groups = store
        .aggregate_sensitive_data_by_category(&filter(tenant))
        .await
        .expect("aggregate");
    assert!(groups.iter().any(|g| g.category == UNRESOLVABLE_CATEGORY));
}

// ---------------------------------------------------------------------------
// The flag
// ---------------------------------------------------------------------------

/// With the flag off nothing is written and no tables are created.
///
/// Takes an un-migrated store, so it must be run before the schema exists.
pub async fn a_disabled_projection_writes_nothing<S: SensitiveDataProjection>(store: &Arc<S>) {
    let w = SensitiveDataProjectionWriter::new(Arc::clone(store), SensitiveDataProjectionConfig::disabled());
    assert!(!w.is_enabled());
    assert_eq!(w.migrate().await.expect("migrate"), WriteOutcome::Disabled);

    let (event, findings) = blocked_action_with_three_findings("01HZX9V8ABCDEFGHJKMNFLAG01", "t-flag");
    assert_eq!(
        w.write(&event, &findings, Timestamp::from_nanos(INGESTED))
            .await
            .expect("a disabled write is a no-op, not an error"),
        WriteOutcome::Disabled
    );
    assert!(
        store
            .sensitive_data_projection_columns()
            .await
            .expect("columns")
            .is_empty(),
        "a disabled projection must not create its tables"
    );
}

// ---------------------------------------------------------------------------
// The reviewed column lists
// ---------------------------------------------------------------------------

pub fn expected_qualified_columns() -> Vec<String> {
    EXPECTED_EVENT_COLUMNS
        .iter()
        .map(|c| format!("sensitive_data_events.{c}"))
        .chain(
            EXPECTED_FINDING_COLUMNS
                .iter()
                .map(|c| format!("sensitive_data_findings.{c}")),
        )
        .collect()
}

/// Every column of `sensitive_data_events`, reviewed against ADR 0032 §9.
pub const EXPECTED_EVENT_COLUMNS: &[&str] = &[
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
pub const EXPECTED_FINDING_COLUMNS: &[&str] = &[
    "schema_version_major",
    "schema_version_minor",
    "event_id",
    "finding_ordinal",
    "org_id",
    "tenant_id",
    "occurred_at_ns",
    "verdict",
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

/// Two tenants writing the **same** `event_id` must each read back their own
/// event and their own findings.
///
/// AAASM-5447: `event_id` was the sole primary key on a table every read scopes
/// by `(org_id, tenant_id)`. The uniqueness scope did not match the read scope,
/// so the second tenant's insert was skipped as a duplicate, its child rows were
/// skipped with it, and the write still reported `Written`. The tenant then
/// queried its own data and saw nothing.
///
/// `a_neighbouring_tenant_sees_none_of_it` does not cover this: it gives each
/// tenant a distinct `event_id`, so it passes while the collision is live. The
/// shared id here is the whole point — `event_id` is producer-supplied, so a
/// collision is available to anyone who can influence their own id and arrives
/// by accident across a large enough tenant population.
pub async fn two_tenants_sharing_an_event_id_keep_their_own_rows<S: SensitiveDataProjection>(store: &Arc<S>) {
    const SHARED: &str = "01HZX9V8ABCDEFGHJKMNSHARE1";

    let (event_a, findings_a) = blocked_action_with_three_findings(SHARED, "t-alpha");
    let (event_b, findings_b) = allowed_action_with_one_finding(SHARED, "t-beta", 1_700_000_000_000_000_000);

    writer(store)
        .write(&event_a, &findings_a, Timestamp::from_nanos(INGESTED))
        .await
        .expect("tenant A write");
    writer(store)
        .write(&event_b, &findings_b, Timestamp::from_nanos(INGESTED))
        .await
        .expect("tenant B write");

    // Tenant B's write reported success, so its record must exist. A governance
    // surface that returns zero here is indistinguishable from "nothing
    // happened", which is the failure mode this Epic exists to eliminate.
    let fb = filter("t-beta");
    assert_eq!(
        store.count_sensitive_data_events(&fb).await.expect("count B events"),
        1,
        "tenant B's event was discarded by a cross-tenant key collision while its \
         write returned Written — a silent denial-of-recording"
    );
    assert_eq!(
        store
            .count_sensitive_data_findings(&fb)
            .await
            .expect("count B findings"),
        1,
        "tenant B's findings were skipped along with its parent event"
    );

    // And tenant A must be untouched by B's write — first-write-wins must not
    // become first-tenant-wins.
    let fa = filter("t-alpha");
    assert_eq!(store.count_sensitive_data_events(&fa).await.expect("count A events"), 1);
    assert_eq!(
        store
            .count_sensitive_data_findings(&fa)
            .await
            .expect("count A findings"),
        3
    );

    let a = &store.query_sensitive_data_events(&fa).await.expect("A events")[0];
    let b = &store.query_sensitive_data_events(&fb).await.expect("B events")[0];
    assert_eq!(a.finding_count, 3, "tenant A keeps its own tallies");
    assert_eq!(
        b.finding_count, 1,
        "tenant B keeps its own tallies rather than inheriting tenant A's"
    );
}
