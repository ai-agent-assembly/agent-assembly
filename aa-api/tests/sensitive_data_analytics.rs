//! AAASM-5359 — the sensitive-data analytics surface, driven end to end.
//!
//! Every test here goes through the **real** axum router (`build_app`), the real
//! auth gate, and a **real SQLite projection** written through the production
//! [`SensitiveDataProjectionWriter`]. Nothing re-implements a query or a counter:
//! if a handler stops reading the projection, or a counter is derived from the
//! wrong expression, these fail.
//!
//! # Anti-vacuity
//!
//! A counting test whose fixture only ever produces one finding per event cannot
//! see an event/finding conflation, and a prevention test whose fixture always
//! carries full evidence cannot see "absence of evidence counts as prevented".
//! Each fixture below is shaped so that the bug it guards against would change
//! the asserted number, and each test says in its doc comment what its fixture
//! made true before the assertion ran.

mod common;

use std::sync::Arc;

use aa_api::routes::sensitive_data::ExportAccessLog;
use aa_api::state::AppState;
use aa_core::policy::EnforcementMode;
use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{
    AgentLineage, AuditLabel, Endpoint, EndpointKind, EnforcementPoint, ExecutionEvidence, FieldPath, FindingCounts,
    InspectedAction, OperationKind, PolicyAttribution, RequestDirection, RuntimeVerdictLabel,
    SensitiveDataDecisionEvent, SensitiveDataFindingRecord, Tenancy, TransmissionEvidence, TrustZone,
};
use aa_core::types::AgentId;
use aa_gateway::storage::sensitive_data::{
    SensitiveDataProjection, SensitiveDataProjectionConfig, SensitiveDataProjectionWriter,
};
use aa_gateway::storage::{SqliteBackend, SqliteConfig, StorageBackend};
use aa_security::canonical::{
    ByteSpan, CanonicalCategory, CanonicalFinding, CategoryBase, ConfidenceBand, DetectionMethod, FindingStatus,
    Provenance, Recognizer, Severity,
};
use axum_test::TestServer;
use serde_json::Value;

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// A base instant well inside every test window, and far from the epoch so a
/// bucket index computed from a bad origin does not accidentally land right.
fn base_ns() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // Two hours ago: inside the default 7d window, and inside a 24h one.
    now - 2 * 3_600 * 1_000_000_000
}

/// One event to write into the projection.
#[derive(Clone)]
struct EventSpec {
    event_id: String,
    org: String,
    team: Option<String>,
    agent: String,
    root_agent: String,
    operation: OperationKind,
    destination_kind: EndpointKind,
    destination: String,
    verdict: RuntimeVerdictLabel,
    evidence: ExecutionEvidence,
    /// One finding per entry, in order.
    categories: Vec<CanonicalCategory>,
    transformed: u32,
    blocked: u32,
    occurred_at_ns: u64,
}

impl EventSpec {
    fn new(event_id: &str, org: &str, verdict: RuntimeVerdictLabel) -> Self {
        Self {
            event_id: event_id.to_string(),
            org: org.to_string(),
            team: Some("team-alpha".to_string()),
            agent: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            root_agent: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            operation: OperationKind::ToolCall,
            destination_kind: EndpointKind::Tool,
            destination: "slack.post_message".to_string(),
            verdict,
            evidence: ExecutionEvidence::unrecorded(EnforcementMode::Enforce),
            categories: vec![CanonicalCategory::unqualified(CategoryBase::EmailAddress)],
            transformed: 0,
            blocked: 0,
            occurred_at_ns: base_ns(),
        }
    }

    fn findings(mut self, categories: Vec<CanonicalCategory>) -> Self {
        self.categories = categories;
        self
    }

    fn dispositions(mut self, transformed: u32, blocked: u32) -> Self {
        self.transformed = transformed;
        self.blocked = blocked;
        self
    }

    fn evidence(mut self, point: EnforcementPoint, transmission: TransmissionEvidence, mode: EnforcementMode) -> Self {
        self.evidence = ExecutionEvidence::new(point, transmission, mode);
        self
    }

    fn agent(mut self, agent: &str) -> Self {
        self.agent = agent.to_string();
        self.root_agent = agent.to_string();
        self
    }

    fn destination(mut self, kind: EndpointKind, id: &str) -> Self {
        self.destination_kind = kind;
        self.destination = id.to_string();
        self
    }

    fn at(mut self, occurred_at_ns: u64) -> Self {
        self.occurred_at_ns = occurred_at_ns;
        self
    }
}

/// The categories used by the fixtures, in a fixed order so a per-category
/// assertion is stable.
fn email() -> CanonicalCategory {
    CanonicalCategory::unqualified(CategoryBase::EmailAddress)
}
fn token() -> CanonicalCategory {
    CanonicalCategory::with_scheme(CategoryBase::AccessToken, "github", "personal_access")
}

/// Build the `aa-core` event + finding records for a spec.
fn build_event(spec: &EventSpec) -> (SensitiveDataDecisionEvent, Vec<SensitiveDataFindingRecord>) {
    let event_id = AuditLabel::new(spec.event_id.clone()).expect("event id is a valid label");
    let field_path = FieldPath::parse("body.message").expect("a field name, not a value");

    let records: Vec<SensitiveDataFindingRecord> = spec
        .categories
        .iter()
        .map(|category| {
            let finding = CanonicalFinding::new(
                *category,
                Severity::High,
                ConfidenceBand::High,
                // A real span — the thing ADR 0032 §9 says must not reach this
                // tier. It is discarded by `SensitiveDataFindingRecord`, and the
                // privacy test asserts neither 4 nor 44 appears in a response.
                ByteSpan::new(4, 44),
                DetectionMethod::Deterministic,
                Provenance::new(Recognizer::BuiltinScanner, "0.0.0-test"),
                FindingStatus::Confirmed,
            )
            .expect("a well-formed span");
            SensitiveDataFindingRecord::from_finding(event_id.clone(), &finding, field_path.clone())
                .expect("a span-free record")
        })
        .collect();

    let counts = FindingCounts::tally(&records, spec.transformed, spec.blocked)
        .expect("the fixture respects the disposition invariant");

    let agent = |hex: &str| AgentId::parse(format!("{}/{hex}", spec.org)).expect("a wire agent id");

    let event = SensitiveDataDecisionEvent::builder(
        event_id,
        Timestamp::from_nanos(spec.occurred_at_ns),
        Tenancy {
            org_id: AuditLabel::new(spec.org.clone()).unwrap(),
            tenant_id: AuditLabel::new(spec.org.clone()).unwrap(),
            team_id: spec.team.as_ref().map(|t| AuditLabel::new(t.clone()).unwrap()),
        },
        AgentLineage {
            acting_agent: agent(&spec.agent),
            root_agent: agent(&spec.root_agent),
            parent_agent: None,
            delegation_depth: 0,
        },
        InspectedAction {
            operation: spec.operation,
            source: None,
            destination: Endpoint::new(spec.destination_kind, spec.destination.clone()).expect("an endpoint name"),
            trust_zone: TrustZone::Public,
            direction: RequestDirection::Outbound,
        },
        spec.verdict,
        spec.evidence,
    )
    .inspected_fields(vec![field_path])
    .policy(PolicyAttribution {
        document_id: Some(AuditLabel::new("policy-main").unwrap()),
        version: Some(3),
        matched_rule_ids: vec![AuditLabel::new("rule-dlp-1").unwrap()],
    })
    .finding_counts(counts)
    .build();

    (event, records)
}

/// A live SQLite projection under a temp dir, migrated and ready.
async fn projection() -> (Arc<SqliteBackend>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: dir.path().join("projection.db"),
    })
    .await
    .expect("sqlite opens");
    backend.migrate().await.expect("base schema");
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("projection schema");
    (Arc::new(backend), dir)
}

/// Write the specs through the production writer.
async fn seed(backend: &Arc<SqliteBackend>, specs: &[EventSpec]) {
    let writer = SensitiveDataProjectionWriter::new(Arc::clone(backend), SensitiveDataProjectionConfig::enabled());
    for spec in specs {
        let (event, records) = build_event(spec);
        writer
            .write(&event, &records, Timestamp::from_nanos(spec.occurred_at_ns))
            .await
            .expect("the fixture is projectable");
    }
}

/// A test app whose `AppState` carries the live projection.
///
/// Auth is `AuthMode::Off`, which resolves a synthetic **admin** caller with no
/// org — deliberately, so tenant scoping has to be exercised through an explicit
/// `?org_id=` and cannot be satisfied by an ambient tenant. The tenant-isolation
/// test builds a real API key instead.
async fn app_with(specs: &[EventSpec]) -> (TestServer, Arc<SqliteBackend>, tempfile::TempDir) {
    let (backend, dir) = projection().await;
    seed(&backend, specs).await;

    let mut state = common::test_state();
    state.sensitive_data = Some(Arc::clone(&backend) as Arc<dyn SensitiveDataProjection>);
    let server = TestServer::new(aa_api::server::build_app(state));
    (server, backend, dir)
}

/// Read a `u64` counter out of a summary/timeseries response.
fn counter(body: &Value, name: &str) -> u64 {
    body["counters"][name]
        .as_u64()
        .unwrap_or_else(|| panic!("counter `{name}` missing from {body}"))
}

// ---------------------------------------------------------------------------
// AC2 — the ADR 0032 §8 worked example
// ---------------------------------------------------------------------------

/// **AC2.** The ADR 0032 §8 / AAASM-5359 worked example, over the real endpoint.
///
/// *What the fixture made true first*: exactly **one** event carrying **three**
/// findings, whose verdict is `deny`, and whose finding-level dispositions record
/// **two transformation operations performed** before the request was refused
/// (`transformed = 2`, `blocked = 1` — the shape the storage layer's
/// `transformed + blocked <= total` invariant permits). So event and finding
/// counts differ (1 vs 3), the transformed tally differs from both (2), and the
/// action's verdict is a refusal rather than a scrub. A handler that summed the
/// row's own `blocked_finding_count` column would report 1 instead of 3; one that
/// counted events where it should count findings would report 1 instead of 3;
/// one that treated "some findings were transformed" as "the action was redacted"
/// would report a non-zero `redacted_event_count`.
#[tokio::test]
async fn the_worked_example_counts_events_and_findings_separately() {
    let spec = EventSpec::new("evt-worked-example", "acme", RuntimeVerdictLabel::DENY)
        .findings(vec![email(), email(), token()])
        .dispositions(2, 1);
    let (server, _backend, _dir) = app_with(&[spec]).await;

    let body: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();

    assert_eq!(counter(&body, "event_count"), 1, "one action was inspected");
    assert_eq!(counter(&body, "finding_count"), 3, "it carried three findings");
    assert_eq!(counter(&body, "blocked_event_count"), 1, "the action was refused");
    assert_eq!(
        counter(&body, "blocked_finding_count"),
        3,
        "all three findings were carried into a refused action (ADR 0032 §8)"
    );
    assert_eq!(
        counter(&body, "redacted_event_count"),
        0,
        "a blocked action is not a redacted one — nothing reached the wire"
    );
    assert_eq!(
        counter(&body, "redacted_finding_count"),
        2,
        "two transformation operations were performed, whatever became of the action"
    );
}

/// The six counters over a mixed window, where **every one of them is a
/// different number** — so no counter can be passing by coincidence.
///
/// *What the fixture made true first*: four events —
/// a `deny` with 3 findings (2 transformed), a `scrub` with 2 findings (2
/// transformed), a `scrub` with 1 finding (1 transformed), and an `allow` with
/// 1 finding (none transformed). That makes `event_count=4`, `finding_count=7`,
/// `blocked_event_count=1`, `blocked_finding_count=3`, `redacted_event_count=2`,
/// `redacted_finding_count=5`: six pairwise-distinct values, so swapping any two
/// expressions changes an assertion.
///
/// **AC1** rides on the same fixture: every rate is asserted against its stated
/// denominator, computed by hand from those numbers.
#[tokio::test]
async fn every_counter_and_every_rate_uses_its_stated_denominator() {
    let specs = vec![
        EventSpec::new("evt-mix-deny", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), email(), token()])
            .dispositions(2, 1),
        EventSpec::new("evt-mix-scrub-a", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![email(), token()])
            .dispositions(2, 0),
        EventSpec::new("evt-mix-scrub-b", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![token()])
            .dispositions(1, 0),
        EventSpec::new("evt-mix-allow", "acme", RuntimeVerdictLabel::ALLOW)
            .findings(vec![email()])
            .dispositions(0, 0),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    let body: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();

    assert_eq!(counter(&body, "event_count"), 4);
    assert_eq!(counter(&body, "finding_count"), 7);
    assert_eq!(counter(&body, "blocked_event_count"), 1);
    assert_eq!(counter(&body, "blocked_finding_count"), 3);
    assert_eq!(counter(&body, "redacted_event_count"), 2);
    assert_eq!(counter(&body, "redacted_finding_count"), 5);

    let rate = |name: &str| body["rates"][name].as_f64();
    assert_eq!(rate("block_rate"), Some(1.0 / 4.0), "blocked events / events");
    assert_eq!(rate("redaction_rate"), Some(2.0 / 4.0), "redacted events / events");
    assert_eq!(rate("findings_per_event"), Some(7.0 / 4.0), "findings / events");
    assert_eq!(
        rate("blocked_finding_share"),
        Some(3.0 / 7.0),
        "blocked findings / findings"
    );
    assert_eq!(
        rate("redacted_finding_share"),
        Some(5.0 / 7.0),
        "redacted findings / findings"
    );
    // No fixture event carries prevention evidence, so the rate is a real zero
    // here rather than an absent one — the window is not empty.
    assert_eq!(rate("prevention_rate"), Some(0.0));
    assert_eq!(rate("inspection_incomplete_rate"), Some(0.0));

    // Findings grouped by category, both counts reported and different.
    let by_category = body["by_category"].as_array().expect("a category breakdown");
    let email_bucket = by_category
        .iter()
        .find(|b| b["value"] == "EMAIL_ADDRESS")
        .expect("the email category is present");
    assert_eq!(email_bucket["finding_count"], 4, "four email findings");
    assert_eq!(
        email_bucket["event_count"], 3,
        "carried by three distinct events — never the same measure as the finding count"
    );
}

/// An empty window reports absent rates rather than a fabricated 0%.
///
/// *What the fixture made true first*: the projection exists and is migrated,
/// and contains **no rows at all** — so a handler that returned `0.0` would be
/// asserting a clean posture for a system with no data.
#[tokio::test]
async fn an_empty_window_reports_absent_rates_not_zero() {
    let (server, _backend, _dir) = app_with(&[]).await;
    let body: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();

    assert_eq!(counter(&body, "event_count"), 0);
    assert!(body["rates"]["block_rate"].is_null(), "no events, no block rate");
    assert!(body["rates"]["prevention_rate"].is_null());
    assert!(body["rates"]["findings_per_event"].is_null());
}

// ---------------------------------------------------------------------------
// AC3 — prevention requires evidence
// ---------------------------------------------------------------------------

/// **AC3.** `prevention_rate` does not increment without execution evidence.
///
/// *What the fixture made true first*: five events, of which **exactly one**
/// satisfies all four ADR 0032 §8 conditions. The other four each fail a
/// different single condition while satisfying the rest —
/// (a) `transmission_evidence = not_recorded` (no observation), (b)
/// `enforcement_point = post_transmission`, (c) `enforcement_mode = observe`,
/// (d) verdict `allow` with otherwise-perfect evidence. Every one of them is a
/// `deny` or carries full evidence in every *other* respect, so a handler that
/// dropped any single condition — or that treated "not recorded" as "did not
/// happen" — would count more than one.
#[tokio::test]
async fn prevention_counts_only_events_with_all_four_conditions() {
    let specs = vec![
        // The one true prevention.
        EventSpec::new("evt-prevented", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .evidence(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
        // Condition 3 missing: nothing observed the bytes.
        EventSpec::new("evt-no-observation", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .evidence(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotRecorded,
                EnforcementMode::Enforce,
            ),
        // Condition 1 missing: the decision came after the bytes went.
        EventSpec::new("evt-post-transmission", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .evidence(
                EnforcementPoint::PostTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
        // Condition 4 missing: enforcement was computed, not applied.
        EventSpec::new("evt-observe-mode", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .evidence(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Observe,
            ),
        // Condition 2 missing: the action was permitted.
        EventSpec::new("evt-allowed", "acme", RuntimeVerdictLabel::ALLOW)
            .findings(vec![email(), token()])
            .dispositions(0, 0)
            .evidence(
                EnforcementPoint::PreTransmission,
                TransmissionEvidence::NotForwarded,
                EnforcementMode::Enforce,
            ),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    let body: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();

    assert_eq!(counter(&body, "event_count"), 5, "all five events are in the window");
    assert_eq!(
        counter(&body, "prevented_event_count"),
        1,
        "only the event meeting all four conditions is prevented"
    );
    assert_eq!(
        counter(&body, "prevented_finding_count"),
        2,
        "its two findings, and no others"
    );
    assert_eq!(body["rates"]["prevention_rate"].as_f64(), Some(1.0 / 5.0));

    // …and the same judgement is visible per event on the drill-down, so the
    // aggregate can be reconciled against the rows it came from.
    let events: Value = server
        .get("/api/v1/sensitive-data/events")
        .add_query_param("org_id", "acme")
        .await
        .json();
    let prevented: Vec<&str> = events["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["prevented_transmission"] == true)
        .map(|e| e["event_id"].as_str().unwrap())
        .collect();
    assert_eq!(prevented, vec!["evt-prevented"]);
}

// ---------------------------------------------------------------------------
// AC4 — bounded metric-label cardinality
// ---------------------------------------------------------------------------

/// **AC4.** `/breakdown` refuses the forbidden dimensions and serves the
/// permitted ones.
///
/// *What the fixture made true first*: two events carrying three findings across
/// two categories, so the permitted grouping returns a **non-empty, non-trivial**
/// breakdown. Without that, every `group_by` would look "successful" by returning
/// nothing and the 400s would prove only that the route is broken.
#[tokio::test]
async fn breakdown_rejects_unbounded_dimensions_and_serves_the_bounded_six() {
    let specs = vec![
        EventSpec::new("evt-b1", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .agent("11111111111111111111111111111111"),
        EventSpec::new("evt-b2", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![email()])
            .dispositions(1, 0)
            .agent("22222222222222222222222222222222"),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    // Every permitted dimension answers 200 and groups something.
    for dimension in [
        "category",
        "severity",
        "confidence_band",
        "outcome",
        "detection_method",
        "provider_id",
    ] {
        let response = server
            .get("/api/v1/sensitive-data/breakdown")
            .add_query_param("org_id", "acme")
            .add_query_param("group_by", dimension)
            .await;
        assert_eq!(
            response.status_code(),
            200,
            "`{dimension}` is one of ADR 0032 §9's permitted labels"
        );
        let body: Value = response.json();
        assert_eq!(body["group_by"], dimension);
        let buckets = body["buckets"].as_array().expect("buckets");
        assert!(
            !buckets.is_empty(),
            "`{dimension}` grouped nothing — an empty breakdown would make the rejection tests vacuous"
        );
        let total: u64 = buckets.iter().map(|b| b["finding_count"].as_u64().unwrap()).sum();
        assert_eq!(total, 3, "every finding lands in exactly one `{dimension}` group");
    }

    // The forbidden ones are refused, not silently ignored.
    for forbidden in [
        "agent_id",
        "destination",
        "destination_id",
        "session_id",
        "trace_id",
        "tenant_id",
        "org_id",
        "team_id",
        "field_path",
        "fingerprint",
        "aggregate_key",
    ] {
        let response = server
            .get("/api/v1/sensitive-data/breakdown")
            .add_query_param("org_id", "acme")
            .add_query_param("group_by", forbidden)
            .await;
        assert_eq!(
            response.status_code(),
            400,
            "`group_by={forbidden}` must be refused — ADR 0032 §9 bounds metric labels"
        );
    }
}

// ---------------------------------------------------------------------------
// AC5 — no offsets, lengths or raw values in any response
// ---------------------------------------------------------------------------

/// Every key name appearing anywhere in a JSON document.
fn all_keys(value: &Value, into: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                into.push(key.clone());
                all_keys(child, into);
            }
        }
        Value::Array(items) => items.iter().for_each(|item| all_keys(item, into)),
        _ => {}
    }
}

/// **AC5.** No response carries an offset, a length, a span or a raw value.
///
/// *What the fixture made true first*: the findings were built from a
/// `CanonicalFinding` whose `ByteSpan` is `4..44` — a real span, of length 40 —
/// and the assertion first checks that the drill-down actually **returned those
/// findings** (`field_path` is present and non-empty). A response that carried no
/// findings would pass a "no offsets" check trivially; this one has three
/// findings in hand before it asserts what is absent.
#[tokio::test]
async fn no_response_carries_an_offset_a_length_or_a_raw_value() {
    let spec = EventSpec::new("evt-privacy", "acme", RuntimeVerdictLabel::DENY)
        .findings(vec![email(), email(), token()])
        .dispositions(2, 1);
    let (server, _backend, _dir) = app_with(&[spec]).await;

    let detail: Value = server
        .get("/api/v1/sensitive-data/events/evt-privacy")
        .add_query_param("org_id", "acme")
        .await
        .json();

    // The findings really are here — otherwise everything below is vacuous.
    let findings = detail["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 3, "all three findings are on the drill-down");
    assert_eq!(findings[0]["field_path"], "body.message");
    assert_eq!(findings[0]["redaction_label"], "[REDACTED:EmailAddress]");

    // The finding object's key set is exactly the privacy-safe one — asserted as
    // an equality rather than a series of "does not contain", because the latter
    // keeps passing when a new leaking field is added.
    let mut keys: Vec<&str> = findings[0].as_object().unwrap().keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        vec![
            "category",
            "confidence",
            "field_path",
            "finding_ordinal",
            "method",
            "recognizer",
            "recognizer_version",
            "redaction_label",
            "severity",
            "status",
        ]
    );

    // …and no response anywhere names an offset-shaped thing.
    let summary: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();
    let events: Value = server
        .get("/api/v1/sensitive-data/events")
        .add_query_param("org_id", "acme")
        .await
        .json();
    let breakdown: Value = server
        .get("/api/v1/sensitive-data/breakdown")
        .add_query_param("org_id", "acme")
        .await
        .json();

    for body in [&summary, &events, &breakdown, &detail] {
        let mut keys = Vec::new();
        all_keys(body, &mut keys);
        for key in &keys {
            let lowered = key.to_ascii_lowercase();
            for forbidden in [
                "offset",
                "length",
                "span",
                "byte",
                "raw",
                "payload",
                "secret",
                "fingerprint",
                "matched_text",
            ] {
                assert!(
                    !lowered.contains(forbidden),
                    "response key `{key}` contains `{forbidden}`; ADR 0032 §9 confines those to the audit tier"
                );
            }
        }
        // The span's own numbers must not appear as bare values either.
        let serialized = body.to_string();
        assert!(
            !serialized.contains("\"start\"") && !serialized.contains("\"end\""),
            "a span reached a response body: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// AC6 — tenant scoping
// ---------------------------------------------------------------------------

/// A caller confined to one org, over a real API key.
fn key_for(org: &str, scopes: Vec<aa_api::auth::scope::Scope>) -> (String, aa_api::auth::api_key::ApiKeyEntry) {
    let key = aa_api::auth::api_key::ApiKey::generate();
    let entry = aa_api::auth::api_key::ApiKeyEntry {
        id: format!("key-{org}"),
        key_hash: key.hash().expect("hashes"),
        scopes,
        created_at: 0,
        label: Some(format!("{org} reader")),
        expires_at: None,
        team_id: None,
        org_id: Some(org.to_string()),
        key_lookup: Some(key.lookup()),
    };
    (key.as_str().to_string(), entry)
}

/// **AC6.** Tenant scoping is enforced on every endpoint, and a cross-tenant read
/// is refused rather than silently emptied.
///
/// *What the fixture made true first*: **both** orgs have data — `acme` has one
/// event, `globex` has two — and the test proves globex's rows are readable by a
/// globex-scoped caller before asserting that the acme caller cannot see them.
/// Without that, "acme sees 1 event" would be equally consistent with globex's
/// rows never having been written.
#[tokio::test]
async fn every_endpoint_is_tenant_scoped_and_refuses_a_cross_tenant_read() {
    let specs = vec![
        EventSpec::new("evt-acme", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1),
        EventSpec::new("evt-globex-1", "globex", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2),
        EventSpec::new("evt-globex-2", "globex", RuntimeVerdictLabel::SCRUB)
            .findings(vec![token()])
            .dispositions(1, 0),
    ];

    let (backend, _dir) = projection().await;
    seed(&backend, &specs).await;

    let (acme_key, acme_entry) = key_for("acme", vec![aa_api::auth::scope::Scope::Read]);
    let (globex_key, globex_entry) = key_for("globex", vec![aa_api::auth::scope::Scope::Read]);
    let mut state =
        common::test_state_with_auth(aa_api::auth::config::AuthMode::On, &[acme_entry, globex_entry], 10_000);
    state.sensitive_data = Some(Arc::clone(&backend) as Arc<dyn SensitiveDataProjection>);
    let server = TestServer::new(aa_api::server::build_app(state));

    // Globex's rows exist and are readable by globex — the control that makes
    // the negative below meaningful.
    let globex_view: Value = server
        .get("/api/v1/sensitive-data/summary")
        .authorization_bearer(&globex_key)
        .await
        .json();
    assert_eq!(counter(&globex_view, "event_count"), 2, "globex has two events");
    assert_eq!(counter(&globex_view, "finding_count"), 3);

    // Acme sees only its own, with no org_id supplied at all.
    let acme_view: Value = server
        .get("/api/v1/sensitive-data/summary")
        .authorization_bearer(&acme_key)
        .await
        .json();
    assert_eq!(counter(&acme_view, "event_count"), 1, "acme sees only its own event");
    assert_eq!(acme_view["scope"]["org_id"], "acme");

    // Naming globex explicitly is a 403 on every endpoint, not an empty 200.
    for path in [
        "/api/v1/sensitive-data/summary",
        "/api/v1/sensitive-data/timeseries",
        "/api/v1/sensitive-data/breakdown",
        "/api/v1/sensitive-data/events",
        "/api/v1/sensitive-data/top-offenders",
        "/api/v1/sensitive-data/events/evt-globex-1",
    ] {
        let response = server
            .get(path)
            .authorization_bearer(&acme_key)
            .add_query_param("org_id", "globex")
            .await;
        assert_eq!(
            response.status_code(),
            403,
            "{path} let an acme-scoped caller name globex"
        );
    }

    // And a globex event id, requested inside acme's own scope, is a 404 rather
    // than a cross-tenant read.
    let leaked = server
        .get("/api/v1/sensitive-data/events/evt-globex-1")
        .authorization_bearer(&acme_key)
        .await;
    assert_eq!(leaked.status_code(), 404);
}

// ---------------------------------------------------------------------------
// AC7 — the compliance export
// ---------------------------------------------------------------------------

/// **AC7.** The export needs admin scope *and* an explicit acknowledgement, and
/// is access-logged before anything is released.
///
/// *What the fixture made true first*: one exportable event with two findings
/// exists, and the access log is asserted **empty** immediately before each
/// refused attempt — so "the log has one record" at the end cannot be explained
/// by an earlier attempt having written it.
#[tokio::test]
async fn the_compliance_export_requires_authorisation_and_is_access_logged() {
    let specs = vec![EventSpec::new("evt-export", "acme", RuntimeVerdictLabel::DENY)
        .findings(vec![email(), token()])
        .dispositions(0, 2)];

    let (backend, _dir) = projection().await;
    seed(&backend, &specs).await;

    let (reader_key, reader_entry) = key_for("acme", vec![aa_api::auth::scope::Scope::Read]);
    let (admin_key, admin_entry) = key_for(
        "acme",
        vec![
            aa_api::auth::scope::Scope::Read,
            aa_api::auth::scope::Scope::Write,
            aa_api::auth::scope::Scope::Admin,
        ],
    );
    let log: Arc<dyn ExportAccessLog> = Arc::new(aa_api::routes::sensitive_data::InMemoryExportAccessLog::new());
    let mut state =
        common::test_state_with_auth(aa_api::auth::config::AuthMode::On, &[reader_entry, admin_entry], 10_000);
    state.sensitive_data = Some(Arc::clone(&backend) as Arc<dyn SensitiveDataProjection>);
    state.sensitive_data_export_log = Arc::clone(&log);
    let server = TestServer::new(aa_api::server::build_app(state));

    assert!(log.records().is_empty(), "the log starts empty");

    // A read-scoped caller may not export at all.
    let refused = server
        .get("/api/v1/sensitive-data/export")
        .authorization_bearer(&reader_key)
        .add_query_param("acknowledge_export", "true")
        .await;
    assert_eq!(refused.status_code(), 403, "export requires admin scope");
    assert!(
        log.records().is_empty(),
        "a refused export must not appear in the access log"
    );

    // An admin without the acknowledgement is refused too.
    let unacknowledged = server
        .get("/api/v1/sensitive-data/export")
        .authorization_bearer(&admin_key)
        .await;
    assert_eq!(unacknowledged.status_code(), 400, "an export must be acknowledged");
    assert!(
        log.records().is_empty(),
        "an unacknowledged export must not be logged as one"
    );

    // Admin + acknowledgement releases the data, and records it first.
    let exported = server
        .get("/api/v1/sensitive-data/export")
        .authorization_bearer(&admin_key)
        .add_query_param("acknowledge_export", "true")
        .await;
    assert_eq!(exported.status_code(), 200);
    let body: Value = exported.json();
    assert_eq!(body["events"].as_array().unwrap().len(), 1);
    assert_eq!(body["findings"][0]["findings"].as_array().unwrap().len(), 2);

    let records = log.records();
    assert_eq!(records.len(), 1, "exactly one export was recorded");
    assert_eq!(records[0].principal, "key-acme", "the authenticated principal");
    assert_eq!(records[0].org_id, "acme");
    assert_eq!(records[0].event_count, 1);
    assert_eq!(records[0].finding_count, 2);
    // The record the caller was handed is the record that was written.
    assert_eq!(body["access_record"]["principal"], "key-acme");
    assert_eq!(body["access_record"]["event_count"], 1);
}

// ---------------------------------------------------------------------------
// AC9 — the durable projection, and no silent truncation
// ---------------------------------------------------------------------------

/// **AC9.** Aggregates read every row in the window; only the *list* page is
/// capped, and it says so.
///
/// *What the fixture made true first*: **1 200** events were written — more than
/// the default page (100) and more than the maximum page (1 000) — so an
/// aggregate that inherited either cap would report 100 or 1 000 instead of
/// 1 200. It does not reach 100 000, which would make the test minutes long; the
/// falsification for this test is instead to introduce a `with_limit` on the
/// storage filter and watch it die.
#[tokio::test]
async fn aggregates_are_not_capped_by_the_list_page_size() {
    const EVENTS: usize = 1_200;
    let specs: Vec<EventSpec> = (0..EVENTS)
        .map(|i| {
            EventSpec::new(&format!("evt-bulk-{i:05}"), "acme", RuntimeVerdictLabel::DENY)
                .findings(vec![email()])
                .dispositions(0, 1)
        })
        .collect();
    let (server, _backend, _dir) = app_with(&specs).await;

    let summary: Value = server
        .get("/api/v1/sensitive-data/summary")
        .add_query_param("org_id", "acme")
        .await
        .json();
    assert_eq!(
        counter(&summary, "event_count"),
        EVENTS as u64,
        "the aggregate counted every event in the window"
    );
    assert_eq!(counter(&summary, "finding_count"), EVENTS as u64);

    let events: Value = server
        .get("/api/v1/sensitive-data/events")
        .add_query_param("org_id", "acme")
        .await
        .json();
    assert_eq!(
        events["total"].as_u64(),
        Some(EVENTS as u64),
        "`total` is the true count for the filter, not the page length"
    );
    assert_eq!(
        events["events"].as_array().unwrap().len(),
        100,
        "the page itself is bounded, and is a different number from the total"
    );
}

/// With no projection wired the endpoints say so, rather than reporting a clean
/// window.
///
/// *What the fixture made true first*: the app is otherwise identical to the one
/// every passing test above uses; only `sensitive_data` is absent. So a 200 with
/// zeroes here would be indistinguishable from a genuinely quiet tenant.
#[tokio::test]
async fn a_deployment_without_the_projection_reports_unavailable_not_empty() {
    let state: AppState = common::test_state();
    assert!(state.sensitive_data.is_none());
    let server = TestServer::new(aa_api::server::build_app(state));

    for path in [
        "/api/v1/sensitive-data/summary",
        "/api/v1/sensitive-data/timeseries",
        "/api/v1/sensitive-data/breakdown",
        "/api/v1/sensitive-data/events",
        "/api/v1/sensitive-data/top-offenders",
    ] {
        let response = server.get(path).add_query_param("org_id", "acme").await;
        assert_eq!(response.status_code(), 503, "{path} hid an unwired projection");
    }
}

// ---------------------------------------------------------------------------
// Timeseries, filters and top offenders
// ---------------------------------------------------------------------------

/// The timeseries places each event in exactly one bucket, and emits empty
/// buckets rather than closing the gap.
///
/// *What the fixture made true first*: three events at **distinct hours** — now-1h,
/// now-3h and now-5h — inside a 6-hour window bucketed hourly, leaving at least
/// three empty buckets between them. A handler that dropped empty buckets, or
/// that put everything in one bucket, changes both the bucket count and where the
/// counts land.
#[tokio::test]
async fn the_timeseries_buckets_events_by_time_and_keeps_the_gaps() {
    let hour = 3_600u64 * 1_000_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let specs = vec![
        EventSpec::new("evt-t1", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .at(now - hour / 2),
        EventSpec::new("evt-t3", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .at(now - 5 * hour / 2),
        EventSpec::new("evt-t5", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![token()])
            .dispositions(1, 0)
            .at(now - 9 * hour / 2),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    let body: Value = server
        .get("/api/v1/sensitive-data/timeseries")
        .add_query_param("org_id", "acme")
        .add_query_param("range", "24h")
        .add_query_param("bucket", "1h")
        .await
        .json();

    assert_eq!(body["bucket_seconds"], 3_600);
    let points = body["points"].as_array().expect("points");
    assert_eq!(points.len(), 24, "a 24h window at 1h buckets is 24 points");

    let occupied: Vec<usize> = points
        .iter()
        .enumerate()
        .filter(|(_, p)| p["counters"]["event_count"].as_u64() != Some(0))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(occupied.len(), 3, "three occupied buckets, with gaps between them");
    let total: u64 = points
        .iter()
        .map(|p| p["counters"]["finding_count"].as_u64().unwrap())
        .sum();
    assert_eq!(total, 4, "every finding lands in exactly one bucket");

    // An unknown bucket width is refused rather than defaulted.
    let bad = server
        .get("/api/v1/sensitive-data/timeseries")
        .add_query_param("org_id", "acme")
        .add_query_param("bucket", "13m")
        .await;
    assert_eq!(bad.status_code(), 400);
}

/// Each filter narrows to what it names, and a filter that matches nothing
/// returns nothing.
///
/// *What the fixture made true first*: four events differing in **exactly one**
/// dimension each from a common baseline — a different agent, a different tool, a
/// different verdict, a different finding category. So a filter wired to the
/// wrong column returns the wrong subset rather than coincidentally the right one.
#[tokio::test]
async fn each_filter_narrows_to_the_dimension_it_names() {
    let specs = vec![
        EventSpec::new("evt-f-base", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .agent("11111111111111111111111111111111")
            .destination(EndpointKind::Tool, "slack.post_message"),
        EventSpec::new("evt-f-agent", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .agent("22222222222222222222222222222222")
            .destination(EndpointKind::Tool, "slack.post_message"),
        EventSpec::new("evt-f-tool", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .agent("11111111111111111111111111111111")
            .destination(EndpointKind::HttpHost, "api.example.com"),
        EventSpec::new("evt-f-category", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![token()])
            .dispositions(1, 0)
            .agent("11111111111111111111111111111111")
            .destination(EndpointKind::Tool, "slack.post_message"),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    let count_with = |key: &'static str, value: String| {
        let server = &server;
        async move {
            let body: Value = server
                .get("/api/v1/sensitive-data/summary")
                .add_query_param("org_id", "acme")
                .add_query_param(key, value)
                .await
                .json();
            counter(&body, "event_count")
        }
    };

    assert_eq!(
        count_with("agent_id", "acme/22222222222222222222222222222222".to_string()).await,
        1
    );
    assert_eq!(
        count_with("root_agent_id", "acme/11111111111111111111111111111111".to_string()).await,
        3
    );
    assert_eq!(count_with("outcome", "scrub".to_string()).await, 1);
    assert_eq!(count_with("outcome", "deny".to_string()).await, 3);
    assert_eq!(count_with("category", "EMAIL_ADDRESS".to_string()).await, 3);
    assert_eq!(
        count_with("category", "ACCESS_TOKEN[github:personal_access]".to_string()).await,
        1
    );
    assert_eq!(count_with("destination", "api.example.com".to_string()).await, 1);
    assert_eq!(
        count_with("tool", "api.example.com".to_string()).await,
        0,
        "`tool` must not match an HTTP host that happens to share the identifier"
    );
    assert_eq!(count_with("tool", "slack.post_message".to_string()).await, 3);
    assert_eq!(count_with("team_id", "team-alpha".to_string()).await, 4);
    assert_eq!(count_with("team_id", "team-nonexistent".to_string()).await, 0);
    assert_eq!(count_with("severity", "high".to_string()).await, 4);
    assert_eq!(count_with("severity", "low".to_string()).await, 0);
    assert_eq!(count_with("provider", "aa-security::scanner".to_string()).await, 4);
    assert_eq!(count_with("policy_document_id", "policy-main".to_string()).await, 4);
    assert_eq!(count_with("policy_document_id", "policy-other".to_string()).await, 0);
    assert_eq!(count_with("operation", "tool_call".to_string()).await, 4);
    assert_eq!(count_with("operation", "file_write".to_string()).await, 0);
}

/// Top offenders rank the current window and compare it with the one before.
///
/// *What the fixture made true first*: agent A appears in **both** windows with
/// more findings in the current one (a rise), agent B appears in both with fewer
/// (a fall), and agent C appears **only** in the current one (a first
/// appearance). So `up`, `down` and `new` are each produced by a distinct row,
/// and a handler that reported "up from zero" for a newcomer, or that ignored the
/// previous window entirely, changes an assertion.
#[tokio::test]
async fn top_offenders_rank_the_window_and_compare_it_with_the_previous_one() {
    let hour = 3_600u64 * 1_000_000_000;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    // A 6h window: current is [now-6h, now); previous is [now-12h, now-6h).
    let current = now - hour;
    let previous = now - 8 * hour;

    let agent_a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let agent_b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let agent_c = "cccccccccccccccccccccccccccccccc";

    let specs = vec![
        // A: 3 findings now, 1 before → up.
        EventSpec::new("evt-a-now", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), email(), token()])
            .dispositions(0, 3)
            .agent(agent_a)
            .at(current),
        EventSpec::new("evt-a-prev", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .agent(agent_a)
            .at(previous),
        // B: 1 finding now, 2 before → down.
        EventSpec::new("evt-b-now", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email()])
            .dispositions(0, 1)
            .agent(agent_b)
            .at(current),
        EventSpec::new("evt-b-prev", "acme", RuntimeVerdictLabel::DENY)
            .findings(vec![email(), token()])
            .dispositions(0, 2)
            .agent(agent_b)
            .at(previous),
        // C: 2 findings now, absent before → new.
        EventSpec::new("evt-c-now", "acme", RuntimeVerdictLabel::SCRUB)
            .findings(vec![token(), token()])
            .dispositions(2, 0)
            .agent(agent_c)
            .at(current),
    ];
    let (server, _backend, _dir) = app_with(&specs).await;

    let from = chrono::DateTime::from_timestamp_nanos((now - 6 * hour) as i64).to_rfc3339();
    let to = chrono::DateTime::from_timestamp_nanos(now as i64).to_rfc3339();

    let body: Value = server
        .get("/api/v1/sensitive-data/top-offenders")
        .add_query_param("org_id", "acme")
        .add_query_param("dimension", "agent")
        .add_query_param("from", &from)
        .add_query_param("to", &to)
        .await
        .json();

    let entries = body["entries"].as_array().expect("entries");
    assert_eq!(entries.len(), 3, "three agents acted in the window");
    // Ranked by current finding count: A(3), C(2), B(1).
    assert_eq!(entries[0]["key"], format!("acme/{agent_a}"));
    assert_eq!(entries[0]["counters"]["finding_count"], 3);
    assert_eq!(entries[0]["previous"]["finding_count"], 1);
    assert_eq!(entries[0]["finding_count_delta"], 2);
    assert_eq!(entries[0]["trend"], "up");

    assert_eq!(entries[1]["key"], format!("acme/{agent_c}"));
    assert_eq!(entries[1]["counters"]["finding_count"], 2);
    assert_eq!(entries[1]["previous"]["finding_count"], 0);
    assert_eq!(
        entries[1]["trend"], "new",
        "an agent absent from the previous window is new, not up-from-zero"
    );

    assert_eq!(entries[2]["key"], format!("acme/{agent_b}"));
    assert_eq!(entries[2]["counters"]["finding_count"], 1);
    assert_eq!(entries[2]["previous"]["finding_count"], 2);
    assert_eq!(entries[2]["finding_count_delta"], -1);
    assert_eq!(entries[2]["trend"], "down");

    // Ranking by tool skips the events whose destination is not a tool.
    let by_tool: Value = server
        .get("/api/v1/sensitive-data/top-offenders")
        .add_query_param("org_id", "acme")
        .add_query_param("dimension", "tool")
        .add_query_param("from", &from)
        .add_query_param("to", &to)
        .await
        .json();
    assert_eq!(by_tool["entries"][0]["key"], "slack.post_message");

    // An unknown dimension is refused.
    let bad = server
        .get("/api/v1/sensitive-data/top-offenders")
        .add_query_param("org_id", "acme")
        .add_query_param("dimension", "agent_id")
        .await;
    assert_eq!(bad.status_code(), 400);
}
