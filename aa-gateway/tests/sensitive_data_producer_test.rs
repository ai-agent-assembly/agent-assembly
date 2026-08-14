//! The sensitive-data projection **producer** (AAASM-5440).
//!
//! AAASM-5357 proved the projection can store a row. This file proves the
//! gateway actually produces one: that a real evaluation through
//! [`PolicyEngine::evaluate`] — the public production entry, not a helper this
//! file could have written — reaches a real store through a real spawned drain.
//!
//! # How the two seams are kept separable
//!
//! `evaluate` dispatches to one of two pipelines and each is wired
//! independently, so each needs a falsification test the *other* seam's
//! mutation leaves green. Every test below is therefore pinned to exactly one
//! pipeline by construction:
//!
//! * `primary_*` tests use [`primary_engine`], whose scope index is empty, so
//!   `evaluate` returns from `evaluate_primary`;
//! * `cascade_*` tests use [`cascade_engine`], which has a Global-scoped
//!   document registered, so `evaluate` routes to `evaluate_with_cascade`.
//!
//! A test that reached both would make the two mutations indistinguishable,
//! which is the failure mode this arrangement exists to prevent.
//!
//! ADR 0032 §8 is the source of the counting rules; §9 of the tiering rules.

use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use async_trait::async_trait;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel, PolicyResult};
use aa_gateway::engine::sensitive_data::{
    SensitiveDataDecision, SensitiveDataProjectionService, SensitiveDataProjectionSink,
};
use aa_gateway::engine::{EvaluationResult, PolicyEngine};
use aa_gateway::policy::document::PolicyDocument;
use aa_gateway::policy::scope::PolicyScope;
use aa_gateway::storage::sensitive_data::{
    CategoryFindingAggregate, SensitiveDataEventFilter, SensitiveDataEventRow, SensitiveDataFindingRow,
    SensitiveDataProjection, SensitiveDataProjectionConfig, SensitiveDataProjectionWriter, TenantScope,
};
use aa_gateway::storage::{SqliteBackend, SqliteConfig, StorageResult};

const ORG: &str = "acme";

/// A GitHub-shaped token with no account behind it. The built-in scanner keys
/// on the `ghp_` prefix, so no real credential is needed — or constructed —
/// anywhere in this file.
///
/// Recognised **twice** — as a `GitHubPat` and as generic high entropy — which
/// is why the one-finding fixture below is a different value.
const SYNTHETIC_TOKEN: &str = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456";

/// AWS's own published documentation key, recognised exactly once. The
/// single-finding boundary fixture.
const SYNTHETIC_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

/// A payload the scanner recognises several distinct things in. Its exact count
/// is deliberately never asserted — the tests compare the stored row count
/// against the evaluation's own `canonical_findings`, so a detector change moves
/// both sides together instead of turning a fixture into a magic number.
fn multi_finding_payload() -> String {
    format!("{SYNTHETIC_TOKEN} {SYNTHETIC_AWS_KEY}")
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

/// A migrated SQLite projection store.
async fn store() -> (tempfile::TempDir, Arc<SqliteBackend>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let backend = SqliteBackend::open(&SqliteConfig {
        path: dir.path().join("projection.db"),
    })
    .await
    .expect("open sqlite");
    backend
        .migrate_sensitive_data_projection()
        .await
        .expect("projection migrate");
    (dir, Arc::new(backend))
}

fn service(store: Arc<SqliteBackend>) -> SensitiveDataProjectionService {
    SensitiveDataProjectionService::spawn(
        SensitiveDataProjectionWriter::new(store, SensitiveDataProjectionConfig::enabled()),
        64,
    )
}

/// An engine whose scope index is empty — `evaluate` reaches `evaluate_primary`.
fn primary_engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
}

/// An engine with one Global-scoped document registered — `evaluate` reaches
/// `evaluate_with_cascade`.
fn cascade_engine() -> PolicyEngine {
    let mut engine = primary_engine();
    engine.load_policy(global_doc());
    engine
}

fn global_doc() -> PolicyDocument {
    PolicyDocument {
        name: Some("global".into()),
        policy_version: None,
        version: None,
        scope: PolicyScope::Global,
        network: None,
        schedule: None,
        budget: None,
        data: None,
        approval_timeout_secs: 300,
        approval_policy: None,
        tools: HashMap::new(),
        capabilities: None,
        filesystem: None,
    }
}

fn ctx() -> AgentContext {
    let mut metadata = BTreeMap::new();
    metadata.insert("org_id".to_string(), ORG.to_string());
    AgentContext {
        agent_id: AgentId::from_bytes([7u8; 16]),
        session_id: SessionId::from_bytes([9u8; 16]),
        pid: 0,
        started_at: aa_core::time::Timestamp::from_nanos(0),
        metadata,
        governance_level: GovernanceLevel::default(),
        parent_agent_id: None,
        team_id: Some("billing".to_string()),
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

/// A context with no attributable org — the projection cannot name a tenant.
fn untenanted_ctx() -> AgentContext {
    AgentContext {
        metadata: BTreeMap::new(),
        team_id: None,
        ..ctx()
    }
}

fn leaky_call(payload: &str) -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: "http_post".to_string(),
        args: payload.to_string(),
    }
}

fn scope() -> TenantScope {
    TenantScope::new(ORG, ORG).expect("well-formed scope")
}

async fn events(store: &Arc<SqliteBackend>) -> Vec<SensitiveDataEventRow> {
    store
        .query_sensitive_data_events(&SensitiveDataEventFilter::new(scope()))
        .await
        .expect("query events")
}

async fn findings(store: &Arc<SqliteBackend>) -> Vec<SensitiveDataFindingRow> {
    store
        .query_sensitive_data_findings(&SensitiveDataEventFilter::new(scope()))
        .await
        .expect("query findings")
}

// ---------------------------------------------------------------------------
// AC1 — a finding reaches the destination, on each seam independently
// ---------------------------------------------------------------------------

/// **Positive control, primary seam.** A real evaluation through the public
/// `evaluate` entry lands one event and its finding rows in a real store.
///
/// Kills the `evaluate_primary` wiring mutation; unaffected by the cascade one.
#[tokio::test]
async fn primary_seam_writes_the_event_and_its_finding_rows() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let result = engine.evaluate(&ctx(), &leaky_call(&format!("send {SYNTHETIC_TOKEN}")));
    assert!(
        !result.canonical_findings.is_empty(),
        "the fixture stopped producing findings, so this test would pass for the wrong reason"
    );

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 1, "{outcome:?}");
    assert_eq!(outcome.dropped, 0, "{outcome:?}");
    assert_eq!(outcome.refused, 0, "{outcome:?}");
    assert_eq!(outcome.write_failures, 0, "{outcome:?}");
    assert!(!outcome.drain_panicked, "{outcome:?}");

    let events = events(&store).await;
    assert_eq!(events.len(), 1, "expected exactly one event row");
    assert_eq!(events[0].org_id, ORG);
    assert_eq!(events[0].tenant_id, ORG);
    assert_eq!(events[0].team_id.as_deref(), Some("billing"));
    assert_eq!(events[0].operation, "tool_call");
    assert_eq!(events[0].destination_id, "http_post");
    assert_eq!(events[0].inspected_field_paths, vec!["args".to_string()]);

    let findings = findings(&store).await;
    assert_eq!(
        findings.len(),
        result.canonical_findings.len(),
        "the stored rows and the evaluation's own findings disagree"
    );
    assert!(findings.iter().all(|f| f.event_id == events[0].event_id));
}

/// **Positive control, cascade seam.** The same claim through the *other*
/// pipeline.
///
/// Kills the `evaluate_with_cascade` wiring mutation; unaffected by the primary
/// one.
#[tokio::test]
async fn cascade_seam_writes_the_event_and_its_finding_rows() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = cascade_engine().with_sensitive_data_sink(service.sink().clone());

    let result = engine.evaluate(&ctx(), &leaky_call(&format!("send {SYNTHETIC_TOKEN}")));
    assert!(
        !result.canonical_findings.is_empty(),
        "the fixture stopped producing findings, so this test would pass for the wrong reason"
    );

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 1, "{outcome:?}");

    let events = events(&store).await;
    assert_eq!(events.len(), 1, "expected exactly one event row");
    let findings = findings(&store).await;
    assert_eq!(
        findings.len(),
        result.canonical_findings.len(),
        "the stored rows and the evaluation's own findings disagree"
    );
    assert!(findings.iter().all(|f| f.event_id == events[0].event_id));
}

/// The cascade engine really does take the cascade pipeline, and the primary
/// engine really does not.
///
/// Without this the two falsification tests above could both be running the
/// same pipeline, and their "disjoint kills" would be an accident of naming.
/// `policy_doc_id` is the discriminator: only the cascade path attributes a
/// deciding document digest (`evaluate_primary` returns `None` by
/// construction — see `EvaluationResult::policy_doc_id`).
#[test]
fn the_two_harness_engines_take_different_pipelines() {
    let action = leaky_call(&format!("send {SYNTHETIC_TOKEN}"));
    assert!(
        primary_engine().evaluate(&ctx(), &action).policy_doc_id.is_none(),
        "the primary harness engine started attributing a cascade document"
    );
    assert!(
        cascade_engine().evaluate(&ctx(), &action).policy_doc_id.is_some(),
        "the cascade harness engine stopped taking the cascade pipeline, so the \
         cascade falsification test no longer covers that seam"
    );
}

// ---------------------------------------------------------------------------
// AC5 — one event, many findings
// ---------------------------------------------------------------------------

/// **ADR 0032 §8's worked example.** One action carrying several findings is
/// one event row and several finding rows, and the event's own counters say so
/// separately.
///
/// Asserted on the stored counters as well as the row counts because collapsing
/// the two measures does not need a missing row — it needs one number written
/// into the other's column.
#[tokio::test]
async fn primary_one_action_with_many_findings_stays_one_event() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let result = engine.evaluate(&ctx(), &leaky_call(&multi_finding_payload()));
    let detected = u32::try_from(result.canonical_findings.len()).unwrap();
    assert!(
        detected >= 2,
        "the multi-finding fixture stopped producing more than one finding, so \
         'one event, many findings' would hold vacuously"
    );

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 1, "{outcome:?}");

    let events = events(&store).await;
    assert_eq!(events.len(), 1, "many findings must not become many events");
    assert_eq!(events[0].event_count, 1);
    assert_eq!(events[0].finding_count, detected);

    let findings = findings(&store).await;
    assert_eq!(findings.len(), detected as usize);
    assert!(
        findings.iter().all(|f| f.event_id == events[0].event_id),
        "every finding row belongs to the one event"
    );

    // A redacted action forwarded the scrubbed bytes, so its findings were
    // transformed and none was blocked. The two counters are separate columns
    // and must not both be filled from `finding_count`.
    assert_eq!(events[0].transformed_finding_count, detected);
    assert_eq!(events[0].blocked_finding_count, 0);
    assert_eq!(events[0].blocked_event_count, 0);

    let aggregate: Vec<CategoryFindingAggregate> = store
        .aggregate_sensitive_data_by_category(&SensitiveDataEventFilter::new(scope()))
        .await
        .expect("aggregate");
    let total_findings: u64 = aggregate.iter().map(|a| a.finding_count).sum();
    assert_eq!(total_findings, u64::from(detected));
    assert!(
        aggregate.iter().all(|a| a.event_count == 1),
        "one action cannot contribute more than one event to any category"
    );
}

/// A single finding is one row — the boundary below the multi-finding case.
#[tokio::test]
async fn primary_one_finding_is_one_row() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let result = engine.evaluate(&ctx(), &leaky_call(SYNTHETIC_AWS_KEY));
    assert_eq!(
        result.canonical_findings.len(),
        1,
        "the single-finding fixture stopped being singular"
    );
    assert_eq!(service.shutdown().await.written, 1);
    assert_eq!(events(&store).await[0].finding_count, 1);
    assert_eq!(findings(&store).await.len(), 1);
}

/// An action with nothing sensitive in it writes nothing at all.
///
/// Not a nicety: a zero-finding row per governed call would make every
/// per-category read a needle hunt, and would make "how many actions carried
/// sensitive data?" answerable only by filtering the thing the table exists to
/// count.
#[tokio::test]
async fn primary_an_action_with_no_findings_writes_nothing() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let result = engine.evaluate(&ctx(), &leaky_call("nothing sensitive here"));
    assert!(result.canonical_findings.is_empty());

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 0, "{outcome:?}");
    assert_eq!(outcome.refused, 0, "a clean action is not a refusal");
    assert!(events(&store).await.is_empty());
    assert!(findings(&store).await.is_empty());
}

// ---------------------------------------------------------------------------
// ordering and duplicate semantics
// ---------------------------------------------------------------------------

/// Two identical actions are two events, written in the order they were
/// offered.
///
/// Both halves matter and they pull in opposite directions. *Two* events,
/// because the store's idempotency key is the event id and a derived id would
/// silently collapse a repeated leak into one row under first-write-wins — the
/// second occurrence would vanish from a governance surface. *In order*,
/// because the drain is the single consumer of an mpsc and `ingested_at` is
/// stamped as each row is written, so a reader can trust that ordering rather
/// than having to sort by a clock the producer set.
#[tokio::test]
async fn primary_two_identical_actions_are_two_ordered_events() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let action = leaky_call(&format!("t={SYNTHETIC_TOKEN}"));
    engine.evaluate(&ctx(), &action);
    engine.evaluate(&ctx(), &action);

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 2, "{outcome:?}");

    let events = events(&store).await;
    assert_eq!(
        events.len(),
        2,
        "an identical repeat is a second occurrence, not a duplicate"
    );
    assert_ne!(
        events[0].event_id, events[1].event_id,
        "two occurrences sharing an event id would deduplicate one of them away"
    );

    let mut by_ingest: Vec<u64> = events.iter().map(|e| e.ingested_at_ns).collect();
    let observed = by_ingest.clone();
    by_ingest.sort_unstable();
    by_ingest.reverse();
    assert_eq!(
        observed, by_ingest,
        "rows came back in an order `ingested_at_ns` does not support"
    );
}

// ---------------------------------------------------------------------------
// AC3 — writing must not change any policy outcome
// ---------------------------------------------------------------------------

/// **Behaviour identity, primary seam.** Every field of the `EvaluationResult`
/// is the same with the projection attached as without it.
///
/// The result is destructured exhaustively rather than spot-checked, so a field
/// added to `EvaluationResult` later is a compile error here instead of a
/// silently unasserted difference. "Both were non-empty" is not identity.
#[test]
fn primary_attaching_the_projection_changes_no_field_of_the_decision() {
    assert_identical_decisions(primary_engine(), primary_engine());
}

/// **Behaviour identity, cascade seam.**
#[test]
fn cascade_attaching_the_projection_changes_no_field_of_the_decision() {
    assert_identical_decisions(cascade_engine(), cascade_engine());
}

fn assert_identical_decisions(bare: PolicyEngine, sunk: PolicyEngine) {
    let (sink, _rx) = SensitiveDataProjectionSink::channel(64);
    let sunk = sunk.with_sensitive_data_sink(sink);

    for payload in [
        format!("token={SYNTHETIC_TOKEN}"),
        format!("two={SYNTHETIC_TOKEN} and {SYNTHETIC_AWS_KEY}"),
        "clean payload".to_string(),
    ] {
        let action = leaky_call(&payload);
        let EvaluationResult {
            decision,
            redacted_payload,
            credential_findings,
            canonical_findings,
            deny_action,
            policy_doc_id,
            narrowed,
        } = bare.evaluate(&ctx(), &action);
        let with_sink = sunk.evaluate(&ctx(), &action);

        assert_eq!(
            format!("{decision:?}"),
            format!("{:?}", with_sink.decision),
            "{payload}"
        );
        assert_eq!(redacted_payload, with_sink.redacted_payload, "{payload}");
        assert_eq!(credential_findings, with_sink.credential_findings, "{payload}");
        assert_eq!(canonical_findings, with_sink.canonical_findings, "{payload}");
        assert_eq!(deny_action, with_sink.deny_action, "{payload}");
        assert_eq!(policy_doc_id, with_sink.policy_doc_id, "{payload}");
        assert_eq!(narrowed, with_sink.narrowed, "{payload}");
    }
}

// ---------------------------------------------------------------------------
// the simulation trap — a dry run writes nothing
// ---------------------------------------------------------------------------

/// **A dry run reaches both seams and must write neither.**
///
/// `simulate` evaluates through an ephemeral engine, and that engine takes the
/// cascade path or the primary path depending on the live scope index — so this
/// is asserted for both. A simulation applies no enforcement and writes no audit
/// entry (ADR 0032); depositing a governance row from one would make the
/// dashboard's own what-if panel a source of the numbers it reports.
#[tokio::test]
async fn a_simulation_writes_nothing_on_either_path() {
    for engine in [primary_engine(), cascade_engine()] {
        let (_dir, store) = store().await;
        let service = service(Arc::clone(&store));
        let engine = engine.with_sensitive_data_sink(service.sink().clone());

        let action = leaky_call(&format!("t={SYNTHETIC_TOKEN}"));
        let simulated = engine.simulate(&ctx(), &action);
        assert!(
            !simulated.canonical_findings.is_empty(),
            "the simulation stopped detecting anything, so writing nothing proves nothing"
        );

        let outcome = service.shutdown().await;
        assert_eq!(outcome.written, 0, "a dry run wrote a governance row: {outcome:?}");
        assert_eq!(outcome.dropped, 0, "{outcome:?}");
        assert_eq!(outcome.refused, 0, "{outcome:?}");
        assert!(events(&store).await.is_empty());
        assert!(findings(&store).await.is_empty());
    }
}

/// The replay primitive is the other ephemeral engine, built by a separate
/// struct literal, and it writes nothing either.
#[tokio::test]
async fn a_replay_against_a_proposed_document_writes_nothing() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let replayed = engine.simulate_against(
        Arc::new(global_doc()),
        &ctx(),
        &leaky_call(&format!("t={SYNTHETIC_TOKEN}")),
    );
    assert!(
        !replayed.canonical_findings.is_empty(),
        "the replay stopped detecting anything, so writing nothing proves nothing"
    );

    let outcome = service.shutdown().await;
    assert_eq!(outcome.written, 0, "a replay wrote a governance row: {outcome:?}");
    assert!(events(&store).await.is_empty());
}

// ---------------------------------------------------------------------------
// AC4 — a write failure must not fail the decision, and must not be silent
// ---------------------------------------------------------------------------

/// A store that fails every write, and counts the attempts so the test can tell
/// "never called" from "called and refused".
#[derive(Default)]
struct FailingStore {
    attempts: AtomicU64,
}

#[async_trait]
impl SensitiveDataProjection for FailingStore {
    async fn migrate_sensitive_data_projection(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn rollback_sensitive_data_projection(&self) -> StorageResult<()> {
        Ok(())
    }

    async fn append_sensitive_data_decision(
        &self,
        _event: &SensitiveDataEventRow,
        _findings: &[SensitiveDataFindingRow],
    ) -> StorageResult<()> {
        self.attempts.fetch_add(1, Ordering::Relaxed);
        Err(aa_gateway::storage::StorageError::QueryFailed(
            "projection table unavailable".into(),
        ))
    }

    async fn query_sensitive_data_events(
        &self,
        _filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataEventRow>> {
        Ok(Vec::new())
    }

    async fn query_sensitive_data_findings(
        &self,
        _filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataFindingRow>> {
        Ok(Vec::new())
    }

    async fn count_sensitive_data_events(&self, _filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        Ok(0)
    }

    async fn count_sensitive_data_findings(&self, _filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        Ok(0)
    }

    async fn aggregate_sensitive_data_by_category(
        &self,
        _filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<CategoryFindingAggregate>> {
        Ok(Vec::new())
    }

    async fn sensitive_data_projection_columns(&self) -> StorageResult<Vec<(String, String)>> {
        Ok(Vec::new())
    }
}

/// **AC4.** The documented decision is *fail open on the enforcement outcome,
/// and never silently* — a reporting outage must not become an enforcement
/// outage, but the resulting hole in the tier must be countable.
///
/// Both halves are asserted here: the decision is byte-identical to the one a
/// working store produced, and the failure shows up on `write_failures`.
#[tokio::test]
async fn primary_a_write_failure_leaves_the_decision_intact_and_is_counted() {
    let store = Arc::new(FailingStore::default());
    let service = SensitiveDataProjectionService::spawn(
        SensitiveDataProjectionWriter::new(Arc::clone(&store), SensitiveDataProjectionConfig::enabled()),
        64,
    );
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());
    let action = leaky_call(&format!("t={SYNTHETIC_TOKEN}"));

    let with_failing_store = engine.evaluate(&ctx(), &action);
    let reference = primary_engine().evaluate(&ctx(), &action);

    assert!(matches!(with_failing_store.decision, PolicyResult::Allow));
    assert_eq!(
        format!("{:?}", with_failing_store.decision),
        format!("{:?}", reference.decision),
        "a projection write failure moved the enforcement decision"
    );
    assert_eq!(with_failing_store.redacted_payload, reference.redacted_payload);
    assert_eq!(with_failing_store.canonical_findings, reference.canonical_findings);

    let outcome = service.shutdown().await;
    assert_eq!(store.attempts.load(Ordering::Relaxed), 1, "the store was never asked");
    assert_eq!(outcome.write_failures, 1, "a lost row was not counted: {outcome:?}");
    assert_eq!(outcome.written, 0, "{outcome:?}");
    assert!(!outcome.drain_panicked, "a failing write must not kill the drain");
}

/// An evaluation that cannot be described truthfully is refused and counted,
/// not written under a fabricated tenant.
///
/// A blank tenant is not a narrower scope — it is a scope that matches whatever
/// the next writer also leaves blank, so the row would surface in some other
/// reader's answer.
#[tokio::test]
async fn primary_an_unattributable_tenancy_is_refused_and_counted() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    engine.evaluate(&untenanted_ctx(), &leaky_call(&format!("t={SYNTHETIC_TOKEN}")));

    let outcome = service.shutdown().await;
    assert_eq!(outcome.refused, 1, "{outcome:?}");
    assert_eq!(outcome.written, 0, "{outcome:?}");
    assert_eq!(
        outcome.dropped, 0,
        "a refusal is not a drop — the two name different holes"
    );
}

// ---------------------------------------------------------------------------
// channel lifecycle: backpressure, receiver loss, sender loss
// ---------------------------------------------------------------------------

/// A full queue drops, counts and does not block the caller.
///
/// The receiver is held but never polled, so the channel fills at exactly
/// `capacity`. Blocking instead would put a stalled database inside the
/// enforcement path — the thing the channel exists to prevent.
#[test]
fn a_full_queue_drops_and_counts_rather_than_blocking() {
    let (sink, _rx) = SensitiveDataProjectionSink::channel(1);
    let engine = primary_engine().with_sensitive_data_sink(sink.clone());
    let action = leaky_call(&format!("t={SYNTHETIC_TOKEN}"));

    for _ in 0..4 {
        engine.evaluate(&ctx(), &action);
    }

    assert_eq!(sink.dropped(), 3, "a full queue must count every decision it sheds");
    assert_eq!(sink.refused(), 0, "a drop is not a refusal");
}

/// A vanished consumer is observable rather than silent.
///
/// Dropping the receiver is what an exited or aborted drain looks like from the
/// producer's side. Every subsequent decision is lost, and a governance tier
/// that loses rows without saying so asserts a completeness it does not have.
#[test]
fn a_consumer_that_exits_makes_every_subsequent_loss_countable() {
    let (sink, rx) = SensitiveDataProjectionSink::channel(64);
    drop(rx);
    let engine = primary_engine().with_sensitive_data_sink(sink.clone());

    engine.evaluate(&ctx(), &leaky_call(&format!("t={SYNTHETIC_TOKEN}")));

    assert_eq!(sink.dropped(), 1, "a closed channel silently swallowed a decision");
}

/// Dropping every sender terminates the drain, without a cancellation.
///
/// The second of the two documented termination conditions, and the one that
/// applies when an engine is simply dropped: `run` must not park forever on a
/// receiver nothing can ever feed.
#[tokio::test]
async fn dropping_every_sender_terminates_the_drain() {
    let (_dir, store) = store().await;
    let writer = SensitiveDataProjectionWriter::new(Arc::clone(&store), SensitiveDataProjectionConfig::enabled());
    let (sink, rx) = SensitiveDataProjectionSink::channel(64);
    let drain = aa_gateway::engine::sensitive_data::SensitiveDataProjectionDrain::new(rx, writer);
    let handle = tokio::spawn(drain.run(tokio_util::sync::CancellationToken::new()));

    drop(sink);

    tokio::time::timeout(std::time::Duration::from_secs(5), handle)
        .await
        .expect("the drain did not terminate when its last sender was dropped")
        .expect("the drain panicked");
}

/// A shutdown drains what was already accepted rather than discarding it.
///
/// The engine holds a live sink clone throughout, so this exercises the
/// cancellation path specifically — "drop the last sender" is not available to
/// a composition root whose `Arc<PolicyEngine>` outlives the serve call.
#[tokio::test]
async fn shutdown_persists_decisions_already_queued() {
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    for _ in 0..8 {
        engine.evaluate(&ctx(), &leaky_call(&format!("t={SYNTHETIC_TOKEN}")));
    }

    let outcome = service.shutdown().await;
    // The engine is still alive and still holds a sender; termination came from
    // the token, and nothing accepted before it was discarded.
    drop(engine);
    assert_eq!(outcome.written, 8, "shutdown discarded accepted decisions: {outcome:?}");
    assert_eq!(events(&store).await.len(), 8);
}

// ---------------------------------------------------------------------------
// AC6 — no raw value and no byte span reaches the projection
// ---------------------------------------------------------------------------

/// **ADR 0032 §9.** Neither the scanned value nor either end of its byte span
/// appears anywhere in what was stored.
///
/// The payload is padded so every finding's span carries four-digit offsets
/// that no schema version, delegation depth or count can collide with. The whole
/// serialized event and every finding row are searched, keys and values alike,
/// because an offset leaks as a number under an innocent name just as easily as
/// under `offset`.
///
/// The two `*_at_ns` clock columns are removed before searching. They are
/// nineteen-digit wall-clock values, so any four-digit needle appears inside one
/// of them a few times in a thousand runs — a flake that says nothing about
/// tiering. Nothing else is excluded, and the length is not searched separately:
/// a two-digit needle would collide with unrelated small integers, and the
/// storage tier's own `sensitive_data_contract` already pins from outside this
/// crate that neither table has a length column at all.
#[tokio::test]
async fn primary_no_raw_value_and_no_byte_span_reaches_the_projection() {
    const PAD: usize = 4321;
    let (_dir, store) = store().await;
    let service = service(Arc::clone(&store));
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    let payload = format!("{}{SYNTHETIC_TOKEN}", "-".repeat(PAD));
    let result = engine.evaluate(&ctx(), &leaky_call(&payload));
    assert!(!result.canonical_findings.is_empty());
    let mut offsets: Vec<String> = Vec::new();
    for finding in &result.canonical_findings {
        let span = finding.span();
        assert!(
            span.start() >= PAD,
            "the padding stopped pushing the span past the digits other columns use"
        );
        offsets.push(span.start().to_string());
        offsets.push(span.end().to_string());
    }

    assert_eq!(service.shutdown().await.written, 1);

    let mut serialized = clock_free_json(&events(&store).await);
    serialized.push_str(&clock_free_json(&findings(&store).await));

    for forbidden in offsets {
        assert!(
            !serialized.contains(&forbidden),
            "`{forbidden}` — a byte offset — reached the projection tier"
        );
    }
    assert!(
        !serialized.contains(SYNTHETIC_TOKEN),
        "the scanned value reached the projection tier"
    );
    for forbidden in ["span", "offset", "start", "end", "length"] {
        assert!(
            !serialized.contains(forbidden),
            "`{forbidden}` appeared as a key in a projection row"
        );
    }
}

/// Serialize `rows` with every `*_at_ns` clock column removed — see the caller
/// for why the clocks are the one exclusion.
fn clock_free_json<T: serde::Serialize>(rows: &T) -> String {
    let mut value = serde_json::to_value(rows).expect("rows serialize");
    strip_clocks(&mut value);
    serde_json::to_string(&value).expect("stripped rows serialize")
}

fn strip_clocks(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(map) => {
            map.retain(|key, _| !key.ends_with("_at_ns"));
            for nested in map.values_mut() {
                strip_clocks(nested);
            }
        }
        serde_json::Value::Array(items) => items.iter_mut().for_each(strip_clocks),
        _ => {}
    }
}

/// The only shape the producer hands to the writer is
/// `SensitiveDataFindingRecord`, which is span-free by construction.
///
/// Asserted over the value the channel actually carries rather than over the
/// stored row, because the store is the second line of defence: if a span
/// reached the channel, a later writer change could publish it without anything
/// in the storage tier's own tests noticing.
#[test]
fn the_channel_carries_only_the_span_free_record_shape() {
    let (sink, mut rx) = SensitiveDataProjectionSink::channel(4);
    let engine = primary_engine().with_sensitive_data_sink(sink);
    engine.evaluate(&ctx(), &leaky_call(SYNTHETIC_AWS_KEY));

    let decision: SensitiveDataDecision = rx.try_recv().expect("one decision was offered");
    let json = serde_json::to_string(&decision.findings).expect("records serialize");
    for forbidden in ["span", "offset", "start", "end", "length"] {
        assert!(
            !json.contains(forbidden),
            "`{forbidden}` reached the producer's own payload"
        );
    }
    assert_eq!(decision.event.total_finding_count(), 1);
    assert_eq!(decision.findings.len(), 1);
}

/// A disabled writer is not a write, and must not be counted as one.
///
/// The composition root only builds enabled writers, so this configuration is
/// unreachable in production today — which is exactly why the counter would
/// have over-reported for as long as it took someone to reach it. `written` is
/// what a reader consults to decide whether the tier is complete.
#[tokio::test]
async fn a_disabled_writer_records_neither_a_row_nor_a_write() {
    let (_dir, store) = store().await;
    let service = SensitiveDataProjectionService::spawn(
        SensitiveDataProjectionWriter::new(Arc::clone(&store), SensitiveDataProjectionConfig::disabled()),
        64,
    );
    let engine = primary_engine().with_sensitive_data_sink(service.sink().clone());

    engine.evaluate(&ctx(), &leaky_call(SYNTHETIC_AWS_KEY));

    let outcome = service.shutdown().await;
    assert_eq!(
        outcome.written, 0,
        "a disabled write was counted as a write: {outcome:?}"
    );
    assert_eq!(outcome.write_failures, 0, "a disabled write is not a failure either");
    assert!(events(&store).await.is_empty());
}
