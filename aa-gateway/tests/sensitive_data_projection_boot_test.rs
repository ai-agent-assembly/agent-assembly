//! The composition root that turns the projection on (AAASM-5440).
//!
//! `sensitive_data_producer_test` proves an engine *given* a sink produces rows.
//! This file proves the shipped gateway gives it one: it calls
//! [`aa_gateway::server::attach_sensitive_data_projection`] — the same function
//! `serve_tcp` and `serve_uds` call, not a fixture written for a test — and
//! checks that the store it opened, the drain it spawned and the sink it
//! attached are all real.
//!
//! Each test sets a process-wide environment variable, so each must be the only
//! test in its process. `cargo nextest` runs every test in its own process,
//! which is the harness this repository uses.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;

use aa_core::identity::{AgentId, SessionId};
use aa_core::{AgentContext, GovernanceAction, GovernanceLevel};
use aa_gateway::engine::PolicyEngine;
use aa_gateway::server::{attach_sensitive_data_projection, SENSITIVE_DATA_PROJECTION_DB_ENV};
use aa_gateway::storage::sensitive_data::{SensitiveDataEventFilter, SensitiveDataProjection, TenantScope};
use aa_gateway::storage::{SqliteBackend, SqliteConfig};

const ORG: &str = "acme";
const SYNTHETIC_AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

fn engine() -> PolicyEngine {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    writeln!(tmp, "version: \"1\"").unwrap();
    tmp.flush().unwrap();
    let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
    PolicyEngine::load_from_file(tmp.path(), alert_tx).unwrap()
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
        team_id: None,
        depth: 0,
        delegation_reason: None,
        spawned_by_tool: None,
        root_agent_id: None,
    }
}

fn leaky_call() -> GovernanceAction {
    GovernanceAction::ToolCall {
        name: "http_post".to_string(),
        args: SYNTHETIC_AWS_KEY.to_string(),
    }
}

/// **The production lifecycle, end to end.** The composition root opens the
/// store, migrates it, spawns the drain and attaches the sink; an evaluation on
/// the returned engine lands a durable row in the configured file.
///
/// The row is read back through a *separately opened* connection to that file,
/// so what is asserted is what is on disk rather than what a handle held open by
/// the writer says.
#[tokio::test]
async fn the_configured_projection_persists_a_finding_to_its_database() {
    let dir = tempfile::tempdir().expect("temp dir");
    let db = dir.path().join("projection.db");
    std::env::set_var(SENSITIVE_DATA_PROJECTION_DB_ENV, &db);

    let (engine, projection) = attach_sensitive_data_projection(engine())
        .await
        .expect("the projection is configured and openable");
    let projection = projection.expect("a configured projection is built");

    let result = engine.evaluate(&ctx(), &leaky_call());
    assert_eq!(
        result.canonical_findings.len(),
        1,
        "the fixture stopped producing a finding"
    );

    let outcome = projection.shutdown().await;
    assert_eq!(outcome.written, 1, "{outcome:?}");
    assert_eq!(outcome.dropped, 0, "{outcome:?}");
    assert_eq!(outcome.refused, 0, "{outcome:?}");
    assert!(!outcome.drain_panicked, "{outcome:?}");

    let reopened = Arc::new(
        SqliteBackend::open(&SqliteConfig { path: db })
            .await
            .expect("reopen the projection database"),
    );
    let filter = SensitiveDataEventFilter::new(TenantScope::new(ORG, ORG).unwrap());
    assert_eq!(
        reopened.count_sensitive_data_events(&filter).await.unwrap(),
        1,
        "nothing was durable in the file the composition root was told to write"
    );
    assert_eq!(reopened.count_sensitive_data_findings(&filter).await.unwrap(), 1);
}

/// Unconfigured is off, and off means the engine is exactly what it was before
/// this feature existed.
///
/// ADR 0032 §8 makes the tier opt-in; defaulting it on would make the safe state
/// the one an operator has to choose. Asserted on the engine's behaviour rather
/// than only on the `None`, so "no service was built" and "no rows are produced"
/// are both covered.
#[tokio::test]
async fn an_unconfigured_projection_builds_nothing_and_writes_nothing() {
    std::env::remove_var(SENSITIVE_DATA_PROJECTION_DB_ENV);

    let (engine, projection) = attach_sensitive_data_projection(engine())
        .await
        .expect("an unconfigured projection is not an error");
    assert!(projection.is_none(), "an unset variable built a projection anyway");

    // The engine still evaluates, and still detects — it just records nothing.
    let result = engine.evaluate(&ctx(), &leaky_call());
    assert_eq!(result.canonical_findings.len(), 1);
}

/// A configured-but-unopenable database is a boot failure, not a silent
/// downgrade to "projection off".
///
/// An operator who set the variable asked for the tier. Starting without it and
/// logging a warning would leave a governance surface empty for exactly as long
/// as nobody read the log, and an empty table is indistinguishable from a quiet
/// period.
#[tokio::test]
async fn a_configured_but_unopenable_database_fails_the_boot() {
    let dir = tempfile::tempdir().expect("temp dir");
    // A directory where a file is required: `open` cannot create a database here.
    std::env::set_var(SENSITIVE_DATA_PROJECTION_DB_ENV, dir.path());

    // `PolicyEngine` is not `Debug`, so the success arm cannot be unwrapped for a
    // message — match instead of `expect_err`.
    let Err(error) = attach_sensitive_data_projection(engine()).await else {
        panic!("an unopenable projection database must not boot quietly");
    };
    assert!(
        error.to_string().contains("sensitive-data projection"),
        "the boot error does not name the subsystem that failed: {error}"
    );
}
