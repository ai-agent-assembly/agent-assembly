//! End-to-end persistence check for the SQLite [`StorageBackend`] —
//! demonstrates that data survives gateway restarts (drop pool → re-open
//! same file → read identical data back).
//!
//! Story-level acceptance evidence for AAASM-1584 (Epic 18 S-B).

use std::collections::BTreeMap;

use aa_core::identity::AgentId;
use aa_gateway::storage::{
    AgentRecord, AuditEvent, AuditFilter, MetricQuery, PolicyDocument, SqliteBackend, SqliteConfig, StorageBackend,
};
use chrono::{TimeZone, Utc};
use tempfile::TempDir;

#[tokio::test]
async fn sqlite_data_survives_gateway_restart() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("restart.db");

    let ts = Utc.with_ymd_and_hms(2026, 5, 21, 10, 0, 0).unwrap();
    let agent = AgentId::from_bytes([42; 16]);

    // --- Session 1: open, migrate, write one row in each table. -----------
    {
        let backend = SqliteBackend::open(&SqliteConfig { path: path.clone() })
            .await
            .expect("open #1");
        backend.migrate().await.expect("migrate");

        backend
            .append_audit_event(&AuditEvent {
                ts,
                event_id: uuid::Uuid::from_u128(7),
                agent_id: agent,
                team_id: Some("team-x".into()),
                action: "tool_call".into(),
                decision: "allow".into(),
                dry_run: false,
                shadow_decision: None,
                matched_rule_id: Some("rule-7".into()),
                payload: Some(serde_json::json!({"survives": true})),
            })
            .await
            .expect("append");

        let mut metadata = BTreeMap::new();
        metadata.insert("name".to_owned(), "Persistence".to_owned());
        backend
            .upsert_agent(AgentRecord {
                agent_id: agent,
                team_id: Some("team-x".into()),
                org_id: Some("org-1".into()),
                metadata,
                registered_at: ts,
                last_seen_at: ts,
                enforcement_mode: "enforce".into(),
            })
            .await
            .expect("upsert");

        backend
            .save_policy(PolicyDocument {
                name: "restart-guard".into(),
                bytes: b"rules: persist-me".to_vec(),
            })
            .await
            .expect("save_policy");

        backend
            .record_metric(aa_gateway::storage::Metric {
                ts,
                agent_id: agent,
                metric: "tokens_used".into(),
                value: 123.0,
                labels: BTreeMap::new(),
            })
            .await
            .expect("record_metric");
        // backend dropped at end of scope — pool flushes WAL.
    }

    // --- Session 2: re-open same file, read everything back. --------------
    let backend = SqliteBackend::open(&SqliteConfig { path: path.clone() })
        .await
        .expect("open #2");
    // migrate() is idempotent — calling again must be a no-op and keep data intact.
    backend.migrate().await.expect("migrate #2");

    let events = backend
        .query_audit_events(AuditFilter::default())
        .await
        .expect("query audit");
    assert_eq!(events.len(), 1, "audit row must persist across restart");
    let ev = &events[0];
    assert_eq!(ev.event_id, uuid::Uuid::from_u128(7));
    assert_eq!(ev.agent_id, agent);
    assert_eq!(ev.team_id.as_deref(), Some("team-x"));
    assert_eq!(ev.action, "tool_call");
    assert_eq!(ev.payload, Some(serde_json::json!({"survives": true})));

    let agent_row = backend
        .get_agent(&agent)
        .await
        .expect("get_agent")
        .expect("agent must persist across restart");
    assert_eq!(agent_row.org_id.as_deref(), Some("org-1"));
    assert_eq!(agent_row.metadata.get("name").map(String::as_str), Some("Persistence"));

    backend.rollback_policy("restart-guard", 1).await.expect("activate v1");
    let policy = backend
        .get_active_policy("restart-guard")
        .await
        .expect("get_active")
        .expect("policy must persist across restart");
    assert_eq!(policy.bytes, b"rules: persist-me");

    let metrics = backend
        .query_metrics(MetricQuery::default())
        .await
        .expect("query metric");
    assert_eq!(metrics.len(), 1, "metric row must persist across restart");
    assert_eq!(metrics[0].value, 123.0);

    // Final liveness probe + row-count sanity check.
    let health = backend.healthcheck().await.expect("healthcheck");
    assert_eq!(health.backend, "sqlite");
    assert_eq!(health.row_counts.audit_events, 1);
    assert_eq!(health.row_counts.agents, 1);
    assert_eq!(health.row_counts.policy_versions, 1);
}
