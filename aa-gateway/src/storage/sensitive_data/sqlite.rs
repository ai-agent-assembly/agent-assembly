//! SQLite implementation of the sensitive-data projection.
//!
//! Local-mode's backing store, and the one the property tests run against —
//! it needs no container, so the invariants that matter (span-freedom, count
//! separation, tenant isolation, idempotency, rollback) are exercised on every
//! `cargo nextest run -p aa-gateway` rather than only where Docker is present.

use async_trait::async_trait;
use sqlx::{Row, SqlitePool};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::sqlite::SqliteBackend;

use super::rows::{check_readable, narrow, CategoryTally, SensitiveDataEventRow, SensitiveDataFindingRow};
use super::store::{CategoryFindingAggregate, SensitiveDataEventFilter, SensitiveDataProjection};

/// The projection's DDL, applied by
/// [`migrate_sensitive_data_projection`](SensitiveDataProjection::migrate_sensitive_data_projection).
///
/// Every statement is `IF NOT EXISTS`, so the slice is safe against a fresh
/// file or an already-migrated one. There is no offset, length, start, end or
/// payload column in either table — ADR 0032 §9 confines those to the
/// tamper-evident tier, and `tests/sensitive_data_projection_test.rs` asserts
/// the column sets from outside this module so the omission cannot be undone
/// quietly.
const PROJECTION_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS sensitive_data_events (
        schema_version_major      INTEGER NOT NULL,
        schema_version_minor      INTEGER NOT NULL,
        event_id                  TEXT    NOT NULL PRIMARY KEY,
        occurred_at_ns            INTEGER NOT NULL,
        ingested_at_ns            INTEGER NOT NULL,
        org_id                    TEXT    NOT NULL,
        tenant_id                 TEXT    NOT NULL,
        team_id                   TEXT,
        acting_agent_id           TEXT    NOT NULL,
        root_agent_id             TEXT    NOT NULL,
        parent_agent_id           TEXT,
        delegation_depth          INTEGER NOT NULL,
        session_id                TEXT,
        trace_id                  TEXT,
        request_id                TEXT,
        correlation_id            TEXT,
        operation                 TEXT    NOT NULL,
        destination_kind          TEXT    NOT NULL,
        destination_id            TEXT    NOT NULL,
        trust_zone                TEXT    NOT NULL,
        direction                 TEXT    NOT NULL,
        policy_document_id        TEXT,
        policy_version            INTEGER,
        matched_rule_ids          TEXT    NOT NULL,
        inspected_field_paths     TEXT    NOT NULL,
        verdict                   TEXT    NOT NULL,
        enforcement_point         TEXT    NOT NULL,
        transmission_evidence     TEXT    NOT NULL,
        enforcement_mode          TEXT    NOT NULL,
        inspection_failure_path   TEXT    NOT NULL,
        severity                  TEXT,
        confidence                TEXT,
        method                    TEXT,
        status                    TEXT,
        event_count               INTEGER NOT NULL,
        blocked_event_count       INTEGER NOT NULL,
        finding_count             INTEGER NOT NULL,
        blocked_finding_count     INTEGER NOT NULL,
        transformed_finding_count INTEGER NOT NULL,
        finding_count_by_category TEXT    NOT NULL,
        reason_codes              TEXT    NOT NULL
    )",
    // Every read is tenant-scoped, so every index leads with the tenant keys.
    "CREATE INDEX IF NOT EXISTS idx_sd_events_scope_ts
        ON sensitive_data_events(org_id, tenant_id, occurred_at_ns)",
    "CREATE INDEX IF NOT EXISTS idx_sd_events_scope_verdict
        ON sensitive_data_events(org_id, tenant_id, verdict)",
    "CREATE TABLE IF NOT EXISTS sensitive_data_findings (
        schema_version_major INTEGER NOT NULL,
        schema_version_minor INTEGER NOT NULL,
        event_id             TEXT    NOT NULL,
        finding_ordinal      INTEGER NOT NULL,
        org_id               TEXT    NOT NULL,
        tenant_id            TEXT    NOT NULL,
        occurred_at_ns       INTEGER NOT NULL,
        verdict              TEXT    NOT NULL,
        category             TEXT    NOT NULL,
        severity             TEXT    NOT NULL,
        confidence           TEXT    NOT NULL,
        method               TEXT    NOT NULL,
        status               TEXT    NOT NULL,
        recognizer           TEXT    NOT NULL,
        recognizer_version   TEXT    NOT NULL,
        field_path           TEXT    NOT NULL,
        redaction_label      TEXT    NOT NULL,
        aggregate_key        TEXT    NOT NULL,
        PRIMARY KEY (event_id, finding_ordinal)
    )",
    "CREATE INDEX IF NOT EXISTS idx_sd_findings_scope_category
        ON sensitive_data_findings(org_id, tenant_id, verdict, category)",
    "CREATE INDEX IF NOT EXISTS idx_sd_findings_scope_ts
        ON sensitive_data_findings(org_id, tenant_id, occurred_at_ns)",
];

/// The inverse of [`PROJECTION_SCHEMA`].
///
/// Dropping the table drops its indexes with it, so naming only the tables is
/// the whole undo. Ordered children-first purely so the statements read in the
/// reverse of the order they were created.
const PROJECTION_ROLLBACK: &[&str] = &[
    "DROP TABLE IF EXISTS sensitive_data_findings",
    "DROP TABLE IF EXISTS sensitive_data_events",
];

/// The event columns, in the order the row struct declares them.
const EVENT_COLUMNS: &str = "schema_version_major, schema_version_minor, event_id, occurred_at_ns, \
     ingested_at_ns, org_id, tenant_id, team_id, acting_agent_id, root_agent_id, parent_agent_id, \
     delegation_depth, session_id, trace_id, request_id, correlation_id, operation, destination_kind, \
     destination_id, trust_zone, direction, policy_document_id, policy_version, matched_rule_ids, \
     inspected_field_paths, verdict, enforcement_point, transmission_evidence, enforcement_mode, \
     inspection_failure_path, severity, confidence, method, status, event_count, blocked_event_count, \
     finding_count, blocked_finding_count, transformed_finding_count, finding_count_by_category, reason_codes";

/// The finding columns, in the order the row struct declares them.
const FINDING_COLUMNS: &str = "schema_version_major, schema_version_minor, event_id, finding_ordinal, \
     org_id, tenant_id, occurred_at_ns, verdict, category, severity, confidence, method, status, recognizer, \
     recognizer_version, field_path, redaction_label, aggregate_key";

/// Encode a list column as a JSON array.
///
/// The list columns (`matched_rule_ids`, `inspected_field_paths`,
/// `reason_codes`, `finding_count_by_category`) are never grouped by — grouping
/// by category goes through the normalized findings table, which is why the
/// findings are normalized at all — so a JSON column costs nothing and keeps
/// the event row one row.
fn encode_json<T: serde::Serialize>(value: &T, column: &'static str) -> StorageResult<String> {
    serde_json::to_string(value).map_err(|e| StorageError::QueryFailed(format!("encode {column}: {e}")))
}

fn decode_json<T: serde::de::DeserializeOwned>(raw: &str, column: &'static str) -> StorageResult<T> {
    serde_json::from_str(raw).map_err(|e| StorageError::QueryFailed(format!("decode {column}: {e}")))
}

fn column<'r, T>(row: &'r sqlx::sqlite::SqliteRow, name: &'static str) -> StorageResult<T>
where
    T: sqlx::Decode<'r, sqlx::Sqlite> + sqlx::Type<sqlx::Sqlite>,
{
    row.try_get(name)
        .map_err(|e| StorageError::QueryFailed(format!("{name} column: {e}")))
}

fn row_to_event(row: &sqlx::sqlite::SqliteRow) -> StorageResult<SensitiveDataEventRow> {
    let event_id: String = column(row, "event_id")?;
    let schema_version_major: u16 = narrow(column::<i64>(row, "schema_version_major")?, "schema_version_major")?;
    check_readable(&event_id, schema_version_major)?;

    let matched_rule_ids: String = column(row, "matched_rule_ids")?;
    let inspected_field_paths: String = column(row, "inspected_field_paths")?;
    let by_category: String = column(row, "finding_count_by_category")?;
    let reason_codes: String = column(row, "reason_codes")?;

    Ok(SensitiveDataEventRow {
        schema_version_major,
        schema_version_minor: narrow(column::<i64>(row, "schema_version_minor")?, "schema_version_minor")?,
        event_id,
        occurred_at_ns: narrow(column::<i64>(row, "occurred_at_ns")?, "occurred_at_ns")?,
        ingested_at_ns: narrow(column::<i64>(row, "ingested_at_ns")?, "ingested_at_ns")?,
        org_id: column(row, "org_id")?,
        tenant_id: column(row, "tenant_id")?,
        team_id: column(row, "team_id")?,
        acting_agent_id: column(row, "acting_agent_id")?,
        root_agent_id: column(row, "root_agent_id")?,
        parent_agent_id: column(row, "parent_agent_id")?,
        delegation_depth: narrow(column::<i64>(row, "delegation_depth")?, "delegation_depth")?,
        session_id: column(row, "session_id")?,
        trace_id: column(row, "trace_id")?,
        request_id: column(row, "request_id")?,
        correlation_id: column(row, "correlation_id")?,
        operation: column(row, "operation")?,
        destination_kind: column(row, "destination_kind")?,
        destination_id: column(row, "destination_id")?,
        trust_zone: column(row, "trust_zone")?,
        direction: column(row, "direction")?,
        policy_document_id: column(row, "policy_document_id")?,
        policy_version: column::<Option<i64>>(row, "policy_version")?
            .map(|v| narrow(v, "policy_version"))
            .transpose()?,
        matched_rule_ids: decode_json(&matched_rule_ids, "matched_rule_ids")?,
        inspected_field_paths: decode_json(&inspected_field_paths, "inspected_field_paths")?,
        verdict: column(row, "verdict")?,
        enforcement_point: column(row, "enforcement_point")?,
        transmission_evidence: column(row, "transmission_evidence")?,
        enforcement_mode: column(row, "enforcement_mode")?,
        inspection_failure_path: column(row, "inspection_failure_path")?,
        severity: column(row, "severity")?,
        confidence: column(row, "confidence")?,
        method: column(row, "method")?,
        status: column(row, "status")?,
        event_count: narrow(column::<i64>(row, "event_count")?, "event_count")?,
        blocked_event_count: narrow(column::<i64>(row, "blocked_event_count")?, "blocked_event_count")?,
        finding_count: narrow(column::<i64>(row, "finding_count")?, "finding_count")?,
        blocked_finding_count: narrow(column::<i64>(row, "blocked_finding_count")?, "blocked_finding_count")?,
        transformed_finding_count: narrow(
            column::<i64>(row, "transformed_finding_count")?,
            "transformed_finding_count",
        )?,
        finding_count_by_category: decode_json::<Vec<CategoryTally>>(&by_category, "finding_count_by_category")?,
        reason_codes: decode_json(&reason_codes, "reason_codes")?,
    })
}

fn row_to_finding(row: &sqlx::sqlite::SqliteRow) -> StorageResult<SensitiveDataFindingRow> {
    let event_id: String = column(row, "event_id")?;
    let schema_version_major: u16 = narrow(column::<i64>(row, "schema_version_major")?, "schema_version_major")?;
    check_readable(&event_id, schema_version_major)?;

    Ok(SensitiveDataFindingRow {
        schema_version_major,
        schema_version_minor: narrow(column::<i64>(row, "schema_version_minor")?, "schema_version_minor")?,
        event_id,
        finding_ordinal: narrow(column::<i64>(row, "finding_ordinal")?, "finding_ordinal")?,
        org_id: column(row, "org_id")?,
        tenant_id: column(row, "tenant_id")?,
        occurred_at_ns: narrow(column::<i64>(row, "occurred_at_ns")?, "occurred_at_ns")?,
        verdict: column(row, "verdict")?,
        category: column(row, "category")?,
        severity: column(row, "severity")?,
        confidence: column(row, "confidence")?,
        method: column(row, "method")?,
        status: column(row, "status")?,
        recognizer: column(row, "recognizer")?,
        recognizer_version: column(row, "recognizer_version")?,
        field_path: column(row, "field_path")?,
        redaction_label: column(row, "redaction_label")?,
        aggregate_key: column(row, "aggregate_key")?,
    })
}

/// Append the tenant predicate and the optional narrowings.
///
/// `org_id` and `tenant_id` are pushed unconditionally and first, so there is
/// no code path through this function that produces an unscoped `WHERE`.
fn push_scope<'a>(qb: &mut sqlx::QueryBuilder<'a, sqlx::Sqlite>, filter: &'a SensitiveDataEventFilter) {
    qb.push(" WHERE org_id = ").push_bind(filter.scope().org_id());
    qb.push(" AND tenant_id = ").push_bind(filter.scope().tenant_id());
    if let Some(from) = filter.from {
        qb.push(" AND occurred_at_ns >= ").push_bind(from.as_nanos() as i64);
    }
    if let Some(to) = filter.to {
        qb.push(" AND occurred_at_ns < ").push_bind(to.as_nanos() as i64);
    }
    // No `with_verdict` switch: both tables carry the column, so there is no
    // caller that can be handed a filter whose verdict is quietly dropped.
    if let Some(verdict) = filter.verdict.as_deref() {
        qb.push(" AND verdict = ").push_bind(verdict);
    }
}

#[async_trait]
impl SensitiveDataProjection for SqliteBackend {
    async fn migrate_sensitive_data_projection(&self) -> StorageResult<()> {
        apply_statements(self.pool(), PROJECTION_SCHEMA).await
    }

    async fn rollback_sensitive_data_projection(&self) -> StorageResult<()> {
        apply_statements(self.pool(), PROJECTION_ROLLBACK).await
    }

    async fn append_sensitive_data_decision(
        &self,
        event: &SensitiveDataEventRow,
        findings: &[SensitiveDataFindingRow],
    ) -> StorageResult<()> {
        let matched_rule_ids = encode_json(&event.matched_rule_ids, "matched_rule_ids")?;
        let inspected_field_paths = encode_json(&event.inspected_field_paths, "inspected_field_paths")?;
        let by_category = encode_json(&event.finding_count_by_category, "finding_count_by_category")?;
        let reason_codes = encode_json(&event.reason_codes, "reason_codes")?;

        let mut tx = self
            .pool()
            .begin()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("begin: {e}")))?;

        // `OR IGNORE` is the idempotency rule: a replayed event is a no-op, so
        // a retried publish cannot double-count. First write wins.
        let placeholders = vec!["?"; 41].join(", ");
        let inserted = sqlx::query(&format!(
            "INSERT OR IGNORE INTO sensitive_data_events ({EVENT_COLUMNS}) VALUES ({placeholders})"
        ))
        .bind(i64::from(event.schema_version_major))
        .bind(i64::from(event.schema_version_minor))
        .bind(&event.event_id)
        .bind(event.occurred_at_ns as i64)
        .bind(event.ingested_at_ns as i64)
        .bind(&event.org_id)
        .bind(&event.tenant_id)
        .bind(event.team_id.as_deref())
        .bind(&event.acting_agent_id)
        .bind(&event.root_agent_id)
        .bind(event.parent_agent_id.as_deref())
        .bind(i64::from(event.delegation_depth))
        .bind(event.session_id.as_deref())
        .bind(event.trace_id.as_deref())
        .bind(event.request_id.as_deref())
        .bind(event.correlation_id.as_deref())
        .bind(&event.operation)
        .bind(&event.destination_kind)
        .bind(&event.destination_id)
        .bind(&event.trust_zone)
        .bind(&event.direction)
        .bind(event.policy_document_id.as_deref())
        .bind(event.policy_version.map(|v| v as i64))
        .bind(&matched_rule_ids)
        .bind(&inspected_field_paths)
        .bind(&event.verdict)
        .bind(&event.enforcement_point)
        .bind(&event.transmission_evidence)
        .bind(&event.enforcement_mode)
        .bind(&event.inspection_failure_path)
        .bind(event.severity.as_deref())
        .bind(event.confidence.as_deref())
        .bind(event.method.as_deref())
        .bind(event.status.as_deref())
        .bind(i64::from(event.event_count))
        .bind(i64::from(event.blocked_event_count))
        .bind(i64::from(event.finding_count))
        .bind(i64::from(event.blocked_finding_count))
        .bind(i64::from(event.transformed_finding_count))
        .bind(&by_category)
        .bind(&reason_codes)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::QueryFailed(format!("insert event: {e}")))?;

        // First-write-wins has to cover the children, not just the parent.
        // `OR IGNORE` on the child rows alone is *additive*: a replay carrying
        // more findings than the stored event would insert the new ordinals
        // while the parent's `finding_count` stayed frozen, leaving the tally
        // disagreeing with the rows it describes — and the per-category
        // aggregate, which reads the child table, over-reporting against it.
        // A no-op parent insert therefore ends the transaction here.
        if inserted.rows_affected() == 0 {
            tracing::debug!(
                event_id = %event.event_id,
                "sensitive-data projection: event already stored, ignoring replay"
            );
            return tx
                .commit()
                .await
                .map_err(|e| StorageError::QueryFailed(format!("commit: {e}")));
        }

        let finding_placeholders = vec!["?"; 18].join(", ");
        for finding in findings {
            sqlx::query(&format!(
                "INSERT OR IGNORE INTO sensitive_data_findings ({FINDING_COLUMNS}) \
                 VALUES ({finding_placeholders})"
            ))
            .bind(i64::from(finding.schema_version_major))
            .bind(i64::from(finding.schema_version_minor))
            .bind(&finding.event_id)
            .bind(i64::from(finding.finding_ordinal))
            .bind(&finding.org_id)
            .bind(&finding.tenant_id)
            .bind(finding.occurred_at_ns as i64)
            .bind(&finding.verdict)
            .bind(&finding.category)
            .bind(&finding.severity)
            .bind(&finding.confidence)
            .bind(&finding.method)
            .bind(&finding.status)
            .bind(&finding.recognizer)
            .bind(&finding.recognizer_version)
            .bind(&finding.field_path)
            .bind(&finding.redaction_label)
            .bind(&finding.aggregate_key)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::QueryFailed(format!("insert finding: {e}")))?;
        }

        tx.commit()
            .await
            .map_err(|e| StorageError::QueryFailed(format!("commit: {e}")))
    }

    async fn query_sensitive_data_events(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataEventRow>> {
        let mut qb =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!("SELECT {EVENT_COLUMNS} FROM sensitive_data_events"));
        push_scope(&mut qb, filter);
        qb.push(" ORDER BY occurred_at_ns DESC, event_id ASC");
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
        }
        let rows = qb
            .build()
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        rows.iter().map(row_to_event).collect()
    }

    async fn query_sensitive_data_findings(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataFindingRow>> {
        let mut qb =
            sqlx::QueryBuilder::<sqlx::Sqlite>::new(format!("SELECT {FINDING_COLUMNS} FROM sensitive_data_findings"));
        push_scope(&mut qb, filter);
        qb.push(" ORDER BY occurred_at_ns DESC, event_id ASC, finding_ordinal ASC");
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
        }
        let rows = qb
            .build()
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        rows.iter().map(row_to_finding).collect()
    }

    async fn count_sensitive_data_events(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT COUNT(*) FROM sensitive_data_events");
        push_scope(&mut qb, filter);
        let count: i64 = qb
            .build_query_scalar()
            .fetch_one(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(count.max(0) as u64)
    }

    async fn count_sensitive_data_findings(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new("SELECT COUNT(*) FROM sensitive_data_findings");
        push_scope(&mut qb, filter);
        let count: i64 = qb
            .build_query_scalar()
            .fetch_one(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(count.max(0) as u64)
    }

    async fn sensitive_data_projection_columns(&self) -> StorageResult<Vec<(String, String)>> {
        let mut out = Vec::new();
        for table in ["sensitive_data_events", "sensitive_data_findings"] {
            // `PRAGMA table_info` reports what the file actually has, which is
            // the point — a test reading PROJECTION_SCHEMA back would only
            // prove the constant agrees with itself.
            let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
                .fetch_all(self.pool())
                .await
                .map_err(|e| StorageError::QueryFailed(format!("table_info {table}: {e}")))?;
            for row in &rows {
                out.push((table.to_string(), column::<String>(row, "name")?));
            }
        }
        Ok(out)
    }

    async fn aggregate_sensitive_data_by_category(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<CategoryFindingAggregate>> {
        // COUNT(*) counts findings; COUNT(DISTINCT event_id) counts events.
        // Both are selected because they are different measures — collapsing
        // them is ADR 0032 forbidden design #11.
        let mut qb = sqlx::QueryBuilder::<sqlx::Sqlite>::new(
            "SELECT category, COUNT(*) AS finding_count, COUNT(DISTINCT event_id) AS event_count \
             FROM sensitive_data_findings",
        );
        push_scope(&mut qb, filter);
        qb.push(" GROUP BY category ORDER BY category ASC");
        // The category vocabulary is not closed (see `CategoryFindingAggregate`),
        // so the row cap is also the group cap — the only bound available
        // against an attacker-influenced grouping value.
        if let Some(limit) = filter.limit {
            qb.push(" LIMIT ").push_bind(i64::from(limit));
        }
        let rows = qb
            .build()
            .fetch_all(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;

        rows.iter()
            .map(|row| {
                Ok(CategoryFindingAggregate {
                    category: column(row, "category")?,
                    finding_count: column::<i64>(row, "finding_count")?.max(0) as u64,
                    event_count: column::<i64>(row, "event_count")?.max(0) as u64,
                })
            })
            .collect()
    }
}

/// Apply a DDL set atomically.
///
/// In one transaction because both SQLite and PostgreSQL support transactional
/// DDL: a migration that fails on its fourth statement should leave no tables
/// at all, rather than a half-created schema that the next `IF NOT EXISTS` run
/// would silently accept as complete.
async fn apply_statements(pool: &SqlitePool, statements: &[&str]) -> StorageResult<()> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| StorageError::MigrationFailed(format!("begin: {e}")))?;
    for stmt in statements {
        sqlx::query(stmt)
            .execute(&mut *tx)
            .await
            .map_err(|e| StorageError::MigrationFailed(e.to_string()))?;
    }
    tx.commit()
        .await
        .map_err(|e| StorageError::MigrationFailed(format!("commit: {e}")))
}
