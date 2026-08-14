//! PostgreSQL implementation of the sensitive-data projection.
//!
//! Deliberately **not** added to `migrations/postgres/`. That directory is the
//! audit/registry schema's migrator, applied unconditionally by
//! [`StorageBackend::migrate`](crate::storage::StorageBackend::migrate); putting
//! the projection there would create its tables on every deployment including
//! the ones that leave the flag off, and would make "roll the projection back"
//! mean "roll a shared migration back". The projection owns its own up and down
//! statements instead, and both are executed in tests.
//!
//! No TimescaleDB hypertable and no compression policy: those belong with a
//! retention decision, and retention tiering is explicitly deferred (see the
//! module doc). Plain tables grow visibly; a half-configured tier drops rows.

use async_trait::async_trait;
use sqlx::{PgPool, Row};

use crate::storage::error::{StorageError, StorageResult};
use crate::storage::postgres::PostgresBackend;

use super::rows::{check_readable, narrow, CategoryTally, SensitiveDataEventRow, SensitiveDataFindingRow};
use super::store::{CategoryFindingAggregate, SensitiveDataEventFilter, SensitiveDataProjection};

/// The projection's DDL. Mirrors the SQLite shape column for column so a row
/// written by one backend means the same thing when read from the other.
///
/// That mirroring extends to the primary key and to every `ON CONFLICT` target:
/// see the SQLite module's schema documentation for why the key carries
/// `(org_id, tenant_id, event_id)` rather than `event_id` alone (AAASM-5447),
/// and for the migration position. The two backends must be changed together —
/// a key that matches on one and not the other reintroduces the defect on
/// whichever deployment uses the unfixed one.
const PROJECTION_SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS sensitive_data_events (
        schema_version_major      INTEGER     NOT NULL,
        schema_version_minor      INTEGER     NOT NULL,
        event_id                  TEXT        NOT NULL,
        occurred_at_ns            BIGINT      NOT NULL,
        ingested_at_ns            BIGINT      NOT NULL,
        org_id                    TEXT        NOT NULL,
        tenant_id                 TEXT        NOT NULL,
        team_id                   TEXT,
        acting_agent_id           TEXT        NOT NULL,
        root_agent_id             TEXT        NOT NULL,
        parent_agent_id           TEXT,
        delegation_depth          INTEGER     NOT NULL,
        session_id                TEXT,
        trace_id                  TEXT,
        request_id                TEXT,
        correlation_id            TEXT,
        operation                 TEXT        NOT NULL,
        destination_kind          TEXT        NOT NULL,
        destination_id            TEXT        NOT NULL,
        trust_zone                TEXT        NOT NULL,
        direction                 TEXT        NOT NULL,
        policy_document_id        TEXT,
        policy_version            BIGINT,
        matched_rule_ids          TEXT        NOT NULL,
        inspected_field_paths     TEXT        NOT NULL,
        verdict                   TEXT        NOT NULL,
        enforcement_point         TEXT        NOT NULL,
        transmission_evidence     TEXT        NOT NULL,
        enforcement_mode          TEXT        NOT NULL,
        inspection_failure_path   TEXT        NOT NULL,
        severity                  TEXT,
        confidence                TEXT,
        method                    TEXT,
        status                    TEXT,
        event_count               INTEGER     NOT NULL,
        blocked_event_count       INTEGER     NOT NULL,
        finding_count             INTEGER     NOT NULL,
        blocked_finding_count     INTEGER     NOT NULL,
        transformed_finding_count INTEGER     NOT NULL,
        finding_count_by_category TEXT        NOT NULL,
        reason_codes              TEXT        NOT NULL,
        PRIMARY KEY (org_id, tenant_id, event_id)
    )",
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
        occurred_at_ns       BIGINT  NOT NULL,
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
        PRIMARY KEY (org_id, tenant_id, event_id, finding_ordinal)
    )",
    "CREATE INDEX IF NOT EXISTS idx_sd_findings_scope_category
        ON sensitive_data_findings(org_id, tenant_id, verdict, category)",
    "CREATE INDEX IF NOT EXISTS idx_sd_findings_scope_ts
        ON sensitive_data_findings(org_id, tenant_id, occurred_at_ns)",
];

/// The inverse of [`PROJECTION_SCHEMA`].
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

fn encode_json<T: serde::Serialize>(value: &T, column: &'static str) -> StorageResult<String> {
    serde_json::to_string(value).map_err(|e| StorageError::QueryFailed(format!("encode {column}: {e}")))
}

fn decode_json<T: serde::de::DeserializeOwned>(raw: &str, column: &'static str) -> StorageResult<T> {
    serde_json::from_str(raw).map_err(|e| StorageError::QueryFailed(format!("decode {column}: {e}")))
}

fn column<'r, T>(row: &'r sqlx::postgres::PgRow, name: &'static str) -> StorageResult<T>
where
    T: sqlx::Decode<'r, sqlx::Postgres> + sqlx::Type<sqlx::Postgres>,
{
    row.try_get(name)
        .map_err(|e| StorageError::QueryFailed(format!("{name} column: {e}")))
}

fn row_to_event(row: &sqlx::postgres::PgRow) -> StorageResult<SensitiveDataEventRow> {
    let event_id: String = column(row, "event_id")?;
    let schema_version_major: u16 = narrow(
        i64::from(column::<i32>(row, "schema_version_major")?),
        "schema_version_major",
    )?;
    check_readable(&event_id, schema_version_major)?;

    let matched_rule_ids: String = column(row, "matched_rule_ids")?;
    let inspected_field_paths: String = column(row, "inspected_field_paths")?;
    let by_category: String = column(row, "finding_count_by_category")?;
    let reason_codes: String = column(row, "reason_codes")?;

    Ok(SensitiveDataEventRow {
        schema_version_major,
        schema_version_minor: narrow(
            i64::from(column::<i32>(row, "schema_version_minor")?),
            "schema_version_minor",
        )?,
        event_id,
        occurred_at_ns: narrow(column::<i64>(row, "occurred_at_ns")?, "occurred_at_ns")?,
        ingested_at_ns: narrow(column::<i64>(row, "ingested_at_ns")?, "ingested_at_ns")?,
        org_id: column(row, "org_id")?,
        tenant_id: column(row, "tenant_id")?,
        team_id: column(row, "team_id")?,
        acting_agent_id: column(row, "acting_agent_id")?,
        root_agent_id: column(row, "root_agent_id")?,
        parent_agent_id: column(row, "parent_agent_id")?,
        delegation_depth: narrow(i64::from(column::<i32>(row, "delegation_depth")?), "delegation_depth")?,
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
        event_count: narrow(i64::from(column::<i32>(row, "event_count")?), "event_count")?,
        blocked_event_count: narrow(
            i64::from(column::<i32>(row, "blocked_event_count")?),
            "blocked_event_count",
        )?,
        finding_count: narrow(i64::from(column::<i32>(row, "finding_count")?), "finding_count")?,
        blocked_finding_count: narrow(
            i64::from(column::<i32>(row, "blocked_finding_count")?),
            "blocked_finding_count",
        )?,
        transformed_finding_count: narrow(
            i64::from(column::<i32>(row, "transformed_finding_count")?),
            "transformed_finding_count",
        )?,
        finding_count_by_category: decode_json::<Vec<CategoryTally>>(&by_category, "finding_count_by_category")?,
        reason_codes: decode_json(&reason_codes, "reason_codes")?,
    })
}

fn row_to_finding(row: &sqlx::postgres::PgRow) -> StorageResult<SensitiveDataFindingRow> {
    let event_id: String = column(row, "event_id")?;
    let schema_version_major: u16 = narrow(
        i64::from(column::<i32>(row, "schema_version_major")?),
        "schema_version_major",
    )?;
    check_readable(&event_id, schema_version_major)?;

    Ok(SensitiveDataFindingRow {
        schema_version_major,
        schema_version_minor: narrow(
            i64::from(column::<i32>(row, "schema_version_minor")?),
            "schema_version_minor",
        )?,
        event_id,
        finding_ordinal: narrow(i64::from(column::<i32>(row, "finding_ordinal")?), "finding_ordinal")?,
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
/// As on SQLite: the tenant keys are pushed unconditionally and first, so no
/// path through this function yields an unscoped `WHERE`.
fn push_scope<'a>(qb: &mut sqlx::QueryBuilder<'a, sqlx::Postgres>, filter: &'a SensitiveDataEventFilter) {
    qb.push(" WHERE org_id = ").push_bind(filter.scope().org_id());
    qb.push(" AND tenant_id = ").push_bind(filter.scope().tenant_id());
    if let Some(from) = filter.from {
        qb.push(" AND occurred_at_ns >= ").push_bind(from.as_nanos() as i64);
    }
    if let Some(to) = filter.to {
        qb.push(" AND occurred_at_ns < ").push_bind(to.as_nanos() as i64);
    }
    // As on SQLite: no switch, because both tables carry the column.
    if let Some(verdict) = filter.verdict.as_deref() {
        qb.push(" AND verdict = ").push_bind(verdict);
    }
}

/// `$1, $2, … $n`.
fn placeholders(count: usize) -> String {
    (1..=count).map(|n| format!("${n}")).collect::<Vec<_>>().join(", ")
}

#[async_trait]
impl SensitiveDataProjection for PostgresBackend {
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

        // `ON CONFLICT DO NOTHING` is the idempotency rule: first write wins,
        // so a replayed event cannot double-count and a late duplicate cannot
        // rewrite tallies a reader may already have seen.
        let event_placeholders = placeholders(41);
        let inserted = sqlx::query(&format!(
            "INSERT INTO sensitive_data_events ({EVENT_COLUMNS}) VALUES ({event_placeholders}) \
             ON CONFLICT (org_id, tenant_id, event_id) DO NOTHING"
        ))
        .bind(i32::from(event.schema_version_major))
        .bind(i32::from(event.schema_version_minor))
        .bind(&event.event_id)
        .bind(event.occurred_at_ns as i64)
        .bind(event.ingested_at_ns as i64)
        .bind(&event.org_id)
        .bind(&event.tenant_id)
        .bind(event.team_id.as_deref())
        .bind(&event.acting_agent_id)
        .bind(&event.root_agent_id)
        .bind(event.parent_agent_id.as_deref())
        .bind(event.delegation_depth as i32)
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
        .bind(event.event_count as i32)
        .bind(event.blocked_event_count as i32)
        .bind(event.finding_count as i32)
        .bind(event.blocked_finding_count as i32)
        .bind(event.transformed_finding_count as i32)
        .bind(&by_category)
        .bind(&reason_codes)
        .execute(&mut *tx)
        .await
        .map_err(|e| StorageError::QueryFailed(format!("insert event: {e}")))?;

        // See the SQLite backend: `DO NOTHING` on the children alone is
        // additive, so a replay carrying more findings would desynchronise the
        // parent's `finding_count` from the rows beneath it.
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

        let finding_placeholders = placeholders(18);
        for finding in findings {
            sqlx::query(&format!(
                "INSERT INTO sensitive_data_findings ({FINDING_COLUMNS}) VALUES ({finding_placeholders}) \
                 ON CONFLICT (org_id, tenant_id, event_id, finding_ordinal) DO NOTHING"
            ))
            .bind(i32::from(finding.schema_version_major))
            .bind(i32::from(finding.schema_version_minor))
            .bind(&finding.event_id)
            .bind(finding.finding_ordinal as i32)
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
            sqlx::QueryBuilder::<sqlx::Postgres>::new(format!("SELECT {EVENT_COLUMNS} FROM sensitive_data_events"));
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
            sqlx::QueryBuilder::<sqlx::Postgres>::new(format!("SELECT {FINDING_COLUMNS} FROM sensitive_data_findings"));
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
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT COUNT(*) FROM sensitive_data_events");
        push_scope(&mut qb, filter);
        let count: i64 = qb
            .build_query_scalar()
            .fetch_one(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(count.max(0) as u64)
    }

    async fn count_sensitive_data_findings(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new("SELECT COUNT(*) FROM sensitive_data_findings");
        push_scope(&mut qb, filter);
        let count: i64 = qb
            .build_query_scalar()
            .fetch_one(self.pool())
            .await
            .map_err(|e| StorageError::QueryFailed(e.to_string()))?;
        Ok(count.max(0) as u64)
    }

    async fn sensitive_data_projection_columns(&self) -> StorageResult<Vec<(String, String)>> {
        // `information_schema` reports what the cluster actually has, for the
        // same reason SQLite's impl reads `PRAGMA table_info`.
        // `table_schema = current_schema()` closes the **over**-reporting half:
        // without it, a same-named table in any other schema on the search path
        // is reported as if it were ours, and the contract test's exact-set
        // assertion would fail — or, worse, pass while describing the wrong
        // table. `the_projection_contract_holds_on_postgres` plants a decoy
        // schema carrying a `span_start` column to prove that filter is load-
        // bearing.
        //
        // The **under**-reporting half stays open and is worth naming, because
        // this query is the mechanism the whole "no offset column" claim rests
        // on: `information_schema.columns` is a privilege-filtered view, so a
        // role without privilege on a column simply does not see it. A caller
        // reading this catalogue with a restricted role would be told a column
        // does not exist when it does. The claim is therefore "no offset column
        // is visible to the role that created these tables" — which is the role
        // the migration runs as, and the one the tests use. A stronger
        // guarantee needs `pg_catalog.pg_attribute`, which is not
        // privilege-filtered.
        let rows = sqlx::query(
            "SELECT table_name, column_name FROM information_schema.columns \
             WHERE table_schema = current_schema() \
               AND table_name IN ('sensitive_data_events', 'sensitive_data_findings') \
             ORDER BY table_name, ordinal_position",
        )
        .fetch_all(self.pool())
        .await
        .map_err(|e| StorageError::QueryFailed(format!("information_schema: {e}")))?;

        rows.iter()
            .map(|row| {
                Ok((
                    column::<String>(row, "table_name")?,
                    column::<String>(row, "column_name")?,
                ))
            })
            .collect()
    }

    async fn aggregate_sensitive_data_by_category(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<CategoryFindingAggregate>> {
        let mut qb = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "SELECT category, COUNT(*) AS finding_count, COUNT(DISTINCT event_id) AS event_count \
             FROM sensitive_data_findings",
        );
        push_scope(&mut qb, filter);
        qb.push(" GROUP BY category ORDER BY category ASC");
        // As on SQLite: the row cap is also the group cap.
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

/// Apply a DDL set atomically — PostgreSQL has transactional DDL, so a
/// migration that fails partway leaves no tables rather than a half-created
/// schema the next `IF NOT EXISTS` run would accept as complete.
async fn apply_statements(pool: &PgPool, statements: &[&str]) -> StorageResult<()> {
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
