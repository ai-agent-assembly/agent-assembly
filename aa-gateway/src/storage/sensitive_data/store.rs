//! The projection's persistence contract, its query scope, and the flag that
//! gates writing it at all.

use async_trait::async_trait;

use aa_core::time::Timestamp;
use aa_core::types::sensitive_data::{SensitiveDataDecisionEvent, SensitiveDataFindingRecord};

use crate::storage::error::StorageResult;

use super::rows::{ProjectionError, SensitiveDataEventRow, SensitiveDataFindingRow, TenantScope};

/// Everything a projection read may be narrowed by.
///
/// The scope is a constructor argument rather than an `Option` field: there is
/// no way to build a filter that reads across tenants, so tenant isolation
/// survives a caller who forgets, which is the failure mode "scope it by
/// convention" has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SensitiveDataEventFilter {
    scope: TenantScope,
    /// Inclusive lower bound on `occurred_at`.
    pub from: Option<Timestamp>,
    /// Exclusive upper bound on `occurred_at`.
    pub to: Option<Timestamp>,
    /// Restrict to one enforcement outcome.
    ///
    /// Honoured on **every** read, findings included — `sensitive_data_findings`
    /// replicates the parent's verdict for exactly this. It previously applied
    /// only to the events table and was silently dropped elsewhere, so a
    /// "blocked findings by category" read returned every finding under a
    /// "denied" label.
    pub verdict: Option<String>,
    /// Maximum rows to return — groups, for
    /// [`aggregate_sensitive_data_by_category`](SensitiveDataProjection::aggregate_sensitive_data_by_category).
    ///
    /// Applies to every read. On the aggregate it is the cap on how many
    /// distinct categories a caller can be handed, which is the one bound
    /// available against a category vocabulary that is not closed.
    pub limit: Option<u32>,
}

impl SensitiveDataEventFilter {
    /// Read everything within one tenant.
    pub fn new(scope: TenantScope) -> Self {
        Self {
            scope,
            from: None,
            to: None,
            verdict: None,
            limit: None,
        }
    }

    /// The tenant this filter is pinned to.
    pub fn scope(&self) -> &TenantScope {
        &self.scope
    }

    /// Narrow to a half-open `occurred_at` window.
    #[must_use]
    pub fn between(mut self, from: Timestamp, to: Timestamp) -> Self {
        self.from = Some(from);
        self.to = Some(to);
        self
    }

    /// Narrow to one enforcement outcome.
    #[must_use]
    pub fn with_verdict(mut self, verdict: impl Into<String>) -> Self {
        self.verdict = Some(verdict.into());
        self
    }

    /// Cap the number of rows returned.
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }
}

/// Findings of one category within a tenant and window, counted two ways.
///
/// Both counts are reported because they answer different questions — "how much
/// sensitive data of this class did we see?" and "how many actions carried
/// any?" — and ADR 0032 forbidden design #11 is precisely about a dashboard
/// that picks one and labels it the other. A consumer wanting only one still
/// has to name which.
///
/// `category` is the only grouping dimension this aggregate offers. That is
/// deliberate but it is **not** a bounded-cardinality guarantee, and an earlier
/// draft of this doc claimed it was: `CategoryLabel::new` is a shape check, so a
/// stored category is whatever the writing build put there — the projection's
/// own tests persist `acme_internal_customer_ssn_v3_9f2c1b` on purpose. Three
/// unknown categories are three groups.
///
/// What the single dimension does buy is that the *other* dimensions — the
/// destination, the agent id, the tenant id — cannot be grouped by at all, and
/// those are unbounded by nature rather than by accident. The remaining risk is
/// bounded two ways: [`SensitiveDataEventFilter::limit`] caps the number of
/// groups returned, and a caller minting a metric series from a group must
/// resolve the category through
/// [`SensitiveDataMetricLabels`](aa_core::types::sensitive_data::SensitiveDataMetricLabels),
/// which returns `None` for anything this build cannot name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryFindingAggregate {
    /// The category, as the writing build spelled it. Not guaranteed to
    /// resolve against *this* build's catalogue — a consumer minting a metric
    /// label must resolve it through
    /// [`SensitiveDataMetricLabels`](aa_core::types::sensitive_data::SensitiveDataMetricLabels)
    /// rather than trusting the string.
    pub category: String,
    /// How many **findings** of this category the window contains.
    pub finding_count: u64,
    /// How many distinct **events** carried at least one. Never the same
    /// measure as `finding_count`, and frequently a smaller number.
    pub event_count: u64,
}

/// Durable persistence for the sensitive-data projection.
///
/// Deliberately **not** part of [`StorageBackend`](crate::storage::StorageBackend):
/// the projection is additive and optional, and folding it into the backend
/// trait would force every existing implementor and test double to grow methods
/// it will never call. Backends opt in by implementing this alongside.
#[async_trait]
pub trait SensitiveDataProjection: Send + Sync + 'static {
    /// Create the projection's tables and indexes.
    ///
    /// Idempotent — safe on an already-migrated database. Separate from
    /// [`StorageBackend::migrate`](crate::storage::StorageBackend::migrate) so
    /// that a deployment which never enables the projection never grows its
    /// tables, and so that the rollback below is a real inverse rather than a
    /// partial undo of a shared migration.
    ///
    /// # Errors
    ///
    /// `StorageError::MigrationFailed` when any statement is rejected.
    async fn migrate_sensitive_data_projection(&self) -> StorageResult<()>;

    /// Drop the projection's tables and indexes — the documented rollback.
    ///
    /// The whole rollback story for this feature: turn the flag off, drop the
    /// tables. Nothing else in the schema references them, and the audit path
    /// never wrote to them, so no other data can be lost by running this.
    ///
    /// # Errors
    ///
    /// `StorageError::MigrationFailed` when a drop is rejected.
    async fn rollback_sensitive_data_projection(&self) -> StorageResult<()>;

    /// Persist one event and its normalized finding rows atomically.
    ///
    /// **Idempotency and the late-arrival rule.** The write is keyed on
    /// `event_id` (and `(event_id, finding_ordinal)` for the children) and
    /// ignores a conflict, so replaying an event — a retried publish, a
    /// restarted consumer, a duplicate delivery — does not double-count. The
    /// consequence is that **first write wins**: an event that arrives late,
    /// after a row with the same id is already durable, is discarded rather
    /// than allowed to rewrite the tallies a reader may already have seen.
    /// First-write-wins covers the children too — an implementation must not
    /// insert child rows when the parent insert was a no-op, or a replay
    /// carrying *more* findings would add ordinals beneath a frozen
    /// `finding_count` and desynchronise the parent from its own rows. An
    /// event arriving late but *for the first time* is stored normally and
    /// lands in its own `occurred_at` bucket, with `ingested_at` recording that
    /// it was late; a window already reported on can therefore gain rows, which
    /// is why `ingested_at` is stored rather than inferred.
    ///
    /// # Errors
    ///
    /// `StorageError::QueryFailed` when the transaction cannot be committed.
    async fn append_sensitive_data_decision(
        &self,
        event: &SensitiveDataEventRow,
        findings: &[SensitiveDataFindingRow],
    ) -> StorageResult<()>;

    /// Events within the filter's tenant, newest first.
    ///
    /// # Errors
    ///
    /// `StorageError::QueryFailed` on driver failure or an undecodable column.
    async fn query_sensitive_data_events(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataEventRow>>;

    /// Finding rows within the filter's tenant, newest event first.
    ///
    /// Scoped by the findings table's own `org_id`/`tenant_id` columns, not by
    /// a join onto the events table — a join is a place isolation can be
    /// dropped by a later query rewrite.
    ///
    /// # Errors
    ///
    /// As [`query_sensitive_data_events`](Self::query_sensitive_data_events).
    async fn query_sensitive_data_findings(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataFindingRow>>;

    /// How many **events** match. Not the finding count.
    ///
    /// # Errors
    ///
    /// As [`query_sensitive_data_events`](Self::query_sensitive_data_events).
    async fn count_sensitive_data_events(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64>;

    /// How many **findings** match. Not the event count.
    ///
    /// # Errors
    ///
    /// As [`query_sensitive_data_events`](Self::query_sensitive_data_events).
    async fn count_sensitive_data_findings(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64>;

    /// Findings grouped by category, with both counts.
    ///
    /// # Errors
    ///
    /// As [`query_sensitive_data_events`](Self::query_sensitive_data_events).
    async fn aggregate_sensitive_data_by_category(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<CategoryFindingAggregate>>;

    /// `(table, column)` pairs for the projection's tables, read from the live
    /// database catalogue.
    ///
    /// Exists so the tiering obligation can be *checked* rather than asserted:
    /// ADR 0032 §9's ban on offsets and lengths is a property of what is
    /// durably stored, and reading the DDL constant back would only prove the
    /// test and the constant agree. `tests/sensitive_data_projection_test.rs`
    /// pins the exact set from outside this module, which is the only vantage
    /// point from which "there is no offset column" is a real claim.
    ///
    /// # Errors
    ///
    /// `StorageError::QueryFailed` when the catalogue cannot be read.
    async fn sensitive_data_projection_columns(&self) -> StorageResult<Vec<(String, String)>>;
}

/// Delegates to the wrapped store.
///
/// Exists so a single store can back several
/// [`SensitiveDataProjectionWriter`]s — which the writer's by-value `store`
/// otherwise prevents — and so the shared cross-backend contract test can hand
/// the same handle to a writer and to a direct reader.
#[async_trait]
impl<T: SensitiveDataProjection> SensitiveDataProjection for std::sync::Arc<T> {
    async fn migrate_sensitive_data_projection(&self) -> StorageResult<()> {
        (**self).migrate_sensitive_data_projection().await
    }

    async fn rollback_sensitive_data_projection(&self) -> StorageResult<()> {
        (**self).rollback_sensitive_data_projection().await
    }

    async fn append_sensitive_data_decision(
        &self,
        event: &SensitiveDataEventRow,
        findings: &[SensitiveDataFindingRow],
    ) -> StorageResult<()> {
        (**self).append_sensitive_data_decision(event, findings).await
    }

    async fn query_sensitive_data_events(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataEventRow>> {
        (**self).query_sensitive_data_events(filter).await
    }

    async fn query_sensitive_data_findings(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<SensitiveDataFindingRow>> {
        (**self).query_sensitive_data_findings(filter).await
    }

    async fn count_sensitive_data_events(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        (**self).count_sensitive_data_events(filter).await
    }

    async fn count_sensitive_data_findings(&self, filter: &SensitiveDataEventFilter) -> StorageResult<u64> {
        (**self).count_sensitive_data_findings(filter).await
    }

    async fn aggregate_sensitive_data_by_category(
        &self,
        filter: &SensitiveDataEventFilter,
    ) -> StorageResult<Vec<CategoryFindingAggregate>> {
        (**self).aggregate_sensitive_data_by_category(filter).await
    }

    async fn sensitive_data_projection_columns(&self) -> StorageResult<Vec<(String, String)>> {
        (**self).sensitive_data_projection_columns().await
    }
}

/// Whether the projection is written at all.
///
/// Off by default. ADR 0032 §8 requires the new projection to be switchable
/// without touching existing audit behaviour, and defaulting it on would make
/// the safe state the one an operator has to opt into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SensitiveDataProjectionConfig {
    /// `true` to persist decision events and their findings.
    pub enabled: bool,
}

impl SensitiveDataProjectionConfig {
    /// A configuration that writes the projection.
    pub const fn enabled() -> Self {
        Self { enabled: true }
    }

    /// A configuration that writes nothing.
    pub const fn disabled() -> Self {
        Self { enabled: false }
    }
}

/// What a [`SensitiveDataProjectionWriter::write`] call did.
///
/// A distinct type rather than `()` so a caller can tell "the flag is off" from
/// "the rows are durable" — otherwise a disabled projection is indistinguishable
/// from a working one at the call site, and the first sign of a
/// misconfiguration is an empty dashboard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteOutcome {
    /// Rows were persisted (or were already present — see the idempotency rule).
    Written,
    /// The flag is off; nothing was written and nothing was validated.
    Disabled,
}

/// Projects decision events into rows and writes them, subject to the flag.
///
/// The flag lives here rather than in the store so that the persistence
/// contract stays purely about persistence, and so the gate is exercised by a
/// test that needs no database at all.
#[derive(Debug, Clone)]
pub struct SensitiveDataProjectionWriter<S> {
    store: S,
    config: SensitiveDataProjectionConfig,
}

impl<S: SensitiveDataProjection> SensitiveDataProjectionWriter<S> {
    /// Wrap a store with a configuration.
    pub fn new(store: S, config: SensitiveDataProjectionConfig) -> Self {
        Self { store, config }
    }

    /// Whether writes are enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// The underlying store, for reads — which the flag does not gate.
    ///
    /// Turning the projection off stops new rows being written; it does not
    /// make the rows already written unreadable.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Ensure the projection's schema exists, if writing is enabled.
    ///
    /// A disabled projection creates no tables — the flag is the whole
    /// deployment decision, not just a write switch.
    ///
    /// # Errors
    ///
    /// As [`SensitiveDataProjection::migrate_sensitive_data_projection`].
    pub async fn migrate(&self) -> StorageResult<WriteOutcome> {
        if !self.config.enabled {
            return Ok(WriteOutcome::Disabled);
        }
        self.store.migrate_sensitive_data_projection().await?;
        Ok(WriteOutcome::Written)
    }

    /// Project and persist one decision and its findings.
    ///
    /// `findings` must be the same set the event's tallies were computed from;
    /// a mismatch is
    /// [`ProjectionError::FindingCountMismatch`](super::ProjectionError::FindingCountMismatch)
    /// rather than a silently wrong row.
    ///
    /// # Errors
    ///
    /// [`ProjectionError`](super::ProjectionError) for an event that cannot be
    /// projected, and whatever the store returns for a write failure.
    pub async fn write(
        &self,
        event: &SensitiveDataDecisionEvent,
        findings: &[SensitiveDataFindingRecord],
        ingested_at: Timestamp,
    ) -> Result<WriteOutcome, ProjectionError> {
        if !self.config.enabled {
            return Ok(WriteOutcome::Disabled);
        }

        let event_row = SensitiveDataEventRow::project(event, findings, ingested_at)?;
        // Children are projected from the parent *row*, not from the event and a
        // separately-derived scope: it is the only way a child cannot disagree
        // with its parent about tenant, timestamp or verdict.
        let finding_rows = findings
            .iter()
            .enumerate()
            .map(|(ordinal, record)| {
                SensitiveDataFindingRow::project(record, &event_row, u32::try_from(ordinal).unwrap_or(u32::MAX))
            })
            .collect::<Result<Vec<_>, _>>()?;

        self.store
            .append_sensitive_data_decision(&event_row, &finding_rows)
            .await
            .map_err(|e| ProjectionError::Storage(e.to_string()))?;
        Ok(WriteOutcome::Written)
    }
}
