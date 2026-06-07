# AAASM-1585 — E18 S-C PostgreSQL StorageBackend acceptance verification

| Field | Value |
|---|---|
| Story | [AAASM-1585](https://lightning-dust-mite.atlassian.net/browse/AAASM-1585) — E18 S-C: PostgreSQL StorageBackend implementation for production deployment |
| Epic | [AAASM-1569](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569) — Epic 18: Durable Persistence Layer |
| Verifier | Bryant Liu |
| Verification date | 2026-05-23 |
| Master commit verified | `413fe0fe` (post-AAASM-1741 merge) |
| PostgreSQL version | 18.4 (Alpine, aarch64-unknown-linux-musl) |

## Sub-task ledger

All 8 implementation sub-tasks merged on `master` before this verification:

| # | Sub-task | PR | Merge commit |
|---|---|---|---|
| 1 | AAASM-1719 — Scaffold PostgresBackend skeleton + PostgresConfig | [#658](https://github.com/ai-agent-assembly/agent-assembly/pull/658) | `c61a46ce` |
| 2 | AAASM-1724 — Initial schema migration + `migrate()` | [#688](https://github.com/ai-agent-assembly/agent-assembly/pull/688) | `0fda1064` |
| 3 | AAASM-1727 — Audit-event ops (`append`/`query`/`count`) | [#695](https://github.com/ai-agent-assembly/agent-assembly/pull/695) | `6d4c48f5` |
| 4 | AAASM-1729 — Agent-registry ops (`upsert`/`get`/`list`/`delete`) | [#700](https://github.com/ai-agent-assembly/agent-assembly/pull/700) | `49b67201` |
| 5 | AAASM-1730 — Policy-store ops (`save`/`get_active`/`list`/`rollback`) | [#702](https://github.com/ai-agent-assembly/agent-assembly/pull/702) | `a8329aa2` |
| 6 | AAASM-1734 — Metrics ops (`record_metric`/`query_metrics` w/ bucket) | [#704](https://github.com/ai-agent-assembly/agent-assembly/pull/704) | `5ab1f9f0` |
| 7 | AAASM-1738 — `apply_retention` + `healthcheck` | [#706](https://github.com/ai-agent-assembly/agent-assembly/pull/706) | `e24b8463` |
| 8 | AAASM-1741 — CI `postgres:18-alpine` service for Test + Coverage | [#707](https://github.com/ai-agent-assembly/agent-assembly/pull/707) | `413fe0fe` |

## Story acceptance criteria

Each AC is verified below against the merged master at `413fe0fe`, running
against an ephemeral `postgres:18-alpine` instance (`docker run … postgres:18-alpine`).

### AC-1 — All `StorageBackend` trait methods compile and pass against PostgreSQL 15+

**Status:** ✅ PASS

`PostgresBackend` now exposes every trait method as an inherent method:
`connect`, `migrate`, `append_audit_event`, `query_audit_events`,
`count_audit_events`, `upsert_agent`, `get_agent`, `list_agents`,
`delete_agent`, `save_policy`, `get_active_policy`,
`list_policy_versions`, `rollback_policy`, `record_metric`,
`query_metrics`, `apply_retention`, `healthcheck` (17 methods, 1:1 with
the trait surface from AAASM-1583).

Compilation:

```
$ cargo clippy -p aa-gateway --all-targets --all-features -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 24.42s
```

Test suite (22/22 against live PG 18, total runtime 229 ms):

```
$ AAASM_DATABASE_URL='postgres://aasm:aasm@localhost:54329/aasm_test' \
    cargo nextest run -p aa-gateway storage::postgres::tests
    Starting 22 tests across 41 binaries (918 tests skipped)
        PASS connect_rejects_missing_database_url
        PASS query_metrics_unsupported_bucket_unit_returns_query_failed
        PASS apply_retention_dry_run_does_not_delete
        PASS query_metrics_with_bucket_aggregates
        PASS record_metric_then_query_round_trip
        PASS count_matches_query_length
        PASS append_then_query_round_trip
        PASS delete_unknown_returns_not_found
        PASS apply_retention_drop_removes_old_rows
        PASS healthcheck_returns_ok_with_row_counts
        PASS list_filters_by_team
        PASS dry_run_only_filter_excludes_non_dry_events
        PASS apply_retention_archive_returns_error_until_s_d
        PASS migrate_creates_expected_tables
        PASS migrate_is_idempotent
        PASS rollback_then_get_active_returns_chosen_version
        PASS query_filters_by_time_range
        PASS rollback_unknown_version_returns_not_found
        PASS save_policy_does_not_activate_by_default
        PASS save_policy_assigns_monotonic_versions
        PASS upsert_then_get_round_trip
        PASS upsert_updates_last_seen_at
     Summary [   0.229s] 22 tests run: 22 passed, 918 skipped
```

The ticket specified "PostgreSQL 15+"; verification used PG 18.4, the
current GA major. Schema (TIMESTAMPTZ, UUID, JSONB, BIGSERIAL, `ON
CONFLICT`, `date_trunc`) is forward-compatible from PG 12 onward, so
the suite would also pass on PG 15/16/17 — only the latest GA was
exercised here.

### AC-2 — Connection pool respects `max_connections` and `min_connections` from config

**Status:** ✅ PASS — by construction

`PostgresBackend::connect` (`aa-gateway/src/storage/postgres.rs`) passes
both fields straight through to `sqlx::postgres::PgPoolOptions`:

```rust
let pool = PgPoolOptions::new()
    .max_connections(config.max_connections)
    .min_connections(config.min_connections)
    .acquire_timeout(Duration::from_secs(config.connect_timeout_secs))
    .connect(database_url)
    .await
    .map_err(|e| StorageError::ConnectionFailed(e.to_string()))?;
```

`PostgresConfig::default()` documents the defaults `max=20`, `min=2`,
`timeout=10s` — locked down by
`storage::postgres_config::tests::defaults_match_spec`.

### AC-3 — Missing `database_url` → clear startup error mentioning `AAASM_DATABASE_URL`

**Status:** ✅ PASS

```rust
let database_url = config.database_url.as_deref().ok_or_else(|| {
    StorageError::ConnectionFailed(
        "AAASM_DATABASE_URL is not set and storage.postgres.database_url is not configured"
            .into(),
    )
})?;
```

Asserted by
`storage::postgres::tests::connect_rejects_missing_database_url` —
pattern-matches `Err(StorageError::ConnectionFailed(msg))` and asserts
`msg.contains("AAASM_DATABASE_URL")`. Test passes both with and without
a live database (no DB required).

### AC-4 — `AuditFilter` with time range works correctly with `TIMESTAMPTZ`

**Status:** ✅ PASS

`push_audit_where` binds `from` / `to` directly as `DateTime<Utc>` —
sqlx encodes these as native `TIMESTAMPTZ`, never as string:

```rust
if let Some(from) = filter.from {
    qb.push("ts >= ").push_bind(from);
}
if let Some(to) = filter.to {
    qb.push("ts < ").push_bind(to);
}
```

End-to-end exercised by
`storage::postgres::tests::query_filters_by_time_range`: inserts three
events at `base / base − 10 min / base − 20 min`, filters with
`from = base − 15 min`, asserts exactly two rows return in `ts DESC`
order. Live run: PASS in 172 ms.

### AC-5 — `upsert_agent` updates `last_seen_at` on second call for same `agent_id`

**Status:** ✅ PASS

```sql
INSERT INTO agent_registry (…)
VALUES ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (agent_id) DO UPDATE SET
    team_id          = EXCLUDED.team_id,
    org_id           = EXCLUDED.org_id,
    metadata         = EXCLUDED.metadata,
    last_seen_at     = EXCLUDED.last_seen_at,
    enforcement_mode = EXCLUDED.enforcement_mode;
```

`registered_at` is deliberately excluded from the SET clause so
re-registration preserves the original registration time.

End-to-end asserted by
`storage::postgres::tests::upsert_updates_last_seen_at`: two upserts at
`(t1, t1)` and `(t1, t2 = t1 + 60 s)` for the same `agent_id`, then
`get_agent` confirms `last_seen_at == t2` AND `registered_at == t1`.
Live run: PASS in 81 ms.

### AC-6 — `cargo nextest run -p aa-gateway storage::postgres::tests` green when `AAASM_DATABASE_URL` is set

**Status:** ✅ PASS

Local run (above): 22/22 PASS against `postgres:18-alpine` in 229 ms.

CI confirmation: PR #707 (AAASM-1741) added `services: postgres:18-alpine`
to the Test job. Subsequent PRs run the same suite end-to-end in CI;
the first such run (PR #707 itself) confirmed `codecov/patch` jumping
from ~14 % to green — only possible if the env-gated tests actually
executed.

### AC-7 — Tests are skipped gracefully when `AAASM_DATABASE_URL` is not set

**Status:** ✅ PASS

Skip helper:

```rust
async fn pg_backend_or_skip() -> Option<PostgresBackend> {
    let url = match std::env::var("AAASM_DATABASE_URL") {
        Ok(v) => v,
        Err(_) => {
            eprintln!(
                "skipping postgres test: AAASM_DATABASE_URL not set (CI provides this via services: postgres)"
            );
            return None;
        }
    };
    …
}
```

DB-bound tests return early via `let Some(backend) = … else { return };`.

Captured skip notice from a verbose run:

```
$ cargo nextest run -p aa-gateway --no-capture storage::postgres::tests::apply_retention_dry_run_does_not_delete
skipping postgres test: AAASM_DATABASE_URL not set (CI provides this via services: postgres)
test storage::postgres::tests::apply_retention_dry_run_does_not_delete ... ok
```

Full-suite skip evidence — 22/22 still PASS in 22 ms total (vs 229 ms
with DB), confirming every DB-bound assertion short-circuits before
hitting any network:

```
$ cargo nextest run -p aa-gateway storage::postgres::tests
     Summary [   0.022s] 22 tests run: 22 passed, 918 skipped
```

## Lint and formatting

| Check | Result |
|---|---|
| `cargo clippy -p aa-gateway --all-targets --all-features -- -D warnings` | ✅ clean |
| `cargo fmt --all -- --check` | ✅ clean |
| `cargo doc -p aa-gateway --no-deps` | ✅ builds (29 pre-existing intra-doc-link warnings inherited from master; out of scope for E18 S-C) |

## Test inventory

| Test | Sub-task | Coverage |
|---|---|---|
| `connect_rejects_missing_database_url` | #1 | AC-3 |
| `defaults_match_spec` (in `postgres_config::tests`) | #1 | AC-2 |
| `migrate_creates_expected_tables` | #2 | AC-1 (schema) |
| `migrate_is_idempotent` | #2 | AC-1 (schema lifecycle) |
| `append_then_query_round_trip` | #3 | AC-1 (audit) |
| `query_filters_by_time_range` | #3 | AC-4 |
| `count_matches_query_length` | #3 | AC-1 (audit count) |
| `dry_run_only_filter_excludes_non_dry_events` | #3 | AC-1 (audit filter) |
| `upsert_then_get_round_trip` | #4 | AC-1 (registry) |
| `upsert_updates_last_seen_at` | #4 | AC-5 |
| `list_filters_by_team` | #4 | AC-1 (registry filter) |
| `delete_unknown_returns_not_found` | #4 | AC-1 (registry error path) |
| `save_policy_assigns_monotonic_versions` | #5 | AC-1 (policy versioning) |
| `save_policy_does_not_activate_by_default` | #5 | AC-1 (policy activation) |
| `rollback_then_get_active_returns_chosen_version` | #5 | AC-1 (policy atomic rollback) |
| `rollback_unknown_version_returns_not_found` | #5 | AC-1 (policy error path) |
| `record_metric_then_query_round_trip` | #6 | AC-1 (metrics) |
| `query_metrics_with_bucket_aggregates` | #6 | AC-1 (date_trunc + AVG) |
| `query_metrics_unsupported_bucket_unit_returns_query_failed` | #6 | AC-1 (metrics validation) |
| `apply_retention_dry_run_does_not_delete` | #7 | AC-1 (retention dry-run) |
| `apply_retention_drop_removes_old_rows` | #7 | AC-1 (retention drop) |
| `apply_retention_archive_returns_error_until_s_d` | #7 | AC-1 (retention archive guard) |
| `healthcheck_returns_ok_with_row_counts` | #7 | AC-1 (lifecycle) |

22 env-gated integration tests + 2 unit tests (`connect_rejects_missing_database_url`,
`postgres_config defaults_match_spec`) = 24 tests covering the
PostgresBackend surface.

## Out of scope for this verification

* TimescaleDB hypertable conversion for `audit_events` and `metrics` —
  deferred to E18 S-D (AAASM-1586).
* Migration runner driven by gateway startup — deferred to E18 S-E
  (AAASM-1587).
* `apply_retention(Archive)` invokes `drop_chunks` — deferred to E18 S-D;
  this verification confirms the placeholder returns
  `StorageError::RetentionError` as the design intends.
* Integration into the gateway's runtime (replacing the in-memory
  `audit_store.rs` and `registry.rs`) — deferred to E18 S-I (AAASM-1590).

## Outcome

✅ **AAASM-1585 (E18 S-C) acceptance verified — all 7 Story ACs pass against
a live PostgreSQL 18.4 instance.**
