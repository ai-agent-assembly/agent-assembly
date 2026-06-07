# AAASM-1584 — E18 S-B: SQLite StorageBackend — Acceptance Report

**Story:** [AAASM-1584](https://lightning-dust-mite.atlassian.net/browse/AAASM-1584)
**Epic:** [AAASM-1569 — Durable Persistence Layer](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569)
**Verified:** 2026-05-21
**Worktree:** `agent-assembly-v0.0.1-AAASM-1723-test-verify_e18_s_b_ac`
**Branch:** `v0.0.1/AAASM-1723/test/verify_e18_s_b_ac`

---

## Summary

The SQLite implementation of the `StorageBackend` trait introduced in Story
AAASM-1583 (E18 S-A) lands in this Story across 7 implementation sub-tasks
(S-B.1 through S-B.7), with this sub-task (S-B.8) providing the cross-restart
persistence evidence and this acceptance report.

All 7 parent-Story acceptance criteria are confirmed by tests under
`aa-gateway/src/storage/sqlite.rs::tests` (23 in-module tests) plus the
end-to-end restart test under `aa-gateway/tests/sqlite_restart_persistence_test.rs`
(1 integration test). Total: **24 tests, all green**.

---

## Sub-task → PR map

| Sub-task | Scope | PR |
|---|---|---|
| AAASM-1697 (S-B.1) | sqlx chrono feature, `SqliteConfig`, `SqliteBackend::open` (WAL + parent-dir creation) | [#656](https://github.com/ai-agent-assembly/agent-assembly/pull/656) |
| AAASM-1700 (S-B.2) | Schema DDL + idempotent `migrate()` | [#665](https://github.com/ai-agent-assembly/agent-assembly/pull/665) |
| AAASM-1704 (S-B.3) | Audit-event slice (`append` / `query` / `count`) + `impl StorageBackend` skeleton | [#673](https://github.com/ai-agent-assembly/agent-assembly/pull/673) |
| AAASM-1708 (S-B.4) | Agent-registry slice (`upsert` / `get` / `list` / `delete`) | [#675](https://github.com/ai-agent-assembly/agent-assembly/pull/675) |
| AAASM-1712 (S-B.5) | Policy-version slice (`save` / `get_active` / `list_versions` / `rollback`) | [#678](https://github.com/ai-agent-assembly/agent-assembly/pull/678) |
| AAASM-1714 (S-B.6) | Metric slice (`record` / `query`) | [#679](https://github.com/ai-agent-assembly/agent-assembly/pull/679) |
| AAASM-1721 (S-B.7) | Retention DELETE + `healthcheck` with row counts | [#680](https://github.com/ai-agent-assembly/agent-assembly/pull/680) |
| AAASM-1723 (S-B.8) | Cross-restart integration test + this report | _this PR_ |

---

## Acceptance Criteria Matrix

### AC 1 — All `StorageBackend` trait methods compile and pass against a real SQLite file

**Status:** ✅ Met.

`impl StorageBackend for SqliteBackend` lives in `aa-gateway/src/storage/sqlite.rs`
(introduced under S-B.3, fully populated by S-B.7) and implements all 16 trait
methods plus `migrate`. Every method is exercised by an integration test against
a tempfile-backed `SqliteBackend`.

```text
$ cargo nextest run -p aa-gateway storage::sqlite
Summary: 23 tests run: 23 passed, 829 skipped
```

### AC 2 — WAL journal mode enabled on every connection

**Status:** ✅ Met.

`SqliteBackend::open` (`aa-gateway/src/storage/sqlite.rs:120`) runs
`PRAGMA journal_mode=WAL` immediately after constructing the pool. The
WAL pragma sticks at the database file level — it applies to every
subsequent connection the pool hands out.

Evidence: `tests::open_creates_parent_dir_and_enables_wal` probes
`PRAGMA journal_mode` after the pool is up and asserts the response is
`"wal"`.

### AC 3 — Data written in one gateway session is readable after restarting

**Status:** ✅ Met.

`aa-gateway/tests/sqlite_restart_persistence_test.rs::sqlite_data_survives_gateway_restart`
opens a `SqliteBackend`, writes one row to each of `audit_events`,
`agent_registry`, `policy_versions`, and `metrics`, drops the backend (so
the connection pool is closed and WAL is flushed), then re-opens the
same temp file and asserts each row is readable with identical content,
including the JSON payload, the agent metadata map, and the policy
document bytes.

```text
$ cargo nextest run -p aa-gateway --test sqlite_restart_persistence_test
PASS [0.032s] sqlite_data_survives_gateway_restart
Summary: 1 test run: 1 passed
```

### AC 4 — Parent directories of SQLite path created automatically if absent

**Status:** ✅ Met.

`SqliteBackend::open` calls `std::fs::create_dir_all(parent)` for any
non-empty parent component of the configured path (`sqlite.rs:122-131`).
Filesystem errors map to `StorageError::ConnectionFailed`.

Evidence: `tests::open_creates_parent_dir_and_enables_wal` deliberately
points at a nested-but-missing path (`<tmp>/nested/dir/test.db`) and
asserts both the file and its parents exist after `open()` returns.

### AC 5 — `AuditFilter` filters work: by agent_id, time range, dry_run_only, limit/offset

**Status:** ✅ Met.

The shared `push_audit_where` helper (`sqlite.rs:240`) drives both
`query_audit_events` and `count_audit_events`. Each filter dimension is
covered by a dedicated test:

| AuditFilter dimension | Test |
|---|---|
| `agent_id` / `team_id` | `audit_filter_dimensions_independently_narrow_results` |
| `from` / `to` (time range) | `audit_filter_dimensions_independently_narrow_results` |
| `dry_run_only` | `audit_filter_dimensions_independently_narrow_results` |
| `limit` / `offset` paging | `audit_query_limit_and_offset_produce_disjoint_pages` |
| `count` parity with `query` | `audit_count_matches_query_result_size` |

### AC 6 — `apply_retention` deletes rows older than the cold threshold

**Status:** ✅ Met.

`SqliteBackend::apply_retention` (sqlite.rs S-B.7) computes
`cold_threshold = now - (hot_days + warm_days)` and either reports the
count (`dry_run = true`) or deletes rows (`dry_run = false`).

Evidence:

* `tests::retention_deletes_rows_older_than_cold_threshold` — seeds
  events at 0 / 100 / 365 days ago and asserts that
  `apply_retention(hot=30, warm=60, Drop)` removes the two old rows and
  reports `dropped_rows == 2`.
* `tests::retention_dry_run_reports_drop_count_without_deleting` —
  confirms `dry_run = true` reports the would-be drop count but leaves
  the rows in place.
* `tests::retention_archive_falls_back_to_drop_with_warn` —
  `ColdAction::Archive` is logged as unsupported on SQLite and the
  cold-tier rows are still dropped, per the documented limitation.

### AC 7 — `cargo nextest run -p aa-gateway storage::sqlite::tests` green

**Status:** ✅ Met.

```text
$ cargo nextest run -p aa-gateway storage::sqlite
Starting 23 tests across 37 binaries (829 tests skipped)
        PASS aa-gateway storage::sqlite::tests::agent_delete_removes_row_and_second_delete_returns_not_found
        PASS aa-gateway storage::sqlite::tests::agent_get_returns_none_for_unknown_id
        PASS aa-gateway storage::sqlite::tests::agent_list_filters_by_team_org_and_name_substring
        PASS aa-gateway storage::sqlite::tests::agent_upsert_is_idempotent_and_updates_existing_row
        PASS aa-gateway storage::sqlite::tests::audit_count_matches_query_result_size
        PASS aa-gateway storage::sqlite::tests::audit_filter_dimensions_independently_narrow_results
        PASS aa-gateway storage::sqlite::tests::audit_query_limit_and_offset_produce_disjoint_pages
        PASS aa-gateway storage::sqlite::tests::audit_round_trip_preserves_all_columns_including_payload
        PASS aa-gateway storage::sqlite::tests::expand_tilde_leaves_non_tilde_path_unchanged
        PASS aa-gateway storage::sqlite::tests::healthcheck_reports_ok_and_correct_row_counts
        PASS aa-gateway storage::sqlite::tests::metric_filter_by_agent_metric_and_time_range_narrows_results
        PASS aa-gateway storage::sqlite::tests::metric_query_bucket_emits_warning_and_returns_raw_samples
        PASS aa-gateway storage::sqlite::tests::metric_record_and_query_round_trip_without_filter
        PASS aa-gateway storage::sqlite::tests::migrate_creates_all_expected_tables_and_indexes
        PASS aa-gateway storage::sqlite::tests::migrate_is_idempotent_across_repeated_calls
        PASS aa-gateway storage::sqlite::tests::open_creates_parent_dir_and_enables_wal
        PASS aa-gateway storage::sqlite::tests::policy_get_active_is_none_until_rollback_activates
        PASS aa-gateway storage::sqlite::tests::policy_rollback_enforces_single_active_per_name
        PASS aa-gateway storage::sqlite::tests::policy_rollback_missing_returns_not_found
        PASS aa-gateway storage::sqlite::tests::policy_save_assigns_monotonic_versions_and_lists_desc
        PASS aa-gateway storage::sqlite::tests::retention_archive_falls_back_to_drop_with_warn
        PASS aa-gateway storage::sqlite::tests::retention_deletes_rows_older_than_cold_threshold
        PASS aa-gateway storage::sqlite::tests::retention_dry_run_reports_drop_count_without_deleting
Summary: 23 tests run: 23 passed, 829 skipped
```

---

## Notes / Documented Limitations

1. **`MetricQuery.bucket` is unsupported on SQLite** — when set, the
   query emits a single `tracing::warn!` and returns raw samples (no
   aggregation). Time-bucketing will land with the TimescaleDB backend
   under E18 S-D.
2. **`ColdAction::Archive` falls back to drop on SQLite** — likewise
   logged with a `tracing::warn!`; archive support is a TimescaleDB
   capability tracked under S-D.
3. **`freed_bytes` is always 0** in SQLite mode — `VACUUM` is out of
   scope for this Story.
4. **`SqliteConfig` lives in `aa-gateway/src/storage/sqlite.rs`** rather
   than `aa-core` for the duration of this Story. E18 S-H (AAASM-1582,
   StorageConfig parser) is expected to subsume / move the type once it
   lands.

---

## Spec Conformance

* Spec lines 7113–7134 (three data categories) → the four tables
  (`audit_events`, `agent_registry`, `policy_versions`, `metrics`)
  match the categorization.
* Spec lines 7140–7155 (local mode storage stack — "SQLite, zero-deps")
  → `SqliteBackend` is single-file at the configured path with WAL
  journal mode; no external infrastructure required.
* Spec line 7213 (architecture decision — "Local → SQLite") → this
  backend is the canonical local-mode implementation.
