# Verification report — AAASM-2389 (MVP four-table schema consolidation)

- **Story:** AAASM-2389 — consolidate `orgs`/`agents`/`policies`/`audit_logs` into one canonical migration set
- **Implementation:** AAASM-2395 — PR [#900](https://github.com/AI-agent-assembly/agent-assembly/pull/900)
- **Verification subtask:** AAASM-2396
- **Date:** 2026-06-04
- **Environment:** macOS dev box, Docker 28.3.2, Postgres 18-alpine, `cargo nextest`

## Result: ✅ All acceptance criteria pass

---

## Parent-Story acceptance criteria

| # | Criterion | Status | Evidence |
|---|---|---|---|
| 1 | Single migration set lives in `aa-storage-postgres/migrations/` | ✅ | Only `aa-storage-postgres/migrations/{0001_orgs,0002_agents,0003_policies,0004_audit_logs,0005_credentials}.sql` define the MVP tables (§A). |
| 2 | Gateway uses the same migrations (no duplicate copy) | ✅ | `aa-gateway/tests/migration_boot.rs` runs the **driver's** `aa_storage_postgres::MIGRATOR` via a `path` dev-dependency — no copied files (§C). |
| 3 | `audit_logs.event_id UUID UNIQUE NOT NULL` for idempotency | ✅ | `\d audit_logs`: `event_id uuid … not null`, `PRIMARY KEY btree (event_id)` (UNIQUE + NOT NULL) (§B). |
| 4 | `audit_logs.payload` does NOT exist (metadata only) | ✅ | `\d audit_logs` shows only `event_id/agent_id/tool_name/decision/latency_ms/ts`; no `payload`/`body`/`prompt`/`completion` (§B). |
| 5 | Index on `(agent_id, ts DESC)` | ✅ | `idx_audit_logs_agent_ts btree (agent_id, ts DESC)` present (§B). |
| 6 | Migration test: apply to fresh Postgres 18; assert all four tables + indexes | ✅ | `migrations_apply_cleanly_and_audit_logs_is_metadata_only` + `gateway_boots_driver_migrations_on_fresh_postgres` (§C). |
| 7 | CI drift check; fails if migrations changed without gateway test passing | ✅ | `migration-drift-check` job in `.github/workflows/ci.yml` runs the boot test on a fresh Postgres (§D). |

## Subtask AAASM-2396 checklist

- [x] Single migration source in driver crate — §A
- [x] Gateway picks it up via test — §C
- [x] `event_id UUID UNIQUE NOT NULL` present — §B
- [x] No `payload` column — §B
- [x] CI drift check job exists — §D (runs on PR #900)
- [x] README points the right way — `aa-storage-postgres/README.md` (§E)

No AC failed; **no Bug Subtask filed.**

---

## §A — Stray-migration scan

```text
$ find . -name "*.sql" | grep -i migrat | sort
aa-gateway/migrations/20260509000000_approval_routing_config.sql      # SQLite approval routing
aa-gateway/migrations/20260510000001_pending_escalations.sql          # SQLite escalation
aa-gateway/migrations/postgres/0001_initial.sql                       # agent_registry / audit_events / metrics (Epic-F schema)
aa-gateway/migrations/postgres/0002_timescaledb_hypertables.sql       # TimescaleDB (Epic F)
aa-gateway/migrations/postgres/0003_timescaledb_compression_policies.sql
aa-gateway/src/storage/test_fixtures/migrations/{good,bad}/*.sql      # test fixtures
aa-storage-postgres/migrations/0001_orgs.sql                          # ── canonical MVP set ──
aa-storage-postgres/migrations/0002_agents.sql
aa-storage-postgres/migrations/0003_policies.sql
aa-storage-postgres/migrations/0004_audit_logs.sql
aa-storage-postgres/migrations/0005_credentials.sql

$ grep -rln "CREATE TABLE .*(orgs|audit_logs)" --include=*.sql .
aa-storage-postgres/migrations/0001_orgs.sql
aa-storage-postgres/migrations/0004_audit_logs.sql
```

The four MVP tables are defined **only** under `aa-storage-postgres/migrations/`.
`aa-gateway/migrations/postgres/` is a *different* schema (`agent_registry`,
`audit_events` with `payload`, `metrics` + TimescaleDB hypertables — Epic F) and
is intentionally left untouched; it is not a duplicate of the MVP set.

## §B — `\d audit_logs` on a fresh Postgres 18 (driver migrations applied in order)

```text
                       Table "public.audit_logs"
   Column   |           Type           | Nullable | Default
------------+--------------------------+----------+---------
 event_id   | uuid                     | not null |
 agent_id   | text                     | not null |
 tool_name  | text                     | not null |
 decision   | text                     | not null |
 latency_ms | integer                  |          |
 ts         | timestamp with time zone | not null | now()
Indexes:
    "audit_logs_pkey" PRIMARY KEY, btree (event_id)
    "idx_audit_logs_agent_ts" btree (agent_id, ts DESC)

List of tables: agents, audit_logs, credentials, orgs, policies
```

## §C — Test runs (Docker / Postgres 18 testcontainers)

```text
$ cargo nextest run -p aa-storage-postgres
  PASS migrations_apply_cleanly_and_audit_logs_is_metadata_only
  PASS audit_sink_writes_metadata_only_row
  PASS audit_sink_dedups_repeated_emit_on_event_id
  PASS lifecycle_register_heartbeat_deregister
  PASS policy_store_satisfies_conformance
  PASS credential_store_secret_roundtrip
  (+3 unit) — 9 tests run: 9 passed, 0 skipped

$ cargo nextest run -p aa-gateway -E 'binary(migration_boot)'
  PASS aa-gateway::migration_boot gateway_boots_driver_migrations_on_fresh_postgres
  1 test run: 1 passed
```

> Filter note: in this nextest version a bare positional matches only the
> test-name segment, so the drift test is selected with `-E 'binary(migration_boot)'`
> (the form the CI job and this report use).

## §D — CI drift gate

`.github/workflows/ci.yml` job `migration-drift-check` (gated on the `rust`
paths-filter) installs protoc + nextest and runs
`cargo nextest run -p aa-gateway -E 'binary(migration_boot)'` against a throwaway
Postgres. A migration that no longer applies cleanly — or an `audit_logs` drift —
fails the job. It executes on PR #900.

## §E — Documentation

`aa-storage-postgres/README.md` names `migrations/` the single source of truth and
directs the Gateway team to run the driver `MIGRATOR` instead of copying files.

## Local quality gates

`cargo fmt --all --check`, `cargo clippy -p aa-storage-postgres -p aa-gateway
--all-targets -- -D warnings`, and `cargo deny check` all pass clean.
