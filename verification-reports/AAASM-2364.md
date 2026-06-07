# Verification Report — AAASM-2364

**Story:** As an OSS operator, I want an `aa-storage-postgres` driver with sqlx
migrations for `orgs`/`agents`/`policies`/`audit_logs`
**Epic:** AAASM-2348 (OSS concrete storage drivers)
**Component / repo:** `agent-assembly`
**Verification subtask:** AAASM-2371
**Date:** 2026-06-03
**Result:** ✅ PASS — all acceptance criteria met.

## Delivered by

| Subtask | PR | Scope |
|---|---|---|
| AAASM-2369 | [#874](https://github.com/ai-agent-assembly/agent-assembly/pull/874) | Crate scaffold, four MVP migrations, `[storage.postgres]` pool config |
| AAASM-2370 | [#886](https://github.com/ai-agent-assembly/agent-assembly/pull/886) | `PgPolicyStore` / `PgAuditSink` / `PgCredentialStore` / `PgLifecycleStore`, `0005_credentials` migration, driver registration, testcontainers conformance suite |

## Acceptance criteria

| # | Acceptance criterion | Status | Evidence |
|---|---|---|---|
| 1 | Crate ships impls for `PolicyStore`, `AuditSink`, `CredentialStore`, `LifecycleStore` | ✅ | `aa-storage-postgres/src/{policy_store,audit_sink,credential_store,lifecycle_store}.rs`; each `impl <Trait> for Pg<...>` over `aa_core::storage`. Exercised by `conformance_pg.rs`. |
| 2 | `migrations/` has sqlx migrations for the four MVP tables with appropriate indexes | ✅ | `migrations/0001_orgs.sql`..`0004_audit_logs.sql`; indexes `idx_agents_org_id`, `idx_policies_agent_version (agent_id, policy_version DESC)`, `idx_audit_logs_agent_ts (agent_id, ts DESC)`. `migrations_apply_cleanly_*` test applies them on a fresh Postgres 18 and asserts every table exists. |
| 3 | Connection pool configurable via `[storage.postgres]` (url, max connections, statement timeout) | ✅ | `config::PostgresPoolConfig { url, max_connections, statement_timeout_ms }`; `config::tests::parses_storage_postgres_subsection` parses the TOML subsection; `PostgresPool::connect` applies `SET statement_timeout` per connection when non-zero. |
| 4 | Registers as `name = "postgres"` | ✅ | `aa_storage_postgres::NAME == "postgres"`; `tests::driver_registers_as_postgres`. |
| 5 | Trait-conformance suite passes using `testcontainers-modules` Postgres | ✅ | `cargo nextest run -p aa-storage-postgres` → 8/8 pass (see below), 5 integration cases against a fresh Postgres 18 testcontainer; policy path drives `aa_storage::conformance::assert_policy_store_conformance`. |
| 6 | `cargo deny check` clean (no BSL conflicts; pin sqlx) | ✅ | `advisories ok, bans ok, licenses ok, sources ok`. sqlx pinned at 0.8.6 (already in the workspace tree via `aa-gateway`); no new licenses introduced. |

## Commands run

```
$ cargo nextest run -p aa-storage-postgres
    Starting 8 tests across 2 binaries
        PASS tests::driver_registers_as_postgres
        PASS config::tests::applies_defaults_for_omitted_knobs
        PASS config::tests::parses_storage_postgres_subsection
        PASS conformance_pg::policy_store_satisfies_conformance
        PASS conformance_pg::audit_sink_writes_metadata_only_row
        PASS conformance_pg::lifecycle_register_heartbeat_deregister
        PASS conformance_pg::migrations_apply_cleanly_and_audit_logs_is_metadata_only
        PASS conformance_pg::credential_store_secret_roundtrip
     Summary  8 tests run: 8 passed, 0 skipped

$ cargo clippy -p aa-storage-postgres --all-targets -- -D warnings
    Finished — no warnings

$ cargo deny check
    advisories ok, bans ok, licenses ok, sources ok
```

## audit_logs is metadata-only (spec line 7551)

`migrations/0004_audit_logs.sql` defines:

```sql
CREATE TABLE audit_logs (
    id         UUID PRIMARY KEY,
    agent_id   TEXT NOT NULL,
    tool_name  TEXT NOT NULL,
    decision   TEXT NOT NULL,
    latency_ms INT,
    ts         TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

No `payload`, `prompt`, or `body` column exists. This is enforced by
`migrations_apply_cleanly_and_audit_logs_is_metadata_only`, which queries
`information_schema.columns` and asserts none of those columns are present, and
by `audit_sink_writes_metadata_only_row`, which emits an entry whose payload
carries a secret and confirms the payload is never persisted.

## Notes

- **AgentId encoding:** the storage traits identify agents by
  `aa_core::identity::AgentId` (opaque 16-byte UUID); text agent-id columns store
  the canonical hyphenated UUID string (the encoding the gateway driver already
  uses). `agents.org_id` is nullable since `LifecycleStore::register` carries no
  org context.
- **AuditEntry → audit_logs mapping:** `AuditEntry` has no native tool/latency
  fields, so `tool_name` records the governance event-type discriminant,
  `decision` a coarse `allow`/`deny`/`review` posture, and `latency_ms` is NULL.
  This is an MVP approximation; richer fields can follow when a consumer needs
  them.
- **Out of scope (unchanged):** TimescaleDB hypertables (Epic F),
  `audit_logs` time partitioning.

No bug subtasks filed — all acceptance criteria pass.
