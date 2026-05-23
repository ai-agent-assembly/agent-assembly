# AAASM-1591 — E18 S-J `aasm status` Storage Health — Acceptance Verification

| | |
| --- | --- |
| **Story** | [AAASM-1591](https://lightning-dust-mite.atlassian.net/browse/AAASM-1591) — E18 S-J: `aasm status` storage health — backend type, DB connection latency, and hot-tier row counts |
| **Epic** | [AAASM-1569](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569) — Epic 18: Durable Persistence Layer |
| **Verified against `master` SHA** | `4e733a3e` (pre-merge of Sub-1 / Sub-2 PRs; this report is the Sub-3 evidence pack) |
| **Verification date** | 2026-05-23 |
| **Verification sub-task** | [AAASM-1910](https://lightning-dust-mite.atlassian.net/browse/AAASM-1910) |
| **Conclusion** | ✅ Ready for Done — all 8 ACs verified via unit + integration tests across `aa-gateway` and `aa-cli` |

---

## Sub-tasks landed (in dependency order)

| # | Key | PR | Title |
| --- | --- | --- | --- |
| 1 | [AAASM-1908](https://lightning-dust-mite.atlassian.net/browse/AAASM-1908) | [#762](https://github.com/AI-agent-assembly/agent-assembly/pull/762) | Add `GET /api/v1/admin/status` storage-health route (aa-gateway) |
| 2 | [AAASM-1909](https://lightning-dust-mite.atlassian.net/browse/AAASM-1909) | [#763](https://github.com/AI-agent-assembly/agent-assembly/pull/763) | `aasm status` renders storage block + non-zero exit on DB unhealthy (aa-cli) |
| 3 | [AAASM-1910](https://lightning-dust-mite.atlassian.net/browse/AAASM-1910) | _(this PR)_ | Verify AAASM-1591 acceptance criteria |

---

## Acceptance Criteria walkthrough

### AC #1 — `GET /api/v1/admin/status` returns 200 with the documented storage health block

✅ **Verified** via `aa-gateway::admin_status_e2e::admin_status_returns_documented_storage_block_through_router`. The test boots an in-process Axum listener around the production `remote_mode::router(Some(backend), Some(database_url))`, issues a real `reqwest` GET against `/api/v1/admin/status`, and asserts:

- HTTP body parses as JSON.
- Top-level keys `mode`, `version`, `uptime_secs`, `storage` are all present.
- `storage.backend == "sqlite"`, `storage.health == "ok"`, `storage.latency_ms` is a number.
- All three documented `row_counts` keys (`audit_events_hot`, `agents`, `policy_versions`) are present.

```text
$ cargo nextest run -p aa-gateway --test admin_status_e2e
Starting 1 test across 1 binary
    PASS [   0.028s] (1/1) aa-gateway::admin_status_e2e admin_status_returns_documented_storage_block_through_router
Summary [   0.029s] 1 test run: 1 passed, 0 skipped
```

### AC #2 — Password in database URL redacted in all output (API, CLI, logs)

✅ **Verified** at two layers:

1. **Server side** — `aa-gateway::routes::admin_status::tests::redact_replaces_postgres_password_with_stars` and `from_health_redacts_postgres_database_url_and_drops_sqlite_path` confirm `postgresql://aasm:secret@db.internal:5432/aasm` → `postgresql://aasm:***@db.internal:5432/aasm`. The handler stores the redacted URL inside `StorageHealthBlock`, so the raw password never reaches the response body. The same redact helper is invoked from a `tracing::warn!` site that runs on the healthcheck-error path, ensuring logs never carry the password either.
2. **Client side** — `aa-cli::commands::status::render::tests::format_storage_health_renders_postgres_block_with_redacted_url_and_timescaledb` asserts `assert!(!rendered.contains("secret"))` against the rendered CLI output. Since the CLI receives an already-redacted URL from the gateway, the secret cannot reach the rendered display.

Edge cases pinned in unit tests:

- `redact_leaves_url_without_userinfo_unchanged` — no userinfo → URL unchanged.
- `redact_leaves_user_only_userinfo_unchanged` — no `:password` segment → URL unchanged.
- `redact_leaves_sqlite_url_unchanged` — `sqlite:///...` URLs are passed through verbatim.
- `redact_handles_at_inside_password_via_rightmost_at_split` — rightmost `@` is the split point, so a stray `@` in the password is tolerated.

### AC #3 — DB latency shown in ms (time to execute `SELECT 1`)

✅ **Verified**. `StorageBackend::healthcheck()` returns `StorageHealth.latency_ms: u32` measured at the backend layer (existing AAASM-1719 / E18 S-C contract). The route handler propagates this verbatim into `StorageHealthBlock.latency_ms`, and the CLI renders `DB Health: ✓ ok  ({latency_ms}ms)` in the storage section.

The e2e test above (`admin_status_returns_documented_storage_block_through_router`) asserts `latency_ms` is a JSON number; the unit test `handler_returns_documented_body_against_sqlite_backend` exercises the same path against a real SQLite backend with applied migrations.

### AC #4 — Row counts include `audit_events`, `agents`, `policy_versions`

✅ **Verified**. The wire contract is pinned by:

- `aa-gateway::routes::admin_status::tests::row_counts_block_serialises_with_documented_keys` — the server-side struct serialises to `{"audit_events_hot", "agents", "policy_versions"}`.
- `aa-cli::commands::status::models::tests::admin_row_counts_block_deserialises_documented_keys` — the client-side struct decodes the same keys.
- `aa-cli::commands::status::models::tests::admin_row_counts_block_tolerates_extra_keys` — future warm-/cold-tier additions won't break older CLIs.

The hot-tier focus is intentional: warm/cold counts require backend-specific roll-ups that aren't cheap on both backends. The retention engine surfaces those in a follow-up sub-task once both SQLite and PostgreSQL/TimescaleDB can report them in a single round-trip.

### AC #5 — TimescaleDB block only present when TimescaleDB is active

✅ **Verified** by two paired tests:

- `aa-gateway::routes::admin_status::tests::from_health_populates_timescaledb_block_when_stats_present` — when `StorageHealth.timescale = Some(_)`, the resulting JSON includes the `timescaledb` block.
- `aa-gateway::routes::admin_status::tests::storage_block_omits_optional_fields_when_none` — when `StorageHealth.timescale = None`, the block is omitted entirely (verified via `assert!(json.get("timescaledb").is_none())`).
- `aa-cli::commands::status::render::tests::format_storage_health_renders_sqlite_block_without_timescaledb_line` — the CLI's `STORAGE` section omits the `TimescaleDB:` line on SQLite.

`#[serde(skip_serializing_if = "Option::is_none")]` is what enforces the wire-level omission; the deserialise side uses `#[serde(default)]` so older gateways without the block still decode.

### AC #6 — `aasm status` CLI prints storage section after mode/uptime section

✅ **Verified**. `aa-cli::commands::status::render::format_storage_health` produces the `STORAGE` section, and `render_all` calls it between the deployment-overview header and the runtime-health section. The gating logic `if let Some(storage_health) = snapshot.storage_health.as_ref()` ensures older gateways without `/api/v1/admin/status` keep their pre-AAASM-1591 output verbatim.

The route is mounted in **both** deployment modes so the CLI sees a storage section regardless of how the gateway was started:

- Remote mode: `aa-gateway::remote_mode::server::router(Some(storage), database_url)` mounts the route — pinned by `aa-gateway::admin_status_e2e::admin_status_returns_documented_storage_block_through_router`.
- Local mode: `aa-gateway::local_mode::router(config, Some(storage))` mounts the route — pinned by `aa-gateway::local_mode::tests::router_serves_admin_status_when_storage_is_wired` and the gate-test `router_omits_admin_status_when_storage_is_none` for the no-storage path.

Captured rendered output (from `format_storage_health_renders_postgres_block_with_redacted_url_and_timescaledb`, with ANSI codes stripped):

```text
STORAGE
───────
  Backend:     postgres
  DB:          postgresql://aasm-user:***@db.internal:5432/aasm
  DB Health:   ✓ ok  (3ms)
  Rows:        audit_events: 14,293 hot
               agents: 8  |  policies: 3
  TimescaleDB: ✓ active  (8/12 chunks compressed, 11.4× ratio)
```

And on SQLite without TimescaleDB:

```text
STORAGE
───────
  Backend:     sqlite
  Path:        ~/.aasm/local.db
  DB Health:   ✓ ok  (1ms)
  Rows:        audit_events: 47 hot
               agents: 2  |  policies: 1
```

### AC #7 — Non-zero exit code when DB health check fails

✅ **Verified** by `aa-cli::commands::status::tests::exit_code_1_when_storage_health_is_unavailable`. The test seeds a `StatusSnapshot` whose `storage_health.health == "unavailable"` and asserts `compute_exit_code(...) == ExitCode::from(1)`.

Two companion tests guard against false positives:

- `exit_code_0_when_storage_health_is_ok` — healthy storage doesn't trip the exit code.
- `exit_code_0_when_storage_health_is_degraded` — `degraded` storage is reachable, so it must keep a healthy exit code.

End-to-end, the wiring works as: gateway probe error → `StorageHealthBlock.health = "unavailable"` (server side) → CLI deserialises → `compute_exit_code` → exit code 1.

### AC #8 — `cargo nextest run -p aa-gateway routes::admin_status::tests` green

✅ **Verified**:

```text
$ cargo nextest run -p aa-gateway routes::admin_status::
Starting 16 tests across 44 binaries (994 tests skipped)
    PASS [   0.024s] ( 1/16) aa-gateway routes::admin_status::tests::from_health_populates_timescaledb_block_when_stats_present
    PASS [   0.025s] ( 2/16) aa-gateway routes::admin_status::tests::from_health_redacts_postgres_database_url_and_drops_sqlite_path
    PASS [   0.025s] ( 3/16) aa-gateway routes::admin_status::tests::storage_block_omits_optional_fields_when_none
    PASS [   0.025s] ( 4/16) aa-gateway routes::admin_status::tests::from_health_renders_unavailable_status_label
    PASS [   0.025s] ( 5/16) aa-gateway routes::admin_status::tests::redact_leaves_non_url_inputs_unchanged
    PASS [   0.025s] ( 6/16) aa-gateway routes::admin_status::tests::redact_handles_at_inside_password_via_rightmost_at_split
    PASS [   0.027s] ( 7/16) aa-gateway routes::admin_status::tests::from_health_propagates_sqlite_path_and_drops_database_url
    PASS [   0.029s] ( 8/16) aa-gateway routes::admin_status::tests::redact_leaves_sqlite_url_unchanged
    PASS [   0.029s] ( 9/16) aa-gateway routes::admin_status::tests::row_counts_block_serialises_with_documented_keys
    PASS [   0.029s] (10/16) aa-gateway routes::admin_status::tests::admin_status_body_serialises_with_documented_top_level_keys
    PASS [   0.029s] (11/16) aa-gateway routes::admin_status::tests::redact_replaces_postgres_password_with_stars
    PASS [   0.029s] (12/16) aa-gateway routes::admin_status::tests::redact_leaves_url_without_userinfo_unchanged
    PASS [   0.029s] (13/16) aa-gateway routes::admin_status::tests::redact_leaves_user_only_userinfo_unchanged
    PASS [   0.029s] (14/16) aa-gateway routes::admin_status::tests::timescaledb_block_serialises_with_documented_keys
    PASS [   0.042s] (15/16) aa-gateway routes::admin_status::tests::handler_uptime_reflects_started_at
    PASS [   0.043s] (16/16) aa-gateway routes::admin_status::tests::handler_returns_documented_body_against_sqlite_backend
Summary [   0.045s] 16 tests run: 16 passed, 994 skipped
```

Full gateway suite also green: `1013 tests run: 1013 passed, 0 skipped` (the +2 tests over master are the two new local-mode router tests landed by the AAASM-1908 follow-up commit `🔧 (local_mode): Mount /api/v1/admin/status when storage is wired`).

CLI side (PR #763 evidence): `cargo nextest run -p aa-cli` → `566 tests run: 566 passed, 0 skipped`.

---

## Conclusion

All 8 ACs are verified via the test suite across `aa-gateway` and `aa-cli`. The implementation is bisectable (each commit compiles and tests pass), the wire contract matches the AAASM-1591 story description verbatim, and password redaction is enforced at both the API response layer and the log layer.

Recommend transitioning AAASM-1908, AAASM-1909, AAASM-1910, and AAASM-1591 to **Done** once PR #762, #763, and this verification PR all merge.
