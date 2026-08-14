# AAASM-3600 — Verify DB-enforced RLS + per-tenant isolation

**Story:** AAASM-3564 — DB-enforced Postgres RLS + per-tenant runtime/memory isolation
**Date:** 2026-06-23
**Verifier:** dev (local, real Postgres 18 + TimescaleDB pg16 via testcontainers)

This report records evidence that the three acceptance criteria of AAASM-3564
hold across `agent-assembly` (`aa-storage-postgres`, `aa-api`) and
`agent-assembly-cloud` (`aa-cloud-persistence`, `aa-cloud-control-plane`).

## AC#1 — An intentionally-removed app-layer filter cannot leak cross-tenant rows

**Mechanism:** FORCE ROW LEVEL SECURITY + a `tenant_isolation` policy on every
tenant table, keyed on `app.tenant_id` set per connection (migrations
`aa-storage-postgres/migrations/0006_tenant_columns.sql`,
`0007_enable_rls.sql`; cloud `aa-cloud-persistence/migrations/0013_audit_logs_rls.sql`).

**Evidence — agent-assembly** (`cargo nextest run -p aa-storage-postgres`):
- `rls_isolation_pg::dropped_filter_still_excludes_other_tenant_rows` — a
  `SELECT … FROM audit_logs` with NO `WHERE org_id` predicate, under tenant A's
  GUC, returns exactly 1 row (A's), not 2. PASS.
- `rls_isolation_pg::unset_or_empty_guc_returns_zero_rows` — a connection with no
  `app.tenant_id`, and one with an empty-string GUC, both return 0 rows from
  every tenant table (fail-closed via `NULLIF(current_setting(…, true), '')`). PASS.
- `rls_isolation_pg::pooled_connection_reuse_does_not_bleed_guc` — with
  `max_connections = 1`, a tenant-B checkout reusing tenant A's physical
  connection sees only B's row (`set_config(..., is_local = true)`). PASS.
- `rls_isolation_pg::write_with_mismatched_tenant_is_rejected` — a cross-tenant
  INSERT under the wrong GUC is rejected by the policy `WITH CHECK`. PASS.

Full suite result: **15 tests run, 15 passed** (10 conformance + 5 RLS; legacy
trait paths unaffected — they route through the reserved system org).

**Evidence — cloud** (`cargo nextest run -p aa-cloud-persistence`):
- `rls_isolation::{dropped_filter_still_excludes_other_tenant_rows,
  unset_or_empty_guc_returns_zero_rows, pooled_connection_reuse_does_not_bleed_guc,
  client_supplied_tenant_cannot_widen_past_guc}` — all PASS on real TimescaleDB.
- `migrations::retention_policy_is_registered_and_compression_is_traded_for_rls`
  — confirms FORCE RLS is on `audit_logs` and the retention policy is kept. PASS.

Full suite result: **78 tests run, 78 passed**.

**Harness note (important):** RLS does not bind a PostgreSQL superuser, and the
testcontainer bootstrap user IS a superuser. The RLS assertions therefore run
through a second pool connected as a restricted, non-superuser `app_user` role —
the same migrator-vs-row-access role split the production deployment uses (and
which migrations `0007` / `0013` document as an operational requirement).

## AC#2 — tenant_id cannot be spoofed by the client (set only from the verified JWT)

**Mechanism:** the value feeding the storage `app.tenant_id` GUC comes only from
the verified identity. In `aa-api`, `AuthenticatedCaller::storage_tenant_org()`
reads only `caller.tenant.org_id` (verified JWT claim / API-key entry), never a
request `Query`/header/body. In cloud, `Tenanted<T>` is only constructible from a
verified-mTLS `AuthenticatedTenant`.

**Evidence:**
- `aa-api auth::tenant_guard_tests::{storage_tenant_org_is_the_verified_org,
  client_supplied_org_cannot_redirect_storage_scope,
  no_tenant_scope_yields_none_not_a_client_value}` — 3 tests run, 3 passed: a
  client-chosen org cannot become the storage tenant; no scope yields `None`
  (fail-closed), never a synthesized client value.
- DB-level corroboration:
  `rls_isolation_pg::client_supplied_org_cannot_widen_past_guc` (agent-assembly)
  and `rls_isolation::client_supplied_tenant_cannot_widen_past_guc` (cloud) — a
  query hard-coding another tenant's id in its WHERE still returns 0 rows under
  the connection's GUC. PASS.

## AC#3 — High-tier tenants get OS-process-level memory isolation

**Mechanism:** the isolation-tier design (`agent-assembly-cloud/docs/architecture/
isolation-tiers.md`) defines the high tier as a dedicated `aa-runtime` OS process
per tenant (no shared address space → no residual-memory/cache side-channel) plus
a per-tenant Postgres schema; the standard tier is shared runtime + shared schema
+ RLS. The tier is a selectable property: `IsolationTier{Standard,High}` in
`aa-cloud-control-plane`, with `IsolationTier::High.has_process_isolation() == true`.

**Evidence:**
- `aa-cloud-control-plane isolation::tests::*` + `config::tests::default_isolation_tier_is_standard`
  — 6 + relevant config tests pass: default is `Standard`, only `High` reports
  process isolation, parsing round-trips, the control-plane `Config` carries a
  `default_isolation_tier`.
- ADR merged in the cloud PR describing both tiers, tradeoffs, and assignment.

> Scope note: this Story delivers the design + config surface for the high tier
> (AC#3 as specified by subtask AAASM-3599 — "design + config only, no runtime
> orchestration"). The orchestration that physically spins up a dedicated
> process/schema per high-tier tenant is explicitly out of scope here.

## Discovered constraints (handled, not deferred)

1. **Superuser bypasses RLS** — tests connect as a restricted role (above).
2. **TimescaleDB: RLS ⊥ columnstore** — on pg16, enabling RLS on a hypertable
   with columnstore, or re-enabling columnstore on an RLS table, both error
   (`0A000`). The Story makes RLS the required control, so cloud migration `0013`
   removes the `0012` compression setting + policy and keeps the retention
   policy. Recorded in the migration header and the migrations test.
3. **Empty-string GUC** — a pooled-connection GUC residue can be `''`, which
   errors on `::uuid`. All policies use `NULLIF(current_setting(…, true), '')`
   so empty is treated as NULL (fail-closed), verified by the unset/empty test.

## Conclusion

All three acceptance criteria are verified with passing tests on real
Postgres/TimescaleDB. No gaps requiring new bug subtasks were found.
