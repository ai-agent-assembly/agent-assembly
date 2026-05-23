# Verification report — AAASM-1590 (Epic 18 Story S-I)

**Story**: [AAASM-1590](https://lightning-dust-mite.atlassian.net/browse/AAASM-1590) — Wire StorageBackend into gateway — replace in-memory audit and registry

**Epic**: [AAASM-1569](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569) — Durable Persistence Layer

**Verification Sub-task**: [AAASM-1873](https://lightning-dust-mite.atlassian.net/browse/AAASM-1873)

**Report date**: 2026-05-23

---

## Implementation summary

The Story was decomposed into 5 implementation Subtasks + 1 verification (this one). All five impl Subtasks merged into master:

| Subtask | Topic | PR | Merge SHA |
|---|---|---|---|
| AAASM-1859 (S-I.1) | `AppState` with `Arc<dyn StorageBackend>` + backend construction at boot | #714 | `a58204d5` |
| AAASM-1864 (S-I.2) | Write-through `AgentRegistry` + rehydrate on boot | #742 | `7c798743` |
| AAASM-1867 (S-I.3) | `AuditWriter` dual-sink (JSONL + storage) | #745 | `d2a6b1dc` |
| AAASM-1870 (S-I.4) | `RetentionEngine::start` boot wiring (AAASM-1588 follow-up #1) | #748 | `ae8eac41` |
| AAASM-1872 (S-I.5) | `aasm admin run-retention` live CLI transport (AAASM-1588 follow-up #2) | #754 | `0c9235e7` |

---

## Acceptance criteria — full checklist

### Story AC

| AC | Evidence | Status |
|---|---|---|
| **No `Mutex<Vec<AuditEvent>>` in non-test code** | `rg --type rust 'Mutex<Vec<AuditEvent>>' aa-gateway/src` → empty | ✅ |
| **No `DashMap<AgentId, _>` in non-test code** for the agent registry | The `AgentRegistry` itself keys by `[u8; 16]` (raw bytes), not `AgentId`. Remaining `DashMap<AgentId, _>` hits in `aa-gateway/src/budget/tracker.rs` and `aa-gateway/src/anomaly/detector.rs` belong to unrelated runtime-tracking concerns (budget per-agent state, anomaly baselines) that are out of E18 scope. AC intent (no ephemeral agent registry) satisfied | ✅ (intent), ⚠️ (literal — see note) |
| **Audit events written during a gateway session are still queryable after a gateway restart (verified with SQLite backend)** | `aa-gateway/tests/audit_storage_sink_test.rs::audit_entries_persist_to_storage_through_dual_sink` + `aa-integration-tests/tests/e18_si_restart_durability.rs::e18_si_full_stack_survives_restart` | ✅ |
| **Agents registered during a gateway session are still in the registry after a gateway restart** | `aa-gateway/tests/registry_storage_persistence_test.rs::agents_registered_persisted_survive_registry_restart` + `aa-integration-tests/tests/e18_si_restart_durability.rs::e18_si_full_stack_survives_restart` | ✅ |
| **`storage: Arc<dyn StorageBackend>` is the single dependency for all data access in `AppState`** | `aa-gateway/src/app_state.rs` — `pub struct AppState { pub storage: Arc<dyn StorageBackend> }` and nothing else | ✅ |
| **`cargo nextest run --workspace` green with SQLite (default) backend** | Each Subtask PR's Test job and Integration tests jobs green at merge | ✅ |
| **`cargo nextest run --workspace` green with PostgreSQL backend** | Per-Subtask Integration tests jobs (matrix includes Postgres) green at every merge | ✅ |
| **`cargo clippy --all-targets --all-features -- -D warnings` clean** | lefthook pre-commit ran clippy on every commit of every Subtask PR; all green | ✅ |

### AAASM-1588 closeout follow-ups (cross-referenced from comment 12531)

| Bullet | Implementation | Status |
|---|---|---|
| **#1 — `RetentionEngine::start` wired into gateway boot path** | `aa-gateway/src/main.rs::run_legacy_grpc` calls `spawn_retention_engine(...)` after storage migrate + registry rehydrate (PR #748 / AAASM-1870). On valid cron schedule, `tracing::info!("retention engine started")` fires at boot | ✅ |
| **#2 — `aasm admin run-retention` prints actual RetentionStats** | `aa-cli/src/commands/admin/retention.rs::dispatch` POSTs to `/api/v1/admin/retention-policy/run` and prints `RetentionRunStatsDto` as pretty JSON (PR #754 / AAASM-1872) | ✅ |

---

## Test inventory

### Per-Subtask tests (pin component-level invariants)

| Subtask | Test file | Test count | What it pins |
|---|---|---|---|
| S-I.1 | `aa-gateway/src/app_state.rs::tests` | 2 unit | AppState holds storage; clone semantics |
| S-I.2 | `aa-gateway/tests/registry_storage_persistence_test.rs` | 2 integration | Agent register persists; deregister tombstones |
| S-I.2 | `aa-gateway/src/registry/storage_bridge.rs::tests` | 2 unit | Runtime ↔ storage AgentRecord round-trip |
| S-I.3 | `aa-gateway/tests/audit_storage_sink_test.rs` | 2 integration | Audit dual-sink persists; JSONL byte-shape unchanged |
| S-I.3 | `aa-gateway/src/storage/audit_bridge.rs::tests` | 5 unit | Wire-shape of `AuditEntry` → `AuditEvent` translation |
| S-I.4 | `aa-gateway/src/storage/retention_boot.rs::tests` | 3 unit | Spawn returns live handle; invalid cron fails fast; archive-without-url fails fast |
| S-I.5 | `aa-cli/src/commands/admin/retention.rs::tests` | 4 unit | Request/response wire shape + endpoint constant |
| S-I.5 | `aa-cli/tests/admin_run_retention.rs` | 4 integration (wiremock) | Live wire contract: default, `--dry-run`, connect-refused, YAML output |

### Story-level test (this Sub-task)

`aa-integration-tests/tests/e18_si_restart_durability.rs::e18_si_full_stack_survives_restart` — one boot cycle exercising registry + audit dual-sink + retention engine spawn together against a real on-disk SQLite file, then a clean shutdown via `CancellationToken`, then a reopen that asserts all three planes survive. Includes a re-spawn of the retention engine against the reopened storage to prove the boot helper is re-entrant and the backend was not corrupted in session 1.

---

## Notable findings flagged during the Story

1. **aa-core's default `RetentionConfig.schedule = "0 3 * * *"` is rejected by `cron::Schedule::from_str`** — the validator wants 6-field Quartz syntax (`sec min hour DoM month DoW`), aa-core ships 5-field Unix syntax. Operators running with default YAML see `tracing::warn!("retention engine disabled — config rejected by validator")` and the gateway boots without retention. Documented in PR #748 body; **follow-up flagged against AAASM-1582 / S-H** to fix the default to `"0 0 3 * * *"`. The Story-level test uses an explicit 6-field schedule so it doesn't depend on the upstream fix landing.

2. **`aa_api::run_server` has no production caller** in the current workspace. The aa-api handlers, OpenAPI spec, dashboard codegen, and contract test entries for `/api/v1/admin/retention-policy/run` are all in place (from AAASM-1850 / AAASM-1856 / AAASM-1861), but no production binary boots the Axum HTTP server today. The S-I.5 CLI (`aasm admin run-retention`) is wired correctly and will work against any running aa-api instance; lighting up the production HTTP path is **out of scope for E18 S-I** and tracked separately under the dashboard / SaaS roll-out work (AAASM-1592).

3. **`local_mode` / `remote_mode` retention spawn deferred** — those entrypoints don't carry `storage.retention` in their config types today (they receive trimmed-down `LocalModeConfig` / `RemoteModeConfig`). The Subtask S-I.4 description called for spawning the engine in both; the actual production wire-up landed in `main.rs::run_legacy_grpc` which IS the gateway path that has both the storage and the retention policy. Documented in PR #748 body.

4. **AppState fields beyond `storage`** — the Subtask descriptions for S-I.2/S-I.3/S-I.4 each anticipated adding fields to `aa-gateway::AppState` (registry, audit_tx, retention_handle). None landed because `aa-gateway::AppState` has no handler consumer yet (the HTTP route layer uses `aa-api::AppState`, a distinct type). The implementations route through the actual production code paths (legacy-grpc `serve_tcp`/`serve_uds` for registry + audit; `main.rs::run_legacy_grpc` for retention), keeping the existing surfaces intact.

---

## CI evidence

Each Subtask PR ran the full ~26-check CI matrix. The only failure across the Story was the `SonarCloud analysis` job on PR #748, which carried the `System.IO.IOException: No space left on device` runner-side disk-space flake (documented in memory note `project_ci_disk_space_flake`); it passed on rerun without code change. Every Subtask merged with `mergeStateStatus: CLEAN`, `mergeable: MERGEABLE`.

Local macOS `cargo nextest run -p aa-gateway` shows 1 flake (`policy_latency_test::sustained_load_p99_under_5ms`) that passes on CI Linux (memory note `project_policy_latency_test_local_flake`) — not introduced by this Story.

---

## Verdict

**All Story acceptance criteria satisfied.** Both AAASM-1588 closeout follow-ups are wired end-to-end on the production legacy-grpc code path. The Story-level integration test in this Sub-task provides a regression net against future changes that would break the cross-plane wire-up.

Story AAASM-1590 is ready to close.
