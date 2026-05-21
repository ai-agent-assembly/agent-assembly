# AAASM-1386 Verification — Add alert-rules CRUD endpoints (`/api/v1/alerts/rules`)

> **Status**: All nine sub-tasks complete. The Story's 7 acceptance criteria
> are satisfied against `master @ d64616b9`. Six divergences from the Story
> description (response shape, wire casing, deferred follow-ups for the
> non-budget metric backends) were either pre-planned or fall within the
> AC's explicit "minimum viable; full anomaly hookup can be a follow-up"
> clause. **No Bug Sub-task opened**.

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| AAASM-1615 | Add `AlertRule` domain types + validation | Done | [#592](https://github.com/AI-agent-assembly/agent-assembly/pull/592) |
| AAASM-1616 | Add `AlertRuleStore` trait + `InMemoryAlertRuleStore` | Done | [#601](https://github.com/AI-agent-assembly/agent-assembly/pull/601) |
| AAASM-1617 | Add in-memory `DestinationRegistry` stub | Done | [#602](https://github.com/AI-agent-assembly/agent-assembly/pull/602) |
| AAASM-1618 | Extend `ProblemDetail` with optional `error_code` field | Done | [#603](https://github.com/AI-agent-assembly/agent-assembly/pull/603) |
| AAASM-1619 | Wire `alert_rule_store` + `destination_registry` into `AppState` | Done | [#604](https://github.com/AI-agent-assembly/agent-assembly/pull/604) |
| AAASM-1620 | Add CRUD handlers + register routes + utoipa annotations | Done | [#607](https://github.com/AI-agent-assembly/agent-assembly/pull/607) |
| AAASM-1621 | Add minimum-viable rule evaluator + wire into `run_server` | Done | [#608](https://github.com/AI-agent-assembly/agent-assembly/pull/608) |
| AAASM-1622 | Add integration tests `aa-api/tests/alert_rules.rs` | Done | [#610](https://github.com/AI-agent-assembly/agent-assembly/pull/610) |
| AAASM-1623 | Verify Add alert-rules CRUD endpoints acceptance criteria | in this report | — |

## Acceptance-criteria walkthrough

### ✅ `aa-api` routes registered for all five operations with `utoipa` annotations

`aa-api/src/routes/mod.rs:82-90` registers two path items
(`/alerts/rules` and `/alerts/rules/{id}`) covering all five operations
(`GET`/`POST` on the collection; `GET`/`PUT`/`DELETE` on the item).
Each handler in `aa-api/src/routes/alert_rules.rs` carries a
`#[utoipa::path]` annotation with the response codes and the
`alert-rules` tag.

The literal `rules` segment is placed *before* `/alerts/{id}` so it
isn't captured as an alert id (same convention used for `/alerts/ws`
and `/alerts/silence`).

### ✅ `openapi/v1.yaml` regenerated

`cargo run -p aa-api --bin generate_openapi 2>/dev/null > /tmp/x.yaml && diff openapi/v1.yaml /tmp/x.yaml`
→ no output, exit 0 (verified 2026-05-21 against master). The spec
contains both new path items, the `AlertRuleRequest` and `AlertRule`
schemas, and the `RuleMetric` / `RuleOperator` / `RuleSeverity`
enums. Spectral lint passes with no errors.

### ✅ `AlertRuleStore` trait + in-memory impl (persisted store deferred)

`aa-api/src/alerts/rules/store.rs` defines:

* `AlertRuleStore` trait — `create`, `get`, `list(Option<bool>)`,
  `update`, `delete`, `find_by_name`.
* `InMemoryAlertRuleStore` — `RwLock<HashMap<String, AlertRule>>`;
  ULID-style id assignment; name-uniqueness check on `create`;
  preserves `id` + `created_at` on `update`; bumps `updated_at`.
* `AlertRuleStoreError::{NameConflict, NotFound}` with `error_code()`.

12 unit tests cover CRUD + name conflict + the `enabled` filter.
Persisted-store backend deferred per the AC parenthetical.

### ✅ Rule evaluator (minimum viable)

`aa-api/src/alerts/rules/evaluator.rs` ships:

* `MetricSource` trait — `current_value(metric) -> Option<f64>`.
* `NullMetricSource` — returns `None` for every metric; wired as the
  active backend in `run_server`.
* `evaluate(rule, value) -> bool` — `>`, `>=`, `<`, `=` with f64
  epsilon tolerance.
* `evaluate_once(rules, metrics, alerts)` — single pass over enabled
  rules; records a synthetic `BudgetAlert` for `BudgetSpentPct` fires.
* `spawn_rule_evaluator(rules, metrics, alerts, tick_period)` — tokio
  background task; `MissedTickBehavior::Skip`.

`aa-api/src/server.rs` spawns the evaluator at a 60 s tick alongside
the alert-capture, secret-alert-capture, and silence-expiry watchers.

Falls under the AC's "minimum viable; full anomaly hookup can be a
follow-up" clause — see Divergences below.

### ✅ Integration tests cover happy path + each error code

`aa-api/tests/alert_rules.rs` ships 7 `#[tokio::test]`s driving the
real `v1_router` via `tower::ServiceExt::oneshot`:

| # | Test | Coverage |
|---|---|---|
| 1 | `full_crud_round_trip` | POST→GET-list→GET-id→PUT→DELETE→GET-404; assigned id/timestamps; `updatedAt` bumps with `createdAt` preserved |
| 2 | `create_with_unknown_metric_returns_invalid_metric` | 400 + `invalid_metric` |
| 3 | `create_with_out_of_range_threshold_returns_invalid_threshold` | 400 + `invalid_threshold` |
| 4 | `create_with_unknown_destination_returns_destination_unknown` | 400 + `destination_unknown` |
| 5 | `get_unknown_id_returns_rule_not_found` | 404 + `rule_not_found` (cold-store) |
| 6 | `create_with_duplicate_name_returns_rule_name_conflict` | 409 + `rule_name_conflict` |
| 7 | `list_filters_by_enabled_query` | `?enabled=true|false` shape |

All 7 pass via `cargo nextest run -p aa-api --test alert_rules`.

### ✅ `cargo nextest run -p aa-api -p aa-gateway` green

**1341 tests run: 1341 passed, 0 skipped** against master `d64616b9`
(verified 2026-05-21).

### ✅ `cargo clippy --all-targets -- -D warnings` green

`cargo clippy --workspace --all-targets --all-features --exclude aa-ebpf -- -D warnings`
→ finished with no warnings (verified 2026-05-21).

## Divergences from the Story description

Each is either deliberate planning-time alignment with the dashboard
contract or falls inside the AC's explicit follow-up window.

### ⚠️ `GET /rules` returns a bare array, not `{ data, next_page_token }`

The Story example shows `{ data: AlertRule[], next_page_token? }`.
Shipped: `Vec<AlertRule>` bare array. **Reason**: AAASM-1075 (the
dashboard's `useAlertRulesQuery`, marked Done) consumes a bare array
and does client-side filtering. Matching the existing dashboard
contract was the explicit planning decision (memory:
`feedback_check_dashboard_contract_first`). Pagination can be
introduced later without breaking the wire if the rule count grows.

### ⚠️ Wire shape is camelCase, not snake_case

Story example uses `evaluation_window_seconds`, `destination_ids`,
`dedup_window_seconds`, `suppression_labels`. Shipped: same fields via
`#[serde(rename_all = "camelCase")]` — `evaluationWindowSeconds`,
`destinationIds`, etc. **Reason**: AAASM-1075's TS schema is camelCase
to match the rest of the dashboard's wire layer.

### ⚠️ Evaluator tick cadence vs `evaluation_window_seconds`

Story says "poll metric source, fire when condition holds for
`evaluation_window_seconds`". Shipped: a 60 s wall-clock tick that
fires on a single observation (no window-aware accumulation).
**Reason**: covered by AC's "minimum viable; full anomaly hookup can
be a follow-up" clause. `evaluation_window_seconds` is validated and
persisted but not consumed by the loop.

### ⚠️ Non-budget metric backends not wired

`RuleMetric::AnomalyScore`, `ApprovalPendingAge`, `PolicyViolationCount`
are accepted by the validator and stored, but the active
`MetricSource` (`NullMetricSource`) returns `None` for every metric,
so no rule of those metric types will ever fire today. **Reason**:
explicit follow-up per the AC.

### ⚠️ Synthetic alert lacks `rule_id` / `rule_snapshot` propagation

When the MVP evaluator fires (only possible on `BudgetSpentPct` once a
real `MetricSource` is wired), it records a `BudgetAlert` without a
`rule_id` link or `rule_snapshot`. **Reason**: `BudgetAlert` is the
only shape `AlertStore::record` accepts today; the snapshot-aware
recording path requires a separate `AlertSeed`-based ingestion that
the existing wiring doesn't expose. **No functional impact today**
because `NullMetricSource` never fires — but it is the natural next
step when a real `BudgetTracker`-backed metric source lands.

### ⚠️ `suppression_labels` / `dedup_window_seconds` accepted but not consumed

Both fields land in `AlertRuleRequest` → `AlertRule` and round-trip
through the store. The evaluator does not consult them today.
Labels-aware deduplication is a follow-up tied to the same metric-
backend work above.

## Follow-up suggestions (not in scope for AAASM-1386)

1. **Budget-tracker-backed `MetricSource`** — replace
   `NullMetricSource` with one that reads `aa-gateway::budget::tracker`
   for `BudgetSpentPct`. Unblocks real rule firings.
2. **Window-aware accumulation** — tick at each rule's
   `evaluation_window_seconds` and require the condition to hold for
   the full window before firing. Removes single-observation flapping.
3. **Snapshot-aware alert recording** — propagate `rule_id` and a
   `RuleSnapshot` onto the recorded alert so the detail view links
   back to the originating rule even after deletion.
4. **Labels-aware deduplication** — use `suppression_labels` +
   `dedup_window_seconds` to suppress duplicate fires.
5. **Persistent `AlertRuleStore`** — replace the in-memory store with
   a SQLite-backed impl once rule count or restart-survivability
   becomes a concern. The trait was designed to support this.
6. **Real metric backends for the remaining three metrics** —
   `anomaly_score` (anomaly detector), `approval_pending_age`
   (approval store time scan), `policy_violation_count` (audit
   aggregator).
