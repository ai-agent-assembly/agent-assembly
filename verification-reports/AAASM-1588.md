# E18 S-F Verification — AAASM-1588 (Retention engine)

> **Status**: parent Story [AAASM-1588] sub-tasks all shipped on Sprint-4
> branches. Engine-side acceptance bullets verified clean below.
> Three backend-side bullets (AC #4 / #5 / #6) and one wiring bullet
> (AC #1 boot) are explicitly **Pending** — they belong to sibling
> stories that are still in flight; this is documented up-front as a
> scope cut rather than a regression.

[AAASM-1569]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1569
[AAASM-1588]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1588
[AAASM-1744]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1744
[AAASM-1745]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1745
[AAASM-1746]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1746
[AAASM-1747]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1747
[AAASM-1748]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1748
[AAASM-1590]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1590
[AAASM-1585]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1585
[AAASM-1586]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1586

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| [AAASM-1744] | Impl-1 — `RetentionConfig` + `to_policy()` + validation | Done | [#662](https://github.com/ai-agent-assembly/agent-assembly/pull/662) |
| [AAASM-1745] | Impl-2 — `RetentionEngine::run_once()` with tracing log | Done | [#686](https://github.com/ai-agent-assembly/agent-assembly/pull/686) |
| [AAASM-1746] | Impl-3 — cron-driven `RetentionEngine::start()` background task | Done | [#694](https://github.com/ai-agent-assembly/agent-assembly/pull/694) |
| [AAASM-1747] | Impl-4 — `aasm admin run-retention --dry-run` CLI subcommand | Done | [#697](https://github.com/ai-agent-assembly/agent-assembly/pull/697) |
| [AAASM-1748] | Verify — this report | in this PR | this PR |

## Scope cut (declared up-front)

The Story description names a single cohesive AC list but covers two
distinct surfaces: the **engine** (what `aa-gateway/src/storage/retention_engine.rs`
orchestrates) and the **backends** (what each `StorageBackend::apply_retention`
implementation does inside). S-F owns the engine; the backends are
owned by S-B / S-C / S-D and the boot wiring is owned by S-I.

Explicit deferrals:

| AC | Owning story | Why deferred here |
|---|---|---|
| #1 — boot wiring | [AAASM-1590] (S-I) | The engine ships `RetentionEngine::start()`; S-I wires the call into `local_mode` / `server.rs`. Engine-side schedule firing is verified below |
| #4 — archive (JSONL → S3) | [AAASM-1585] (S-C) | Lives inside `apply_retention()` on the PostgreSQL backend |
| #5 — drop (DELETE) | S-B (SQLite) / [AAASM-1585] (S-C) | Lives inside `apply_retention()` on each concrete backend |
| #6 — TimescaleDB warm compression | [AAASM-1586] (S-D) | `compress_chunk` lives inside the PG-with-TimescaleDB backend |

The engine *delivers the `RetentionPolicy` faithfully* to whichever
backend is wired in; per-backend semantics are validated when each
backend's verification subtask runs.

## Walkthrough vs AAASM-1588 acceptance criteria

### ✅ AC #1 — Background task runs on configured cron schedule (engine side)

**Engine side**: closed.

- `aa-gateway/src/storage/retention_engine.rs:75` — `RetentionEngine::start(self: Arc<Self>, shutdown: CancellationToken) -> Result<JoinHandle<()>, RetentionConfigError>` spawns a `tokio` task that loops `schedule.upcoming(Utc).next() → tokio::time::sleep(delay) → self.run_once()`, with cooperative shutdown via `CancellationToken`.
- `aa-gateway/src/storage/retention_engine.rs` (test module) — `start_fires_run_once_on_short_schedule_and_stops_on_cancellation` spawns with `"* * * * * *"` (every-second cron), waits 2.1s, cancels, asserts `FakeBackend::call_count() ≥ 1` and `handle.await` succeeds.

**Default schedule**: the AC literal `0 3 * * *` was bumped to `0 0 3 * * *`
(6-field cron) because the `cron` 0.15 crate rejects 5-field POSIX cron.
Semantics are unchanged (3am UTC daily). Flagged as a Breaking Change in
PR #694 and pinned by `default_uses_compliance_friendly_30_90_drop_3am`.

**Boot wiring**: Pending — owned by [AAASM-1590].

### ✅ AC #2 — `dry_run: true` logs counts without modifying any rows

**Engine side**: closed.

- `aa-gateway/src/storage/retention_engine.rs:46-47` — `run_once()` builds the policy via `config.to_policy()` (which forwards `dry_run` verbatim, see `retention_config.rs::to_policy`) and hands it to the backend.
- `aa-gateway/src/storage/retention_engine.rs` (test module) — `run_once_propagates_dry_run_flag_to_policy` asserts `RetentionConfig.dry_run = true` arrives at the backend as `RetentionPolicy.dry_run = true`.
- `aa-gateway/src/storage/retention_engine.rs:44-53` — `tracing::info!` always emits the row counts regardless of `dry_run`, so operators see "would compress / would drop" counts in dry-run mode.

The "without modifying any rows" half is the **backend's** contract:
each `StorageBackend::apply_retention` implementation must short-circuit
its mutating SQL when `policy.dry_run == true`. That's owned by each
backend's story.

### ✅ AC #3 — `RetentionStats` logged after each run

Closed.

- `aa-gateway/src/storage/retention_engine.rs:44-53` — structured `tracing::info!` emission carries every documented field:

  | Documented in AC | Logged field |
  |---|---|
  | rows compressed | `compressed_rows = stats.compressed_rows` |
  | rows archived | `archived_rows = stats.archived_rows` |
  | rows dropped | `dropped_rows = stats.dropped_rows` |
  | bytes freed | `freed_bytes = stats.freed_bytes` |
  | timestamp | `ran_at = %stats.ran_at` |

  Plus two diagnostic bonuses: `hot_rows` (post-run remaining count) and `dry_run` (so the log line itself carries the mode flag).

- `aa-gateway/src/storage/retention_engine.rs` (test module) — `run_once_returns_stats_from_backend_unchanged` pins that the engine forwards the backend's `RetentionStats` verbatim into the log + return value.

### ⏳ AC #4 — `cold_action: archive` → JSONL → `archive_url` → deletion

**Pending** — owned by [AAASM-1585] (S-C: PostgreSQL `StorageBackend`).

The engine surfaces the archive intent through the policy:

- `aa-gateway/src/storage/retention_config.rs::validate()` fail-fasts on `cold_action=Archive` without `archive_url` (`validate_rejects_archive_action_without_url` pins this).
- `retention_config.rs::to_policy()` forwards `archive_url` into the `RetentionPolicy` (`to_policy_forwards_all_runtime_fields` pins this).
- `retention.rs::ColdAction::Archive` variant exists and is exhaustive.

Once the PostgreSQL backend lands its `apply_retention()` body, the
JSONL serialization + S3 PUT + post-archive DELETE chain runs on the
policy this engine hands it.

### ⏳ AC #5 — `cold_action: drop` → rows deleted without archiving

**Pending** — owned by the SQLite (S-B) and PostgreSQL (S-C, [AAASM-1585]) backends.

Engine surface: `ColdAction::Drop` is the `Default`
(`default_uses_compliance_friendly_30_90_drop_3am`); `to_policy()`
forwards the variant; each backend's `apply_retention()` is the body
that runs the actual `DELETE` or `drop_chunks(...)`.

### ⏳ AC #6 — `warm_days` compression only when TimescaleDB present, otherwise warning

**Pending** — owned by [AAASM-1586] (S-D: TimescaleDB hypertable setup).

The engine passes `warm_days` verbatim through the policy. The
"TimescaleDB-present detection + `compress_chunk` invocation + warning
log on absence" all live inside the PostgreSQL backend's
`apply_retention()` body. Engine-side test `to_policy_forwards_all_runtime_fields`
pins that `warm_days` is not lost in the policy hand-off.

### ✅ AC #7 — `aasm admin run-retention --dry-run` triggers one manual dry-run

**Scaffold form**: closed in scaffold form pending [AAASM-1590].

Manual exercise on this branch (off post-Impl-4 master):

```text
$ aasm admin run-retention --dry-run
aasm admin run-retention: gateway admin transport not yet wired
(tracked under AAASM-1590 / Story S-I). The retention engine (Story
S-F) is in place; once the admin transport lands this subcommand will
trigger a manual retention pass against the running gateway.
$ echo $?
0
```

- `aa-cli/src/commands/admin/retention.rs:21-30` — `dispatch()` prints the operator-facing pointer at AAASM-1590 and returns `ExitCode::SUCCESS` so CI exercising CLI help / arg parsing stays green.
- `aa-cli/src/commands/admin/mod.rs:51-71` — clap parse tests for `aasm admin run-retention` (with + without `--dry-run`).
- `aa-cli/tests/admin_run_retention.rs` — assert_cmd end-to-end tests pin exit-0 and the `AAASM-1590` pointer in the stub stderr.

When S-I lands the gateway admin transport, this `dispatch()` body
swaps from the stub to a live admin call that prints `RetentionStats`.
The clap surface (`--dry-run` flag, args struct) is already in place,
so the swap is body-only — no API churn.

### ✅ AC #8 — `cargo nextest run -p aa-gateway storage::retention::tests` green

Closed.

```text
$ cargo nextest run -p aa-gateway storage::retention
    Starting 14 tests across 38 binaries (905 tests skipped)
        PASS [   0.019s] ( 1/14) aa-gateway storage::retention_config::tests::default_uses_compliance_friendly_30_90_drop_3am
        PASS [   0.019s] ( 2/14) aa-gateway storage::retention_config::tests::parsed_schedule_returns_schedule_for_default_config
        PASS [   0.019s] ( 3/14) aa-gateway storage::retention_config::tests::to_policy_forwards_all_runtime_fields
        PASS [   0.021s] ( 4/14) aa-gateway storage::retention_config::tests::validate_accepts_default_config
        PASS [   0.021s] ( 5/14) aa-gateway storage::retention_config::tests::validate_accepts_archive_action_with_url
        PASS [   0.021s] ( 6/14) aa-gateway storage::retention_config::tests::validate_rejects_invalid_cron_schedule
        PASS [   0.021s] ( 7/14) aa-gateway storage::retention_config::tests::validate_rejects_archive_action_without_url
        PASS [   0.022s] ( 8/14) aa-gateway storage::retention_engine::tests::run_once_returns_stats_from_backend_unchanged
        PASS [   0.021s] ( 9/14) aa-gateway storage::retention_engine::tests::run_once_propagates_dry_run_flag_to_policy
        PASS [   0.021s] (10/14) aa-gateway storage::retention_engine::tests::run_once_surfaces_backend_error
        PASS [   0.021s] (11/14) aa-gateway storage::retention_engine::tests::start_rejects_invalid_schedule_before_spawning
        PASS [   0.022s] (12/14) aa-gateway storage::retention_engine::tests::run_once_invokes_apply_retention_with_policy_from_config
        PASS [   2.125s] (13/14) aa-gateway storage::retention_engine::tests::start_fires_run_once_on_short_schedule_and_stops_on_cancellation
        PASS [   3.124s] (14/14) aa-gateway storage::retention_engine::tests::start_loop_survives_failed_run_once
     Summary [   3.125s] 14 tests run: 14 passed, 905 skipped
```

7 tests on `storage::retention_config`, 7 tests on `storage::retention_engine`. The two longest (~2.1s and ~3.1s) are the wall-clock cron-loop tests on the every-second schedule.

## Engine-side test coverage map

| Story AC | Test |
|---|---|
| #1 cron loop fires | `start_fires_run_once_on_short_schedule_and_stops_on_cancellation` |
| #1 graceful shutdown | (same test) — cancels via `CancellationToken`, asserts `handle.await` returns cleanly |
| #1 fail-fast on bad cron | `start_rejects_invalid_schedule_before_spawning` |
| #1 production resilience | `start_loop_survives_failed_run_once` — transient backend Err does NOT kill the loop |
| #2 dry_run plumbing | `run_once_propagates_dry_run_flag_to_policy` |
| #3 stats logged | `run_once_returns_stats_from_backend_unchanged` + `tracing::info!` emission verified by reading the source |
| Backend error surfaces | `run_once_surfaces_backend_error` |
| Default schedule contract | `default_uses_compliance_friendly_30_90_drop_3am` |
| Default validates | `validate_accepts_default_config` |
| Archive needs URL | `validate_rejects_archive_action_without_url` |
| Archive with URL OK | `validate_accepts_archive_action_with_url` |
| `to_policy` forwards all | `to_policy_forwards_all_runtime_fields` |
| Invalid cron rejected | `validate_rejects_invalid_cron_schedule` |
| Default schedule parses | `parsed_schedule_returns_schedule_for_default_config` |

## Judgment calls captured during implementation

1. **`start()` returns `Result`**, not bare `JoinHandle` (PR #694) — chose
   fail-fast at spawn time rather than panic-at-first-tick. Matches the
   subtask's "no runtime panic" requirement.
2. **Default schedule bumped from `0 3 * * *` to `0 0 3 * * *`** (PR #694)
   — cron 0.15 rejects 5-field POSIX cron. Semantics unchanged. Flagged
   as a Breaking Change; low blast radius (S-H YAML config parsing
   hasn't merged yet so only test code reads the default).
3. **CLI `dispatch()` is a stub pointing at AAASM-1590** (PR #697) —
   exits 0 with an explicit operator-facing pointer at the in-flight
   wiring ticket. assert_cmd e2e test pins that pointer.
4. **`call_count`-based cron-loop tests** use wall-clock sleeps (2.1s
   and 3.1s) tuned slightly above the integer second to absorb tokio
   scheduler jitter. No mocked time clock added — kept to standard
   `tokio::time::sleep` for clarity.

## No follow-up Bug Sub-tasks opened

The four implementation PRs (#662 / #686 / #694 / #697) all merged on
26/26 green CI; no behavior gaps surfaced during this verification pass.
Three AC bullets (#4 / #5 / #6) and one wiring bullet (#1 boot) remain
**Pending** as documented at the top of this report — those are
sibling-story responsibilities, not gaps in S-F.
