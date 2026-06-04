# AAASM-2375 — Verify `aa-storage-sqlite-buffer` acceptance criteria

Parent Story: **AAASM-2366** · Epic: **AAASM-2348** · Implementation: **AAASM-2374** (PR #878)
Verified against branch `v0.0.1/AAASM-2375/test/verify_sqlite_buffer` (stacked on the impl branch).

## Story (AAASM-2366) acceptance criteria results

| # | Acceptance criterion | Result | Evidence |
|---|---|---|---|
| 1 | Event-buffer module with `enqueue(event)` and `drain_and_send(sink)` | ✅ Pass | `EventBuffer::enqueue(&AuditEntry)` + `EventBuffer::drain_and_send(&dyn AuditSink)`; exercised by `tests/drain.rs::enqueues_and_drains_in_fifo_order`. |
| 2 | `rusqlite` single-file DB at a configurable path (default `~/.local/share/agent-assembly/buffer.db`) | ✅ Pass | `EventBuffer::new(path, cap)` / `from_config`; `SqliteBufferConfig`/`default_path` join the platform data dir + `agent-assembly/buffer.db` — exactly `~/.local/share/agent-assembly/buffer.db` on Linux (XDG). |
| 3 | WAL mode + `synchronous = NORMAL` | ✅ Pass | `tests/pragma.rs` asserts `journal_mode == "wal"` and `synchronous == 1` (NORMAL) on the live connection. |
| 4 | Configurable cap; oldest dropped with a counter (never silent — emit a metric) | ✅ Pass | `tests/cap.rs` proves DB retains the newest 10 of 15 in order; `tests/metrics.rs` asserts `aa_events_dropped_total == 5` (and `aa_events_buffered == 15`, `aa_events_flushed_total == 10`) via a `DebuggingRecorder`. |
| 5 | Restart test: enqueue, terminate process, restart, prove flush on reconnect | ✅ Pass | `tests/kill_restart.rs` spawns a child, enqueues 5 events, **`kill -9`** the child, then reopens the file and replays all 5; `tests/restart.rs` covers the drop/reopen variant. |
| 6 | Drains in insertion order (FIFO) | ✅ Pass | All drain assertions compare against the exact insertion-ordered `Vec<AuditEntry>`. |

## Subtask "How" checklist

1. `cargo nextest run -p aa-storage-sqlite-buffer` → **8 passed, 0 failed**.
2. Restart under a tmp dir, child `kill -9`, restart, drain, assert exact order → `kill_restart.rs` ✅.
3. Cap test cap=10, enqueue 15, `aa_events_dropped_total == 5`, DB holds latest 10 → `cap.rs` + `metrics.rs` ✅.
4. `PRAGMA journal_mode` / `PRAGMA synchronous` checked on the open DB → `pragma.rs` ✅.
5. No AC failed → **no Bug subtask filed**.

## Commands run

```
cargo nextest run -p aa-storage-sqlite-buffer     # 8 tests run: 8 passed, 0 skipped
cargo test  -p aa-storage-sqlite-buffer --doc     # 2 doctests pass
cargo fmt --all -- --check                        # clean
cargo clippy --all-targets --all-features -- -D warnings   # clean
cargo deny check                                  # advisories/bans/licenses/sources ok
cargo doc -p aa-storage-sqlite-buffer --no-deps   # clean under -D warnings
```

### Tests (8 across 7 binaries)

```
kill_restart  child_enqueue_then_block                              PASS
kill_restart  survives_sigkill_and_replays_in_order                 PASS
restart       buffered_events_survive_restart_and_replay_in_order   PASS
drain         enqueues_and_drains_in_fifo_order                     PASS
drain         drain_stops_at_first_sink_failure_and_resumes_later   PASS
cap           cap_evicts_oldest_and_retains_newest_in_order         PASS
metrics       cap_eviction_is_metered                               PASS
pragma        opens_in_wal_mode_with_synchronous_normal             PASS
```

## Notes on implementation choices (carried from AAASM-2374)

- Uses the real contract types `AuditEntry` + `AuditSink` (the ticket text said `AuditEvent`).
- Crate lives at the repo top-level (`aa-storage-sqlite-buffer/`); this repo has no `crates/` directory.
- Serialization uses `serde_json` (BLOB) rather than `bincode`: `AuditEntry`'s `#[serde(skip_serializing_if)]`
  fields cannot round-trip through bincode, which is not self-describing. Round-trip is proven by every
  drain test comparing decoded entries for equality.
- `rusqlite` is pinned to `0.32` so it shares `libsqlite3-sys 0.30` with `sqlx-sqlite 0.8.6`; only one crate
  may link the native `sqlite3` library.

**Verdict: all Story AAASM-2366 acceptance criteria pass.**
