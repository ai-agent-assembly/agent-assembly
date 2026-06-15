# Verification Report: AAASM-3000

**Bug:** [AAASM-3000](https://lightning-dust-mite.atlassian.net/browse/AAASM-3000) — SDK⇄aa-runtime IPC deadlock: client blocks on a heartbeat/event Ack the runtime never sends
**Verified by:** AAASM-3003
**Date:** 2026-06-15
**Status:** ✅ Fixed — `aa-sdk-client` IPC event reporting is now fire-and-forget

---

## Root cause (recap)

`aa-sdk-client/src/ipc.rs` `ipc_loop` was synchronous request/response: it `write_heartbeat` →
`read_response` (blocked for `TAG_ACK`), and after every `write_event_report` → `read_response`
(blocked for `TAG_ACK`). But `aa-runtime` never sends those acks — `pipeline/mod.rs:137` ignores
heartbeats and the server only emits *unsolicited* responses (violation/policy/approval). So the
background IPC thread blocked at the first read (heartbeat ack), never drained the command channel,
and `shutdown()`'s `thread.join()` hung forever. No events were delivered.

## Fix (option A — fire-and-forget)

`ipc_loop` now:
- splits the stream with `into_split()` (owned halves),
- sends the heartbeat fire-and-forget (no ack read),
- ships event reports fire-and-forget (write only, no per-event ack read),
- drains *unsolicited* runtime responses on a **dedicated reader task** (`drain_responses`) so reads
  never race writes (no cancellation hazard) and the connection can't stall,
- aborts the reader task on `Shutdown`.

This matches `aa-runtime`'s design (hot-path events are async; only violations/decisions come back).
Shared `aa-sdk-client` ⇒ fixes the deadlock for **all three SDKs** at once.

## Acceptance criteria

### AC 1 — The deadlock is gone (regression test)

**Status:** ✅ PASS. New test `ipc::tests::shutdown_is_clean_when_runtime_never_acks` stands up a mock
server that mimics the real runtime (reads frames, **never acks**), ships 5 events fire-and-forget, and
asserts `shutdown()`/`thread.join()` returns within 5s. The **pre-fix** loop blocked forever here.

```
PASS [0.010s] aa-sdk-client ipc::tests::shutdown_is_clean_when_runtime_never_acks
```

### AC 2 — No existing behaviour regressed

**Status:** ✅ PASS. `cargo nextest run -p aa-sdk-client` → **27 passed, 0 failed** (incl. the existing
`ipc_loop_with_mock_server` and `lifecycle_e2e::client_ships_event_to_mock_runtime_and_shuts_down`).

### AC 3 — Style/lint clean

**Status:** ✅ PASS. `cargo fmt -p aa-sdk-client --check` clean; lefthook `fmt` + `clippy` (workspace,
`-D warnings`) green on both commits.

## End-to-end note

The defect was originally reproduced end-to-end in `agent-assembly-integration-tests`
(`tests/live/test_sdk_runtime.py`, AAASM-2989 PR #60), where the real `agent_assembly._core` against a
real `aa-runtime` hung on `close()` — marked `xfail`. With this fix, once the SDKs' `aa-sdk-client`
git-SHA pin is advanced to include this commit and `_core` is rebuilt, that test flips `XPASS` (the
designed signal). The unit regression test above proves the fix at the contract level (a non-acking peer
no longer deadlocks shutdown), which is the exact failure mode.
