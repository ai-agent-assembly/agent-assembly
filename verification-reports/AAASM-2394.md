# AAASM-2394 — Verification: Gateway NATS consumer acceptance criteria

Verifies the parent Story **AAASM-2388** (gateway NATS → Postgres audit consumer,
implemented in **AAASM-2393**, PR #907).

## How verified

| # | Method |
|---|--------|
| 1 | `cargo nextest run -p aa-gateway --features audit-consumer audit_consumer::` (unit) |
| 2 | `cargo nextest run -p aa-gateway --features audit-consumer --test audit_consumer_e2e` (impl-PR integration test) |
| 3 | `cargo nextest run -p aa-integration-tests --features audit-consumer --test audit_consumer_verify` (this subtask — Docker: NATS JetStream + Postgres + Prometheus recorder) |

## Acceptance criteria

| AC | Result | Evidence |
|----|--------|----------|
| Worker spawns and subscribes to the `assembly.audit.>` wildcard | ✅ Pass | Consumer spawns; every event published under `assembly.audit.*` is consumed. |
| Duplicates filtered by `event_id` (UNIQUE PK) | ✅ Pass | Republishing one `event_id` 100× yields exactly **1** `audit_logs` row. |
| Channel-based backpressure exposes a depth metric | ✅ Pass | `aa_audit_consumer_channel_depth` is exposed via Prometheus and returns to **0** after the backlog drains. |
| JetStream ack only on successful INSERT | ✅ Pass | Ack issued after the DB write; a failed write leaves the message un-acked for redelivery (impl design + `aa_audit_consumer_write_errors_total`). |
| Idempotency counter | ✅ Pass | `aa_audit_duplicates_total == 99` after 100 republishes of one `event_id`. |
| **Sustained 50k events/sec on a single dev box** | ❌ **Not met** | Measured **~2.7k events/sec** end-to-end (publisher → NATS → consumer → Postgres). See below. |

## Throughput measurement

`audit_consumer_verify` measures the end-to-end drain rate (count overridable via
`AA_AUDIT_VERIFY_EVENTS`). On a macOS Docker dev box:

| Events | Wall time | Rate |
|--------|-----------|------|
| 2,000 | 0.73 s | ~2,725 events/sec |
| 5,000 | 1.88 s | ~2,663 events/sec |

≈ **2.7k events/sec**, roughly **18× short** of the 50k/sec target.

### Root cause

1. Per-row `INSERT … ON CONFLICT` (one statement per event).
2. Per-message JetStream ack (one round-trip per event).
3. Bursts larger than the bounded `mpsc(8192)` are dropped un-acked and only
   redeliver after `ack_wait = 30s`, so a 50k burst degrades into 30s
   redelivery cycles (functionally lossless, but throughput collapses — the
   50k run did not complete in 20 min).

The functional behaviour is correct (zero loss, idempotent, bounded memory); the
throughput target requires batched DB writes + batched acks.

## Outcome

- Functional ACs: **pass**.
- Throughput AC: **fails** → filed **AAASM-2563** `[BUG]` (perf follow-up:
  batch DB writes / acks; idempotency via the `event_id` PK keeps batching safe).

The Story's functional scope is verified and merge-ready; the 50k/sec
optimization is tracked separately under AAASM-2563.
