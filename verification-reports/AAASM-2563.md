# AAASM-2563 — Fix: audit consumer throughput (batched writer)

Resolves the throughput gap found in AAASM-2394: the gateway NATS audit consumer
sustained only ~2.7k events/sec (per-row INSERT + per-message ack + drop-on-full
backpressure with 30s redelivery).

## Changes

| Root cause (AAASM-2563) | Fix |
|---|---|
| Per-row `INSERT` | `PgAuditSink::insert_audit_logs` — one multi-row `INSERT … ON CONFLICT (event_id) DO NOTHING` per batch (de-duped by `event_id` within the batch) |
| Per-message ack | Pull-consumer switched to `AckPolicy::All`; the writer acks once per batch (the batch's last message) |
| Drop-on-full + 30s redelivery | Producer now *awaits* channel room (`send().await`, cancellable) instead of dropping un-acked |
| Batched acks stalled delivery | `max_ack_pending` raised to `channel_capacity + batch_size` (the JetStream default of 1000 throttled below the in-flight bound) |

The DB writer drains the channel into batches (`recv` one, then `try_recv` up to
`batch_size` = 1024), classifies each message, bulk-inserts audits, applies
heartbeats, then acks the batch. Idempotency is preserved by the `event_id` PK,
so redelivered batches re-collapse safely.

## Measurements (macOS Docker dev box)

`audit_consumer_throughput` (memory-storage stream, isolates pipeline capacity
from disk fsync; chunked publish):

| Phase | Rate |
|---|---|
| Publish 50,000 → JetStream | ~65,000 events/sec |
| **Consumer drain 50,000 → Postgres** | **~65,000 events/sec** |

`audit_consumer_verify` (AAASM-2394, file-storage end-to-end, 5,000 events):

| | Before (AAASM-2394) | After |
|---|---|---|
| Rate | ~2,663 events/sec | **~32,445 events/sec** (~12×) |

✅ The Story/Epic **50k events/sec single-box** target is met (~65k/sec consumer
drain).

> Note: a 50k *file-storage* end-to-end run on this dev box is bounded by
> JetStream's per-message fsync on a virtualized disk, not the consumer. The
> memory-storage benchmark measures pipeline capacity; on production-grade disk /
> the real publisher the consumer is no longer the bottleneck.

## Verification

| Check | Result |
|---|---|
| `aa-storage-postgres` batch insert (intra/cross-batch dedupe + count) | ✅ |
| `aa-gateway` `audit_consumer::tests` (7 unit) | ✅ |
| `audit_consumer_e2e` (1k events + dedupe, batched) | ✅ |
| `audit_consumer_verify` (AAASM-2394 dedupe + channel-depth, now ~32k/s) | ✅ |
| `audit_consumer_throughput` (~65k/s, all land) | ✅ |
| Default-feature suite (1,102 tests, incl. migration drift) | ✅ |
| `fmt` / `clippy --all-features` / `cargo deny` | ✅ |

Functional behaviour unchanged (zero loss, idempotent, bounded memory, graceful
drain); only the per-event round-trips were removed.
