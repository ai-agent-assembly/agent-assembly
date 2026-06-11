# Data flows

This page follows the **data** — not the control decisions — through the system:
how an intercepted event becomes a decision, then a durable, tamper-evident
audit record. For the decision logic itself, see [Key workflows](workflows.md);
for the trust view, see the [Security Model](../security/audit-assurance.md).

---

## End-to-end: layer → gateway → policy → audit → storage

```mermaid
flowchart TD
    subgraph layers["Interception layers"]
        L1["L1 SDK<br/>(aa-sdk-client)"]
        L2["L2 proxy<br/>(aa-proxy)"]
        L3["L3 eBPF<br/>(aa-ebpf)"]
    end

    subgraph runtime["aa-runtime"]
        IPC["ipc/ — UDS IpcFrame"]
        PIPE["pipeline — enrich + batch"]
        ENF["enforcement — scan + redact<br/>(fail-closed)"]
        PUB["audit_publisher — NATS"]
    end

    subgraph gateway["aa-gateway"]
        POL["PolicyService.CheckAction"]
        AW["AuditWriter (audit.rs)<br/>append-only JSONL"]
        SAN["sanitizer/ — sanitize()<br/>drop 'never store' data"]
        CONS["audit_consumer.rs<br/>JetStream pull-consumer"]
    end

    NATS[("NATS JetStream<br/>assembly.audit.>")]
    JSONL[("per-session JSONL<br/>tamper-evident")]
    PG[("aa-storage-postgres<br/>audit_logs")]

    L1 -->|IpcFrame| IPC
    L2 -->|event| IPC
    L3 -->|ring buffer| IPC
    IPC --> PIPE --> ENF
    ENF --> POL
    ENF --> PUB
    POL -->|decision| AW
    AW --> JSONL
    AW -. dual sink .-> PG
    PUB -->|publish| NATS
    NATS --> CONS
    CONS --> SAN --> PG
```

There are **two paths** an audit record can take, and the design is
deliberately layered so neither is a single point of failure:

1. **Synchronous decision audit (in-gateway).** Every `CheckAction` decision is
   appended by `AuditWriter` (`aa-gateway/src/audit.rs`) as one JSON line to a
   per-session JSONL file. The JSONL file is the **tamper-evident primary
   record** (hash-chained `AuditEntry`). When a durable `StorageBackend` is
   configured, the writer follows each JSONL append with
   `storage.append_audit_event(...)` (the *dual-sink* path); a storage failure is
   logged but never stops the pipeline, and a restart can replay missed entries
   from the JSONL file.
2. **Asynchronous event stream (via NATS).** `aa-runtime`'s `audit_publisher`
   publishes audit records to the NATS subject
   `assembly.audit.<tenant>.<agent>` and returns control to the agent
   immediately (fire-and-forget). The gateway's `audit_consumer` is a durable
   JetStream pull-consumer over `assembly.audit.>` that batches, sanitises, and
   persists to Postgres.

---

## The audit write path in detail

```mermaid
sequenceDiagram
    autonumber
    participant RT as aa-runtime<br/>audit_publisher
    participant NATS as NATS JetStream<br/>assembly.audit.>
    participant Cons as audit_consumer.rs<br/>(producer task)
    participant Chan as bounded mpsc
    participant Writer as audit_consumer.rs<br/>(DB-writer task)
    participant San as sanitizer::sanitize
    participant PG as audit_logs<br/>(Postgres)

    RT->>NATS: publish AuditEvent (fire-and-forget)
    NATS->>Cons: deliver (pull-consumer, AckPolicy::All)
    Cons->>Chan: send().await (backpressure, never drop)
    Chan->>Writer: drain up to batch_size
    loop per batch
        Writer->>San: sanitize(RawAuditEvent)
        San-->>Writer: SanitizedAuditEvent / HeartbeatUpdate
        Writer->>PG: multi-row INSERT … ON CONFLICT (event_id) DO NOTHING
        Writer->>NATS: ack last message (acks whole batch)
    end
```

Properties enforced by `aa-gateway/src/audit_consumer.rs`:

- **Batching** — the writer drains the channel into batches and writes each with
  a single multi-row `INSERT`, one DB round-trip and one ack per batch.
- **Idempotency** — each event becomes an `AuditLogRecord` keyed by its own
  `event_id`; `ON CONFLICT (event_id) DO NOTHING` dedupes retries and intra-batch
  repeats (bumping `aa_audit_duplicates_total`).
- **At-least-once** — `AckPolicy::All` acks the batch's last message only after
  the whole batch persists; a failed batch is left un-acked so NATS redelivers
  after `ack_wait`.
- **Backpressure** — the channel is bounded; a full channel makes the producer
  *await* room rather than drop, so bursts queue durably in JetStream
  (`aa_audit_consumer_channel_depth` exposes the in-flight depth).

---

## The write-boundary sanitizer

Before *anything* reaches `audit_logs`, the consumer runs the write-boundary
`sanitize()` pass (`aa-gateway/src/sanitizer/`). The sanitizer is the *last* line
of defense and never trusts the inbound shape — it operates on the untyped JSON
tree as received:

```mermaid
flowchart LR
    Raw["RawAuditEvent<br/>(untyped JSON)"] --> Strip["strip banned keys<br/>recursively"]
    Strip --> Drop["drop unknown top-level fields<br/>(count them as a metric)"]
    Drop --> Beat{"heartbeat?"}
    Beat -->|yes| Collapse["collapse into<br/>HeartbeatUpdate<br/>(last-seen, not per-beat)"]
    Beat -->|no| Out["SanitizedAuditEvent"]
    Collapse --> Out
```

Four classes of "never store" data are dropped at this boundary regardless of
what an upstream SDK or proxy emitted: raw LLM prompts / completions, full
tool-call payloads, eBPF packet bodies, and per-heartbeat sequence records.
Counting unknown fields means a newly-emitting sender is noticed rather than
silently persisted.

> **Two-layer defense:** the *sender* (runtime enforcement) is the first line —
> it scans and redacts before forwarding; the *sanitizer* is the last line — it
> strips before persisting. Neither trusts the other. See
> [trust boundaries](../security/trust-boundaries.md).

---

## Storage data flow

The gateway never talks to a concrete database directly — it goes through the
`aa-storage` trait facade, and the active **driver** decides where bytes land.

```mermaid
flowchart TD
    GW["aa-gateway"] --> Facade["aa-storage<br/>trait facade + Registry"]
    Facade --> Cache["aa-cache<br/>L1Cache (cache-aside, TTL)"]
    Cache --> Driver{"active driver"}
    Driver --> Mem[("aa-storage-memory<br/>DashMap")]
    Driver --> PG[("aa-storage-postgres<br/>sqlx")]
    Driver --> Redis[("aa-storage-redis<br/>deadpool")]
    Driver --> SQLite[("aa-storage-sqlite-buffer<br/>local write-buffer")]
```

- **L1 cache.** Read-heavy stores (e.g. the policy store) are fronted by
  `aa-cache::L1Cache`, a `DashMap`-backed cache-aside layer with TTL and
  stampede protection — concurrent misses for the same key collapse to one
  backend load.
- **Driver selection.** `aa-storage`'s `Registry` + `register_builtin_drivers`
  resolves the configured backend at boot; `aasm config validate` and
  `aasm config boot` exercise this loader.
- **Audit storage shape.** `audit_entry_to_storage_event`
  (`aa-gateway/src/storage/audit_bridge.rs`) maps a hash-chained `AuditEntry`
  into the storage `AuditEvent` keyed by `event_id`; the Postgres driver writes
  it as a metadata-only `audit_logs` row (no raw payloads — those were already
  dropped by the sanitizer).

---

## Summary of the data's journey

| Stage | Component | Form of the data |
|---|---|---|
| Observe | L1/L2/L3 layer | agent action → `aa-proto` event |
| Normalise | `aa-runtime` pipeline | `EnrichedEvent` |
| Redact | `aa-runtime` enforcement | secrets scanned, oversized redacted whole |
| Decide | `aa-gateway` policy engine | `Allow` / `Deny` / `RequireApproval` |
| Record (sync) | `AuditWriter` | hash-chained JSONL line (+ optional dual sink) |
| Publish (async) | `audit_publisher` → NATS | `assembly.audit.<tenant>.<agent>` |
| Sanitise | `sanitizer::sanitize` | "never store" data stripped |
| Persist | `aa-storage-postgres` | `audit_logs` row, deduped by `event_id` |
