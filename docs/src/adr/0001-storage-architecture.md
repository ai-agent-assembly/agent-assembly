# ADR 0001: Storage Architecture — SQLite (local) / PostgreSQL + TimescaleDB (production)

**Status**: Accepted
**Date**: 2026-05
**Spec reference**: lines 7107–7215

---

## Context

`agent-assembly` needs to persist three categories of data, and the spec (lines 7113–7134) is explicit that they have fundamentally different access patterns and **must not** be forced into a single store:

| Category | Nature | Query pattern |
| --- | --- | --- |
| **① Audit events** — tool-call records, policy decisions, behaviour log | write-heavy, append-only, strong time-series, large volume | time-range scan, filter by `agent_id`, filter by `dry_run` |
| **② Agent registry & config** — online agents, identity, policy configuration | read-heavy, small volume, requires ACID | key lookup, simple joins |
| **③ Metrics / aggregates** — token usage, cost, event rate, anomaly data | time-series, requires fast rollup | time-series range query, rollup, window functions |

The product ships in two deployment modes — **Local Dev Mode** (single machine, zero ops, fast feedback loop) and **Production** (multi-instance gateway behind a load balancer, durable retention, compliance evidence) — and a single backend cannot serve both well.

Without a deliberate decision recorded here, two failure modes become likely as Epic 18 lands:

1. Future contributors encountering `sqlite.rs` and `postgres.rs` side by side propose replacing one to "simplify"; the asymmetric requirements of the two deployment modes are not visible from the code alone.
2. A contributor reading "time-series workloads at thousands of events per second" reaches for Cassandra by reflex without seeing that the agent-registry ACID requirement and the operational cost rule it out at current scale.

---

## Decision

| Concern | Choice |
| --- | --- |
| Local Dev Mode storage | **SQLite** (single file at `~/.aasm/local.db`, WAL journal mode) |
| Production storage | **PostgreSQL 15+** with the **TimescaleDB 2.x** extension |
| Policy hot-path cache | **Redis 7+**, **optional**, off by default; enable only when policy-eval latency becomes measurable |
| Wide-column / NoSQL audit store | **Not used** (see [Why not Cassandra](#cassandra-rejected) below) |
| Backend abstraction | A single `StorageBackend` trait in `aa-gateway/src/storage/`; both SQLite and Postgres implement it; business logic depends only on the trait |
| Compression / retention for warm data | TimescaleDB native column-store compression (production); manual rolling-delete (local dev) |

The `StorageBackend` trait surface, configuration schema, retention-policy structure, and environment-variable overrides are defined in [Epic AAASM-1569](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569).

---

## Storage Stack

### Local Dev Mode

```
SQLite (single file: ~/.aasm/local.db, journal_mode = wal)
  ├── Audit events      — table with (ts, agent_id) index
  ├── Agent registry    — table
  ├── Policy versions   — table (BLOB for the YAML/JSON document)
  └── Metrics           — in-memory aggregation only; not persisted
                          (dev does not need historical trends)
```

Rationale: zero external dependencies, single process, single user. A developer can open the file in any SQLite browser. Performance is sufficient because dev volumes do not approach the multi-writer or multi-machine ceiling.

### Production (Self-hosted / SaaS)

```
PostgreSQL 15+
  + TimescaleDB 2.x extension     (same Postgres instance, single connection pool)
    ├── audit_events  (hypertable, chunk_interval = 7 days,
    │                  compression policy = 30 days)
    ├── metrics       (hypertable, chunk_interval = 1 day)
    ├── agent_registry  (standard table, JSONB metadata column)
    └── policy_versions (standard table, JSONB document column)

Redis 7+                          (optional; enable when measured needed)
  ├── Policy cache (TTL: 30s)     — hot-path policy decisions
  ├── Session state               — approval queue, pending decisions
  └── Rate-limit counters         — per-agent, per-team
```

Rationale: PostgreSQL alone handles the registry and policy store cleanly (ACID, JSONB for flexible schema, async-native via `sqlx`). TimescaleDB is a PostgreSQL **extension** — not a separate system — so it adds time-series partitioning and compression to the same instance with negligible operational overhead. Redis stays opt-in because policy-eval latency is acceptable straight from Postgres at current scale.

---

## Alternatives Considered

### Cassandra (rejected)

Cassandra is appropriate for workloads with **extremely high sustained write volume, multi-region geo-distribution, and a tolerance for eventual consistency** (the Netflix-scale event-stream archetype). It is the wrong fit here because:

1. **ACID is required for the agent registry.** Registry mutations (agent online / offline, identity rotation, enforcement-mode change) must be linearizable; an eventually-consistent registry produces visible correctness bugs — for example, an agent that is "offline" in one node's view and "online" in another's, racing policy evaluations against itself.
2. **Current scale is far below Cassandra's sweet spot.** Early production deployments are in the low-thousands-of-events-per-second range; PostgreSQL + TimescaleDB handles this comfortably on commodity hardware.
3. **Operational complexity is disproportionate.** Cassandra demands cluster sizing, repair scheduling, compaction tuning, and tombstone management. For a small operating team, this overhead is not justified by any benefit at the current data volume.
4. **No reuse of existing investment.** Postgres expertise, `sqlx` integration, and the same TimescaleDB hypertable cover the time-series workload without introducing a second data system.

### MongoDB (rejected)

Considered for the agent registry and policy store because of the JSON-document schema flexibility. Rejected because:

- PostgreSQL's `JSONB` column type covers the same flexible-schema use case (indexed, queryable, schema-evolution-friendly) without introducing a second data system to operate.
- Strict ACID semantics for the registry are stronger in Postgres than in MongoDB's default replication model.
- Splitting "events go to one DB, registry goes to another" complicates joins (for example, listing audit events grouped by registered-agent metadata) that PostgreSQL handles trivially.

### Single SQLite for production (rejected)

Considered for symmetry with Local Dev Mode. Rejected because:

- SQLite has no network protocol; a multi-instance gateway cannot share a single database file safely.
- SQLite's single-writer model becomes a hard bottleneck for the audit-event write rate seen in production.
- WAL mode improves concurrent reads but does not address the multi-machine or multi-writer requirement.
- Backup, replication, and point-in-time recovery — table-stakes in production — are not first-class in SQLite.

### PostgreSQL alone (without TimescaleDB) (rejected)

Plain PostgreSQL is viable for the registry and policy store, but for `audit_events`:

- Time-bucketed query patterns degrade as the table grows; manual partition management is error-prone.
- Compression of old data requires an external tool or a custom ETL job.
- TimescaleDB provides both (hypertable partitioning + native compression) as PostgreSQL extensions, so adopting it costs only an extension install — no separate process or operational target.

Since TimescaleDB is strictly additive (compatible with the rest of the Postgres schema and tooling), there is no reason to defer it.

---

## Consequences

### Positive

- **Zero external dependencies for local development.** A first-time contributor can run the gateway and immediately have a working, persistent store.
- **Production-grade time-series performance** via TimescaleDB hypertables and compression policies, without standing up a separate data system.
- **Business logic stays storage-agnostic.** All gateway code talks to the `StorageBackend` trait; swapping backends is a configuration change, not a code change.
- **Compression and retention come for free in production** via TimescaleDB compression policies; the application-level `apply_retention` only handles tier transitions (warm → cold archive or drop).
- **Compliance posture is clean** (GDPR, SOC 2 Type II, ISO 27001): retention is operator-configurable and audit-event durability is guaranteed once the row commits.

### Negative / Accepted trade-offs

- **Two backend implementations to maintain.** The CI matrix must cover both SQLite and PostgreSQL. The `StorageBackend` trait constrains this cost: feature parity is enforced at compile time.
- **TimescaleDB extension is an operational requirement** for production PostgreSQL deployments. Managed-PG offerings (Aiven, Timescale Cloud, RDS with the extension available) cover this; self-hosted operators must install the extension package.
- **Redis adds a moving part** when enabled. The optional, off-by-default flag keeps it out of the dependency surface until measured latency justifies it.
- **Local-dev and production semantics differ slightly** (for example, no compression in SQLite). The differences are documented in the gateway config reference and reflected in `aasm status` output.

---

## Spec Reference

| Spec lines | Topic |
| --- | --- |
| 7107–7215 | Complete storage architecture discussion (Q&A format) |
| 7113–7134 | Three data categories and their access patterns |
| 7140–7155 | Local Dev Mode storage stack (SQLite) |
| 7157–7191 | Production storage stack (PostgreSQL + TimescaleDB) |
| 7165–7172 | "Why not Cassandra" rationale |
| 7175–7213 | Recommended complete storage stack + hot / warm / cold tiering |
| 7213 | Architecture decision (one-sentence conclusion) |
| 7215 | Spec recommendation that this decision be recorded as an ADR |

---

## Related

- Epic: [AAASM-1569](https://lightning-dust-mite.atlassian.net/browse/AAASM-1569) — Durable Persistence Layer (this ADR is its S-L deliverable)
- Story: [AAASM-1593](https://lightning-dust-mite.atlassian.net/browse/AAASM-1593) — ADR 0001 story ticket
- All E18 implementation stories (`StorageBackend` trait, SQLite backend, PostgreSQL backend, migration runner, retention engine, etc.) implement the decision recorded here.
