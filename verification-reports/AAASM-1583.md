# E18 S-A Verification — AAASM-1583 (`StorageBackend` trait)

> **Status**: parent Story [AAASM-1583] sub-tasks both shipped on Sprint-4
> branches. Implementation lands in [AI-agent-assembly/agent-assembly#644],
> verification lands in this PR. All six Story-level acceptance bullets
> verified clean below — no follow-up Bug Sub-task opened.

[AAASM-1569]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1569
[AAASM-1583]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1583
[AAASM-1694]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1694
[AAASM-1695]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1695
[AI-agent-assembly/agent-assembly#644]: https://github.com/AI-agent-assembly/agent-assembly/pull/644

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| [AAASM-1694] | E18 S-A Impl — define trait + value types | Done (open PR) | [#644](https://github.com/AI-agent-assembly/agent-assembly/pull/644) |
| [AAASM-1695] | E18 S-A Verify — confirm AC | in this report | this PR |

## Walkthrough vs AAASM-1583 acceptance criteria

### ✅ `StorageBackend` trait defined and exported from `aa-gateway::storage`

File evidence:

- `aa-gateway/src/storage/backend.rs:26` — `#[async_trait] pub trait StorageBackend: Send + Sync + 'static { … }`
- `aa-gateway/src/storage/mod.rs:35` — `pub use backend::StorageBackend;`

The dyn-safety probe in `aa-gateway/tests/storage_trait_object_safety.rs:103-106` constructs a `Box<dyn StorageBackend>` from a no-op stub, demonstrating that the trait is both publicly importable and object-safe.

### ✅ `StorageError` covers all failure modes with `thiserror` derives

File: `aa-gateway/src/storage/error.rs`. Six variants confirmed by the exhaustive-match probe in `tests/storage_trait_object_safety.rs:109-131`:

| Variant | `thiserror` message |
|---|---|
| `ConnectionFailed(String)` | `"connection failed: {0}"` |
| `QueryFailed(String)` | `"query failed: {0}"` |
| `MigrationFailed(String)` | `"migration failed: {0}"` |
| `NotFound(String)` | `"record not found: {0}"` |
| `Conflict(String)` | `"conflict: {0}"` |
| `RetentionError(String)` | `"retention error: {0}"` |

The `storage_error_covers_six_failure_modes` test exhaustively matches every variant — adding a new variant without updating the test causes a compilation error.

### ✅ `StorageHealth`, `RowCounts`, `RetentionStats`, `AuditFilter` types defined

| Type | File | Test exercising it |
|---|---|---|
| `StorageHealth`  | `aa-gateway/src/storage/health.rs:30`    | `supporting_types_are_publicly_constructible` (line 140) |
| `RowCounts`      | `aa-gateway/src/storage/health.rs:18`    | line 138 |
| `RetentionStats` | `aa-gateway/src/storage/retention.rs:33` | constructed by `NoopStorage::apply_retention` (line 82) |
| `AuditFilter`    | `aa-gateway/src/storage/audit.rs:39`     | line 135 |

### ✅ No database-driver imports (`sqlx`, `rusqlite`, etc.) anywhere under `aa-gateway/src/storage/`

```text
$ grep -rE 'use (sqlx|rusqlite|postgres|redis|tokio_postgres)' aa-gateway/src/storage/
(no matches)
```

This holds for **every file** under `aa-gateway/src/storage/`, not only `mod.rs`. The bulk of `sqlx` imports in `aa-gateway/Cargo.toml` exist because of features pulled in transitively; concrete SQLite (S-B) and PostgreSQL (S-C) backends will introduce them inside `storage/sqlite.rs` / `storage/postgres.rs` in their own Stories.

### ✅ Docs on every trait method explaining expected behaviour and error conditions

Every method in `aa-gateway/src/storage/backend.rs` carries a `///` block with:

1. A behavioural summary.
2. An `# Errors` section enumerating which `StorageError` variants the method may produce.

Spot check (`get_agent`, line 62-69):

```rust
/// Return the agent record for `id`, if registered.
///
/// # Errors
///
/// Returns `Ok(None)` for unknown ids; only backend failure surfaces
/// as [`StorageError::QueryFailed`](super::StorageError::QueryFailed) /
/// [`StorageError::ConnectionFailed`](super::StorageError::ConnectionFailed).
async fn get_agent(&self, id: &AgentId) -> StorageResult<Option<AgentRecord>>;
```

`cargo doc -p aa-gateway --no-deps` produces zero warnings inside `aa-gateway/src/storage/` (pre-existing rustdoc warnings under `aa-gateway/src/registry/` and elsewhere are untouched by this PR).

### ✅ `cargo check -p aa-gateway` green with the trait defined

```text
$ cargo check -p aa-gateway
    Checking aa-gateway v0.0.1
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 9.33s
```

`cargo nextest run -p aa-gateway --test storage_trait_object_safety` — 3 tests, 3 passed:

```text
    Starting 3 tests across 1 binary
        PASS [   0.009s] (1/3) aa-gateway::storage_trait_object_safety storage_error_covers_six_failure_modes
        PASS [   0.009s] (2/3) aa-gateway::storage_trait_object_safety storage_backend_trait_is_dyn_safe
        PASS [   0.009s] (3/3) aa-gateway::storage_trait_object_safety supporting_types_are_publicly_constructible
     Summary [   0.010s] 3 tests run: 3 passed, 0 skipped
```

## Module layout shipped

```text
aa-gateway/src/storage/
  mod.rs        (module root + public re-exports)
  error.rs      (StorageError, StorageResult<T>)
  health.rs     (HealthStatus, RowCounts, StorageHealth)
  agent.rs      (AgentRecord, AgentFilter, TeamId — storage-layer types)
  audit.rs      (AuditEvent, AuditFilter — storage-layer types)
  metric.rs     (Metric, MetricQuery, MetricPoint)
  policy.rs     (PolicyDocument, PolicyMeta, PolicyVersion — storage-layer types)
  retention.rs  (ColdAction, RetentionPolicy, RetentionStats)
  backend.rs    (`#[async_trait] pub trait StorageBackend` — 16 methods)
```

## Adaptations vs the ticket's literal trait snippet

The ticket's example trait body references types that don't yet exist in the
crate (e.g. it names `AuditEvent` but `aa-core` only has `AuditEntry`). The
shipped trait keeps the method shape but defines its own storage-layer
records (`storage::AuditEvent`, `storage::AgentRecord`, etc.) rather than
reusing the runtime types. Rationale documented inline in
`aa-gateway/src/storage/mod.rs:18-22`:

> The storage layer defines its own value types … rather than reusing the
> gateway's richer runtime structs. Keeping the two sides separate prevents
> the storage schema from drifting whenever a runtime type grows new fields.

No AC bullet is downscoped by this choice — every named type in the AC
(`StorageHealth`, `RowCounts`, `RetentionStats`, `AuditFilter`) is shipped
with the exact name the ticket gave.

## Follow-up Stories under AAASM-1569 (unchanged by this verification)

- S-B [AAASM-1584] — SQLite implementation (will populate `storage/sqlite.rs`)
- S-C [AAASM-1585] — PostgreSQL implementation (will populate `storage/postgres.rs`)
- S-D [AAASM-1586] — TimescaleDB hypertables
- S-E [AAASM-1587] — Migration runner
- S-F [AAASM-1588] — Retention engine
- S-G [AAASM-1589] — Redis cache (optional)
- S-H [AAASM-1582] — Storage config
- S-I [AAASM-1590] — Wire the trait into the gateway, removing in-memory stores
- S-J [AAASM-1591] — `aasm status` storage health
- S-K [AAASM-1592] — Dashboard retention-policy UI
- S-L [AAASM-1593] — ADR 0001 storage architecture

[AAASM-1582]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1582
[AAASM-1584]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1584
[AAASM-1585]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1585
[AAASM-1586]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1586
[AAASM-1587]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1587
[AAASM-1588]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1588
[AAASM-1589]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1589
[AAASM-1590]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1590
[AAASM-1591]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1591
[AAASM-1592]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1592
[AAASM-1593]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1593
