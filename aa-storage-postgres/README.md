# aa-storage-postgres

PostgreSQL storage driver (L3 primary) for the Agent Assembly persistence layer.
Implements the `aa-storage` traits (`LifecycleStore`, `PolicyStore`, `AuditSink`,
`CredentialStore`) over a `sqlx` connection pool.

## Canonical migration set

`migrations/` in this crate is the **single source of truth** for the Phase 1 MVP
four-table schema:

| File | Table | Notes |
|---|---|---|
| `0001_orgs.sql` | `orgs` | Top-level tenant boundary |
| `0002_agents.sql` | `agents` | Liveness bookkeeping (`id` = canonical `AgentId` text) |
| `0003_policies.sql` | `policies` | Versioned effective policy documents |
| `0004_audit_logs.sql` | `audit_logs` | Metadata-only; `event_id UUID PRIMARY KEY` is the idempotency key |
| `0005_credentials.sql` | `credentials` | Opaque ciphertext at rest |

`audit_logs` is deliberately **metadata-only** (spec line 7551): it has no
`payload`/`body`/`prompt`/`completion` column. The `event_id` UUID is `UNIQUE NOT
NULL`, so a retried publish collapses to one row
(`INSERT … ON CONFLICT (event_id) DO NOTHING`).

The migrations are embedded at compile time and exposed as
[`aa_storage_postgres::MIGRATOR`](src/pool.rs); call
[`PostgresPool::migrate`](src/pool.rs) once on startup to apply them.

## For the Gateway team

**Do not copy these files.** `aa-gateway` must run the **same** migration set,
not a duplicate, so the async consumer and the OSS driver never drift. Depend on
this crate and run its embedded migrator:

```rust
// In aa-gateway, against a fresh Postgres:
aa_storage_postgres::MIGRATOR.run(&pool).await?;
// or, via the pool wrapper that calls the same MIGRATOR:
aa_storage_postgres::PostgresPool::connect(&cfg).await?.migrate().await?;
```

`aa-gateway/tests/migration_boot.rs` exercises exactly this against a fresh
Postgres 18, and the `migration-drift-check` CI job runs it on every change to
`aa-storage-*` or the gateway — a failed migration apply fails the build.

> `aa-gateway/migrations/postgres/` is a **separate** schema
> (`audit_events` + TimescaleDB hypertables, Epic F) and is unrelated to this
> canonical MVP set.
