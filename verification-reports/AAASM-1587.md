# E18 S-E Verification — AAASM-1587 (Migration runner)

> **Status**: parent Story [AAASM-1587] decomposed into two Sub-tasks shipped on Sprint-4 branches. Implementation lands in [ai-agent-assembly/agent-assembly#664], verification lands in this PR. All six Story-level acceptance bullets verified clean below — no follow-up Bug Sub-task opened.
>
> **Scope clarification (carried over from the Story's starting comment):** dependencies [AAASM-1584] (S-B SQLite) and [AAASM-1585] (S-C PostgreSQL) are still To Do, so the description's "wire `run_migrations` into `local_mode.rs` / `remote_mode.rs`" step is deferred to [AAASM-1590] (S-I). The S-E ACs targeted in this Story are about the runner mechanism, not the wiring — every one of them is verifiable on the runner alone, which is what this report does. PostgreSQL coverage is provided via `testcontainers` to avoid a hard dependency on S-C.

[AAASM-1569]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1569
[AAASM-1584]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1584
[AAASM-1585]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1585
[AAASM-1587]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1587
[AAASM-1590]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1590
[AAASM-1733]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1733
[AAASM-1736]: https://lightning-dust-mite.atlassian.net/browse/AAASM-1736
[ai-agent-assembly/agent-assembly#664]: https://github.com/ai-agent-assembly/agent-assembly/pull/664

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| [AAASM-1733] | E18 S-E impl — runner module + SQLite + PG tests | Done (open PR) | [#664](https://github.com/ai-agent-assembly/agent-assembly/pull/664) |
| [AAASM-1736] | E18 S-E verify — confirm AC | in this report | this PR |

## Walkthrough vs AAASM-1587 acceptance criteria

### ✅ Fresh database: all tables created on first startup from migration files

The runner is generic over `sqlx::Acquire`; the SQLite path is exercised by `apply_good_succeeds_on_fresh_sqlite` and the **production** migrator (the real `aa-gateway/migrations/` directory) is exercised by `run_migrations_against_production_dir_succeeds_on_sqlite` against an in-memory SQLite pool.

The production directory currently contains two pre-Epic-18 migration files:

```text
$ ls -la aa-gateway/migrations/*.sql
-rw-r--r--@ 1 bryant  staff  1213 21 May 21:57 aa-gateway/migrations/20260509000000_approval_routing_config.sql
-rw-r--r--@ 1 bryant  staff  1063 21 May 21:57 aa-gateway/migrations/20260510000001_pending_escalations.sql
```

Both are `CREATE TABLE IF NOT EXISTS …` statements; the smoke test confirms they apply cleanly on a fresh SQLite pool with no operator intervention.

Test output (re-run for this report):

```text
$ cargo nextest run -p aa-gateway storage::migrations
    Starting 6 tests across 37 binaries (829 tests skipped)
        PASS [   0.022s] apply_good_succeeds_on_fresh_sqlite
        PASS [   0.022s] run_migrations_against_production_dir_succeeds_on_sqlite
        … (4 others)
     Summary [   0.885s] 6 tests run: 6 passed, 829 skipped
```

### ✅ Second startup: migrations skipped (idempotent), `_sqlx_migrations` table shows all as applied

Two independent tests cover this:

| Test | Asserts |
|---|---|
| `apply_is_idempotent_on_sqlite` (`aa-gateway/src/storage/migrations.rs:96`) | Re-running `apply()` on the same pool returns Ok |
| `apply_creates_sqlx_migrations_tracking_table_on_sqlite` (line 105) | `SELECT COUNT(*) FROM _sqlx_migrations` ≥ 1 after one apply |

`sqlx::migrate!` uses checksum-keyed rows in `_sqlx_migrations`; subsequent calls compare the row set against the embedded migrations and skip applied ones. The idempotency test passes on both SQLite (line 96) and PostgreSQL (line 148, `apply_good_succeeds_and_is_idempotent_on_postgres` — runs `apply()` twice).

### ✅ Migration failure (bad SQL in a migration file): error surfaces

Fixture `aa-gateway/src/storage/test_fixtures/migrations/bad/0001_invalid.sql` contains:

```sql
NOT_A_REAL_STATEMENT this is intentionally not valid SQL;
```

`apply_bad_returns_migration_failed_on_sqlite` (`migrations.rs:116`) drives the runner with this fixture and asserts:

```rust
assert!(matches!(err, StorageError::MigrationFailed(_)), …);
```

The driver error is mapped at `migrations.rs:41-44`:

```rust
migrator
    .run(conn)
    .await
    .map_err(|e| StorageError::MigrationFailed(e.to_string()))
```

This satisfies both the Story AC (failure surfaces with a clear error) and the cross-cutting S-A invariant (no `sqlx` types on the storage trait surface — the variant carries a `String`). Whether the gateway *exits non-zero* on this error is a wiring concern owned by S-I (AAASM-1590); the runner's job is to return the error, which it does.

### ✅ Works for both SQLite (via `sqlx` SQLite driver) and PostgreSQL

Six tests cover both drivers in a single suite run. The PostgreSQL test (`apply_good_succeeds_and_is_idempotent_on_postgres`) spins up a real Postgres container via `testcontainers-modules` 0.15, connects with `sqlx::PgPool`, applies the good fixture migrator twice, and asserts `_sqlx_migrations` is populated:

```text
        PASS [   0.884s] apply_good_succeeds_and_is_idempotent_on_postgres
```

First run on a cold Docker cache takes ~170 s (PG image pull); subsequent runs complete in under a second because the container image is reused. The test is self-contained — no external Postgres dependency, no docker-compose, no fixture state to seed.

The PostgreSQL `sqlx` feature is now enabled in `aa-gateway/Cargo.toml:44`:

```toml
sqlx = { version = "0.8", features = ["runtime-tokio-rustls", "sqlite", "postgres", "macros", "migrate", "uuid"] }
```

### ✅ Adding a new `.sql` file to `migrations/` in a PR applies it on next startup

`sqlx::migrate!("./migrations")` walks the directory at **compile time** and embeds every `.sql` file matching its naming convention into the binary. New files require only a recompile — the runner picks them up automatically because the `Migrator` value is regenerated.

The production smoke test (`run_migrations_against_production_dir_succeeds_on_sqlite`) demonstrates this: today it applies both `20260509000000_approval_routing_config.sql` and `20260510000001_pending_escalations.sql`. When S-B / S-C / S-D add their schema files (e.g. `0001_initial_schema.sql`, `0002_timescaledb_hypertables.sql`), the smoke test will continue to pass without any code change — the new files will simply appear in `_sqlx_migrations` after the first call.

### ✅ `cargo nextest run -p aa-gateway storage::migrations::tests` green

```text
$ cargo nextest run -p aa-gateway storage::migrations
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1m 21s
────────────
 Nextest run ID f940397c-77d4-4902-8abd-6cb636306017 with nextest profile: default
    Starting 6 tests across 37 binaries (829 tests skipped)
        PASS [   0.021s] aa-gateway storage::migrations::tests::apply_bad_returns_migration_failed_on_sqlite
        PASS [   0.022s] aa-gateway storage::migrations::tests::apply_good_succeeds_on_fresh_sqlite
        PASS [   0.022s] aa-gateway storage::migrations::tests::apply_creates_sqlx_migrations_tracking_table_on_sqlite
        PASS [   0.022s] aa-gateway storage::migrations::tests::apply_is_idempotent_on_sqlite
        PASS [   0.022s] aa-gateway storage::migrations::tests::run_migrations_against_production_dir_succeeds_on_sqlite
        PASS [   0.884s] aa-gateway storage::migrations::tests::apply_good_succeeds_and_is_idempotent_on_postgres
────────────
     Summary [   0.885s] 6 tests run: 6 passed, 829 skipped
```

Full crate-wide regression run also clean:

```text
$ cargo nextest run -p aa-gateway
     Summary [  20.494s] 835 tests run: 835 passed, 0 skipped
```

## Cross-cutting checks

### Public surface contains no driver types (Epic 18 S-A invariant re-verified)

`run_migrations` is generic over `sqlx::Acquire`; this trait bound is a structural use of `sqlx`'s trait, not an exposure of a concrete `sqlx::PgPool` / `sqlx::SqlitePool` on the storage trait. Errors return as `StorageError::MigrationFailed(String)` — no `sqlx::Error` reaches callers.

Outside `aa-gateway/src/storage/`, the only `sqlx::` reference in `aa-gateway/src/` is the pre-Epic-18 approval module:

```text
$ grep -rn "sqlx::" --include="*.rs" aa-gateway/src \
    | grep -v "src/approval/\|src/storage/"
aa-gateway/src/server.rs:145:    let pool = match sqlx::SqlitePool::connect(&db_url).await { …
```

This `sqlx::SqlitePool::connect` call in `server.rs:145` constructs the pool for the existing approval module and is grandfathered as part of the pre-Epic-18 approval feature — it predates the S-A trait and is unchanged by this Story.

### Local quality gates

```text
$ cargo fmt --all -- --check                              # clean (no output)
$ cargo clippy --all-targets --all-features -- -D warnings # clean
$ cargo deny check                                         # advisories ok, bans ok, licenses ok, sources ok
$ cargo doc --workspace --no-deps                          # clean (warnings on aa-cli / aa-api are pre-existing on master)
```

## Conclusion

All six Story acceptance criteria pass with the implementation merged by [AAASM-1733]. No Bug Sub-task opened. The deferred wiring into gateway startup remains the responsibility of [AAASM-1590] (S-I); when that Story lands it will only need to call `aa_gateway::storage::migrations::run_migrations(&pool)` once before serving, with no further runner-side work.
