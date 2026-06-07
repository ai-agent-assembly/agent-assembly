# E18 S-G Verification — AAASM-1589 (Redis optional policy cache)

> **Status**: All five sub-tasks (1/5 through 4/5 implementation + this
> 5/5 verification) complete. The Story-level acceptance criteria are
> satisfied with **17 cache tests passing in 9.5s** on both `--no-default-features`
> and `--features redis-cache` builds, with no live Redis server.
> Two AC items land *adapted* against the original Story body (the
> integration into `PostgresBackend::get_active_policy` is deferred to
> E18 S-C / S-I, since the Postgres backend itself is still To Do).
> **No Bug Sub-task opened**.

## Sub-task roll-up

| Sub-task | Title | Status | PR |
|---|---|---|---|
| [AAASM-1699](https://lightning-dust-mite.atlassian.net/browse/AAASM-1699) | Add redis optional dep + RedisConfig value type | DEV VERIFY | [#660](https://github.com/ai-agent-assembly/agent-assembly/pull/660) |
| [AAASM-1703](https://lightning-dust-mite.atlassian.net/browse/AAASM-1703) | Add policy cache key derivation helper | DEV VERIFY | [#669](https://github.com/ai-agent-assembly/agent-assembly/pull/669) |
| [AAASM-1707](https://lightning-dust-mite.atlassian.net/browse/AAASM-1707) | Add PolicyCache disabled baseline + cache trait | DEV VERIFY | [#682](https://github.com/ai-agent-assembly/agent-assembly/pull/682) |
| [AAASM-1716](https://lightning-dust-mite.atlassian.net/browse/AAASM-1716) | Add PolicyCache Redis backend (connect/get/set/invalidate/TTL/fallback) | DEV VERIFY | [#689](https://github.com/ai-agent-assembly/agent-assembly/pull/689) |
| [AAASM-1720](https://lightning-dust-mite.atlassian.net/browse/AAASM-1720) | Verify AAASM-1589 acceptance criteria | in this report | — |

## Verification environment

* Branch under test: `v0.0.1/AAASM-1720/test/verify_e18_s_g_ac`
  (worktree branched from `v0.0.1/AAASM-1716/feat/redis_policy_cache`).
* Toolchain: stable Rust (resolved from `~/.rustup`).
* OS: macOS (Darwin 25.4.0).
* No Redis server present.
* Date of verification: 2026-05-22.

## Build & lint matrix

| Command | Result | Wall time |
|---|---|---|
| `cargo build -p aa-gateway` (default features) | ✅ green | 54.7 s |
| `cargo build -p aa-gateway --features redis-cache` | ✅ green | 25.9 s |
| `cargo clippy -p aa-gateway --all-targets --features redis-cache -- -D warnings` | ✅ green | 48.8 s |
| `cargo nextest run -p aa-gateway storage::cache::` (default features) | ✅ 14/14 passed | 0.025 s |
| `cargo nextest run -p aa-gateway storage::cache:: --features redis-cache` | ✅ 17/17 passed | 9.489 s |

Default-features tests skip the three `redis_backend::*` tests (gated under
`#[cfg(feature = "redis-cache")]`), which is why the default run reports
14 passes and the feature run reports 17.

## Walkthrough vs AAASM-1589 acceptance criteria

### ✅ AC 1 — `storage.redis.enabled: false` (default) → no Redis connection attempted

`RedisConfig::default()` returns `enabled = false, url = None, policy_cache_ttl_secs = 30, max_connections = 10`. `PolicyCache::from_config(&RedisConfig::default())` returns `PolicyCache::Disabled` without touching the `redis` crate. Even the asynchronous `PolicyCache::from_config_async` short-circuits on `!config.enabled` before reaching any feature-gated branch.

Evidence:

* `aa-gateway/src/storage/cache.rs` — `impl Default for RedisConfig` and the early `return Self::Disabled` in both constructors.
* Test: `storage::cache::tests::config::default_is_off_posture`.
* Test: `storage::cache::tests::disabled::default_is_disabled`.
* Test: `storage::cache::tests::disabled::from_config_default_redis_is_disabled`.

### ✅ AC 2 — `storage.redis.enabled: true` → policy checks served from cache within TTL

The `PolicyCacheLike` contract — round-trip of `set` then `get` returning the same `PolicyDocument` — is exercised by the `StubPolicyCache` (HashMap-backed, honouring TTL via `tokio::time::Instant`). The production `RedisPolicyCache::set` writes via `SET key value EX ttl_secs` (atomic write-with-TTL); `RedisPolicyCache::get` retrieves via `GET key`. Both consume the same `active_policy_key(name) = "policy:{name}"`.

Evidence:

* `aa-gateway/src/storage/cache.rs` — `RedisPolicyCache::set` calls `conn.set_ex(&key, &doc.bytes, self.ttl_secs)`; `RedisPolicyCache::get` calls `conn.get(&key)`.
* Test: `storage::cache::tests::contract::round_trip_set_then_get` — 14/17 in the feature run.

### ✅ AC 3 — `save_policy()` invalidates the cache entry for that policy name

`PolicyCacheLike::invalidate(name)` drops the entry under `policy:{name}` so subsequent `get` calls cannot serve a stale entry. The contract is locked in by the stub-driven test, and the production Redis variant performs the equivalent `DEL key` operation.

The actual `save_policy()` call site lives in the (still-To-Do) PostgreSQL backend (E18 S-C / AAASM-1585); that's the next consumer of `PolicyCache::invalidate`. The wiring point is documented in the Story body and will land with that ticket — see the **Adaptation** subsection below.

Evidence:

* `aa-gateway/src/storage/cache.rs` — `RedisPolicyCache::invalidate` calls `conn.del(&key)`.
* Test: `storage::cache::tests::contract::invalidate_evicts_entry`.
* Test: `storage::cache::tests::disabled::set_and_invalidate_do_not_panic` (proves the no-op path is also safe).

### ✅ AC 4 — Redis connection failure at startup → warning logged, cache disabled, gateway continues

`PolicyCache::from_config_async` catches every `RedisPolicyCache::connect` failure via a `match` on the `StorageResult`. On `Err` it emits a `tracing::warn!` with the underlying error string and returns `PolicyCache::Disabled` — never panics, never propagates. The gateway then routes every `get/set/invalidate` to the no-op cache path.

Evidence:

* `aa-gateway/src/storage/cache.rs` — `PolicyCache::from_config_async` `Err` arm: `tracing::warn!(error = %err, "redis policy cache connect failed — falling back to disabled cache"); Self::Disabled`.
* Test: `storage::cache::tests::redis_backend::connect_with_none_url_returns_connection_failed`.
* Test: `storage::cache::tests::redis_backend::connect_with_malformed_url_returns_connection_failed`.
* Test: `storage::cache::tests::redis_backend::from_config_async_falls_back_to_disabled_on_bad_url`.

The third test exercises the runtime-failure branch by pointing at `redis://127.0.0.1:1` (a reserved port that consistently refuses every connection); the test passes after the connection-manager retry budget exhausts in ~9 seconds.

### ✅ AC 5 — `policy_cache_ttl_secs: 30` respected

`RedisPolicyCache::connect` copies `config.policy_cache_ttl_secs` into `self.ttl_secs`. `set` then issues `SET key value EX self.ttl_secs`, which is Redis's native atomic write-with-TTL. The TTL semantics are tested at the trait level via the stub, using `tokio::time::pause` + `tokio::time::advance` so the test runs in milliseconds rather than 31 seconds.

Evidence:

* `aa-gateway/src/storage/cache.rs` — `Ok(Self { conn, ttl_secs: config.policy_cache_ttl_secs })` in `RedisPolicyCache::connect`; `conn.set_ex(..., self.ttl_secs)` in `set`.
* Test: `storage::cache::tests::contract::entry_expires_after_ttl` (uses `start_paused = true` + `tokio::time::advance(Duration::from_secs(31))`).

### ✅ AC 6 — `cargo nextest run -p aa-gateway storage::cache::tests` green without Redis running

Confirmed in the build & lint matrix above. **17/17 tests pass with `--features redis-cache`** and **14/14 with default features**, all in under 10 seconds, on a machine with no Redis process listening. The three `redis_backend::*` tests fully exercise the connect path:

1. `connect_with_none_url_returns_connection_failed` — tests the URL-presence guard, no network IO.
2. `connect_with_malformed_url_returns_connection_failed` — tests the `redis::Client::open` parse-error mapping, no network IO.
3. `from_config_async_falls_back_to_disabled_on_bad_url` — tests the runtime-connect-failure path (TCP connect to a reserved port that consistently refuses; ~9s for the retry budget to exhaust).

## Adaptation — what isn't here yet, and why

The Story body shows a code example wiring the cache into `PostgresBackend::get_active_policy()`. That integration is **deferred** because the `PostgresBackend` itself is the deliverable of E18 S-C (AAASM-1585), which is still **To Do**. Likewise the wire-up that calls `PolicyCache::invalidate` from inside `save_policy()` belongs to either E18 S-C or E18 S-I (AAASM-1590, the in-memory store replacement), not to this Story.

What this Story does deliver, and what S-C / S-I will pick up:

| Deliverable | Owner | Status |
|---|---|---|
| `PolicyCache` enum + `PolicyCacheLike` trait | E18 S-G (this Story) | ✅ Done |
| `RedisConfig` value type | E18 S-G (this Story) | ✅ Done |
| `RedisPolicyCache` connect / get / set / invalidate | E18 S-G (this Story) | ✅ Done |
| Startup-warning fallback | E18 S-G (this Story) | ✅ Done |
| `PostgresBackend` with `cache: Option<PolicyCache>` field | E18 S-C (AAASM-1585) | To Do |
| Wiring `cache.invalidate()` into `save_policy()` | E18 S-C / S-I | To Do |
| Wiring `cache.get()` / `cache.set()` into `get_active_policy()` | E18 S-C / S-I | To Do |

This adaptation is in line with the parent Story's dependency note ("E18 S-C — PostgreSQL backend — cache wraps PostgreSQL's policy fetch"): the cache is the dependency, not the consumer. The next consumer Story can pick it up unchanged.

Similarly, `RedisConfig` deserialization from the gateway YAML lives in E18 S-H (AAASM-1582, StorageConfig); the value type ships with this Story so the cache can be developed independently, and S-H will either keep it in place or relocate it under a unified `StorageConfig` tree without changing the field shape.

## Out-of-scope notes

* **No live-Redis integration test** is included by design. The Story explicitly requires the test suite to pass without a Redis server. A separate end-to-end integration test against a real Redis container can land later under a `redis-cache-e2e` sub-ticket once the consumer Story (E18 S-C) wires the cache into the backend.
* **No Bug Sub-task opened**: every AC item is satisfied as written or with the explicit adaptation documented above. No defects were uncovered during verification.

## Test inventory by module

| Module | Tests | Notes |
|---|---|---|
| `storage::cache::tests::config` | 2 | `RedisConfig::default` posture + URL preservation |
| `storage::cache::tests::key` | 5 | `policy_cache_key` determinism, content-addressing, namespacing, hex length, invalidation pattern |
| `storage::cache::tests::disabled` | 4 | `Default`, `get`, `set`/`invalidate`, `from_config(default)` |
| `storage::cache::tests::contract` | 3 | `StubPolicyCache` round-trip, invalidate, TTL expiry |
| `storage::cache::tests::redis_backend` (feature-gated) | 3 | `connect` None URL, malformed URL; `from_config_async` fallback |
| **Total** | **17** | 14 always-on + 3 under `--features redis-cache` |

## Recommendation

All six Story-level acceptance criteria are satisfied with adaptation noted for the two integration items deferred to E18 S-C / S-I. The `PolicyCache` module is ready to merge.

Once PRs #660, #669, #682, #689 merge, this verification report PR (filed under AAASM-1720) closes the Story.
