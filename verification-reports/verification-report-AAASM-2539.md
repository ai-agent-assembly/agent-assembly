# Verification Report — AAASM-2539

**Story:** As an OSS operator, I want to select `redis` as my storage backend and boot Assembly end-to-end
**Epic:** AAASM-2348 — OSS concrete storage drivers
**Implementation subtask / PR:** AAASM-2540 → PR #896
**Verification subtask:** AAASM-2541
**Component / repo:** `agent-assembly`
**Date:** 2026-06-04

## Method

- `cargo nextest run -p aa-storage-redis` (factory + registry-integration + the new boot e2e) against a real Redis provisioned by `testcontainers-modules::redis` (Docker).
- `cargo nextest run -p aa-cli` config/boot tests.
- `cargo clippy -p aa-storage-redis -p aa-cli --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`, `cargo deny check`, `cargo doc` (pre-push gate).

## Acceptance criteria

| # | Acceptance criterion | Status | Evidence |
|---|---|---|---|
| 1 | `aa-storage-redis` implements the `*Factory` traits for the kinds it backs (`PolicyStore`, `SessionStore`, `RateLimitCounter`) from `[storage.redis]` | ✅ Pass | `aa-storage-redis/src/factory.rs`; per-factory build-from-`toml::Value` unit tests |
| 2 | `register(&mut Registry)` overrides the `"redis"` placeholder for those kinds | ✅ Pass | `aa-storage-redis/src/registration.rs`; `registry_integration::redis_registers_for_the_kinds_it_backs` |
| 3 | CLI boot path calls `aa_storage_redis::register()` so a redis-backed config resolves to a real `RedisBackend` (not `NotImplemented`) | ✅ Pass | `aa-cli/src/commands/config/boot.rs`; e2e builds + runs ops through the registry-resolved driver |
| 4 | End-to-end boot of a redis-backed config (testcontainers Redis) performs a real store operation through the registry-resolved driver | ✅ Pass | `tests/boot_e2e.rs::redis_backed_config_boots_and_serves_real_ops` — real rate-limit `INCR`, session save/load round-trip, policy-cache query, all via `&dyn` from `Registry::build_*` against a live container |

### Design guard (out-of-scope kinds)

`redis_for_a_durable_kind_is_rejected` confirms a config selecting `redis` for `audit_sink` stays on the builtin placeholder and **fails the build** — Redis is an L2 cache and must not be used as a system of record for the durable kinds. A working redis deployment is therefore a **mixed** config (redis L2 + memory/postgres for audit/credential/lifecycle).

## Test run

```
cargo nextest run -p aa-storage-redis
  PASS aa-storage-redis factory::tests::{policy,session,rate_limit}_factory_builds_from_config
  PASS aa-storage-redis config::tests::{parses_storage_redis_subsection,applies_defaults_for_missing_fields,tls_toggle_upgrades_scheme}
  PASS aa-storage-redis tests::driver_name_is_redis
  PASS aa-storage-redis::registry_integration::{redis_registers_for_the_kinds_it_backs, mixed_redis_memory_config_validates_and_builds_every_backend}
  PASS aa-storage-redis::boot_e2e::redis_backed_config_boots_and_serves_real_ops
  PASS aa-storage-redis::boot_e2e::redis_for_a_durable_kind_is_rejected
  PASS aa-storage-redis::conformance_redis::{session_roundtrip, policy_conformance, rate_limit_atomic_under_concurrency, rate_limit_increments_and_resets}
  (all passed, 0 skipped)

cargo nextest run -p aa-cli  (config/boot)
  PASS aa-cli commands::config::boot::tests::all_memory_config_boots_successfully
  PASS aa-cli commands::config::validate::tests::* (unknown_driver / missing_subsection / valid_config)
```

## Result

**All acceptance criteria met.** No bugs found; no `[BUG]` subtask filed. An OSS operator can now set `redis` for the L2 cache kinds in `agent-assembly.toml` and boot Assembly end-to-end, with the durable kinds backed by another driver. This completes the redis registry-wiring follow-up noted on Story AAASM-2365.
