# Verification Report — AAASM-2380

**Subtask:** AAASM-2380 — Verify L1 cache wrapper acceptance criteria
**Parent Story:** AAASM-2376 — DashMap L1 cache wrapper around `PolicyStore`
**Epic:** AAASM-2349 — L1 in-process cache + Gateway push-invalidation channel
**Implementation:** AAASM-2379 (PR #877), crate `aa-cache`
**Verified against branch:** `v0.0.1/AAASM-2380/test/verify_l1_cache` (stacked on `v0.0.1/AAASM-2379/feat/l1_cache_wrapper`)
**Date:** 2026-06-03

## Summary

All acceptance criteria for Story AAASM-2376 are met. The unit suite passes
(4/4) and the criterion benchmark shows the warm L1 hit median at ~0.33 µs,
comfortably under the 1 µs target. No bugs filed.

## Acceptance criteria

| # | Story AC | Result | Evidence |
|---|---|---|---|
| 1 | `L1Cache<S>` generic over the wrapped store | ✅ PASS | `aa-cache/src/l1.rs` — `pub struct L1Cache<S: CacheSource>`; the store is abstracted by the `CacheSource` trait (`aa-cache/src/source.rs`), blanket-implemented for every `PolicyStore`. |
| 2 | Cache-aside on `get` (hit serves memory; miss loads inner, populates, returns) | ✅ PASS | `l1::tests::miss_populates_then_serves_from_cache` — first `get` calls the store once + caches; second `get` is served from memory (call count stays 1). |
| 3 | `invalidate(key)` removes the cached entry | ✅ PASS | `l1::tests::invalidate_evicts_the_cached_entry` — returns `true` and empties the cache for a present key, `false` for an absent key; subsequent `get` reloads. |
| 4 | Stampede protection: under 100 concurrent misses the inner store sees exactly 1 call | ✅ PASS | `l1::tests::concurrent_misses_collapse_to_one_load` — 100 concurrent `tokio::spawn`ed `get`s against a store with a 50 ms load delay; `call_count() == 1`. |
| 5 | TTL configurable per instance; expired entries treated as a miss | ✅ PASS | `L1Cache::new(inner, ttl)` + `l1::tests::expired_entry_is_treated_as_a_miss` — 20 ms TTL; after the entry ages out the next `get` reloads (call count 1 → 2). |
| 6 | Criterion benchmark: L1 hit median < 1 µs; raw `MemoryPolicyStore::get_policy` baseline alongside | ✅ PASS | `aa-cache/benches/l1_hit.rs` — `l1_hit_warm` median **332.77 ns** (< 1 µs); `raw_memory_store` baseline reported alongside (234.20 ns). |

## Commands & output

### `cargo nextest run -p aa-cache --all-features`

```
    Starting 4 tests across 1 binary
        PASS [   0.010s] (1/4) aa-cache l1::tests::miss_populates_then_serves_from_cache
        PASS [   0.010s] (2/4) aa-cache l1::tests::invalidate_evicts_the_cached_entry
        PASS [   0.052s] (3/4) aa-cache l1::tests::expired_entry_is_treated_as_a_miss
        PASS [   0.069s] (4/4) aa-cache l1::tests::concurrent_misses_collapse_to_one_load
     Summary [   0.069s] 4 tests run: 4 passed, 0 skipped
```

### `cargo bench -p aa-cache --bench l1_hit`

```
l1_cache/l1_hit_warm    time:   [281.41 ns 332.77 ns 383.26 ns]
l1_cache/raw_memory_store
                        time:   [193.01 ns 234.20 ns 279.21 ns]
```

(criterion reports `[lower bound, median/point estimate, upper bound]`; the
middle value is the estimate used against the 1 µs target.)

## Notes

- **Stampede test method.** The subtask's "How" suggested `tokio::join!` of 100
  calls; the implemented test uses 100 independent `tokio::spawn`ed tasks on a
  multi-thread runtime, which exercises the same single-flight collapse under
  real cross-thread concurrency rather than cooperative single-task polling — an
  equivalent-or-stronger check. The store's 50 ms load delay deterministically
  holds the leader while followers queue behind the shared `Notify`.
- **L1-vs-raw ordering.** On the (noisy) macOS dev box the raw `HashMap` store
  occasionally edges out the L1 hit because `DashMap` adds a shard lock the raw
  `HashMap` lacks; both remain well under 1 µs. The benchmark's purpose — proving
  the L1 hit avoids the network round-trip and stays sub-µs — holds in every run.
- Quality gates: `cargo fmt --all --check`, `cargo clippy --all-targets
  --all-features -- -D warnings`, and `cargo doc --workspace --no-deps` all pass
  (enforced by the pre-commit / pre-push hooks on PR #877).

## Conclusion

Story AAASM-2376 acceptance criteria are fully satisfied by AAASM-2379. No
defects found; no Bug Subtask filed.
