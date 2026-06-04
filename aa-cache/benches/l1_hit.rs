//! Criterion benchmark: L1 cache hit latency vs the raw store (AAASM-2379).
//!
//! `l1_hit_warm` measures a warm `L1Cache` hit — the tool-call critical path —
//! and must land in the sub-microsecond range. `raw_memory_store` is the
//! baseline: the same `MemoryPolicyStore::get_policy` the cache fronts, shown
//! alongside so the cache's per-call cost is visible against the unwrapped store.

use std::hint::black_box;
use std::time::Duration;

use aa_cache::testing::{sample_policy, MemoryPolicyStore};
use aa_cache::L1Cache;
use aa_core::storage::{AgentId, PolicyStore};
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_l1_hit(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let id = AgentId::from_bytes([7; 16]);

    // Warm the L1 cache: one load, after which every `get` is an in-memory hit.
    let cache = L1Cache::new(
        MemoryPolicyStore::with_policy(id, sample_policy(1)),
        Duration::from_secs(3600),
    );
    rt.block_on(async { cache.get(id).await.expect("warm load") });

    // Raw baseline store, fronted by no cache.
    let raw = MemoryPolicyStore::with_policy(id, sample_policy(1));

    let mut group = c.benchmark_group("l1_cache");
    group.bench_function("l1_hit_warm", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(cache.get(black_box(id)).await.expect("hit")) });
    });
    group.bench_function("raw_memory_store", |b| {
        b.to_async(&rt)
            .iter(|| async { black_box(raw.get_policy(black_box(&id)).await.expect("present")) });
    });
    group.finish();
}

criterion_group!(benches, bench_l1_hit);
criterion_main!(benches);
