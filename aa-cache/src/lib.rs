//! In-process **L1 cache** for the Agent Assembly storage layer.
//!
//! Policy is queried on the tool-call critical path, so a backend round-trip
//! (Postgres or Gateway) per call is too expensive. [`L1Cache`] wraps any store
//! behind an in-process [`DashMap`](dashmap::DashMap) with a configurable TTL and
//! per-key stampede protection, so hot lookups hit memory and never cross the
//! network.
//!
//! The wrapped store is abstracted by the [`CacheSource`] trait, which is
//! blanket-implemented for [`aa_core::storage::PolicyStore`]; the cache itself is
//! agnostic to which store it fronts.
//!
//! Invalidation (this is what the Epic C push-invalidation channel will call)
//! is provided by [`L1Cache::invalidate`].

mod cached_value;
mod l1;
mod source;

#[cfg(any(test, feature = "test-utils"))]
pub mod testing;

pub use cached_value::CachedValue;
pub use l1::L1Cache;
pub use source::CacheSource;
