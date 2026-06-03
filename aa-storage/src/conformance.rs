//! Reusable trait-conformance harness for driver crates.
//!
//! Downstream backend crates (Epic B: Postgres, Redis, memory; Epic E: the
//! Enterprise gateway driver) import this module to prove their implementation
//! honors the trait contract, exercising it through a `&dyn` reference so
//! object-safety is checked at the same time.
//!
//! The harness functions panic on the first violated invariant, so they are
//! meant to be called from within a `#[test]` (driven by the caller's own async
//! runtime).

use crate::{AgentId, PolicyStore, StorageError};

/// Assert that a [`PolicyStore`] implementation honors the trait contract.
///
/// Drives `store` through `&dyn PolicyStore` and checks:
///
/// - `get_policy(present)` resolves to a policy
/// - `get_policy(absent)` returns [`StorageError::NotFound`]
/// - `invalidate(present)` succeeds
/// - `invalidate(absent)` succeeds (invalidation is idempotent)
///
/// `present` must be an agent the store has a policy for; `absent` must be one it
/// does not. Panics with a descriptive message on the first violated invariant.
pub async fn assert_policy_store_conformance(store: &dyn PolicyStore, present: &AgentId, absent: &AgentId) {
    store
        .get_policy(present)
        .await
        .expect("get_policy(present) should resolve to a policy");

    match store.get_policy(absent).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("get_policy(absent) should return NotFound, got {other:?}"),
    }

    store
        .invalidate(present)
        .await
        .expect("invalidate(present) should succeed");

    store
        .invalidate(absent)
        .await
        .expect("invalidate(absent) should be idempotent");
}
