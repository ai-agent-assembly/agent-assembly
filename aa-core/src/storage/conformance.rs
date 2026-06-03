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

use super::{
    AgentId, AuditEntry, AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, SessionRecord,
    SessionStore, StorageError,
};

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

/// Assert that an [`AuditSink`] implementation honors the trait contract.
///
/// Drives `sink` through `&dyn AuditSink` and checks that emitting an entry
/// succeeds — the sink is append-only, so a successful `emit` is the only
/// observable invariant the trait guarantees. Panics on failure.
pub async fn assert_audit_sink_conformance(sink: &dyn AuditSink, event: AuditEntry) {
    sink.emit(event).await.expect("emit should persist the entry");
}

/// Assert that a [`SessionStore`] implementation honors the trait contract.
///
/// Drives `store` through `&dyn SessionStore` and checks:
///
/// - `save` then `load` round-trips the record unchanged
/// - `delete` removes it, after which `load` returns [`StorageError::NotFound`]
/// - a second `delete` of the now-absent id still succeeds (idempotent)
///
/// `record` must use a session id the store does not already hold. Panics with a
/// descriptive message on the first violated invariant.
pub async fn assert_session_store_conformance(store: &dyn SessionStore, record: SessionRecord) {
    let id = record.session_id;

    store.save(record.clone()).await.expect("save(new) should succeed");

    let loaded = store.load(&id).await.expect("load(present) should return the record");
    assert_eq!(loaded, record, "loaded record should equal the saved record");

    store.delete(&id).await.expect("delete(present) should succeed");

    match store.load(&id).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("load(deleted) should return NotFound, got {other:?}"),
    }

    store.delete(&id).await.expect("delete(absent) should be idempotent");
}

/// Assert that a [`CredentialStore`] implementation honors the trait contract.
///
/// Drives `store` through `&dyn CredentialStore` and checks:
///
/// - `put_secret` then `get_secret` round-trips the bytes unchanged
/// - `delete_secret` removes it, after which `get_secret` returns [`StorageError::NotFound`]
/// - a second `delete_secret` of the now-absent key still succeeds (idempotent)
///
/// `key` must be one the store does not already hold. Panics with a descriptive
/// message on the first violated invariant.
pub async fn assert_credential_store_conformance(store: &dyn CredentialStore, key: &str, value: Vec<u8>) {
    store
        .put_secret(key, value.clone())
        .await
        .expect("put_secret(new) should succeed");

    let got = store
        .get_secret(key)
        .await
        .expect("get_secret(present) should return the value");
    assert_eq!(got, value, "round-tripped secret bytes should match");

    store
        .delete_secret(key)
        .await
        .expect("delete_secret(present) should succeed");

    match store.get_secret(key).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("get_secret(deleted) should return NotFound, got {other:?}"),
    }

    store
        .delete_secret(key)
        .await
        .expect("delete_secret(absent) should be idempotent");
}

/// Assert that a [`RateLimitCounter`] implementation honors the trait contract.
///
/// Drives `counter` through `&dyn RateLimitCounter` and checks:
///
/// - a fresh key reads `0`
/// - `increment` returns the accumulating window total
/// - `current` reflects the accumulated total without modifying it
/// - `reset` returns the counter to `0` and is idempotent
///
/// `key` must be one the counter has never seen. A long window is used so the
/// assertions never race a window rollover. Panics on the first violated
/// invariant.
pub async fn assert_rate_limit_counter_conformance(counter: &dyn RateLimitCounter, key: &str) {
    const WINDOW_SECS: u64 = 3600;

    assert_eq!(
        counter.current(key).await.expect("current(fresh) should succeed"),
        0,
        "a key that was never incremented reads 0"
    );

    assert_eq!(
        counter
            .increment(key, 5, WINDOW_SECS)
            .await
            .expect("increment should succeed"),
        5,
        "first increment returns the amount added"
    );

    assert_eq!(
        counter
            .increment(key, 3, WINDOW_SECS)
            .await
            .expect("increment should succeed"),
        8,
        "second increment accumulates within the window"
    );

    assert_eq!(
        counter.current(key).await.expect("current should succeed"),
        8,
        "current reflects the accumulated total"
    );

    counter.reset(key).await.expect("reset should succeed");

    assert_eq!(
        counter.current(key).await.expect("current after reset should succeed"),
        0,
        "reset returns the counter to 0"
    );

    counter.reset(key).await.expect("reset(absent) should be idempotent");
}

/// Assert that a [`LifecycleStore`] implementation honors the trait contract.
///
/// Drives `store` through `&dyn LifecycleStore` and checks:
///
/// - `register` then `heartbeat` succeeds for a registered agent
/// - `heartbeat` on an unregistered agent returns [`StorageError::NotFound`]
/// - `deregister` removes the registration, after which `heartbeat` returns
///   [`StorageError::NotFound`]
/// - `deregister` is idempotent for both registered and absent agents
///
/// `present` is registered and deregistered by the harness; `absent` must be an
/// agent the store never holds. Panics on the first violated invariant.
pub async fn assert_lifecycle_store_conformance(store: &dyn LifecycleStore, present: &AgentId, absent: &AgentId) {
    store.register(present).await.expect("register should succeed");

    store
        .heartbeat(present)
        .await
        .expect("heartbeat(registered) should succeed");

    match store.heartbeat(absent).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("heartbeat(unregistered) should return NotFound, got {other:?}"),
    }

    store
        .deregister(present)
        .await
        .expect("deregister(registered) should succeed");

    match store.heartbeat(present).await {
        Err(StorageError::NotFound(_)) => {}
        other => panic!("heartbeat(deregistered) should return NotFound, got {other:?}"),
    }

    store
        .deregister(present)
        .await
        .expect("deregister(present) should be idempotent");

    store
        .deregister(absent)
        .await
        .expect("deregister(absent) should be idempotent");
}
