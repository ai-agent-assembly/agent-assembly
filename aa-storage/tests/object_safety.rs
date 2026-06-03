//! Storage-trait object-safety verification, covering both import paths.
//!
//! The traits now live in `aa-core::storage` and are re-exported by this facade
//! crate (AAASM-2458), so they are reachable both as `aa_core::storage::*` and
//! `aa_storage::*`. This test asserts every trait is object-safe through *both*
//! paths — the earlier Cargo-cycle obstacle (AAASM-2358 finding) is resolved by
//! hosting the traits in `aa-core` instead of re-exporting back into it.

#[test]
fn all_six_storage_traits_are_object_safe_via_aa_storage_path() {
    use aa_storage::{AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, SessionStore};

    // Each binding compiles only if the trait is object-safe and reachable from
    // the `aa_storage::*` path. The successful build is the assertion; the values
    // stay `None` because a real trait object would need a concrete backend.
    let _policy: Option<Box<dyn PolicyStore>> = None;
    let _audit: Option<Box<dyn AuditSink>> = None;
    let _session: Option<Box<dyn SessionStore>> = None;
    let _credential: Option<Box<dyn CredentialStore>> = None;
    let _rate: Option<Box<dyn RateLimitCounter>> = None;
    let _lifecycle: Option<Box<dyn LifecycleStore>> = None;
}

#[test]
fn all_six_storage_traits_are_object_safe_via_aa_core_storage_path() {
    use aa_core::storage::{AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, SessionStore};

    // Proves the canonical `aa_core::storage::*` path (Story AC #4) resolves and
    // every trait is object-safe through it.
    let _policy: Option<Box<dyn PolicyStore>> = None;
    let _audit: Option<Box<dyn AuditSink>> = None;
    let _session: Option<Box<dyn SessionStore>> = None;
    let _credential: Option<Box<dyn CredentialStore>> = None;
    let _rate: Option<Box<dyn RateLimitCounter>> = None;
    let _lifecycle: Option<Box<dyn LifecycleStore>> = None;
}
