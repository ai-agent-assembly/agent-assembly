//! AAASM-2358 verification: every storage trait is object-safe and reachable
//! from the single import path.
//!
//! The parent Story's AC asks for the traits at `aa_core::storage::*`. That
//! re-export is infeasible: `aa-storage` depends on `aa-core` for the concrete
//! shared types, so re-exporting the traits back from `aa-core` would create a
//! Cargo dependency cycle (`aa-storage -> aa-core -> aa-storage`). The single
//! import path is therefore `aa_storage::*`, which this test exercises. See the
//! verification report and the Bug subtask filed under AAASM-2354.

use aa_storage::{AuditSink, CredentialStore, LifecycleStore, PolicyStore, RateLimitCounter, SessionStore};

#[test]
fn all_six_storage_traits_are_object_safe_via_single_import_path() {
    // Each binding compiles only if the trait is object-safe and reachable from
    // the `aa_storage::*` import path. The successful build is the assertion; the
    // values stay `None` because a real trait object would need a concrete
    // backend.
    let _policy: Option<Box<dyn PolicyStore>> = None;
    let _audit: Option<Box<dyn AuditSink>> = None;
    let _session: Option<Box<dyn SessionStore>> = None;
    let _credential: Option<Box<dyn CredentialStore>> = None;
    let _rate: Option<Box<dyn RateLimitCounter>> = None;
    let _lifecycle: Option<Box<dyn LifecycleStore>> = None;
}
