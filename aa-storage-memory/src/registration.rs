//! Driver registration: announce the memory backends to an [`aa_storage::Registry`].

use aa_storage::Registry;

use crate::factory::{
    MemoryAuditSinkFactory, MemoryCredentialStoreFactory, MemoryLifecycleStoreFactory, MemoryPolicyStoreFactory,
    MemoryRateLimitCounterFactory, MemorySessionStoreFactory,
};

/// The name the memory driver registers all six storage backends under.
pub const DRIVER_NAME: &str = "memory";

/// Register the in-memory factories for all six storage kinds into `reg` under
/// [`DRIVER_NAME`].
///
/// Call this from boot code *after*
/// [`aa_storage::builtin::register_builtin_drivers`] to replace the `"memory"`
/// placeholder with the real backends — `register_*` is last-write-wins, so the
/// real factory overrides the not-yet-implemented stub.
pub fn register(reg: &mut Registry) {
    reg.register_policy_store(DRIVER_NAME, Box::new(MemoryPolicyStoreFactory));
    reg.register_audit_sink(DRIVER_NAME, Box::new(MemoryAuditSinkFactory));
    reg.register_session_store(DRIVER_NAME, Box::new(MemorySessionStoreFactory));
    reg.register_credential_store(DRIVER_NAME, Box::new(MemoryCredentialStoreFactory));
    reg.register_rate_limit_counter(DRIVER_NAME, Box::new(MemoryRateLimitCounterFactory));
    reg.register_lifecycle_store(DRIVER_NAME, Box::new(MemoryLifecycleStoreFactory));
}
