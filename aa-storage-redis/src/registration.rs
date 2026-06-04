//! Driver registration: announce the Redis-backed stores to an
//! [`aa_storage::Registry`].

use aa_storage::Registry;

use crate::factory::{RedisPolicyStoreFactory, RedisRateLimitCounterFactory, RedisSessionStoreFactory};
use crate::DRIVER_NAME;

/// Register the Redis factories for the kinds redis backs — policy, session, and
/// rate-limit — into `reg` under [`DRIVER_NAME`] (`"redis"`).
///
/// Call this from boot code *after*
/// [`aa_storage::builtin::register_builtin_drivers`] to replace the `"redis"`
/// placeholder for those three kinds (registration is last-write-wins).
///
/// Audit, credential, and lifecycle are intentionally left on the placeholder —
/// Redis is an L2 shared cache and does not back those durable kinds, so a
/// config that selects `redis` for them fails the boot with a clear error
/// instead of silently using a cache as a system of record.
pub fn register(reg: &mut Registry) {
    reg.register_policy_store(DRIVER_NAME, Box::new(RedisPolicyStoreFactory));
    reg.register_session_store(DRIVER_NAME, Box::new(RedisSessionStoreFactory));
    reg.register_rate_limit_counter(DRIVER_NAME, Box::new(RedisRateLimitCounterFactory));
}
