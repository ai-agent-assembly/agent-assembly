//! Optional Redis-backed policy cache for the gateway.
//!
//! This module ships in stages across Epic-18 Story S-G:
//!
//! - First commit (this one): the [`RedisConfig`] value type that drives the
//!   feature flag.
//! - Subsequent sub-tasks: cache key derivation, the `PolicyCacheLike` trait,
//!   the `Disabled` baseline, and the Redis-backed implementation.
//!
//! The cache is **off by default** — the gateway should always be runnable
//! without a Redis process. Production deployments opt in by setting
//! `storage.redis.enabled = true` and providing a reachable URL.
