//! Gateway-side L1 push-invalidation channel (Story AAASM-2377).
//!
//! The [`InvalidationHub`] fans `PolicyInvalidated` events out to every
//! connected Assembly over the `assembly.gateway.v1.InvalidationService`
//! bidi stream, keeping each Assembly's in-process L1 cache fresh within
//! ~100 ms of a policy mutation instead of waiting for TTL expiry.

mod hub;

pub use hub::{AssemblyId, InvalidationHub, SubscriptionHandle};
