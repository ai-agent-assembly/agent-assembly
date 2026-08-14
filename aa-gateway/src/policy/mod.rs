//! Policy semantics as the gateway sees them: the shared document model from
//! [`aa_policy`], plus the evaluation context only this crate can supply.
//!
//! # Why the split (AAASM-5349)
//!
//! Parsing and validating a policy document is not a gateway concern — the
//! developer-integration service in `aa-runtime` and `aasm run` must reach the
//! same answer about which policy is in effect, and neither may depend on the
//! gateway. Those semantics therefore live in the leaf crate [`aa_policy`] and
//! are re-exported here unchanged, so `aa_gateway::policy::…` keeps meaning
//! exactly what it did.
//!
//! What stays is [`context`]: evaluating a policy needs a budget tracker and
//! the agent registry, which are gateway state. That dependency is the reason
//! the split falls where it does.

pub use aa_policy::*;

pub mod context;

pub use context::ProductionPolicyContext;
