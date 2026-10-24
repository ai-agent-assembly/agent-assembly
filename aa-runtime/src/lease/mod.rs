//! Capability-lease support for the runtime (AAASM-6259, J81 Option A).
//!
//! `state` is the durable record format, its library API and the operator
//! CLI's storage. `decide` and `gate` are the governed decision and the
//! [`LeaseGate`](crate::pipeline::LeaseGate) built on it. Nothing in this
//! module is read by the runtime yet, so no runtime behaviour is changed by it
//! and none should be inferred from it.

#[cfg(unix)]
pub mod state;

// strip-for-publish:begin devtool
// `aa-isolation` is `publish = false`; everything that names it is removed from
// the crates.io build by `.ci/strip-for-publish.sh`, along with these files.
pub mod authored;
pub mod decide;
pub mod gate;
// strip-for-publish:end devtool
