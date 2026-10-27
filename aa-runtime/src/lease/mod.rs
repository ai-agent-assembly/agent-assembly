//! Capability-lease support for the runtime (AAASM-6259, J81 Option A).
//!
//! `state` is the durable record format, its library API and the operator
//! CLI's storage. `decide` and `gate` are the governed decision and the
//! [`LeaseGate`](crate::pipeline::LeaseGate) built on it. `wiring` is the
//! startup decision: with `AA_LEASE_POLICY` set the runtime runs governed (and
//! refuses to start if it cannot); with it unset nothing here is consulted and
//! the runtime behaves as it did before governed mode existed.

#[cfg(unix)]
pub mod state;
pub mod wiring;

// strip-for-publish:begin devtool
// `aa-isolation` is `publish = false`; everything that names it is removed from
// the crates.io build by `.ci/strip-for-publish.sh`, along with these files.
pub mod authored;
pub mod decide;
pub mod gate;
#[cfg(unix)]
pub mod governed;
// strip-for-publish:end devtool
