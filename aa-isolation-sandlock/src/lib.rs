//! A Linux process-isolation backend for Agent Assembly (AAASM-5708).
//!
//! Implements [`aa_isolation::IsolationBackend`] over an external confinement
//! supervisor — the `sandlock` executable — which restricts a child process
//! in place on the host kernel using the kernel's own per-process access
//! control and system-call filtering. Authority: ADR 0035, *Agent Execution
//! Isolation & Pluggable Enforcement Backends*, §8.
//!
//! # The one claim this crate is careful not to make
//!
//! *A backend being available is not a control being enforced.* Everything here
//! is arranged around keeping those apart:
//!
//! * [`capability`] reports a domain as able to prevent **only when a denial was
//!   observed on this host**, through a [`Prerequisite`](aa_isolation::Prerequisite)
//!   whose status comes from [`probe`]. A domain nobody measured cannot satisfy
//!   a prevention requirement, so `aa_isolation::negotiate` refuses the launch
//!   before the program starts.
//! * [`probe`] measures with a **control**: the same confined command runs
//!   twice, differing by one flag group, and a denial counts only when the
//!   control run produced the effect and the test run did not. A probe that
//!   cannot succeed cannot fail, and a boundary that never engaged makes the
//!   control fail rather than making the test look like a denial.
//! * [`backend`] emits `Configured`, `Installed` and `Exercised` evidence and
//!   **never** `Decision`. The kernel delivers a denial to the confined process,
//!   not to the supervisor, so this backend has no per-decision record to
//!   report. `EnforcementEvidence::supports_prevention_claim` is therefore false
//!   after every run, which is the honest answer and is asserted by test.
//!
//! # No unconfined fallback
//!
//! Exactly one function starts the caller's program, and it starts it as an
//! argument of the confinement executable. There is no error arm that retries
//! without confinement. A preparation or launch failure yields a
//! [`SpawnError`](aa_isolation::SpawnError) and no process.
//!
//! # Argv is argv
//!
//! [`lower`] builds a vector, not a command line. No caller-supplied value is
//! quoted, escaped, joined or split anywhere on the launch path, and the
//! separator between the backend's flags and the caller's program is explicit,
//! so a program named like one of the backend's own flags is a program with a
//! strange name rather than a second instruction.
//!
//! # What this crate is not
//!
//! It is not `aa-sandbox`. That crate runs WebAssembly tool code inside a
//! WASI sandbox with no host process involved; this one confines a native
//! process on the host kernel. They are different boundaries at different
//! layers, they compose, and neither substitutes for the other (ADR 0035 §7).
//!
//! # Packaging
//!
//! `publish = false`, and the mechanism itself is not distributed on any AASM
//! channel — the operator installs it. `metadata/isolation-backends.json`
//! records the measured provenance, and
//! `scripts/check-backend-license-compliance.sh` enforces that the record is
//! complete.

#![warn(missing_docs)]

pub mod host;
pub mod lower;
pub mod probe;

pub use host::{BackendLookupError, HostFacts, KernelVersion, BACKEND_PATH_ENV, BACKEND_PROGRAM};
pub use lower::{Argv, LoweringGap};
pub use probe::{ConfinementProbe, Observation};
