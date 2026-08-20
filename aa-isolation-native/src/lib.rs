//! The AASM-native Linux process-isolation backend (AAASM-5802).
//!
//! Implements [`aa_isolation::IsolationBackend`] for the **filesystem domain**
//! over the kernel's own per-process filesystem access control, applied by a
//! small dedicated launcher binary this crate ships. Authority: ADR 0035,
//! *Agent Execution Isolation & Pluggable Enforcement Backends*, and its
//! AAASM-5801 amendment, which records the launcher boundary, the kernel
//! primitives, and the measurement policy for the kernel floor.
//!
//! # The three-process shape, and why it is not one process
//!
//! ```text
//! aasm run (supervisor, Tokio)  →  aa-isolation-launch  →  the agent's program
//!         builds the argv              installs the             (execve'd; the
//!         and spawns                   boundary on itself        same process id)
//! ```
//!
//! The supervisor never installs a boundary on itself — ADR 0035 §5 requires it
//! to stay outside the confined tree — and it never installs one in a
//! post-`fork` callback, where allocation, locks and ordinary library behaviour
//! are unsafe to audit. The launcher is the "deliberately small and auditable
//! launcher/helper boundary" the ADR asks for, and it is the *only* thing this
//! crate can start: there is no code path that spawns the agent's program
//! directly.
//!
//! # The one claim this crate is careful not to make
//!
//! *A backend being available is not a control being enforced.* Everything here
//! is arranged around keeping those apart:
//!
//! * [`capability`] reports a domain as able to prevent **only when a denial was
//!   observed on this host**, through a [`Prerequisite`](aa_isolation::Prerequisite)
//!   whose status comes from [`probe`]. A domain nobody measured cannot satisfy a
//!   prevention requirement, so `aa_isolation::negotiate` refuses the launch
//!   before the program starts.
//! * [`probe`] measures with a **control**: the same confined command runs twice,
//!   differing by one grant, and a denial counts only when the control run
//!   produced the effect and the test run did not.
//! * [`backend`] emits `Configured`, `Installed` and `Exercised` evidence and
//!   **never** `Decision`. The kernel delivers a denial to the confined process,
//!   not to the supervisor, so this backend has no per-decision record to report.
//!   `EnforcementEvidence::supports_prevention_claim` is therefore false after
//!   every run, which is what ADR 0035's AAASM-5801 amendment decided and is
//!   asserted by test.
//!
//! # What this version does and does not cover
//!
//! Filesystem read and write, and a syscall filter (AAASM-5803, [`seccomp`]).
//! Every other [`CapabilityDomain`](aa_isolation::CapabilityDomain) is reported
//! [`Unsupported`](aa_isolation::SupportLevel::Unsupported) with a reason, so a
//! required requirement for one **refuses the launch** rather than planning
//! successfully against a control that is not installed.
//!
//! The syscall filter is a [`SupportLevel::Partial`](aa_isolation::SupportLevel::Partial)
//! domain, not a `Full` one: it permits a startup baseline beyond what policy
//! named, so that its own `execve` of the confined program is not killed by
//! the filter it just installed on itself — see [`seccomp`]'s module
//! documentation for the deviation from ADR 0035's literal text this
//! entails, and why the baseline is disjoint from the policy vocabulary by
//! construction rather than by convention.
//!
//! # The kernel floor is measured, not assumed
//!
//! [`rules::REQUIRED_ABI_VERSION`] states what this backend's *claim* needs;
//! [`host::HostFacts::abi_floor`] measures what the *host* provides, by asking
//! the kernel rather than by comparing a release string. A host below the floor
//! makes the backend unavailable with a reason, so the launch is refused before
//! anything starts. See [`rules::REQUIRED_ABI`] for why the number is what it is
//! — the short version is that below it a path-scoped write restriction does not
//! stop `truncate(2)`, so the claim would be false rather than merely weaker.
//!
//! # No unconfined fallback
//!
//! Exactly one function starts the caller's program, and it starts it as an
//! argument of the launcher. There is no error arm that retries without
//! confinement, and the launcher itself refuses without executing anything if it
//! cannot install the boundary. A preparation or launch failure yields a
//! [`SpawnError`](aa_isolation::SpawnError) and no process.
//!
//! # Packaging
//!
//! `publish = false`, and this backend redistributes no third-party binary. Its
//! third-party surface is the kernel binding crate named in
//! [`backend::BINDING_CRATE`], which is in the cargo dependency graph and is
//! therefore covered by `cargo deny check` — unlike a prebuilt backend
//! executable, which is what `metadata/isolation-backends.json` and
//! `scripts/check-backend-license-compliance.sh` exist for.

#![warn(missing_docs)]

pub mod backend;
pub mod capability;
pub mod host;
pub mod inherit;
pub mod launch;
pub mod lower;
pub mod probe;
pub mod proc_scope;
pub mod rules;
pub mod seccomp;

pub use backend::{CompletedRun, NativeBackend, BACKEND_ID, BINDING_CRATE, SOURCE_URL, SPDX_LICENSE};
pub use host::{AbiFloor, HostFacts, HostUnusable, SyscallFilterSupport, LAUNCHER_PATH_ENV, LAUNCHER_PROGRAM};
pub use inherit::seal_inherited_descriptors;
pub use launch::{Grants, LauncherArgv, SyscallFilter, EXIT_LAUNCH_REFUSED, FAILURE_MARKER};
pub use lower::LoweringGap;
pub use probe::{ConfinementProbe, Observation};
pub use proc_scope::{ProcListing, ScopedGrants, OWN_PROC};
pub use rules::{RulePlan, REQUIRED_ABI_VERSION, REQUIRED_KERNEL_RELEASE};
pub use seccomp::{FilterProgram, STARTUP_BASELINE};
