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
//! launcher/helper boundary" the ADR asks for.
//!
//! # The kernel floor is measured, not assumed
//!
//! [`rules::REQUIRED_ABI_VERSION`] states what this backend's *claim* needs. See
//! [`rules`] for why the number is what it is — the short version is that below
//! it a path-scoped write restriction does not stop `truncate(2)`, so the claim
//! would be false rather than merely weaker.
//!
//! # Packaging
//!
//! `publish = false`, and this backend redistributes no third-party binary. Its
//! third-party surface is the kernel binding crate, which is in the cargo
//! dependency graph and is therefore covered by `cargo deny check` — unlike a
//! prebuilt backend executable, which is what `metadata/isolation-backends.json`
//! and `scripts/check-backend-license-compliance.sh` exist for.

#![warn(missing_docs)]

pub mod launch;
pub mod rules;

pub use launch::{Grants, LauncherArgv, EXIT_LAUNCH_REFUSED, FAILURE_MARKER};
pub use rules::{RulePlan, REQUIRED_ABI_VERSION, REQUIRED_KERNEL_RELEASE};
