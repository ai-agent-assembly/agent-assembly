//! Capability-restricted facade over [`aa-core`] for `aa-devtool-*` plugins.
//!
//! # Why this crate exists (AAASM-3565)
//!
//! `aa-devtool-*` plugins (claude-code, codex, copilot, windsurf, saas, the
//! sample editor) run inside the developer's trusted environment. Each one used
//! to carry a direct `aa-core` path dependency, which meant a *single*
//! under-reviewed plugin PR could reach the **entire** `aa-core` public API —
//! identity, storage, gateway tokens, the LLM/agent/approval subsystems — even
//! though a devtool adapter only ever needs the [`DevToolAdapter`] surface and
//! a handful of policy/audit value types.
//!
//! This crate is the **compile-time analogue of a restricted IPC interface**:
//! it depends on the full `aa-core` internally but re-exports *only* the audited
//! symbol set below. Plugins depend on this crate, never on `aa-core` directly.
//! A smuggled call to an unrelated `aa-core` subsystem (e.g.
//! `aa_core::storage::…` or a gateway token type) is therefore a **compile
//! error** in a plugin crate, not a silent capability.
//!
//! # The contract surface
//!
//! The re-export list below is the trusted boundary. It was audited from
//! `git grep aa_core` across every `aa-devtool*/src` tree. Adding a symbol here
//! widens the surface a plugin can reach and **must** go through a security
//! reviewer (see `.github/CODEOWNERS` and `deny.toml`). Do not re-export whole
//! `aa-core` modules (`policy::`, `identity`, `storage`, `config`, …) — only the
//! flat value types and the adapter trait the plugins consume.
//!
//! [`aa-core`]: aa_core

#![warn(missing_docs)]
#![forbid(unsafe_code)]

// --- DevToolAdapter capability surface (aa_core::dev_tool) ---------------
pub use aa_core::{AdapterError, DevToolAdapter, DevToolInfo, DevToolKind, GovernanceLevel, McpServerInfo};

// --- Policy value types the adapters read at apply()/settings time -------
pub use aa_core::{EnforcementMode, PolicyDecision, PolicyDocument, PolicyRule};

// --- Capability bridge value types (aa_core::capability) -----------------
pub use aa_core::{Capability, CapabilitySet};

// --- Audit pipeline entry the SaaS overlay emits (aa_core::audit) --------
pub use aa_core::AuditEntry;
