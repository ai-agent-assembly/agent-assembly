//! Core domain logic for Agent Assembly.
//!
//! This crate is `no_std` compatible and contains the foundational types,
//! traits, and pure logic shared across all other crates in the workspace.
//! It has no runtime or I/O dependencies.
//!
//! # Feature Flags
//!
//! - `std` (default): enables `std`-dependent convenience impls (e.g. `From<SystemTime>`)
//! - `alloc`: enables heap types (`String`, `Vec`, `BTreeMap`) in `no_std` environments
//! - `serde`: enables `Serialize`/`Deserialize` derives on all core types (added in AAASM-22–25)
//! - `test-utils`: exposes `PermitAllEvaluator` and `DenyAllEvaluator` for downstream test code
//! - `std` (also default): enables `CredentialScanner` and all std-dependent types
//! - `alloc` (also default via std): enables `AuditEntry`, `AuditEventType`, and all audit types

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

cfg_if::cfg_if! {
    if #[cfg(feature = "alloc")] {
        extern crate alloc;
    }
}

pub mod agent;
#[cfg(feature = "alloc")]
pub mod audit;
#[cfg(feature = "alloc")]
pub mod capability;
pub mod dev_tool;
pub mod evaluators;
pub mod identity;
pub mod policy;
#[cfg(feature = "std")]
pub mod scanner;
pub mod time;
pub mod topology;

pub use dev_tool::GovernanceLevel;
pub use identity::{AgentId, SessionId};
pub use policy::{FileMode, PolicyDecision, PolicyError};

#[cfg(feature = "alloc")]
pub use agent::{AgentContext, AgentContextBuilder};
#[cfg(feature = "alloc")]
pub use dev_tool::DevToolKind;
#[cfg(feature = "alloc")]
pub use dev_tool::McpServerInfo;
#[cfg(feature = "std")]
pub use dev_tool::{AdapterError, DevToolAdapter, DevToolInfo};

#[cfg(feature = "alloc")]
pub use policy::{ArgsJson, GovernanceAction, PolicyDocument, PolicyEvaluator, PolicyResult, PolicyRule};

#[cfg(all(feature = "alloc", feature = "test-utils"))]
pub use evaluators::{DenyAllEvaluator, PermitAllEvaluator};

#[cfg(feature = "alloc")]
pub use audit::{AuditEntry, AuditEventType, AuditLog, AuditLogError, Lineage};

#[cfg(feature = "alloc")]
pub use capability::{action_to_capability, merge_capabilities, Capability, CapabilitySet};

#[cfg(feature = "std")]
pub use scanner::{CredentialFinding, CredentialKind, CredentialScanner, ScanResult, ScannerConfig};

pub use topology::EdgeType;
#[cfg(feature = "alloc")]
pub use topology::UnknownEdgeType;
