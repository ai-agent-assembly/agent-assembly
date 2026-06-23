//! The canonical, cross-layer policy AST and its compilers.
//!
//! This module is the single source of truth for policy structure. It lives in
//! `aa-security` (a leaf crate) so that BOTH the gateway rule engine (L7) and
//! the privilege-separated eBPF loader (kernel) can depend on the exact same
//! types without a dependency cycle — `aa-core` already depends on
//! `aa-security`, so the AST cannot live in `aa-core`.
//!
//! See AAASM-3606 (extract AST), AAASM-3607 (gateway consumes it), and
//! AAASM-3608 (lower it to eBPF map entries).
//!
//! # Layout
//!
//! - [`capability`] — the `file_read` / `network_outbound` / `mcp_tool:<n>`
//!   capability vocabulary.
//! - [`document`] — [`PolicyDocument`] and its sub-structures.
//! - [`parse`] — YAML parsing of the `policy-examples` on-disk contract.
//! - [`ebpf`] — deterministic lowering of the AST to eBPF map entries
//!   (AAASM-3608).

pub mod capability;
pub mod document;
pub mod ebpf;
pub mod error;
#[cfg(feature = "serde")]
pub mod parse;

pub use capability::{Capability, CapabilitySet};
pub use document::{NetworkPolicy, PolicyDocument, ToolRule};
pub use ebpf::{lower_to_ebpf, EbpfRuleSet, PathRule, PathVerdict};
pub use error::PolicyParseError;
