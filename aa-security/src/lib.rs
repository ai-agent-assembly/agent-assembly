//! Security primitives for Agent Assembly.
//!
//! This crate owns the credential-detection scanner, the redaction primitives,
//! the audit-normalization types, and the canonical [`policy`] AST relied on by
//! the trusted enforcement layers (`aa-runtime`, `aa-gateway`, `aa-proxy`, and
//! the privilege-separated eBPF loader).
//!
//! It is deliberately a **leaf** crate: it does *not* depend on `aa-core`, so
//! security authority comes from *where a primitive runs*, not from the core
//! domain crate. Because `aa-core` itself depends on `aa-security`, the shared
//! policy AST is hosted here (not in `aa-core`) so the gateway and the eBPF
//! layer can depend on the same types without a dependency cycle (AAASM-3606).
//!
//! # Feature Flags
//!
//! - `serde`: enables `Serialize`/`Deserialize` derives on the public types and
//!   the YAML parsing of the canonical [`policy::PolicyDocument`].
#![warn(missing_docs)]

pub mod policy;
pub mod redaction;
pub mod scanner;

pub use redaction::Redaction;
pub use scanner::{CredentialFinding, CredentialKind, CredentialScanner, ScanResult, ScannerConfig};
