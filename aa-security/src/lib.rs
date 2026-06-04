//! Security primitives for Agent Assembly.
//!
//! This crate owns the credential-detection scanner, the redaction primitives,
//! and the audit-normalization types relied on by the trusted enforcement
//! layers (`aa-runtime`, `aa-gateway`, `aa-proxy`).
//!
//! It is deliberately a **leaf** crate: it does *not* depend on `aa-core`, so
//! security authority comes from *where a primitive runs*, not from the core
//! domain crate. The primitives are progressively moved here from `aa-core`
//! (see AAASM-2567); `aa-core` keeps temporary `pub use` re-exports for
//! migration compatibility.
#![warn(missing_docs)]
