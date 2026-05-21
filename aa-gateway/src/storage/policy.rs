//! Policy storage value types — input document, stored version, and metadata.

use chrono::{DateTime, Utc};

/// Lightweight metadata for a stored policy version (no document body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMeta {
    /// Policy name (unique key).
    pub name: String,
    /// Monotonic version number assigned by the backend on insert.
    pub version: u32,
    /// When this version was persisted (UTC).
    pub created_at: DateTime<Utc>,
    /// True if this version is currently active.
    pub is_active: bool,
}

/// Input shape for saving a new policy.
///
/// Storage-layer counterpart of the runtime
/// [`crate::policy::document::PolicyDocument`]: this type holds just the name
/// and the raw document bytes (YAML or JSON, as authored) so the storage
/// layer never has to parse policy semantics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDocument {
    /// Policy name.
    pub name: String,
    /// Raw document bytes — YAML or JSON, exactly as authored.
    pub bytes: Vec<u8>,
}

/// Persisted policy version — metadata plus the document body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyVersion {
    /// Metadata (name, version, created_at, is_active).
    pub meta: PolicyMeta,
    /// Document body persisted alongside the metadata.
    pub document: PolicyDocument,
}
