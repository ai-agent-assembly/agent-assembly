//! Policy version history for aa-gateway.
//!
//! Tracks applied policy versions with timestamps and change attribution,
//! enabling rollback to any previous version.
//!
//! # Storage layout
//!
//! Each applied policy is stored as a pair of files in the history directory
//! (default `~/.aa/policy-history/`, configurable via [`HistoryConfig`]):
//!
//! ```text
//! ~/.aa/policy-history/
//!   20260428T120000Z-abcdef12.yaml       # YAML snapshot
//!   20260428T120000Z-abcdef12.meta.json   # JSON metadata sidecar
//! ```
//!
//! The naming convention is `<ISO-8601-timestamp>-<sha256-prefix>`.
//!
//! # Key types
//!
//! - [`PolicyVersionMeta`] — lightweight index entry (JSON sidecar content)
//! - [`PolicySnapshot`] — full version: metadata + YAML body
//! - [`HistoryConfig`] — directory path and retention limit
//! - [`PolicyHistoryError`] — error variants for store operations
//! - [`PolicyHistoryStore`] — async trait for storage backends

pub mod config;
pub mod error;
pub mod fs_store;
pub mod meta;
pub mod snapshot;
pub mod store;

pub use config::HistoryConfig;
pub use error::PolicyHistoryError;
pub use fs_store::FsHistoryStore;
pub use meta::PolicyVersionMeta;
pub use snapshot::PolicySnapshot;
pub use store::PolicyHistoryStore;
