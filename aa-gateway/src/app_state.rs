//! Gateway application state — the single owning struct for runtime
//! dependencies shared across request handlers and background tasks.
//!
//! This module lands as part of Epic 18 Story S-I (AAASM-1590) and is
//! initially small: it owns the [`StorageBackend`] handle and nothing
//! else. Subsequent sub-tasks of the Story progressively migrate
//! `AgentRegistry`, the audit channel, and the retention engine
//! `JoinHandle` onto this struct so that every code path that needs
//! durable data has one canonical place to fetch it from.

use std::sync::Arc;

use crate::storage::StorageBackend;

/// Runtime dependencies shared across the gateway's request handlers
/// and background tasks.
///
/// The struct is intentionally minimal in this Sub-task (E18 S-I.1):
/// only the storage handle is present. Later Sub-tasks extend it with
/// the `AgentRegistry` write-through cache (S-I.2), the audit-event
/// pipeline (S-I.3), and the retention engine `JoinHandle` (S-I.4).
///
/// Cloning is cheap: every field is wrapped in `Arc`.
#[derive(Clone)]
pub struct AppState {
    /// Durable storage backend. `Arc<dyn StorageBackend>` keeps the
    /// concrete backend (SQLite locally, PostgreSQL in production)
    /// invisible to call sites and matches the Story acceptance
    /// criterion "`storage: Arc<dyn StorageBackend>` is the single
    /// dependency for all data access in `AppState`".
    pub storage: Arc<dyn StorageBackend>,
}

impl AppState {
    /// Build a new `AppState` from an already-opened storage backend.
    ///
    /// Callers are expected to have invoked
    /// [`StorageBackend::migrate`](crate::storage::StorageBackend::migrate)
    /// on the backend before passing it in; this constructor does not
    /// re-run migrations.
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self { storage }
    }
}
