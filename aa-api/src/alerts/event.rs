//! Lifecycle event published by the `AlertStore` broadcast bus.
//!
//! Subscribers (notably the `GET /api/v1/alerts/ws` WebSocket handler
//! in AAASM-1389) receive these events whenever an alert's state
//! transitions — fire, resolve, or silence. Each variant carries the
//! `StoredAlert` snapshot at the moment of the transition.

use super::StoredAlert;

/// A single alert-lifecycle transition.
#[derive(Debug, Clone)]
pub enum AlertEvent {
    /// A new alert was recorded into the store (budget threshold crossed
    /// or secret-detection finding).
    Fire(StoredAlert),
    /// An existing alert was acknowledged via
    /// `POST /api/v1/alerts/{id}/resolve` and flipped from
    /// `unresolved` to `resolved`.
    Resolve(StoredAlert),
    /// An existing alert was suppressed by a fresh silence applied via
    /// `POST /api/v1/alerts/silence`. The snapshot's `status` field is
    /// `"suppressed"`; `prior_status` carries the pre-suppression state.
    Silence(StoredAlert),
}
