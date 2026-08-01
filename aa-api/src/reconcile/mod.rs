//! Enforcement-reconciliation background tasks.
//!
//! Reconcilers restore governance state that has drifted from its intended
//! posture. Today this module hosts the shadow-expiry watcher (AAASM-5339),
//! which auto-reverts agents whose time-limited Observe (shadow) enforcement
//! window has expired back to `Enforce`. This is a system action — the revert
//! is attributed to a fixed system principal, never a request-supplied actor.

pub mod shadow_expiry_watcher;
