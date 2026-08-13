//! Auth workflow for the `aasm` CLI (Epic AAASM-5505).
//!
//! Adds a session layer on top of the existing API-key model: `aasm login`
//! exchanges an API key for a short-lived scoped JWT (via [`token`]), the
//! credential is persisted per context (via [`session`]), and the client layer
//! attaches it automatically and silently refreshes it on expiry. The API key
//! itself no longer needs to sit on argv/env or ride in every request.
//!
//! The server remains the sole authorization authority — this module never
//! decides whether an operation is allowed; it only manages the credential the
//! request carries and translates the server's `401`/`403` into actionable
//! guidance.

pub mod session;
pub mod token;
