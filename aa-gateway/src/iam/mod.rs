//! Identity & Access governance state — API key lifecycle for the dashboard.
//!
//! This module is intentionally **distinct** from `aa-api::auth::api_key`,
//! which authenticates *incoming* bearer tokens. `iam::api_keys` is the
//! management surface that backs the dashboard's Identity & Access page
//! (AAASM-119): list / generate / revoke / rotate operations that the
//! operator-facing UI performs.
//!
//! Persistence is **in-memory only** (`DashMap`-backed). Durable storage
//! across gateway restarts is explicitly out of scope; flagging the
//! follow-up if needed.

pub mod api_keys;
pub use api_keys::{ApiKeyEntry, ApiKeyScope, ApiKeyStatus, GeneratedApiKey, IamApiKeyStore, RecentActivityEntry};
