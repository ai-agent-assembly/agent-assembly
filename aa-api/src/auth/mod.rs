//! Authentication and authorization for the API server.
//!
//! Auth is handled via Axum `FromRequestParts` extractors, not middleware
//! layers. The [`AuthenticatedCaller`] extractor validates API keys or JWTs
//! and enforces per-key rate limits. [`scope::RequireScope`] checks scope levels.
//!
//! AAASM-3899: the auth framework itself now lives in the `aa-auth` leaf crate
//! so the gateway can share it. This module is a thin re-export facade so every
//! existing `crate::auth::…` path keeps resolving unchanged. Only
//! [`policy_auth`] — which couples to `aa_gateway::policy` and therefore cannot
//! live in the leaf — still lives here in `aa-api`.

pub use aa_auth::{api_key, config, gate, jwt, rate_limit, scope};
pub use aa_auth::{AuthError, AuthenticatedCaller, Tenant};

pub mod policy_auth;
