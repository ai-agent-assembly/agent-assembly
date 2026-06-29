//! Gateway auth bootstrap (AAASM-3907).
//!
//! Builds the four request-extension objects the shared `aa-auth` extractors
//! ([`aa_auth::AuthenticatedCaller`], [`aa_auth::scope::RequireAdmin`], …) read
//! from request parts: [`AuthConfig`], [`ApiKeyStore`], [`JwtVerifier`], and
//! [`RateLimiter`]. A guarded route fails to resolve unless all four are
//! layered, so both gateway routers apply [`AuthExtensions`] uniformly.
//!
//! ## BYPASS-DEFAULT — the safety contract
//!
//! A bare gateway must keep booting and answering `aasm status` with no
//! credentials (the AAASM-1591 zero-config contract). [`AuthConfig::from_env`]
//! defaults to [`AuthMode::On`] and *hard-errors* without `AA_JWT_SECRET`, so
//! calling it unconditionally would make a zero-config gateway fail to boot and
//! return 401. Instead the gateway constructs an [`AuthMode::Off`] (bypass)
//! config **unless** auth is explicitly opted into — in bypass mode
//! `RequireAdmin` resolves to the synthetic admin caller and every guarded
//! route stays reachable. When an operator *does* opt in (`AA_GATEWAY_AUTH=on`
//! or `AA_JWT_SECRET` set) the bootstrap fails closed: a misconfigured auth-on
//! posture refuses to boot rather than serving open.

use std::path::PathBuf;
use std::sync::Arc;

use aa_auth::api_key::ApiKeyStore;
use aa_auth::config::{AuthConfig, AuthMode};
use aa_auth::jwt::JwtVerifier;
use aa_auth::rate_limit::RateLimiter;
use axum::{Extension, Router};

/// Default per-key requests-per-minute in bypass mode, matching the local
/// single-process default in `aa-api` (`AppState::local_in_memory`).
const BYPASS_RATE_LIMIT_RPM: u32 = 1000;

/// The four auth objects layered as request extensions so the `aa-auth`
/// extractors can resolve them. Cloning is cheap — every field is an `Arc`.
#[derive(Clone)]
pub struct AuthExtensions {
    /// Auth mode + credential config consulted by every extractor.
    pub config: Arc<AuthConfig>,
    /// API-key store for `aa_…` bearer credentials.
    pub key_store: Arc<ApiKeyStore>,
    /// HMAC-SHA256 JWT verifier for bearer JWT credentials.
    pub jwt_verifier: Arc<JwtVerifier>,
    /// Per-key rate limiter.
    pub rate_limiter: Arc<RateLimiter>,
}

impl AuthExtensions {
    /// Build the gateway's auth objects from the environment, BYPASS-DEFAULT.
    ///
    /// Returns an [`AuthMode::Off`] bypass posture unless auth is explicitly
    /// opted into (see [`auth_opted_in`]). When opted in, defers to
    /// [`AuthConfig::from_env`] and *panics* if the resulting config is invalid
    /// (e.g. `AA_GATEWAY_AUTH=on` without a valid `AA_JWT_SECRET`) — a
    /// misconfigured auth-on gateway must refuse to boot rather than serve open.
    pub fn from_env() -> Self {
        if auth_opted_in() {
            let config = AuthConfig::from_env().unwrap_or_else(|e| {
                panic!(
                    "gateway auth was explicitly enabled (AA_GATEWAY_AUTH/AA_JWT_SECRET) but its \
                     configuration is invalid: {e}; refusing to boot in an insecure state"
                )
            });
            Self::from_config(config)
        } else {
            Self::bypass()
        }
    }

    /// Build an [`AuthMode::Off`] (bypass) posture: `RequireAdmin` resolves to
    /// the synthetic admin caller and every guarded route stays reachable with
    /// no credential. This is the zero-config default (AAASM-1591).
    pub fn bypass() -> Self {
        Self::from_config(AuthConfig {
            mode: AuthMode::Off,
            jwt_secret: None,
            // Unused in bypass mode — no key file is consulted.
            api_keys_path: PathBuf::from("/nonexistent-aa-gateway-bypass-keys"),
            rate_limit_rpm: BYPASS_RATE_LIMIT_RPM,
        })
    }

    /// Build the four objects from an already-resolved [`AuthConfig`].
    pub fn from_config(config: AuthConfig) -> Self {
        let rate_limiter = Arc::new(RateLimiter::new(config.rate_limit_rpm));
        // In Off mode the verifier is never consulted; an empty secret is fine.
        let jwt_verifier = Arc::new(JwtVerifier::new(config.jwt_secret.as_deref().unwrap_or(&[])));
        // `load` on a missing path returns an empty store (infallible). In Off
        // mode the store is never consulted; in On mode operators point
        // `AA_API_KEYS_PATH` at their key file.
        let key_store = Arc::new(
            ApiKeyStore::load(&config.api_keys_path).unwrap_or_else(|_| ApiKeyStore::from_entries(Vec::new())),
        );
        Self {
            config: Arc::new(config),
            key_store,
            jwt_verifier,
            rate_limiter,
        }
    }

    /// Layer the four extensions onto `router` so the `aa-auth` extractors can
    /// resolve them from request parts. All four are required by `RequireAdmin`.
    pub fn apply(&self, router: Router) -> Router {
        router
            .layer(Extension(self.config.clone()))
            .layer(Extension(self.key_store.clone()))
            .layer(Extension(self.jwt_verifier.clone()))
            .layer(Extension(self.rate_limiter.clone()))
    }
}

/// Whether the operator has explicitly opted the gateway into enforcing auth.
///
/// True when `AA_GATEWAY_AUTH` is `on` (case-insensitive), or when
/// `AA_JWT_SECRET` is set (a JWT secret is meaningless unless auth is
/// enforced). Otherwise the gateway runs in bypass mode so a bare
/// `aasm status` keeps working with no credential.
fn auth_opted_in() -> bool {
    let flag_on = std::env::var("AA_GATEWAY_AUTH")
        .map(|v| v.eq_ignore_ascii_case("on"))
        .unwrap_or(false);
    flag_on || std::env::var("AA_JWT_SECRET").is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serialize env-var-dependent tests under `cargo test`. (Under
    /// `cargo nextest` each test runs in its own process, so this is redundant
    /// there — it only guards the shared-process `cargo test` path.)
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn clear_auth_env() {
        std::env::remove_var("AA_GATEWAY_AUTH");
        std::env::remove_var("AA_JWT_SECRET");
        std::env::remove_var("AA_AUTH");
    }

    #[test]
    fn bypass_yields_off_mode() {
        let ext = AuthExtensions::bypass();
        assert_eq!(ext.config.mode, AuthMode::Off);
        assert!(ext.config.jwt_secret.is_none());
    }

    /// The AAASM-1591 zero-config contract: with no auth env set, the gateway
    /// must default to bypass so a bare `aasm status` keeps working.
    #[test]
    fn from_env_defaults_to_bypass_when_unset() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        let ext = AuthExtensions::from_env();
        assert_eq!(
            ext.config.mode,
            AuthMode::Off,
            "a zero-config gateway must default to bypass"
        );
    }

    /// `AA_JWT_SECRET` alone is enough to opt the gateway into enforcing auth.
    #[test]
    fn from_env_opts_in_when_jwt_secret_set() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_JWT_SECRET", "a-secret-that-is-at-least-32-bytes-long!!");
        let ext = AuthExtensions::from_env();
        clear_auth_env();
        assert_eq!(ext.config.mode, AuthMode::On, "an explicit JWT secret must enable auth");
    }

    /// `AA_GATEWAY_AUTH=on` (with a valid secret) opts in explicitly.
    #[test]
    fn from_env_opts_in_when_gateway_auth_flag_on() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_GATEWAY_AUTH", "ON");
        std::env::set_var("AA_JWT_SECRET", "a-secret-that-is-at-least-32-bytes-long!!");
        let ext = AuthExtensions::from_env();
        clear_auth_env();
        assert_eq!(ext.config.mode, AuthMode::On, "AA_GATEWAY_AUTH=on must enable auth");
    }
}
