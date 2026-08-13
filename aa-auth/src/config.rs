//! Authentication configuration from environment variables.

use std::path::PathBuf;

use thiserror::Error;

/// Default path for API keys storage.
const DEFAULT_API_KEYS_PATH: &str = "~/.aa/api-keys.json";

/// Default rate limit: requests per minute per API key.
const DEFAULT_RATE_LIMIT_RPM: u32 = 1000;

/// Minimum length for the JWT secret (256 bits).
const MIN_JWT_SECRET_LEN: usize = 32;

/// Authentication mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Authentication is enabled (default).
    On,
    /// Authentication is disabled — all requests are treated as admin.
    Off,
}

/// Authentication configuration for the API server.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// Whether auth is enabled or bypassed.
    pub mode: AuthMode,
    /// HMAC-SHA256 secret for JWT signing. `None` when `mode == Off`.
    pub jwt_secret: Option<Vec<u8>>,
    /// Path to the API keys JSON file.
    pub api_keys_path: PathBuf,
    /// Maximum requests per minute per API key.
    pub rate_limit_rpm: u32,
}

/// Errors that can occur when loading auth configuration.
#[derive(Debug, Error)]
pub enum AuthConfigError {
    #[error("AA_JWT_SECRET must be set when authentication is enabled")]
    MissingJwtSecret,
    #[error("AA_JWT_SECRET must be at least {MIN_JWT_SECRET_LEN} bytes (got {actual} bytes)")]
    JwtSecretTooShort { actual: usize },
    #[error("AA_RATE_LIMIT_RPM must be a positive integer: {0}")]
    InvalidRateLimit(String),
}

impl AuthConfig {
    /// Build auth configuration from environment variables.
    ///
    /// # Environment variables
    ///
    /// - `AA_AUTH`: `"on"` (default) or `"off"` (bypass mode)
    /// - `AA_JWT_SECRET`: HMAC key for JWT, required when auth is enabled
    /// - `AA_API_KEYS_PATH`: path to API keys file (default `~/.aa/api-keys.json`)
    /// - `AA_RATE_LIMIT_RPM`: requests per minute per key (default 1000)
    pub fn from_env() -> Result<Self, AuthConfigError> {
        let mode = match std::env::var("AA_AUTH").as_deref() {
            Ok("off") | Ok("OFF") => {
                tracing::warn!("AA_AUTH=off: authentication is disabled — all requests treated as admin");
                AuthMode::Off
            }
            _ => AuthMode::On,
        };

        let jwt_secret = if mode == AuthMode::On {
            let secret = std::env::var("AA_JWT_SECRET").map_err(|_| AuthConfigError::MissingJwtSecret)?;
            let bytes = secret.into_bytes();
            if bytes.len() < MIN_JWT_SECRET_LEN {
                return Err(AuthConfigError::JwtSecretTooShort { actual: bytes.len() });
            }
            Some(bytes)
        } else {
            None
        };

        let api_keys_path = std::env::var("AA_API_KEYS_PATH").unwrap_or_else(|_| DEFAULT_API_KEYS_PATH.to_string());
        let api_keys_path = expand_tilde(&api_keys_path);

        let rate_limit_rpm = resolve_rate_limit_rpm()?;

        Ok(Self {
            mode,
            jwt_secret,
            api_keys_path,
            rate_limit_rpm,
        })
    }
}

/// Resolve the per-key requests-per-minute limit from `AA_RATE_LIMIT_RPM`.
///
/// Returns [`DEFAULT_RATE_LIMIT_RPM`] when the variable is unset, and an
/// [`AuthConfigError::InvalidRateLimit`] when it is set to a non-`u32` value.
/// Shared by [`AuthConfig::from_env`] and the local-mode entrypoint so the
/// shipped server honours `AA_RATE_LIMIT_RPM` in its live rate limiter.
pub fn resolve_rate_limit_rpm() -> Result<u32, AuthConfigError> {
    match std::env::var("AA_RATE_LIMIT_RPM") {
        Ok(val) => val.parse::<u32>().map_err(|_| AuthConfigError::InvalidRateLimit(val)),
        Err(_) => Ok(DEFAULT_RATE_LIMIT_RPM),
    }
}

/// Expand `~` prefix to the user's home directory.
fn expand_tilde(path: &str) -> PathBuf {
    if let Some(rest) = path.strip_prefix("~/") {
        if let Some(home) = dirs_home() {
            return home.join(rest);
        }
    }
    PathBuf::from(path)
}

/// Get the user's home directory.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Guard to serialize env-var-dependent tests.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: clear all auth-related env vars before a test.
    fn clear_auth_env() {
        std::env::remove_var("AA_AUTH");
        std::env::remove_var("AA_JWT_SECRET");
        std::env::remove_var("AA_API_KEYS_PATH");
        std::env::remove_var("AA_RATE_LIMIT_RPM");
    }

    #[test]
    fn test_config_auth_off_no_secret_required() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_AUTH", "off");

        let config = AuthConfig::from_env().expect("auth=off should succeed without secret");
        assert_eq!(config.mode, AuthMode::Off);
        assert!(config.jwt_secret.is_none());
    }

    #[test]
    fn test_config_auth_on_missing_secret_fails() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        // AA_AUTH defaults to On when unset.

        let result = AuthConfig::from_env();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthConfigError::MissingJwtSecret));
    }

    #[test]
    fn test_config_auth_on_short_secret_fails() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_JWT_SECRET", "too-short");

        let result = AuthConfig::from_env();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), AuthConfigError::JwtSecretTooShort { .. }));
    }

    #[test]
    fn test_config_auth_on_valid_secret_succeeds() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_JWT_SECRET", "a]secret-that-is-at-least-32-bytes-long!!");

        let config = AuthConfig::from_env().expect("valid secret should succeed");
        assert_eq!(config.mode, AuthMode::On);
        assert!(config.jwt_secret.is_some());
    }

    #[test]
    fn test_config_default_rate_limit() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_AUTH", "off");

        let config = AuthConfig::from_env().unwrap();
        assert_eq!(config.rate_limit_rpm, 1000);
    }

    #[test]
    fn test_config_custom_rate_limit() {
        let _lock = ENV_LOCK.lock().unwrap();
        clear_auth_env();
        std::env::set_var("AA_AUTH", "off");
        std::env::set_var("AA_RATE_LIMIT_RPM", "500");

        let config = AuthConfig::from_env().unwrap();
        assert_eq!(config.rate_limit_rpm, 500);
    }
}
