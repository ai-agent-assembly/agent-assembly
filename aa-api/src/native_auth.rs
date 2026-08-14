//! Static configuration for the native email/password auth endpoints
//! (AAASM-5305, ADR 0031).
//!
//! Native accounts are Postgres-gated (ADR 0031 D2); this config is the
//! deployment posture that shapes their behaviour *independently* of whether a
//! Postgres store is wired in, so `/auth/methods` and the closed-registration
//! default behave deterministically. Nothing here holds a secret — only sizing
//! and policy knobs — so it is safe to keep on the cloneable `AppState`.

use uuid::Uuid;

/// The single default workspace/org an OSS deployment bootstraps into (ADR 0031
/// §4: OSS is single-workspace, so `register` takes no `tenant_name`).
///
/// A fixed, non-nil UUID: deliberately NOT the all-zeroes reserved system org
/// (`aa_storage_postgres::support::SYSTEM_ORG`) that untagged agent-liveness rows
/// use, so native accounts never share a tenant scope with those rows.
pub const DEFAULT_ORG_ID: Uuid = Uuid::from_u128(0x0000_5305_0000_0000_0000_0000_0000_0001);

/// Human-readable name stamped on the default workspace org when it is created
/// on first bootstrap.
pub const DEFAULT_ORG_NAME: &str = "Default Workspace";

/// Environment flag that opts a deployment into open self-registration
/// (ADR 0031 §Q3). Default is closed (first-user-then-invite).
pub const OPEN_REGISTRATION_ENV: &str = "AA_AUTH_OPEN_REGISTRATION";

/// Consecutive failed logins before an account is locked (ADR 0031 brute-force).
const LOCKOUT_THRESHOLD: i32 = 5;

/// How long an account stays locked after crossing the threshold, in seconds
/// (15 minutes).
const LOCKOUT_WINDOW_SECS: i64 = 15 * 60;

/// Access-token lifetime, in seconds (ADR 0031 §5: short-lived, ~15 min).
const ACCESS_TTL_SECS: u64 = 15 * 60;

/// Refresh-token lifetime without `remember_me`, in seconds (12 hours).
const REFRESH_TTL_SECS: u64 = 12 * 60 * 60;

/// Refresh-token lifetime with `remember_me`, in seconds (30 days).
const REFRESH_TTL_REMEMBER_SECS: u64 = 30 * 24 * 60 * 60;

/// Minimum accepted password length (ADR 0031 §3 "422 weak password"). A length
/// floor is the one weak-password rule the endpoint ticket calls out; 12 is a
/// conservative modern minimum that stays comfortably above the 8-char legacy
/// floor without imposing composition rules users route around.
const MIN_PASSWORD_LEN: usize = 12;

/// Resolved posture for the native-auth endpoints.
#[derive(Debug, Clone)]
pub struct NativeAuthConfig {
    /// The single default workspace org id native accounts belong to.
    pub default_org_id: Uuid,
    /// The name stamped on the default org when created on bootstrap.
    pub default_org_name: &'static str,
    /// Whether open self-registration is enabled (ADR 0031 §Q3).
    pub open_registration: bool,
    /// Consecutive failures before lockout.
    pub lockout_threshold: i32,
    /// Lockout duration in seconds.
    pub lockout_window_secs: i64,
    /// Access-token lifetime in seconds.
    pub access_ttl_secs: u64,
    /// Refresh-token lifetime without `remember_me`, in seconds.
    pub refresh_ttl_secs: u64,
    /// Refresh-token lifetime with `remember_me`, in seconds.
    pub refresh_ttl_remember_secs: u64,
    /// Minimum accepted password length.
    pub min_password_len: usize,
}

impl NativeAuthConfig {
    /// Resolve the posture from the environment.
    ///
    /// Only the open-registration flag is environment-driven (ADR 0031 §Q3); the
    /// rest are fixed policy for this release. The flag is `true` only for the
    /// explicit truthy spellings (`1`/`true`/`yes`, case-insensitive) — any other
    /// value (or unset) stays closed, the safe default.
    pub fn from_env() -> Self {
        let open_registration = std::env::var(OPEN_REGISTRATION_ENV)
            .ok()
            .map(|v| Self::is_truthy(&v))
            .unwrap_or(false);
        Self {
            default_org_id: DEFAULT_ORG_ID,
            default_org_name: DEFAULT_ORG_NAME,
            open_registration,
            lockout_threshold: LOCKOUT_THRESHOLD,
            lockout_window_secs: LOCKOUT_WINDOW_SECS,
            access_ttl_secs: ACCESS_TTL_SECS,
            refresh_ttl_secs: REFRESH_TTL_SECS,
            refresh_ttl_remember_secs: REFRESH_TTL_REMEMBER_SECS,
            min_password_len: MIN_PASSWORD_LEN,
        }
    }

    /// The refresh-token lifetime for a login, extended when `remember_me` is set.
    pub fn refresh_ttl_for(&self, remember_me: bool) -> u64 {
        if remember_me {
            self.refresh_ttl_remember_secs
        } else {
            self.refresh_ttl_secs
        }
    }

    /// Whether a candidate password clears the minimum-length floor.
    pub fn password_is_strong_enough(&self, password: &str) -> bool {
        password.chars().count() >= self.min_password_len
    }

    /// Parse a truthy environment value (`1` / `true` / `yes`, case-insensitive).
    fn is_truthy(v: &str) -> bool {
        matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes")
    }
}

impl Default for NativeAuthConfig {
    fn default() -> Self {
        Self::from_env()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_org_is_not_the_reserved_system_org() {
        // Native accounts must not share the reserved all-zeroes tenant that
        // untagged agent-liveness rows use.
        assert_ne!(DEFAULT_ORG_ID, Uuid::nil(), "default org must not be the system org");
    }

    #[test]
    fn open_registration_flag_only_true_for_truthy_values() {
        for v in ["1", "true", "TRUE", "yes", "Yes", " true "] {
            assert!(NativeAuthConfig::is_truthy(v), "{v:?} should be truthy");
        }
        for v in ["0", "false", "no", "", "off", "maybe"] {
            assert!(!NativeAuthConfig::is_truthy(v), "{v:?} should not be truthy");
        }
    }

    #[test]
    fn remember_me_extends_the_refresh_lifetime() {
        let cfg = NativeAuthConfig::from_env();
        assert!(
            cfg.refresh_ttl_for(true) > cfg.refresh_ttl_for(false),
            "remember_me must extend the refresh lifetime"
        );
        assert_eq!(cfg.refresh_ttl_for(false), REFRESH_TTL_SECS);
        assert_eq!(cfg.refresh_ttl_for(true), REFRESH_TTL_REMEMBER_SECS);
    }

    #[test]
    fn password_length_floor_is_enforced() {
        let cfg = NativeAuthConfig::from_env();
        // 11 chars: too short. 12: accepted.
        assert!(!cfg.password_is_strong_enough(&"a".repeat(MIN_PASSWORD_LEN - 1)));
        assert!(cfg.password_is_strong_enough(&"a".repeat(MIN_PASSWORD_LEN)));
    }
}
