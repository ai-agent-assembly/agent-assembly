//! On-disk session store for the `aasm` auth workflow (AAASM-5506).
//!
//! A session is the credential minted by `aasm login`: the short-lived scoped
//! JWT returned by `POST /api/v1/auth/token`, its expiry, the granted scopes,
//! and the **source API key** the JWT was exchanged from. The source key is
//! retained so the client layer can silently re-mint an expired JWT without
//! forcing the user to log in again every 24h (the server issues no refresh
//! token — see [`crate::auth::token`]).
//!
//! Sessions live in `~/.aa/credentials.yaml`, kept **separate** from
//! `config.yaml` so that clearing a session (`aasm logout`) never rewrites the
//! user's context definitions. The file holds bearer material, so it is locked
//! to `0600` (dir `0700`) on Unix exactly like `config.yaml`.
//!
//! Sessions are keyed per context: a user may be logged into several gateways
//! at once, and `logout` / refresh must act on the active one only. A corrupt
//! or partially-written file fails **closed** to "no session" rather than
//! panicking — a damaged credential store must never wedge the CLI.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::config::{config_dir, ResolvedContext};
use crate::error::CliError;

/// A persisted authenticated session for one context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    /// The scoped JWT issued by `/api/v1/auth/token`, attached as the bearer
    /// credential on subsequent requests.
    pub token: String,
    /// Unix timestamp (seconds) at which `token` expires.
    pub expires_at: u64,
    /// Scopes granted to `token` (`read` / `write` / `admin`), lowercase to
    /// match the server's `Scope` serde representation.
    pub scopes: Vec<String>,
    /// The API key `token` was exchanged from, retained for silent re-exchange
    /// when the JWT expires. Never printed by any command.
    pub source_key: String,
    /// The gateway base URL this session authenticates against, recorded so
    /// `whoami` can show it and refresh targets the right endpoint.
    pub api_url: String,
}

impl Session {
    /// Whether `token` is expired at `now` (unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }

    /// Seconds until expiry at `now`; negative once expired.
    pub fn expires_in_secs(&self, now: u64) -> i64 {
        self.expires_at as i64 - now as i64
    }
}

/// On-disk schema for `~/.aa/credentials.yaml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CredentialStore {
    /// Sessions keyed by [`session_key`].
    #[serde(default)]
    sessions: BTreeMap<String, Session>,
}

/// Current wall-clock time in unix seconds.
///
/// Clamped at the epoch: a system clock set before 1970 yields `0` rather than
/// panicking, so expiry math stays well-defined on a misconfigured host.
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Path to the credential store file (`~/.aa/credentials.yaml`).
pub fn credentials_path() -> PathBuf {
    config_dir().join("credentials.yaml")
}

/// The key under which a context's session is stored.
///
/// A named context keys by its name (what the user reasons about — "I logged
/// into production"); an unnamed context (explicit `--api-url` or the built-in
/// default) keys by its URL so distinct gateways don't collide.
pub fn session_key(ctx: &ResolvedContext) -> String {
    match &ctx.name {
        Some(name) => name.clone(),
        None => ctx.api_url.clone(),
    }
}

/// Read the whole store, failing **closed** to an empty store on a missing,
/// unreadable, or corrupt file — a damaged credential file must not wedge the CLI.
fn load_store() -> CredentialStore {
    let path = credentials_path();
    let Ok(contents) = std::fs::read_to_string(&path) else {
        return CredentialStore::default();
    };
    serde_yaml::from_str(&contents).unwrap_or_default()
}

/// Persist the store to `~/.aa/credentials.yaml` at `0600` (dir `0700`).
fn save_store(store: &CredentialStore) -> Result<(), CliError> {
    let dir = config_dir();
    ensure_dir(&dir)?;
    let path = credentials_path();
    let yaml = serde_yaml::to_string(store)?;
    write_locked(&path, &yaml)
}

/// Load the session for a context key, or `None` if there is no valid one.
pub fn load_session(key: &str) -> Option<Session> {
    load_store().sessions.get(key).cloned()
}

/// Store (create or replace) the session for a context key.
pub fn save_session(key: &str, session: &Session) -> Result<(), CliError> {
    let mut store = load_store();
    store.sessions.insert(key.to_string(), session.clone());
    save_store(&store)
}

/// Remove the session for a context key. Returns whether one was present, so
/// `logout` can distinguish "ended a session" from an idempotent no-op.
pub fn clear_session(key: &str) -> Result<bool, CliError> {
    let mut store = load_store();
    let existed = store.sessions.remove(key).is_some();
    if existed {
        save_store(&store)?;
    }
    Ok(existed)
}

/// Create `~/.aa/` if missing and tighten it to `0700` (Unix).
///
/// Mirrors [`crate::config`]'s directory locking so the credential store gets
/// the same protection as `config.yaml`.
#[cfg(unix)]
fn ensure_dir(dir: &std::path::Path) -> Result<(), CliError> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if dir.exists() {
        return std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| CliError::Config {
            path: dir.to_path_buf(),
            source: e,
        });
    }
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| CliError::Config {
            path: dir.to_path_buf(),
            source: e,
        })
}

#[cfg(not(unix))]
fn ensure_dir(dir: &std::path::Path) -> Result<(), CliError> {
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).map_err(|e| CliError::Config {
        path: dir.to_path_buf(),
        source: e,
    })
}

/// Write the credential file, restricting it to `0600` on Unix (created with
/// `0600` so there is no world-readable window, and any pre-existing loose file
/// is tightened).
#[cfg(unix)]
fn write_locked(path: &std::path::Path, yaml: &str) -> Result<(), CliError> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| CliError::Config {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|e| CliError::Config {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(yaml.as_bytes()).map_err(|e| CliError::Config {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(not(unix))]
fn write_locked(path: &std::path::Path, yaml: &str) -> Result<(), CliError> {
    std::fs::write(path, yaml).map_err(|e| CliError::Config {
        path: path.to_path_buf(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Session {
        Session {
            token: "jwt.token.value".to_string(),
            expires_at: 1_000_000,
            scopes: vec!["read".to_string(), "write".to_string()],
            source_key: "aa_sourcekey".to_string(),
            api_url: "http://localhost:8080".to_string(),
        }
    }

    #[test]
    fn expiry_math() {
        let s = sample();
        assert!(!s.is_expired(999_999));
        assert!(s.is_expired(1_000_000));
        assert!(s.is_expired(1_000_001));
        assert_eq!(s.expires_in_secs(999_000), 1_000);
        assert!(s.expires_in_secs(1_000_050) < 0);
    }

    #[test]
    fn session_key_prefers_name_then_url() {
        let named = ResolvedContext {
            name: Some("production".to_string()),
            api_url: "https://api.example.com".to_string(),
            api_key: None,
        };
        let unnamed = ResolvedContext {
            name: None,
            api_url: "http://localhost:8080".to_string(),
            api_key: None,
        };
        assert_eq!(session_key(&named), "production");
        assert_eq!(session_key(&unnamed), "http://localhost:8080");
    }

    #[cfg(unix)]
    #[test]
    fn save_load_clear_round_trip_and_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let key = "production";
        let result = (|| {
            save_session(key, &sample())?;
            let path = credentials_path();
            let mode = std::fs::metadata(&path)?.permissions().mode() & 0o777;
            let loaded = load_session(key);
            let cleared = clear_session(key)?;
            let after = load_session(key);
            Ok::<_, CliError>((mode, loaded, cleared, after))
        })();

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        let (mode, loaded, cleared, after) = result.unwrap();
        assert_eq!(mode, 0o600, "credential file must be owner-only (0600)");
        assert_eq!(loaded.as_ref(), Some(&sample()));
        assert!(cleared, "clear must report it removed an existing session");
        assert!(after.is_none(), "session must be gone after clear");
    }

    #[test]
    fn corrupt_file_fails_closed_to_no_session() {
        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let result = (|| {
            let dir = config_dir();
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(credentials_path(), "this: is: not: valid: yaml: [").unwrap();
            load_session("anything")
        })();

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert!(result.is_none(), "corrupt store must resolve to no session, not panic");
    }

    #[test]
    fn clear_missing_session_is_noop() {
        let _guard = crate::test_support::env_guard();
        let tmp = tempfile::TempDir::new().unwrap();
        let prev_home = std::env::var_os("HOME");
        std::env::set_var("HOME", tmp.path());

        let cleared = clear_session("never-logged-in");

        match prev_home {
            Some(v) => std::env::set_var("HOME", v),
            None => std::env::remove_var("HOME"),
        }

        assert!(!cleared.unwrap(), "clearing a nonexistent session is a no-op (false)");
    }
}
