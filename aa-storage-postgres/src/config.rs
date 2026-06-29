//! Connection-pool configuration for the Postgres driver.
//!
//! Parsed from the `[storage.postgres]` subsection of the Agent Assembly config
//! file. Only the knobs an OSS operator needs to point the driver at their own
//! Postgres are exposed here; TimescaleDB and retention tuning live elsewhere.

use std::fmt;

use serde::Deserialize;

/// Default maximum pooled-connection count when unspecified.
const DEFAULT_MAX_CONNECTIONS: u32 = 10;

/// Default per-statement timeout in milliseconds. `0` disables the cap.
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 0;

/// Connection-pool settings for [`PostgresPool`](crate::PostgresPool).
///
/// Deserialized from `[storage.postgres]`:
///
/// ```toml
/// [storage.postgres]
/// url = "postgres://aasm:secret@localhost:5432/aasm"
/// max_connections = 20
/// statement_timeout_ms = 5000
/// ```
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default)]
pub struct PostgresPoolConfig {
    /// PostgreSQL connection URL (`postgres://user:pass@host:port/db`).
    pub url: String,
    /// Maximum number of pooled connections.
    pub max_connections: u32,
    /// Per-statement timeout in milliseconds, applied via `SET statement_timeout`
    /// on each connection. `0` leaves the server default in place.
    pub statement_timeout_ms: u64,
}

/// Custom `Debug` that redacts the password component of the connection URL.
///
/// The DSN carries `postgres://user:pass@host/db` credentials; the derived
/// `Debug` would print the password verbatim, so any future log of this config
/// would leak it. This impl renders the URL with the password replaced by `***`
/// while leaving every other field untouched. It changes only diagnostic output
/// — the unredacted [`url`](Self::url) is still what the pool connects with.
impl fmt::Debug for PostgresPoolConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresPoolConfig")
            .field("url", &redact_dsn_password(&self.url))
            .field("max_connections", &self.max_connections)
            .field("statement_timeout_ms", &self.statement_timeout_ms)
            .finish()
    }
}

/// Replace the password component of a `scheme://user:pass@host/...` DSN with
/// `***`, leaving the scheme, username, host, and path intact.
///
/// URLs without userinfo, or with userinfo but no password, are returned
/// unchanged. Used only for redacted diagnostic rendering — never on the value
/// handed to the connection layer.
fn redact_dsn_password(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_owned();
    };
    let Some((userinfo, host_part)) = rest.split_once('@') else {
        return url.to_owned();
    };
    match userinfo.split_once(':') {
        Some((user, _password)) => format!("{scheme}://{user}:***@{host_part}"),
        None => url.to_owned(),
    }
}

impl Default for PostgresPoolConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            max_connections: DEFAULT_MAX_CONNECTIONS,
            statement_timeout_ms: DEFAULT_STATEMENT_TIMEOUT_MS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `[storage.postgres]` subsection deserializes all three knobs.
    #[derive(Debug, Deserialize)]
    struct Storage {
        postgres: PostgresPoolConfig,
    }

    #[derive(Debug, Deserialize)]
    struct Root {
        storage: Storage,
    }

    #[test]
    fn parses_storage_postgres_subsection() {
        let doc = r#"
            [storage.postgres]
            url = "postgres://aasm:secret@localhost:5432/aasm"
            max_connections = 25
            statement_timeout_ms = 5000
        "#;

        let root: Root = toml::from_str(doc).expect("config should parse");

        assert_eq!(root.storage.postgres.url, "postgres://aasm:secret@localhost:5432/aasm");
        assert_eq!(root.storage.postgres.max_connections, 25);
        assert_eq!(root.storage.postgres.statement_timeout_ms, 5000);
    }

    #[test]
    fn debug_redacts_dsn_password() {
        let config = PostgresPoolConfig {
            url: "postgres://aasm:supersecret@db.internal:5432/aasm".to_owned(),
            ..Default::default()
        };

        let rendered = format!("{config:?}");

        assert!(!rendered.contains("supersecret"), "password leaked in Debug: {rendered}");
        assert!(rendered.contains("aasm:***@db.internal:5432/aasm"), "redacted URL missing: {rendered}");
    }

    #[test]
    fn debug_leaves_passwordless_dsn_untouched() {
        let config = PostgresPoolConfig {
            url: "postgres://localhost/aasm".to_owned(),
            ..Default::default()
        };

        assert!(format!("{config:?}").contains("postgres://localhost/aasm"));
    }

    #[test]
    fn applies_defaults_for_omitted_knobs() {
        let doc = r#"
            [storage.postgres]
            url = "postgres://localhost/aasm"
        "#;

        let root: Root = toml::from_str(doc).expect("config should parse");

        assert_eq!(root.storage.postgres.max_connections, DEFAULT_MAX_CONNECTIONS);
        assert_eq!(root.storage.postgres.statement_timeout_ms, DEFAULT_STATEMENT_TIMEOUT_MS);
    }
}
