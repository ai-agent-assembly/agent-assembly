//! Unified error type for the `aasm` CLI.

use std::path::PathBuf;

/// Errors that can occur during CLI execution.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
    /// Failed to read or write the configuration file.
    #[error("config error at {path}: {source}")]
    Config { path: PathBuf, source: std::io::Error },

    /// The configuration file contains invalid YAML.
    #[error("invalid config YAML: {0}")]
    ConfigParse(#[from] serde_yaml::Error),

    /// The requested named context does not exist.
    #[error("context not found: {0}")]
    ContextNotFound(String),

    /// An HTTP request to the gateway failed.
    #[error("API request failed: {0}")]
    Api(#[from] reqwest::Error),

    /// The gateway rejected the request as unauthenticated (`401`): no
    /// credential, or one that is invalid/expired/revoked. Carries no detail
    /// on purpose — the caller decides the actionable hint (run `aasm login`
    /// vs. re-login) from whether a local session exists (AAASM-5513).
    #[error("authentication required")]
    AuthRequired,

    /// The gateway rejected the request as forbidden (`403`): the caller is
    /// authenticated but the session's scope is insufficient. The string is the
    /// server's problem-detail message where available (AAASM-5513).
    #[error("{0}")]
    ScopeDenied(String),

    /// The `/auth/token` exchange failed for a reason other than `401`/`403`
    /// (e.g. an unexpected status or malformed body).
    #[error("token exchange failed: {0}")]
    AuthExchange(String),

    /// Generic I/O error.
    #[error("{0}")]
    Io(#[from] std::io::Error),
}
