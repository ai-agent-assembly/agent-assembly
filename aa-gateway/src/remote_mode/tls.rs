//! Pre-flight TLS validation for Remote Control-Plane Mode.
//!
//! The gateway calls [`validate`] before binding the listener so any
//! cert / key misconfiguration produces a fast, clearly-attributed
//! startup error rather than a runtime TLS handshake failure that
//! shows up only when the first client tries to connect.

use std::path::PathBuf;

use thiserror::Error;

/// Hard failures that should stop gateway startup in remote-mode TLS.
///
/// The variant carries enough context (paths, parse messages) for the
/// startup log line to point an operator at exactly the file or field
/// that needs fixing.
#[derive(Debug, Error)]
pub enum TlsError {
    /// The configured `cert_file` path does not exist on disk.
    #[error("TLS cert_file not found: {0}")]
    CertFileMissing(PathBuf),

    /// The configured `key_file` path does not exist on disk.
    #[error("TLS key_file not found: {0}")]
    KeyFileMissing(PathBuf),

    /// I/O error reading cert or key file (e.g. permission denied).
    #[error("failed to read TLS file {path}: {source}")]
    Io {
        /// File the gateway tried to read.
        path: PathBuf,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },

    /// The cert file does not parse as PEM-encoded X.509.
    #[error("failed to parse TLS cert as PEM x509: {0}")]
    CertParse(String),
}
