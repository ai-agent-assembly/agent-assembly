//! Error types for the `aa-proxy` crate.

use thiserror::Error;

/// All errors that can arise within `aa-proxy`.
#[derive(Debug, Error)]
pub enum ProxyError {
    /// An underlying I/O error (bind failure, connection reset, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// A TLS handshake or configuration error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// A certificate generation error (rcgen failure).
    #[error("Certificate generation error: {0}")]
    CertGen(String),

    /// A configuration error (missing or invalid env var).
    #[error("Configuration error: {0}")]
    Config(String),

    /// A macOS Keychain operation failed (security CLI returned non-zero).
    #[error("Keychain error: {0}")]
    Keychain(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_variant_wraps_and_displays_source() {
        // The `#[from]` conversion must produce an Io variant whose Display
        // carries the underlying error text.
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing ca");
        let err: ProxyError = io.into();
        assert!(matches!(err, ProxyError::Io(_)));
        assert!(err.to_string().contains("missing ca"));
    }

    #[test]
    fn string_variants_render_their_label_and_message() {
        // Each string-carrying variant must prefix its category and include the
        // supplied detail so log lines are self-describing.
        assert_eq!(ProxyError::Tls("handshake".into()).to_string(), "TLS error: handshake");
        assert_eq!(
            ProxyError::CertGen("rcgen failed".into()).to_string(),
            "Certificate generation error: rcgen failed"
        );
        assert_eq!(
            ProxyError::Config("bad port".into()).to_string(),
            "Configuration error: bad port"
        );
        assert_eq!(
            ProxyError::Keychain("denied".into()).to_string(),
            "Keychain error: denied"
        );
    }
}
