//! Errors raised while parsing the canonical policy AST.

use std::fmt;

/// Errors that can occur while parsing a [`PolicyDocument`](super::PolicyDocument).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyParseError {
    /// The YAML could not be deserialized.
    Yaml(String),
    /// A capability token was not recognised.
    InvalidCapability {
        /// The offending raw token.
        raw: String,
        /// Why it was rejected.
        reason: String,
    },
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(msg) => write!(f, "policy YAML parse error: {msg}"),
            Self::InvalidCapability { raw, reason } => {
                write!(f, "invalid capability {raw:?}: {reason}")
            }
        }
    }
}

impl std::error::Error for PolicyParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_yaml_error() {
        let err = PolicyParseError::Yaml("bad".to_string());
        assert_eq!(err.to_string(), "policy YAML parse error: bad");
    }

}
