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
    /// A syscall name in the `syscalls.allow` list was not recognised.
    InvalidSyscall {
        /// The offending raw token.
        raw: String,
        /// Why it was rejected.
        reason: String,
    },
    /// A structural key was not part of the known policy schema.
    ///
    /// Raised when a security-relevant section or field is misspelled (e.g.
    /// `dney:` for `deny:`, `allow_list:` for `allowlist:`). Such typos would
    /// otherwise be silently dropped by `#[serde(flatten)]` — yielding an empty,
    /// permissive policy that parses successfully. Surfacing them keeps policy
    /// parsing fail-closed (AAASM-3874).
    UnknownKey {
        /// Dotted path to the mapping that contained the unknown key.
        path: String,
        /// The unrecognised key.
        key: String,
    },
    /// The document was empty or null.
    ///
    /// An empty / null / `{}` policy deserializes to an all-`None` document,
    /// which is fully permissive (no capability denials, no allowlist, no tool
    /// gating). A policy must positively declare its posture, so a blank
    /// document is rejected rather than silently defaulting open (AAASM-3997).
    EmptyDocument,
    /// The document parsed but declared no enforcement dimension.
    ///
    /// A metadata-only document (e.g. just `apiVersion`/`kind`/`metadata`, with
    /// no `network`, `capabilities`, `tools`, or `syscalls`) deserializes to a
    /// fully-permissive policy exactly like an empty one. It is rejected so a
    /// policy cannot become open by omission rather than by declaration
    /// (AAASM-4020, extending the AAASM-3997 empty/null floor).
    NoEnforcementSection,
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(msg) => write!(f, "policy YAML parse error: {msg}"),
            Self::InvalidCapability { raw, reason } => {
                write!(f, "invalid capability {raw:?}: {reason}")
            }
            Self::InvalidSyscall { raw, reason } => {
                write!(f, "invalid syscall {raw:?}: {reason}")
            }
            Self::UnknownKey { path, key } => {
                write!(f, "unknown policy key {key:?} under {path}")
            }
            Self::EmptyDocument => {
                write!(
                    f,
                    "empty or null policy document is not permitted (would be fully permissive)"
                )
            }
            Self::NoEnforcementSection => {
                write!(
                    f,
                    "policy declares no enforcement section (network/capabilities/tools/syscalls); \
                     it would be fully permissive"
                )
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

    #[test]
    fn display_invalid_capability() {
        let err = PolicyParseError::InvalidCapability {
            raw: "teleport".to_string(),
            reason: "unknown capability: 'teleport'".to_string(),
        };
        assert!(err.to_string().contains("teleport"));
    }

    #[test]
    fn display_unknown_key() {
        let err = PolicyParseError::UnknownKey {
            path: "capabilities".to_string(),
            key: "dney".to_string(),
        };
        assert_eq!(err.to_string(), "unknown policy key \"dney\" under capabilities");
    }
}
