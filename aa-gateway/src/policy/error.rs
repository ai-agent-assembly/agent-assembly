//! Validation error and warning types for policy YAML parsing.

use std::fmt;

/// An error produced while parsing a policy fragment from its string form.
///
/// Distinct from [`ValidationError`] because it is raised during low-level
/// `FromStr` parsing (e.g. of [`super::scope::PolicyScope`]) before any
/// document-level validation runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyParseError {
    /// The raw scope string did not match any recognised form.
    InvalidScope {
        /// The original string that failed to parse.
        raw: String,
        /// Human-readable explanation of the failure.
        reason: String,
    },
    /// An expression references a variable name that is not in the known set.
    UnknownVariable {
        /// The unrecognised identifier.
        name: String,
        /// Closest known variable within the edit-distance threshold, if any.
        suggestion: Option<String>,
        /// Full list of valid variable names.
        available: Vec<String>,
    },
}

impl fmt::Display for PolicyParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidScope { raw, reason } => {
                write!(f, "invalid policy scope {:?}: {}", raw, reason)
            }
            Self::UnknownVariable {
                name,
                suggestion,
                available,
            } => {
                write!(
                    f,
                    "unknown variable {:?}; valid variables: {}",
                    name,
                    available.join(", ")
                )?;
                if let Some(s) = suggestion {
                    write!(f, "; did you mean {:?}?", s)?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for PolicyParseError {}

/// An error produced during policy document validation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    /// Dot-notation field path, e.g. `"budget.daily_limit_usd"`.
    pub field: String,
    /// Human-readable description of the violated constraint.
    pub message: String,
    /// Best-effort line number from the YAML source (`None` when not determinable).
    pub line: Option<u32>,
}

impl ValidationError {
    /// Create a new error with no line information.
    pub fn new(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            message: message.into(),
            line: None,
        }
    }

    /// Attach a best-effort line number.
    pub fn with_line(mut self, line: u32) -> Self {
        self.line = Some(line);
        self
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(line) => write!(f, "line {}: {} — {}", line, self.field, self.message),
            None => write!(f, "{} — {}", self.field, self.message),
        }
    }
}

/// A non-fatal warning produced during policy document validation.
#[derive(Debug, Clone, PartialEq)]
pub struct ValidationWarning {
    /// Dot-notation path of the unexpected key.
    pub field: String,
    /// Human-readable message.
    pub message: String,
}

impl ValidationWarning {
    /// Construct a warning for an unknown key at the given path.
    pub fn unknown_key(field: impl Into<String>) -> Self {
        let field = field.into();
        let message = format!("Unknown key '{}' will be ignored", field);
        Self { field, message }
    }
}

impl fmt::Display for ValidationWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} — {}", self.field, self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_error_new_sets_field_and_message() {
        let e = ValidationError::new("budget.daily_limit_usd", "must be > 0");
        assert_eq!(e.field, "budget.daily_limit_usd");
        assert_eq!(e.message, "must be > 0");
        assert_eq!(e.line, None);
    }

    #[test]
    fn validation_error_with_line_sets_line() {
        let e = ValidationError::new("network.allowlist[0]", "must not be empty").with_line(7);
        assert_eq!(e.line, Some(7));
    }

    #[test]
    fn validation_error_display_without_line() {
        let e = ValidationError::new("budget.daily_limit_usd", "must be greater than 0");
        assert_eq!(e.to_string(), "budget.daily_limit_usd — must be greater than 0");
    }

    #[test]
    fn validation_error_display_with_line() {
        let e = ValidationError::new("budget.daily_limit_usd", "invalid value").with_line(12);
        assert_eq!(e.to_string(), "line 12: budget.daily_limit_usd — invalid value");
    }

    #[test]
    fn validation_warning_unknown_key_formats_message() {
        let w = ValidationWarning::unknown_key("risk_tier");
        assert_eq!(w.field, "risk_tier");
        assert!(w.message.contains("risk_tier"));
    }

    #[test]
    fn validation_warning_unknown_key_nested_path() {
        let w = ValidationWarning::unknown_key("network.blocklist");
        assert_eq!(w.field, "network.blocklist");
    }

    #[test]
    fn validation_warning_display_formatting() {
        let w = ValidationWarning::unknown_key("risk_tier");
        assert_eq!(w.to_string(), "risk_tier — Unknown key 'risk_tier' will be ignored");
    }

    #[test]
    fn unknown_variable_display_without_suggestion() {
        let e = PolicyParseError::UnknownVariable {
            name: "agent.xyz".into(),
            suggestion: None,
            available: vec!["agent.depth".into()],
        };
        let s = e.to_string();
        assert!(s.contains("agent.xyz"));
        assert!(s.contains("agent.depth"));
        assert!(!s.contains("did you mean"));
    }

    #[test]
    fn unknown_variable_display_with_suggestion() {
        let e = PolicyParseError::UnknownVariable {
            name: "agent.depht".into(),
            suggestion: Some("agent.depth".into()),
            available: vec!["agent.depth".into()],
        };
        let s = e.to_string();
        assert!(s.contains("agent.depht"));
        assert!(s.contains("did you mean"));
        assert!(s.contains("agent.depth"));
    }
}
