//! Error types for the policy simulation module.

use std::fmt;

/// Errors that can occur during policy simulation.
#[derive(Debug)]
pub enum SimulationError {
    /// The policy file could not be loaded or parsed.
    PolicyLoad(String),
    /// The audit log file could not be parsed.
    AuditParse(String),
    /// An I/O error occurred reading a file.
    IoError(std::io::Error),
    /// The duration string could not be parsed (e.g. `--duration 60s`).
    InvalidDuration(String),
}

impl fmt::Display for SimulationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyLoad(msg) => write!(f, "policy load error: {msg}"),
            Self::AuditParse(msg) => write!(f, "audit log parse error: {msg}"),
            Self::IoError(err) => write!(f, "I/O error: {err}"),
            Self::InvalidDuration(msg) => write!(f, "invalid duration: {msg}"),
        }
    }
}

impl std::error::Error for SimulationError {}

impl From<std::io::Error> for SimulationError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_renders_each_variant_with_its_prefix() {
        assert_eq!(
            SimulationError::PolicyLoad("bad yaml".into()).to_string(),
            "policy load error: bad yaml"
        );
        assert_eq!(
            SimulationError::AuditParse("line 3".into()).to_string(),
            "audit log parse error: line 3"
        );
        assert_eq!(
            SimulationError::InvalidDuration("60x".into()).to_string(),
            "invalid duration: 60x"
        );
    }

    #[test]
    fn io_error_converts_and_displays_through_io_variant() {
        // The `?` conversion path and the IoError Display arm must surface the
        // underlying os-error message so a failed file read is actionable.
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "missing.log");
        let err: SimulationError = io.into();
        assert!(matches!(err, SimulationError::IoError(_)));
        assert!(err.to_string().starts_with("I/O error: "));
        assert!(err.to_string().contains("missing.log"));
    }
}
