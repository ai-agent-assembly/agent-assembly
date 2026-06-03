//! [`DriverName`] — the string identifier that selects a storage backend.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Name of a storage driver as written in `agent-assembly.toml`
/// (e.g. `"redis"`, `"postgres"`, `"memory"`).
///
/// A `DriverName` is the key the [`Registry`](crate::Registry) resolves to a
/// concrete backend factory, and also the key of the per-driver
/// `[storage.<name>]` subsection. It is a thin, transparent newtype over
/// [`String`] so it deserializes directly from a TOML string and can be used as
/// a map key.
///
/// ```
/// use aa_storage::DriverName;
///
/// let name = DriverName::new("redis");
/// assert_eq!(name.as_str(), "redis");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DriverName(String);

impl DriverName {
    /// Create a `DriverName` from anything string-like.
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// Borrow the underlying driver name as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DriverName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for DriverName {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for DriverName {
    fn from(s: String) -> Self {
        Self(s)
    }
}
