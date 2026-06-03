//! Wire-stable agent identifier in `<tenant>/<agent>` form.

use alloc::string::String;

/// A storage-wire agent identifier: a validated `<tenant>/<agent>` string.
///
/// Unlike [`crate::identity::AgentId`] — an opaque 16-byte id used inside the
/// runtime — this newtype is the *human-routable* identifier that storage
/// drivers persist and round-trip. It always holds exactly one `/` separating a
/// non-empty tenant from a non-empty agent name. Construct it through
/// [`AgentId::parse`], which rejects malformed input with [`AgentIdParseError`].
///
/// # Wire format
///
/// Serializes transparently as a single JSON string:
///
/// ```json
/// "acme/billing-bot"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schemars", schemars(transparent))]
pub struct AgentId(String);

impl AgentId {
    /// Parse and validate a `<tenant>/<agent>` identifier.
    ///
    /// Returns [`AgentIdParseError`] when the input is empty, does not contain
    /// exactly one `/`, or has an empty tenant or agent component.
    ///
    /// ```
    /// use aa_core::types::AgentId;
    ///
    /// let id = AgentId::parse("acme/billing-bot").unwrap();
    /// assert_eq!(id.tenant(), "acme");
    /// assert_eq!(id.agent(), "billing-bot");
    /// ```
    pub fn parse(input: impl Into<String>) -> Result<Self, AgentIdParseError> {
        let raw = input.into();
        if raw.is_empty() {
            return Err(AgentIdParseError::Empty);
        }
        let (tenant, agent) = match raw.split_once('/') {
            Some(pair) => pair,
            None => return Err(AgentIdParseError::NotExactlyOneSlash),
        };
        if agent.contains('/') {
            return Err(AgentIdParseError::NotExactlyOneSlash);
        }
        if tenant.is_empty() {
            return Err(AgentIdParseError::EmptyTenant);
        }
        if agent.is_empty() {
            return Err(AgentIdParseError::EmptyAgent);
        }
        Ok(Self(raw))
    }

    /// The tenant component (the text before the `/`).
    pub fn tenant(&self) -> &str {
        self.0.split_once('/').map_or(self.0.as_str(), |(tenant, _)| tenant)
    }

    /// The agent component (the text after the `/`).
    pub fn agent(&self) -> &str {
        self.0.split_once('/').map_or("", |(_, agent)| agent)
    }

    /// The full `<tenant>/<agent>` string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Error returned by [`AgentId::parse`] when the input is not a valid
/// `<tenant>/<agent>` identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgentIdParseError {
    /// The input was empty.
    Empty,
    /// The input did not contain exactly one `/` separator.
    NotExactlyOneSlash,
    /// The tenant component (before the `/`) was empty.
    EmptyTenant,
    /// The agent component (after the `/`) was empty.
    EmptyAgent,
}

impl core::fmt::Display for AgentIdParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Empty => "agent id must not be empty",
            Self::NotExactlyOneSlash => "agent id must contain exactly one '/' separator",
            Self::EmptyTenant => "agent id tenant component must not be empty",
            Self::EmptyAgent => "agent id agent component must not be empty",
        };
        f.write_str(message)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AgentIdParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_well_formed_id() {
        let id = AgentId::parse("acme/billing-bot").unwrap();
        assert_eq!(id.as_str(), "acme/billing-bot");
        assert_eq!(id.tenant(), "acme");
        assert_eq!(id.agent(), "billing-bot");
    }

    #[test]
    fn parse_rejects_malformed_input_with_typed_error() {
        assert_eq!(AgentId::parse(""), Err(AgentIdParseError::Empty));
        assert_eq!(AgentId::parse("no-slash"), Err(AgentIdParseError::NotExactlyOneSlash));
        assert_eq!(AgentId::parse("a/b/c"), Err(AgentIdParseError::NotExactlyOneSlash));
        assert_eq!(AgentId::parse("/agent"), Err(AgentIdParseError::EmptyTenant));
        assert_eq!(AgentId::parse("tenant/"), Err(AgentIdParseError::EmptyAgent));
    }
}
