//! Policy scope hierarchy types
//! (`global` / `org:<id>` / `team:<id>` / `agent:<uuid>` / `tool:<name>`).
//!
//! See AAASM-219 (F92) for the design. The 5-level chain is the
//! complete scope vocabulary; the `ScopeIndex` in
//! [`crate::engine::scope_index`] indexes loaded policies by these
//! variants, and the cascading evaluator in F93 (AAASM-220) consults
//! them in `Global → Org → Team → Agent → Tool` order
//! (most-restrictive-wins).

use std::fmt;
use std::str::FromStr;

use aa_core::identity::AgentId;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::policy::error::PolicyParseError;

/// String identifier for an organisation. May be promoted to a newtype later.
pub type OrgId = String;

/// String identifier for a team. May be promoted to a newtype later.
pub type TeamId = String;

/// Hierarchical scope a policy applies to.
///
/// Resolution order is `Global → Org → Team → Agent → Tool`, with
/// most-restrictive-wins merging performed by
/// [`crate::engine::PolicyEngine`] (wired in F93, AAASM-220). `Tool`
/// sits at the most-restrictive end of the chain so a policy can,
/// for example, deny `slack-mcp` for every agent in `team-x` even
/// when team- and agent-level policies would otherwise allow it.
///
/// # Wire format
///
/// `PolicyScope` uses a single colon-separated string in YAML and other serde
/// formats. The forms are:
///
/// | Variant         | Wire form                             |
/// |-----------------|---------------------------------------|
/// | `Global`        | `global`                              |
/// | `Org(id)`       | `org:<id>`                            |
/// | `Team(id)`      | `team:<id>`                           |
/// | `Agent(uuid)`   | `agent:<hyphenated-uuid>`             |
/// | `Tool(name)`    | `tool:<tool-name>`                    |
///
/// # Examples
///
/// Round-tripping through `Display` and `FromStr`:
///
/// ```
/// use aa_gateway::policy::scope::PolicyScope;
///
/// let scope: PolicyScope = "team:platform".parse().unwrap();
/// assert_eq!(scope.to_string(), "team:platform");
/// ```
///
/// Reading from YAML (`scope:` is the canonical key on a policy document):
///
/// ```
/// use aa_gateway::policy::scope::PolicyScope;
///
/// let scope: PolicyScope = serde_yaml::from_str("org:acme").unwrap();
/// assert_eq!(scope, PolicyScope::Org("acme".to_owned()));
/// ```
///
/// Malformed inputs surface as
/// [`PolicyParseError::InvalidScope`](crate::policy::error::PolicyParseError::InvalidScope):
///
/// ```
/// use aa_gateway::policy::scope::PolicyScope;
///
/// assert!("project:foo".parse::<PolicyScope>().is_err());
/// assert!("team:".parse::<PolicyScope>().is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PolicyScope {
    /// Applies to every agent — the default for backward compatibility.
    Global,
    /// Applies to every agent inside the named organisation.
    Org(OrgId),
    /// Applies to every agent that belongs to the named team.
    Team(TeamId),
    /// Applies to a single specific agent.
    Agent(AgentId),
    /// Applies to a specific tool / MCP server, across every agent
    /// otherwise admitted by higher scopes. Sits at the most-restrictive
    /// end of the cascading chain (`Global → Org → Team → Agent → Tool`).
    Tool(String),
}

impl fmt::Display for PolicyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Org(id) => write!(f, "org:{}", id),
            Self::Team(id) => write!(f, "team:{}", id),
            Self::Agent(id) => write!(f, "agent:{}", Uuid::from_bytes(*id.as_bytes())),
            Self::Tool(name) => write!(f, "tool:{}", name),
        }
    }
}

impl FromStr for PolicyScope {
    type Err = PolicyParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = |reason: &str| PolicyParseError::InvalidScope {
            raw: s.to_owned(),
            reason: reason.to_owned(),
        };

        if s == "global" {
            return Ok(Self::Global);
        }

        let (kind, value) = match s.split_once(':') {
            Some(parts) => parts,
            None => return Err(invalid("expected `global` or `<kind>:<id>`")),
        };

        if value.is_empty() {
            return Err(invalid("identifier after ':' must not be empty"));
        }

        match kind {
            "org" => Ok(Self::Org(value.to_owned())),
            "team" => Ok(Self::Team(value.to_owned())),
            "agent" => {
                let uuid =
                    Uuid::parse_str(value).map_err(|e| invalid(&format!("agent id is not a valid UUID: {}", e)))?;
                Ok(Self::Agent(AgentId::from_bytes(*uuid.as_bytes())))
            }
            "tool" => Ok(Self::Tool(value.to_owned())),
            other => Err(invalid(&format!("unknown scope kind {:?}", other))),
        }
    }
}

impl Serialize for PolicyScope {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for PolicyScope {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::error::PolicyParseError;

    const AGENT_UUID: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const AGENT_BYTES: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    ];

    // ── FromStr happy paths ─────────────────────────────────────────────────

    #[test]
    fn parses_global() {
        assert_eq!("global".parse::<PolicyScope>().unwrap(), PolicyScope::Global);
    }

    #[test]
    fn parses_org_with_identifier() {
        assert_eq!(
            "org:acme".parse::<PolicyScope>().unwrap(),
            PolicyScope::Org("acme".to_owned()),
        );
    }

    #[test]
    fn parses_team_with_identifier() {
        assert_eq!(
            "team:platform".parse::<PolicyScope>().unwrap(),
            PolicyScope::Team("platform".to_owned()),
        );
    }

    #[test]
    fn parses_agent_with_uuid() {
        let parsed = format!("agent:{}", AGENT_UUID).parse::<PolicyScope>().unwrap();
        assert_eq!(parsed, PolicyScope::Agent(AgentId::from_bytes(AGENT_BYTES)));
    }

    #[test]
    fn parses_tool_with_name() {
        assert_eq!(
            "tool:slack-mcp".parse::<PolicyScope>().unwrap(),
            PolicyScope::Tool("slack-mcp".to_owned()),
        );
    }

    // ── Display round-trip ──────────────────────────────────────────────────

    #[test]
    fn display_round_trips_for_each_variant() {
        let cases = [
            PolicyScope::Global,
            PolicyScope::Org("acme".to_owned()),
            PolicyScope::Team("platform".to_owned()),
            PolicyScope::Agent(AgentId::from_bytes(AGENT_BYTES)),
            PolicyScope::Tool("slack-mcp".to_owned()),
        ];
        for original in cases {
            let rendered = original.to_string();
            let reparsed: PolicyScope = rendered.parse().unwrap();
            assert_eq!(reparsed, original, "round-trip failed for {}", rendered);
        }
    }

    // ── serde YAML round-trip ───────────────────────────────────────────────

    #[test]
    fn serde_yaml_round_trips_for_each_variant() {
        let cases = [
            PolicyScope::Global,
            PolicyScope::Org("acme".to_owned()),
            PolicyScope::Team("platform".to_owned()),
            PolicyScope::Agent(AgentId::from_bytes(AGENT_BYTES)),
            PolicyScope::Tool("slack-mcp".to_owned()),
        ];
        for original in cases {
            let yaml = serde_yaml::to_string(&original).unwrap();
            let reparsed: PolicyScope = serde_yaml::from_str(&yaml).unwrap();
            assert_eq!(reparsed, original, "serde round-trip failed for {}", yaml);
        }
    }

    // ── FromStr error paths ─────────────────────────────────────────────────

    fn assert_invalid_scope(raw: &str, expected_substring: &str) {
        let err = raw.parse::<PolicyScope>().unwrap_err();
        match err {
            PolicyParseError::InvalidScope { raw: got_raw, reason } => {
                assert_eq!(got_raw, raw);
                assert!(
                    reason.contains(expected_substring),
                    "reason {:?} did not contain {:?}",
                    reason,
                    expected_substring
                );
            }
            other => panic!("unexpected error variant: {other:?}"),
        }
    }

    #[test]
    fn rejects_string_without_colon_or_global() {
        assert_invalid_scope("acme", "expected `global`");
    }

    #[test]
    fn rejects_unknown_scope_kind() {
        assert_invalid_scope("project:foo", "unknown scope kind");
    }

    #[test]
    fn rejects_empty_identifier_after_kind() {
        assert_invalid_scope("team:", "must not be empty");
    }

    #[test]
    fn rejects_agent_with_non_uuid_value() {
        assert_invalid_scope("agent:not-a-uuid", "valid UUID");
    }

    #[test]
    fn rejects_empty_tool_name() {
        // Same empty-identifier guard as `team:` / `org:` / `agent:`,
        // applied to `tool:`. Verifies the AAASM-1008 AC explicitly.
        assert_invalid_scope("tool:", "must not be empty");
    }
}
