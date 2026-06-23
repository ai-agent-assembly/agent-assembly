//! YAML parsing for the canonical [`PolicyDocument`].
//!
//! Accepts the same on-disk contract as `policy-examples/*.yaml`: the
//! Kubernetes-style envelope (`apiVersion` / `kind: Policy` / `metadata` /
//! `spec`) as well as the flat (spec-only) form. Only the canonical,
//! cross-layer dimensions are extracted (capabilities, network egress, tool
//! rules); other spec sections (budget, schedule, data) are accepted and
//! ignored here because they are L7-only and handled by the gateway engine.

#[cfg(feature = "serde")]
use std::collections::BTreeMap;
use std::str::FromStr;

use super::capability::{Capability, CapabilitySet};
use super::document::{NetworkPolicy, PolicyDocument, ToolRule};
use super::error::PolicyParseError;

#[cfg(feature = "serde")]
mod raw {
    use super::BTreeMap;
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    pub struct Envelope {
        pub metadata: Option<Metadata>,
        pub spec: Option<Spec>,
        // Flat form: the spec fields can sit at the top level.
        #[serde(flatten)]
        pub flat: Spec,
    }

    #[derive(Debug, Deserialize)]
    pub struct Metadata {
        pub name: Option<String>,
    }

    #[derive(Debug, Default, Deserialize)]
    pub struct Spec {
        pub network: Option<Network>,
        pub capabilities: Option<Capabilities>,
        pub tools: Option<BTreeMap<String, Tool>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Network {
        pub allowlist: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Capabilities {
        pub allow: Option<Vec<String>>,
        pub deny: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Tool {
        pub allow: Option<bool>,
        pub requires_approval_if: Option<String>,
    }
}

impl PolicyDocument {
    /// Parse a policy YAML string into the canonical [`PolicyDocument`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyParseError`] when the YAML is malformed or a capability
    /// token is unrecognised.
    #[cfg(feature = "serde")]
    pub fn from_yaml(yaml_str: &str) -> Result<Self, PolicyParseError> {
        let env: raw::Envelope = serde_yaml::from_str(yaml_str).map_err(|e| PolicyParseError::Yaml(e.to_string()))?;

        // Prefer the `spec:` section; fall back to flat top-level fields.
        let spec = env.spec.unwrap_or(env.flat);

        let name = env.metadata.and_then(|m| m.name);

        let network = spec.network.map(|n| NetworkPolicy {
            allowlist: n.allowlist.unwrap_or_default(),
        });

        let capabilities = match spec.capabilities {
            Some(c) => {
                let mut set = CapabilitySet::default();
                for raw_cap in c.allow.unwrap_or_default() {
                    set.allow.insert(parse_capability(&raw_cap)?);
                }
                for raw_cap in c.deny.unwrap_or_default() {
                    set.deny.insert(parse_capability(&raw_cap)?);
                }
                Some(set)
            }
            None => None,
        };

        let tools = spec
            .tools
            .unwrap_or_default()
            .into_iter()
            .map(|(name, t)| ToolRule {
                name,
                allow: t.allow.unwrap_or(true),
                requires_approval_if: t.requires_approval_if,
            })
            .collect();

        Ok(PolicyDocument {
            name,
            network,
            capabilities,
            tools,
        })
    }
}

/// Parse a capability token, mapping the parse error onto [`PolicyParseError`].
fn parse_capability(raw: &str) -> Result<Capability, PolicyParseError> {
    Capability::from_str(raw).map_err(|reason| PolicyParseError::InvalidCapability {
        raw: raw.to_string(),
        reason,
    })
}

#[cfg(all(test, feature = "serde"))]
mod tests {
    use super::*;

    #[test]
    fn parses_envelope_capability_policy() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: capability-example
spec:
  capabilities:
    allow:
      - file_read
      - mcp_tool:git
    deny:
      - terminal_exec
      - file_write
"#;
        let doc = PolicyDocument::from_yaml(yaml).unwrap();
        assert_eq!(doc.name.as_deref(), Some("capability-example"));
        let caps = doc.capabilities.unwrap();
        assert!(caps.allow.contains(&Capability::FileRead));
        assert!(caps.allow.contains(&Capability::McpTool("git".to_string())));
        assert!(caps.deny.contains(&Capability::TerminalExec));
        assert!(caps.deny.contains(&Capability::FileWrite));
    }

    #[test]
    fn parses_network_and_tools() {
        let yaml = r#"
spec:
  network:
    allowlist:
      - api.openai.com
  tools:
    "*":
      allow: false
    write_file:
      allow: true
      requires_approval_if: "path starts_with \"/etc\""
"#;
        let doc = PolicyDocument::from_yaml(yaml).unwrap();
        assert_eq!(doc.egress_allowlist(), ["api.openai.com"]);
        let wildcard = doc.tools.iter().find(|t| t.name == "*").unwrap();
        assert!(!wildcard.allow);
        let write = doc.tools.iter().find(|t| t.name == "write_file").unwrap();
        assert!(write.allow);
        assert_eq!(write.requires_approval_if.as_deref(), Some("path starts_with \"/etc\""));
    }

    #[test]
    fn rejects_unknown_capability() {
        let yaml = "spec:\n  capabilities:\n    deny:\n      - teleport\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::InvalidCapability { .. }));
    }

    #[test]
    fn rejects_malformed_yaml() {
        let err = PolicyDocument::from_yaml("spec: [unclosed").unwrap_err();
        assert!(matches!(err, PolicyParseError::Yaml(_)));
    }
}
