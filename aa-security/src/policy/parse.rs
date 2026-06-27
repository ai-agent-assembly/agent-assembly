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
use super::syscall::SyscallAllowlist;

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
        pub syscalls: Option<Syscalls>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Syscalls {
        pub allow: Option<Vec<String>>,
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
        // Parse to a generic value first so the raw mapping can be checked
        // against the known schema. `#[serde(flatten)]` precludes
        // `deny_unknown_fields`, so without this a misspelled security key
        // (e.g. `dney:` for `deny:`) would be silently dropped, yielding an
        // empty — and therefore permissive — policy that still parses
        // successfully (AAASM-3874).
        let value: serde_yaml::Value =
            serde_yaml::from_str(yaml_str).map_err(|e| PolicyParseError::Yaml(e.to_string()))?;
        validate_schema(&value)?;
        let env: raw::Envelope = serde_yaml::from_value(value).map_err(|e| PolicyParseError::Yaml(e.to_string()))?;

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
                // Deny-by-default: a tool entry that omits `allow:` (or whose
                // `allow:` key is misspelled and dropped) must not be silently
                // permitted. Callers must opt a tool in explicitly with
                // `allow: true` (AAASM-3874). This is a deliberate behaviour
                // change from the previous allow-by-default.
                allow: t.allow.unwrap_or(false),
                requires_approval_if: t.requires_approval_if,
            })
            .collect();

        let syscall_allowlist = match spec.syscalls {
            Some(s) => {
                let names = s.allow.unwrap_or_default();
                let mut allow = SyscallAllowlist::default();
                for raw in names {
                    allow.syscalls.insert(parse_syscall(&raw)?);
                }
                Some(allow)
            }
            None => None,
        };

        Ok(PolicyDocument {
            name,
            network,
            capabilities,
            tools,
            syscall_allowlist,
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

/// Parse a syscall name, mapping the parse error onto [`PolicyParseError`].
fn parse_syscall(raw: &str) -> Result<super::syscall::Syscall, PolicyParseError> {
    super::syscall::Syscall::from_str(raw).map_err(|reason| PolicyParseError::InvalidSyscall {
        raw: raw.to_string(),
        reason,
    })
}

/// Top-level / flat-form keys. The flat form lets `spec` fields sit at the top
/// level, so the spec section names are also accepted here.
#[cfg(feature = "serde")]
const TOP_LEVEL_KEYS: &[&str] = &[
    "apiVersion",
    "kind",
    "metadata",
    "spec",
    "scope",
    "network",
    "capabilities",
    "tools",
    "syscalls",
    "schedule",
    "budget",
    "data",
    "approval_timeout_secs",
];

/// Keys accepted inside `spec:`. Mirrors the on-disk `policy-examples/*.yaml`
/// contract. The L7-only sections (`schedule`, `budget`, `data`) are accepted
/// but not descended into here — they are owned and validated by the gateway
/// engine, so this crate deliberately does not couple to their inner schema.
#[cfg(feature = "serde")]
const SPEC_KEYS: &[&str] = &[
    "scope",
    "network",
    "capabilities",
    "tools",
    "syscalls",
    "schedule",
    "budget",
    "data",
    "approval_timeout_secs",
];

#[cfg(feature = "serde")]
const NETWORK_KEYS: &[&str] = &["allowlist"];

#[cfg(feature = "serde")]
const CAPABILITIES_KEYS: &[&str] = &["allow", "deny"];

#[cfg(feature = "serde")]
const SYSCALLS_KEYS: &[&str] = &["allow"];

#[cfg(feature = "serde")]
const TOOL_KEYS: &[&str] = &["allow", "requires_approval_if", "limit_per_hour"];

/// Reject structural typos in the security-relevant dimensions this crate owns.
///
/// `#[serde(flatten)]` rules out `deny_unknown_fields`, so this walks the raw
/// mapping and errors on any unknown key in the top-level, `spec`, and the
/// cross-layer security sections (`network`, `capabilities`, `syscalls`,
/// `tools.<name>`). A misspelled `deny:`/`allowlist:`/`allow:` would otherwise
/// be silently dropped and weaken enforcement (AAASM-3874).
#[cfg(feature = "serde")]
fn validate_schema(root: &serde_yaml::Value) -> Result<(), PolicyParseError> {
    let Some(map) = root.as_mapping() else {
        // Non-mapping documents (null/empty/scalar) carry no keys to check; the
        // typed deserialization step decides whether they are acceptable.
        return Ok(());
    };

    check_keys(map, TOP_LEVEL_KEYS, "(root)")?;

    // Resolve the effective spec exactly as `from_yaml` does: prefer `spec:`,
    // otherwise treat the top-level mapping as the flat spec.
    let effective = match map.get("spec").and_then(|v| v.as_mapping()) {
        Some(spec_map) => {
            check_keys(spec_map, SPEC_KEYS, "spec")?;
            spec_map
        }
        None => map,
    };

    if let Some(net) = effective.get("network").and_then(|v| v.as_mapping()) {
        check_keys(net, NETWORK_KEYS, "network")?;
    }
    if let Some(caps) = effective.get("capabilities").and_then(|v| v.as_mapping()) {
        check_keys(caps, CAPABILITIES_KEYS, "capabilities")?;
    }
    if let Some(sys) = effective.get("syscalls").and_then(|v| v.as_mapping()) {
        check_keys(sys, SYSCALLS_KEYS, "syscalls")?;
    }
    if let Some(tools) = effective.get("tools").and_then(|v| v.as_mapping()) {
        for (tname, tval) in tools {
            if let Some(tool_map) = tval.as_mapping() {
                let tool_name = tname.as_str().unwrap_or("<non-string>");
                check_keys(tool_map, TOOL_KEYS, &format!("tools.{tool_name}"))?;
            }
        }
    }

    Ok(())
}

/// Error on the first string key in `map` that is not in `allowed`.
#[cfg(feature = "serde")]
fn check_keys(map: &serde_yaml::Mapping, allowed: &[&str], path: &str) -> Result<(), PolicyParseError> {
    for k in map.keys() {
        // Non-string keys are left to the typed deserialization step.
        if let Some(s) = k.as_str() {
            if !allowed.contains(&s) {
                return Err(PolicyParseError::UnknownKey {
                    path: path.to_string(),
                    key: s.to_string(),
                });
            }
        }
    }
    Ok(())
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

    #[test]
    fn parses_syscall_allowlist() {
        use super::super::syscall::Syscall;
        let yaml = r#"
spec:
  syscalls:
    allow:
      - read
      - write
      - close
      - read
"#;
        let doc = PolicyDocument::from_yaml(yaml).unwrap();
        // De-duplicated by the BTreeSet, order-stable by enum order.
        assert_eq!(
            doc.allowed_syscalls(),
            vec![Syscall::Read, Syscall::Write, Syscall::Close]
        );
    }

    #[test]
    fn rejects_misspelled_capability_deny_key() {
        // `dney` instead of `deny`: previously dropped silently, leaving an
        // empty (permissive) deny floor. Must now fail closed (AAASM-3874).
        let yaml = "spec:\n  capabilities:\n    dney:\n      - terminal_exec\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(&err, PolicyParseError::UnknownKey { path, key } if path == "capabilities" && key == "dney"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_misspelled_network_allowlist_key() {
        let yaml = "spec:\n  network:\n    allow_list:\n      - api.openai.com\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(&err, PolicyParseError::UnknownKey { path, .. } if path == "network"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_misspelled_spec_section() {
        // `capabilties` instead of `capabilities`: the whole deny floor would
        // vanish silently. Must fail closed.
        let yaml = "spec:\n  capabilties:\n    deny:\n      - file_write\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(&err, PolicyParseError::UnknownKey { path, key } if path == "spec" && key == "capabilties"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_misspelled_tool_allow_key() {
        let yaml = "spec:\n  tools:\n    shell:\n      alow: true\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(&err, PolicyParseError::UnknownKey { path, key } if path == "tools.shell" && key == "alow"),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_unknown_top_level_key() {
        let yaml = "spec:\n  network:\n    allowlist: []\nnetwrok:\n  allowlist: []\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(&err, PolicyParseError::UnknownKey { path, key } if path == "(root)" && key == "netwrok"),
            "got {err:?}"
        );
    }

    #[test]
    fn tool_without_allow_defaults_to_deny() {
        // Deny-by-default: a tool entry that omits `allow:` must not be
        // permitted (AAASM-3874, deliberate behaviour change).
        let yaml = "spec:\n  tools:\n    shell:\n      requires_approval_if: \"command contains \\\"rm\\\"\"\n";
        let doc = PolicyDocument::from_yaml(yaml).unwrap();
        let shell = doc.tools.iter().find(|t| t.name == "shell").unwrap();
        assert!(!shell.allow, "tool without explicit allow must default to deny");
    }

    #[test]
    fn accepts_l7_only_spec_sections() {
        // budget/schedule/data and per-tool limit_per_hour are L7-only; they
        // are accepted (and ignored here) without being descended into.
        let yaml = r#"
spec:
  scope: global
  budget:
    daily_limit_usd: 5.0
    action_on_exceed: deny
  schedule:
    active_hours:
      start: "09:00"
  data:
    credential_action: block
  tools:
    read_file:
      allow: true
      limit_per_hour: 60
"#;
        let doc = PolicyDocument::from_yaml(yaml).unwrap();
        let read = doc.tools.iter().find(|t| t.name == "read_file").unwrap();
        assert!(read.allow);
    }

    #[test]
    fn rejects_unknown_syscall() {
        let yaml = "spec:\n  syscalls:\n    allow:\n      - execve\n";
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, PolicyParseError::InvalidSyscall { .. }));
    }

    #[test]
    fn no_syscalls_section_means_no_allowlist() {
        let doc = PolicyDocument::from_yaml("spec:\n  network:\n    allowlist: []\n").unwrap();
        assert!(doc.syscall_allowlist.is_none());
        assert!(doc.allowed_syscalls().is_empty());
    }
}
