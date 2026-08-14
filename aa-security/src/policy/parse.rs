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
use super::filesystem::{FilesystemPolicy, PathScope};
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
        pub filesystem: Option<Filesystem>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Syscalls {
        pub allow: Option<Vec<String>>,
    }

    #[derive(Debug, Deserialize)]
    pub struct Filesystem {
        pub read: Option<PathScope>,
        pub write: Option<PathScope>,
    }

    #[derive(Debug, Deserialize)]
    pub struct PathScope {
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
        // AAASM-3997: an empty / null / `{}` document deserializes to an
        // all-`None` (fully-permissive) policy. Reject it here — the gateway load
        // path has no live caller that guards against this, so parsing must be
        // the fail-closed floor: a policy must positively declare its posture.
        match &value {
            serde_yaml::Value::Null => return Err(PolicyParseError::EmptyDocument),
            serde_yaml::Value::Mapping(map) if map.is_empty() => return Err(PolicyParseError::EmptyDocument),
            _ => {}
        }
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

        // AAASM-5751. A verb key that is present but carries no `allow:` list
        // becomes an *empty* scope, which is deny-all — the same fail-closed
        // reading `syscalls:` with no `allow:` already gets. A `filesystem:`
        // that states neither verb is normalized to `None`, because it says
        // nothing about either one and "nothing was said" is a state the
        // lowering reports distinctly from "nothing is permitted".
        let filesystem = match spec.filesystem {
            Some(fs) => {
                let node = FilesystemPolicy {
                    read: parse_path_scope(fs.read, "filesystem.read")?,
                    write: parse_path_scope(fs.write, "filesystem.write")?,
                };
                node.is_stated().then_some(node)
            }
            None => None,
        };

        let doc = PolicyDocument {
            name,
            network,
            capabilities,
            tools,
            syscall_allowlist,
            filesystem,
        };

        // AAASM-4020: a document that parses but declares no enforcement
        // dimension (e.g. metadata-only) is fully permissive, just like the
        // empty/null case rejected above. Require at least one enforcement
        // section so a policy cannot become open by omission.
        if doc.network.is_none()
            && doc.capabilities.is_none()
            && doc.tools.is_empty()
            && doc.syscall_allowlist.is_none()
            && doc.filesystem.is_none()
        {
            return Err(PolicyParseError::NoEnforcementSection);
        }

        Ok(doc)
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

/// Parse one `filesystem.<verb>` node into a [`PathScope`] (AAASM-5751).
///
/// An absent verb key is `None` — the operator stated nothing about it. A
/// present key with no `allow:` list is an empty, in-force scope: deny-all.
///
/// # Errors
///
/// [`PolicyParseError::InvalidPath`] naming `node` so the operator is sent to
/// the line they wrote, rather than to "somewhere in the policy".
fn parse_path_scope(raw: Option<raw::PathScope>, node: &str) -> Result<Option<PathScope>, PolicyParseError> {
    let Some(raw) = raw else { return Ok(None) };
    let entries = raw.allow.unwrap_or_default();
    let scope = PathScope::from_paths(&entries).map_err(|reason| PolicyParseError::InvalidPath {
        raw: format!("{node}.allow"),
        reason: reason.to_string(),
    })?;
    Ok(Some(scope))
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
    "filesystem",
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
    "filesystem",
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
const FILESYSTEM_KEYS: &[&str] = &["read", "write"];

#[cfg(feature = "serde")]
const PATH_SCOPE_KEYS: &[&str] = &["allow"];

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
    // AAASM-5751. A misspelled `wrtie:` or `alow:` under `filesystem:` would be
    // dropped by `#[serde(flatten)]`-adjacent leniency and silently leave the
    // verb unscoped, which reads as "the operator restricted nothing" — the
    // exact fail-open AAASM-3874 closed for the other security sections.
    if let Some(fs) = effective.get("filesystem").and_then(|v| v.as_mapping()) {
        check_keys(fs, FILESYSTEM_KEYS, "filesystem")?;
        for verb in FILESYSTEM_KEYS {
            if let Some(scope) = fs.get(*verb).and_then(|v| v.as_mapping()) {
                check_keys(scope, PATH_SCOPE_KEYS, &format!("filesystem.{verb}"))?;
            }
        }
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
    fn rejects_empty_or_null_document() {
        // AAASM-3997: a blank document parsed to a fully-permissive policy. It
        // must now fail closed instead of defaulting open.
        for blank in ["", "   \n  ", "null", "~", "{}"] {
            let err = PolicyDocument::from_yaml(blank).unwrap_err();
            assert!(
                matches!(err, PolicyParseError::EmptyDocument),
                "blank input {blank:?} should be rejected as empty, got {err:?}"
            );
        }
    }

    #[test]
    fn rejects_metadata_only_document() {
        // AAASM-4020: a document with only envelope metadata declares no
        // enforcement dimension and would be fully permissive — reject it.
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: does-nothing
"#;
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, PolicyParseError::NoEnforcementSection),
            "metadata-only doc should be rejected, got {err:?}"
        );
    }

    #[test]
    fn rejects_l7_only_document_with_no_cross_layer_section() {
        // A doc carrying only L7-only sections (budget/schedule/data) declares
        // nothing this crate can enforce → fully permissive here → rejected.
        let yaml = r#"
spec:
  budget:
    daily_limit_usd: 5.0
"#;
        let err = PolicyDocument::from_yaml(yaml).unwrap_err();
        assert!(
            matches!(err, PolicyParseError::NoEnforcementSection),
            "L7-only doc should be rejected, got {err:?}"
        );
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

    // ── filesystem path scope (AAASM-5751) ──────────────────────────────────

    #[test]
    fn parses_filesystem_path_scope_for_both_verbs() {
        let yaml = r#"
apiVersion: agent-assembly/v1
kind: Policy
metadata:
  name: scoped
spec:
  filesystem:
    read:
      allow:
        - /workspace
        - /usr/share/dict
    write:
      allow:
        - /workspace/build
"#;
        let fs = PolicyDocument::from_yaml(yaml).unwrap().filesystem.expect("stated");
        let read = fs.read.expect("read verb stated");
        assert_eq!(
            read.iter().collect::<Vec<_>>(),
            vec!["/usr/share/dict", "/workspace"],
            "prefixes are normalized and order-stable"
        );
        assert!(read.permits("/workspace/src/main.rs"));
        assert!(!read.permits("/etc/passwd"));

        let write = fs.write.expect("write verb stated");
        assert!(write.permits("/workspace/build/out.o"));
        // The narrower write scope must not inherit the wider read scope.
        assert!(!write.permits("/workspace/src/main.rs"));
    }

    /// Both directions. An absent section is `None` — "nobody said" — and a
    /// verb the operator did not name stays `None` even when its sibling is
    /// stated. Asserting only the positive would pass for a parser that
    /// fabricated a scope for every verb.
    #[test]
    fn an_absent_filesystem_node_and_an_absent_verb_are_both_unstated() {
        let none = PolicyDocument::from_yaml("spec:\n  network:\n    allowlist: []\n").unwrap();
        assert!(none.filesystem.is_none());

        let read_only =
            PolicyDocument::from_yaml("spec:\n  filesystem:\n    read:\n      allow: [/workspace]\n").unwrap();
        let fs = read_only.filesystem.expect("stated");
        assert!(fs.read.is_some());
        assert!(fs.write.is_none(), "an unnamed verb must not be fabricated");
    }

    /// A present verb with no `allow:` list is an in-force scope that permits
    /// nothing — deny-all, never "no restriction". The control beside it is the
    /// `filesystem: {}` case, which names no verb and therefore states nothing:
    /// the two produce different documents, so the parser is not collapsing
    /// "empty" and "absent".
    #[test]
    fn an_empty_verb_is_deny_all_and_an_empty_section_is_unstated() {
        let empty_verb = PolicyDocument::from_yaml("spec:\n  filesystem:\n    write:\n      allow: []\n").unwrap();
        let scope = empty_verb.filesystem.expect("stated").write.expect("write stated");
        assert!(scope.permits_nothing());
        assert!(!scope.permits("/workspace"));

        let no_allow_key = PolicyDocument::from_yaml("spec:\n  filesystem:\n    write: {}\n").unwrap();
        assert!(no_allow_key
            .filesystem
            .expect("stated")
            .write
            .expect("write stated")
            .permits_nothing());

        // `filesystem: {}` names no verb: nothing was said, and with no other
        // enforcement section the document is refused rather than loaded as a
        // permissive one.
        assert_eq!(
            PolicyDocument::from_yaml("spec:\n  filesystem: {}\n"),
            Err(PolicyParseError::NoEnforcementSection)
        );
    }

    /// A path scope alone is an enforcement section, so a document carrying
    /// only one must load. The control is the line above it in the previous
    /// test: a `filesystem:` that scopes no verb still gets refused.
    #[test]
    fn a_path_scope_alone_satisfies_the_enforcement_section_floor() {
        let doc = PolicyDocument::from_yaml("spec:\n  filesystem:\n    read:\n      allow: [/workspace]\n").unwrap();
        assert!(doc.network.is_none() && doc.capabilities.is_none() && doc.tools.is_empty());
        assert!(doc.filesystem.is_some());
    }

    /// A malformed prefix is a load failure, not a silently dropped
    /// restriction — the AAASM-3874 fail-closed rule applied to this node.
    #[test]
    fn a_malformed_prefix_fails_the_load() {
        for bad in ["workspace", "/workspace/../etc", "''"] {
            let yaml = format!("spec:\n  filesystem:\n    read:\n      allow: [{bad}]\n");
            let err = PolicyDocument::from_yaml(&yaml).expect_err("a malformed prefix must fail the load");
            assert!(
                matches!(err, PolicyParseError::InvalidPath { ref raw, .. } if raw == "filesystem.read.allow"),
                "{bad:?} produced {err:?}"
            );
        }
        // The control: a well-formed prefix in the same position loads.
        assert!(PolicyDocument::from_yaml("spec:\n  filesystem:\n    read:\n      allow: [/workspace]\n").is_ok());
    }

    /// A typo inside `filesystem:` must not be dropped: `wrtie:` would leave
    /// writes unscoped, which reads as a restriction the operator never got.
    #[test]
    fn a_misspelled_filesystem_key_is_rejected() {
        assert_eq!(
            PolicyDocument::from_yaml("spec:\n  filesystem:\n    wrtie:\n      allow: [/workspace]\n"),
            Err(PolicyParseError::UnknownKey {
                path: "filesystem".to_string(),
                key: "wrtie".to_string(),
            })
        );
        assert_eq!(
            PolicyDocument::from_yaml("spec:\n  filesystem:\n    read:\n      alow: [/workspace]\n"),
            Err(PolicyParseError::UnknownKey {
                path: "filesystem.read".to_string(),
                key: "alow".to_string(),
            })
        );
    }

    #[test]
    fn filesystem_is_accepted_in_the_flat_form_too() {
        let doc = PolicyDocument::from_yaml("filesystem:\n  read:\n    allow: [/workspace]\n").unwrap();
        assert!(doc
            .filesystem
            .expect("stated")
            .read
            .expect("read stated")
            .permits("/workspace"));
    }
}
