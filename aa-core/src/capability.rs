//! Per-level capability types for fine-grained agent permission control.
//!
//! A [`Capability`] represents a discrete action category that policy can allow
//! or deny. A [`CapabilitySet`] aggregates allow and deny sets for a given scope.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use core::str::FromStr;

/// A discrete action category that policy can allow or deny for an agent.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum Capability {
    /// Read access to the filesystem.
    FileRead,
    /// Write access to the filesystem.
    FileWrite,
    /// Delete/unlink access to the filesystem.
    ///
    /// A distinct verb from [`Capability::FileWrite`] so a policy can allow
    /// writes while denying deletes (and vice versa). See AAASM-4103.
    FileDelete,
    /// Outbound network connections.
    NetworkOutbound,
    /// Inbound network connections.
    NetworkInbound,
    /// Execute commands in a terminal/shell.
    TerminalExec,
    /// Use a named MCP tool.
    McpTool(String),
    /// Use a named AI model.
    Model(String),
    /// Spawn child agents.
    AgentSpawn,
}

/// Aggregates allow and deny capability sets for a given policy scope.
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct CapabilitySet {
    /// Capabilities explicitly allowed.
    pub allow: BTreeSet<Capability>,
    /// Capabilities explicitly denied.
    pub deny: BTreeSet<Capability>,
    /// Whether an allow-list restriction is in force, independent of whether
    /// `allow` currently lists anything.
    ///
    /// Set once any cascade tier contributes a non-empty allow-list. It exists
    /// to disambiguate the two meanings an empty `allow` would otherwise
    /// conflate: "no allow-list was ever declared" (unrestricted — only `deny`
    /// governs) versus "an allow-list was declared but a disjoint multi-tier
    /// intersection collapsed it to empty" (deny-all). Without this flag,
    /// merging two disjoint restrictive whitelists produces an empty `allow`
    /// that the guard reads as "no restriction", failing *open* to allow-all —
    /// the inverse of most-restrictive-wins (AAASM-4154). `serde(default)` keeps
    /// older serialized sets (which lack the field) deserializing unchanged.
    #[cfg_attr(feature = "serde", serde(default))]
    pub allow_restricted: bool,
}

impl CapabilitySet {
    /// Whether an allow-list restriction governs this set.
    ///
    /// True when the set whitelists at least one capability, or when a prior
    /// cascade tier declared a non-empty allow that a disjoint merge collapsed
    /// to empty (`allow_restricted`). When this is true, the capability guard
    /// must deny any capability absent from `allow`; an empty `allow` therefore
    /// means deny-all, never "no restriction" (AAASM-4154).
    #[must_use]
    pub fn allow_is_restricted(&self) -> bool {
        self.allow_restricted || !self.allow.is_empty()
    }
}

impl Capability {
    /// Whether declaring this capability in a policy actually governs anything.
    ///
    /// A capability is *enforceable* only if some [`crate::GovernanceAction`]
    /// maps to it via [`action_to_capability`] — otherwise no action ever routes
    /// to it, so a declared allow/deny is silently inert and gives the operator a
    /// false sense of security (AAASM-4099).
    ///
    /// Currently inert (no corresponding action variant): [`Capability::Model`],
    /// [`Capability::NetworkInbound`], and [`Capability::AgentSpawn`]. This
    /// predicate is the single source of truth policy validation uses to warn
    /// loudly when a policy references one of them; keep it in lock-step with
    /// [`action_to_capability`] — when a new action lands that maps to one of
    /// these, wire the mapping there and drop it from the inert arm below.
    #[must_use]
    pub fn is_enforceable(&self) -> bool {
        !matches!(
            self,
            Capability::Model(_) | Capability::NetworkInbound | Capability::AgentSpawn
        )
    }
}

impl FromStr for Capability {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "file_read" => Ok(Capability::FileRead),
            "file_write" => Ok(Capability::FileWrite),
            "file_delete" => Ok(Capability::FileDelete),
            "network_outbound" => Ok(Capability::NetworkOutbound),
            "network_inbound" => Ok(Capability::NetworkInbound),
            "terminal_exec" => Ok(Capability::TerminalExec),
            "agent_spawn" => Ok(Capability::AgentSpawn),
            _ => {
                if let Some(name) = s.strip_prefix("mcp_tool:") {
                    if name.is_empty() {
                        return Err("mcp_tool: name must not be empty".to_string());
                    }
                    Ok(Capability::McpTool(name.to_string()))
                } else if let Some(name) = s.strip_prefix("model:") {
                    if name.is_empty() {
                        return Err("model: name must not be empty".to_string());
                    }
                    Ok(Capability::Model(name.to_string()))
                } else {
                    Err(alloc::format!("unknown capability: '{s}'"))
                }
            }
        }
    }
}

impl core::fmt::Display for Capability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Capability::FileRead => f.write_str("file_read"),
            Capability::FileWrite => f.write_str("file_write"),
            Capability::FileDelete => f.write_str("file_delete"),
            Capability::NetworkOutbound => f.write_str("network_outbound"),
            Capability::NetworkInbound => f.write_str("network_inbound"),
            Capability::TerminalExec => f.write_str("terminal_exec"),
            Capability::AgentSpawn => f.write_str("agent_spawn"),
            Capability::McpTool(name) => write!(f, "mcp_tool:{name}"),
            Capability::Model(name) => write!(f, "model:{name}"),
        }
    }
}

/// Merge a parent [`CapabilitySet`] with a child [`CapabilitySet`] using
/// parent-deny-wins semantics.
///
/// Rules:
/// - `deny` = union of both deny sets; parent deny always wins over child allow.
/// - `allow`:
///   - Both empty → empty (no allow-list restriction).
///   - Parent empty, child non-empty → `child.allow` minus merged deny.
///   - Parent non-empty, child empty → `parent.allow` minus merged deny.
///   - Both non-empty → intersection of `parent.allow` and `child.allow`, minus merged deny.
/// - `allow_restricted` = set once either input restricts (carries its flag) or
///   declares a non-empty allow-list. This preserves the restriction across a
///   disjoint intersection that empties `allow`, so the guard fails *closed*
///   (deny-all) instead of reading empty as "unrestricted" (AAASM-4154).
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn merge_capabilities(parent: &CapabilitySet, child: &CapabilitySet) -> CapabilitySet {
    // deny = union of both deny sets
    let deny: BTreeSet<Capability> = parent.deny.union(&child.deny).cloned().collect();

    let allow: BTreeSet<Capability> = match (parent.allow.is_empty(), child.allow.is_empty()) {
        // Both empty → no allow-list restriction
        (true, true) => BTreeSet::new(),
        // Parent empty, child non-empty → use child.allow
        (true, false) => child.allow.difference(&deny).cloned().collect(),
        // Parent non-empty, child empty → use parent.allow
        (false, true) => parent.allow.difference(&deny).cloned().collect(),
        // Both non-empty → intersection, then subtract deny
        (false, false) => parent
            .allow
            .intersection(&child.allow)
            .filter(|c| !deny.contains(c))
            .cloned()
            .collect(),
    };

    // A restriction is in force if either input already carries one or declares
    // a non-empty allow-list — even when the intersection above empties `allow`.
    let allow_restricted =
        parent.allow_restricted || child.allow_restricted || !parent.allow.is_empty() || !child.allow.is_empty();

    CapabilitySet {
        allow,
        deny,
        allow_restricted,
    }
}

/// Map a [`crate::GovernanceAction`] to the [`Capability`] it exercises,
/// or `None` if the action does not map to a known capability.
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn action_to_capability(action: &crate::GovernanceAction) -> Option<Capability> {
    use crate::policy::FileMode;
    use crate::GovernanceAction;

    // NOTE: Capability::AgentSpawn, NetworkInbound, and Model variants have no
    // corresponding GovernanceAction yet — they are flagged by
    // `Capability::is_enforceable` so policy load warns loudly instead of
    // presenting a silently-inert control (AAASM-4099). When new action variants
    // land, add mappings here AND drop the variant from `is_enforceable`'s inert
    // arm to avoid silent policy bypasses.
    match action {
        GovernanceAction::ToolCall { name, .. } => Some(Capability::McpTool(name.clone())),
        GovernanceAction::ToolResult { tool_name, .. } => Some(Capability::McpTool(tool_name.clone())),
        GovernanceAction::FileAccess {
            mode: FileMode::Read, ..
        } => Some(Capability::FileRead),
        GovernanceAction::FileAccess {
            mode: FileMode::Write | FileMode::Append,
            ..
        } => Some(Capability::FileWrite),
        // Delete is a first-class verb (AAASM-4103): it maps to FileDelete, not
        // FileWrite, so a policy can allow writes yet deny deletes. A pre-4103
        // `file_write` allow no longer implies delete — delete needs an explicit
        // `file_delete` grant (fail-closed). See `capability_is_denied` for the
        // reverse defense-in-depth rule on the deny side.
        GovernanceAction::FileAccess {
            mode: FileMode::Delete, ..
        } => Some(Capability::FileDelete),
        GovernanceAction::NetworkRequest { .. } => Some(Capability::NetworkOutbound),
        GovernanceAction::ProcessExec { .. } => Some(Capability::TerminalExec),
        GovernanceAction::SendMessage { .. } => None,
    }
}

/// Whether a policy `deny` set blocks `cap`, honoring superset denies.
///
/// A `FileWrite` deny also blocks `FileDelete`: policies authored before
/// `FileDelete` existed (AAASM-4103) expressed "no mutation" as a single
/// `file_write` deny, and that intent must keep blocking delete — a stale
/// write-deny must never leak delete (fail-closed migration). The converse is
/// deliberately absent: a `FileWrite` *allow* never grants `FileDelete`;
/// delete requires an explicit `file_delete` allow. Net effect: the new verb
/// can only ever make delete *more* restricted than before, never less.
///
/// Requires the `alloc` feature.
#[cfg(feature = "alloc")]
pub fn capability_is_denied(deny: &BTreeSet<Capability>, cap: &Capability) -> bool {
    if deny.contains(cap) {
        return true;
    }
    // Defense in depth: deny(file_write) ⇒ deny(file_delete).
    matches!(cap, Capability::FileDelete) && deny.contains(&Capability::FileWrite)
}

/// Per-scope contribution to an effective permission set.
///
/// Carries the `allow` and `deny` capabilities a single policy document declares
/// at one scope along the cascade chain. The `scope` field is a wire-format
/// label such as `"global"`, `"org:acme"`, `"team:platform"`, or
/// `"agent:<uuid>"`; the gateway populates it from the policy's own
/// `PolicyScope` so the renderer can show provenance without depending on the
/// gateway's enum.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PermissionSource {
    /// Wire-format scope label (e.g. `"global"`, `"team:platform"`).
    pub scope: String,
    /// Capabilities this scope explicitly allows.
    pub allow: BTreeSet<Capability>,
    /// Capabilities this scope explicitly denies.
    pub deny: BTreeSet<Capability>,
}

/// Effective capability set for a single agent, with cascade provenance.
///
/// `merged` is the result of folding `merge_capabilities` left-to-right over
/// every policy document that applies to the agent (Global → Org → Team →
/// Agent → Tool). `sources` records each contributing scope's individual
/// `allow`/`deny`, in cascade order, so consumers (CLI, dashboard) can show
/// *where* each capability decision originates.
///
/// `sources` may be empty if no policy in the cascade declares a
/// `capabilities` block, in which case `merged` is also empty (no allow-list
/// restriction).
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct EffectivePermissions {
    /// Merged result after most-restrictive-wins cascade.
    pub merged: CapabilitySet,
    /// Per-scope contribution, in cascade order (broadest → narrowest).
    pub sources: alloc::vec::Vec<PermissionSource>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    #[test]
    fn capability_variants_are_distinct() {
        assert_ne!(Capability::FileRead, Capability::FileWrite);
        assert_ne!(
            Capability::McpTool("a".to_string()),
            Capability::McpTool("b".to_string())
        );
    }

    #[test]
    fn mcp_tool_same_name_eq() {
        assert_eq!(
            Capability::McpTool("bash".to_string()),
            Capability::McpTool("bash".to_string())
        );
    }

    #[test]
    fn capability_hashable_in_set() {
        let mut set: BTreeSet<Capability> = BTreeSet::new();
        set.insert(Capability::FileRead);
        set.insert(Capability::FileWrite);
        set.insert(Capability::McpTool("bash".to_string()));
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn capability_set_default_is_empty() {
        let cs = CapabilitySet::default();
        assert!(cs.allow.is_empty());
        assert!(cs.deny.is_empty());
    }

    #[test]
    fn capability_from_str_file_read() {
        assert_eq!("file_read".parse::<Capability>().unwrap(), Capability::FileRead);
    }

    #[test]
    fn capability_from_str_file_write() {
        assert_eq!("file_write".parse::<Capability>().unwrap(), Capability::FileWrite);
    }

    #[test]
    fn capability_from_str_file_delete() {
        assert_eq!("file_delete".parse::<Capability>().unwrap(), Capability::FileDelete);
    }

    #[test]
    fn capability_file_delete_display_round_trips() {
        let cap = Capability::FileDelete;
        assert_eq!(cap.to_string(), "file_delete");
        assert_eq!(cap.to_string().parse::<Capability>().unwrap(), cap);
    }

    #[test]
    fn capability_file_delete_distinct_from_file_write() {
        assert_ne!(Capability::FileDelete, Capability::FileWrite);
    }

    #[test]
    fn capability_from_str_network_outbound() {
        assert_eq!(
            "network_outbound".parse::<Capability>().unwrap(),
            Capability::NetworkOutbound
        );
    }

    #[test]
    fn capability_from_str_network_inbound() {
        assert_eq!(
            "network_inbound".parse::<Capability>().unwrap(),
            Capability::NetworkInbound
        );
    }

    #[test]
    fn capability_from_str_terminal_exec() {
        assert_eq!("terminal_exec".parse::<Capability>().unwrap(), Capability::TerminalExec);
    }

    #[test]
    fn capability_from_str_mcp_tool() {
        assert_eq!(
            "mcp_tool:bash".parse::<Capability>().unwrap(),
            Capability::McpTool("bash".to_string())
        );
    }

    #[test]
    fn capability_from_str_model() {
        assert_eq!(
            "model:gpt-4o".parse::<Capability>().unwrap(),
            Capability::Model("gpt-4o".to_string())
        );
    }

    #[test]
    fn capability_from_str_agent_spawn() {
        assert_eq!("agent_spawn".parse::<Capability>().unwrap(), Capability::AgentSpawn);
    }

    #[test]
    fn capability_from_str_unknown_returns_err() {
        assert!("unknown_cap".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_from_str_mcp_tool_empty_name_returns_err() {
        assert!("mcp_tool:".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_from_str_model_empty_name_returns_err() {
        assert!("model:".parse::<Capability>().is_err());
    }

    #[test]
    fn capability_display_round_trips_simple_variant() {
        let cap = Capability::FileRead;
        assert_eq!(cap.to_string().parse::<Capability>().unwrap(), cap);
    }

    #[test]
    fn capability_display_round_trips_mcp_tool() {
        let cap = Capability::McpTool("bash".to_string());
        assert_eq!(cap.to_string().parse::<Capability>().unwrap(), cap);
    }

    // ------------------------------------------------------------------
    // merge_capabilities tests
    // ------------------------------------------------------------------

    fn cap_set(allow: &[Capability], deny: &[Capability]) -> CapabilitySet {
        CapabilitySet {
            allow: allow.iter().cloned().collect(),
            deny: deny.iter().cloned().collect(),
            allow_restricted: false,
        }
    }

    #[test]
    fn merge_empty_parent_with_child_deny() {
        let parent = CapabilitySet::default();
        let child = cap_set(&[], &[Capability::FileWrite]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.deny.contains(&Capability::FileWrite));
        assert!(result.allow.is_empty());
    }

    #[test]
    fn merge_parent_deny_wins_over_child_allow() {
        let parent = cap_set(&[], &[Capability::NetworkOutbound]);
        let child = cap_set(&[Capability::FileRead, Capability::NetworkOutbound], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.allow.contains(&Capability::FileRead));
        assert!(!result.allow.contains(&Capability::NetworkOutbound));
    }

    #[test]
    fn merge_deny_is_union() {
        let parent = cap_set(&[], &[Capability::FileWrite]);
        let child = cap_set(&[], &[Capability::TerminalExec]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.deny.contains(&Capability::FileWrite));
        assert!(result.deny.contains(&Capability::TerminalExec));
    }

    #[test]
    fn merge_both_allow_nonempty_takes_intersection() {
        let parent = cap_set(&[Capability::FileRead, Capability::FileWrite], &[]);
        let child = cap_set(&[Capability::FileRead, Capability::NetworkOutbound], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_allow_nonempty_child_allow_empty_uses_parent() {
        let parent = cap_set(&[Capability::FileRead], &[]);
        let child = cap_set(&[], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_allow_empty_child_allow_nonempty_uses_child() {
        let parent = cap_set(&[], &[]);
        let child = cap_set(&[Capability::FileRead], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(
            result.allow,
            [Capability::FileRead].iter().cloned().collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn merge_parent_deny_overrides_intersection_allow() {
        let parent = cap_set(&[Capability::FileRead, Capability::FileWrite], &[Capability::FileRead]);
        let child = cap_set(&[Capability::FileRead], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(
            result.allow.is_empty(),
            "FileRead was denied by parent, should be absent from allow"
        );
        assert!(result.deny.contains(&Capability::FileRead));
    }

    #[test]
    fn merge_both_empty_returns_empty() {
        let parent = CapabilitySet::default();
        let child = CapabilitySet::default();
        let result = super::merge_capabilities(&parent, &child);
        assert_eq!(result, CapabilitySet::default());
    }

    // ------------------------------------------------------------------
    // action_to_capability tests
    // ------------------------------------------------------------------

    #[test]
    fn action_to_capability_tool_call() {
        let action = crate::GovernanceAction::ToolCall {
            name: "bash".to_string(),
            args: "{}".to_string(),
        };
        assert_eq!(
            super::action_to_capability(&action),
            Some(Capability::McpTool("bash".to_string()))
        );
    }

    #[test]
    fn action_to_capability_file_read() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Read,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileRead));
    }

    #[test]
    fn action_to_capability_file_write() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Write,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileWrite));
    }

    #[test]
    fn action_to_capability_file_append_is_file_write() {
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Append,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileWrite));
    }

    #[test]
    fn action_to_capability_file_delete_is_file_delete() {
        // AAASM-4103: Delete is its own capability, not FileWrite.
        let action = crate::GovernanceAction::FileAccess {
            path: "/tmp/f".to_string(),
            mode: crate::policy::FileMode::Delete,
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::FileDelete));
    }

    #[test]
    fn action_to_capability_network_request() {
        let action = crate::GovernanceAction::NetworkRequest {
            url: "https://example.com".to_string(),
            method: "GET".to_string(),
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::NetworkOutbound));
    }

    // ------------------------------------------------------------------
    // is_enforceable tests (AAASM-4099)
    // ------------------------------------------------------------------

    #[test]
    fn is_enforceable_false_for_inert_capabilities() {
        // These have no GovernanceAction mapping, so declaring them is silently
        // inert — is_enforceable must flag them so policy load can warn loudly.
        assert!(!Capability::NetworkInbound.is_enforceable());
        assert!(!Capability::AgentSpawn.is_enforceable());
        assert!(!Capability::Model("gpt-4o".to_string()).is_enforceable());
    }

    #[test]
    fn is_enforceable_true_for_action_backed_capabilities() {
        assert!(Capability::FileRead.is_enforceable());
        assert!(Capability::FileWrite.is_enforceable());
        assert!(Capability::NetworkOutbound.is_enforceable());
        assert!(Capability::TerminalExec.is_enforceable());
        assert!(Capability::McpTool("bash".to_string()).is_enforceable());
    }

    #[test]
    fn action_to_capability_only_yields_enforceable_capabilities() {
        // Invariant: every capability an action can produce must be enforceable,
        // otherwise stage_capability could deny on a cap load warned was inert.
        let actions = [
            crate::GovernanceAction::ToolCall {
                name: "bash".to_string(),
                args: "{}".to_string(),
            },
            crate::GovernanceAction::FileAccess {
                path: "/tmp/f".to_string(),
                mode: crate::policy::FileMode::Read,
            },
            crate::GovernanceAction::FileAccess {
                path: "/tmp/f".to_string(),
                mode: crate::policy::FileMode::Write,
            },
            crate::GovernanceAction::NetworkRequest {
                url: "https://example.com".to_string(),
                method: "GET".to_string(),
            },
            crate::GovernanceAction::ProcessExec {
                command: "ls".to_string(),
            },
        ];
        for action in &actions {
            if let Some(cap) = super::action_to_capability(action) {
                assert!(
                    cap.is_enforceable(),
                    "action {action:?} mapped to inert capability {cap:?}"
                );
            }
        }
    }

    #[test]
    fn action_to_capability_process_exec() {
        let action = crate::GovernanceAction::ProcessExec {
            command: "ls".to_string(),
        };
        assert_eq!(super::action_to_capability(&action), Some(Capability::TerminalExec));
    }

    // ------------------------------------------------------------------
    // capability_is_denied tests (AAASM-4103 fail-closed migration)
    // ------------------------------------------------------------------

    fn deny_set(caps: &[Capability]) -> BTreeSet<Capability> {
        caps.iter().cloned().collect()
    }

    #[test]
    fn capability_is_denied_direct_match() {
        let deny = deny_set(&[Capability::FileDelete]);
        assert!(super::capability_is_denied(&deny, &Capability::FileDelete));
    }

    #[test]
    fn capability_is_denied_empty_set_is_false() {
        let deny = deny_set(&[]);
        assert!(!super::capability_is_denied(&deny, &Capability::FileDelete));
    }

    #[test]
    fn capability_is_denied_file_write_deny_also_denies_delete() {
        // Defense in depth: a pre-4103 `file_write` deny keeps blocking delete.
        let deny = deny_set(&[Capability::FileWrite]);
        assert!(super::capability_is_denied(&deny, &Capability::FileDelete));
    }

    #[test]
    fn capability_is_denied_file_delete_deny_does_not_deny_write() {
        // Asymmetric: delete-deny must NOT block writes.
        let deny = deny_set(&[Capability::FileDelete]);
        assert!(!super::capability_is_denied(&deny, &Capability::FileWrite));
    }

    #[test]
    fn capability_is_denied_unrelated_deny_is_false() {
        let deny = deny_set(&[Capability::NetworkOutbound]);
        assert!(!super::capability_is_denied(&deny, &Capability::FileDelete));
    }

    // ------------------------------------------------------------------
    // allow_restricted / allow_is_restricted (AAASM-4154)
    // ------------------------------------------------------------------

    #[test]
    fn allow_is_restricted_true_when_allow_non_empty() {
        // A non-empty allow-list is a restriction even without the flag set.
        let cs = cap_set(&[Capability::FileRead], &[]);
        assert!(cs.allow_is_restricted());
    }

    #[test]
    fn allow_is_restricted_false_when_no_allow_declared() {
        // Deny-only (or empty) set with no restriction flag → unrestricted.
        let cs = cap_set(&[], &[Capability::TerminalExec]);
        assert!(!cs.allow_is_restricted());
    }

    #[test]
    fn allow_is_restricted_true_when_flag_set_but_allow_empty() {
        // The collapsed-cascade shape: empty allow but restriction carried.
        let cs = CapabilitySet {
            allow: BTreeSet::new(),
            deny: BTreeSet::new(),
            allow_restricted: true,
        };
        assert!(cs.allow_is_restricted());
    }

    #[test]
    fn merge_disjoint_allow_lists_stays_restricted_with_empty_allow() {
        // AAASM-4154: two disjoint non-empty allow-lists intersect to empty, but
        // the restriction must survive so the guard fails closed (deny-all)
        // rather than reading empty allow as "no restriction" (allow-all).
        let parent = cap_set(&[Capability::FileRead], &[]);
        let child = cap_set(&[Capability::FileWrite], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.allow.is_empty(), "disjoint allow-lists intersect to empty");
        assert!(result.allow_restricted, "restriction must persist across the collapse");
        assert!(
            result.allow_is_restricted(),
            "guard must treat the collapsed set as restricted (deny-all)"
        );
    }

    #[test]
    fn merge_single_tier_allow_is_restricted() {
        // A lone declared allow-list is a restriction after merge.
        let parent = CapabilitySet::default();
        let child = cap_set(&[Capability::FileRead], &[]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.allow.contains(&Capability::FileRead));
        assert!(result.allow_restricted);
    }

    #[test]
    fn merge_no_allow_declared_is_unrestricted() {
        // Deny-only tiers never manufacture an allow-list restriction.
        let parent = cap_set(&[], &[Capability::FileWrite]);
        let child = cap_set(&[], &[Capability::TerminalExec]);
        let result = super::merge_capabilities(&parent, &child);
        assert!(result.allow.is_empty());
        assert!(!result.allow_restricted);
        assert!(!result.allow_is_restricted());
    }
}
