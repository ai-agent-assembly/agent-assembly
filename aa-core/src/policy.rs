//! Policy types and the [`PolicyEvaluator`] trait for governance decisions.
//!
//! A [`GovernanceAction`] describes what an agent wants to do.
//! A [`PolicyEvaluator`] decides whether that action is permitted,
//! denied, or requires human approval, and returns a [`PolicyResult`].
//! Policy rules are expressed as [`PolicyDocument`] objects containing
//! ordered [`PolicyRule`] entries.

/// Pre-serialized JSON string passed at policy trait boundaries.
///
/// Callers serialize arguments before handing them to an evaluator;
/// evaluators deserialize lazily only if they need to inspect the payload.
/// This keeps the trait boundary free of any serde-json dependency.
#[cfg(feature = "alloc")]
pub type ArgsJson = alloc::string::String;

/// File access mode for `GovernanceAction::FileAccess`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FileMode {
    /// Open the file for reading only.
    Read,
    /// Open the file for writing, truncating any existing content.
    Write,
    /// Open the file for writing, appending to existing content.
    Append,
    /// Delete the file from the filesystem.
    Delete,
}

/// Errors produced during policy loading or evaluation.
///
/// All variants are heap-free so `PolicyError` can be used in bare `no_std`
/// contexts that have no `alloc`.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyError {
    /// The supplied `PolicyDocument` is structurally invalid.
    InvalidDocument,
    /// The `GovernanceAction` variant is not recognized by this evaluator.
    UnknownAction,
    /// The evaluator encountered an internal error during evaluation.
    EvaluationFailed,
}

/// The decision recorded in a `PolicyRule`.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyDecision {
    /// The action is permitted without restriction.
    Allow,
    /// The action is prohibited.
    Deny,
    /// The action may proceed only after explicit human approval.
    RequireApproval,
}

/// Controls whether policy decisions are applied to agent actions or only observed.
///
/// Mirrors the proto `EnforcementMode` enum defined in `proto/policy.proto` so
/// pure-Rust code can reason about the enforcement posture without a proto
/// dependency.
///
/// | Mode       | Proto value | Effect on `Deny` / `Redact` / `Pending` / `BudgetBlock` |
/// |------------|-------------|---------------------------------------------------------|
/// | `Enforce`  | 1           | Decision applied; agent blocked / payload redacted.     |
/// | `Observe`  | 2           | Decision recorded as a shadow audit event; agent proceeds. |
/// | `Disabled` | 3           | Policy evaluation skipped entirely (test environments). |
///
/// `Enforce` is the default — omitting `enforcement_mode` from any
/// policy document or registration payload leaves existing behavior unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum EnforcementMode {
    /// Default: deny blocks, redact strips, pending halts execution.
    #[default]
    Enforce,
    /// Dry-run / sandbox: decisions computed and audited; no enforcement applied.
    Observe,
    /// Policy evaluation disabled entirely. Only valid in hermetic test environments.
    Disabled,
}

impl EnforcementMode {
    /// Convert from the proto integer value (1=Enforce … 3=Disabled).
    ///
    /// Returns `None` for 0 (UNSPECIFIED) and any out-of-range value so callers
    /// can fall back to a server-side default rather than silently coercing.
    pub fn from_proto_i32(v: i32) -> Option<Self> {
        match v {
            1 => Some(Self::Enforce),
            2 => Some(Self::Observe),
            3 => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// A single rule inside a `PolicyDocument`.
///
/// Gated on `alloc` because `action_pattern` is a `String`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyRule {
    /// Glob-style pattern matched against the action name or path.
    pub action_pattern: alloc::string::String,
    /// Decision to apply when the pattern matches.
    pub decision: PolicyDecision,
}

/// Minimal policy document stub.
///
/// Full schema deferred to AAASM-105/AAASM-69. Sufficient for test evaluators
/// to implement `load_policy` and `validate_policy` without a real parser.
///
/// Gated on `alloc` because `name` and `rules` require heap allocation.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PolicyDocument {
    /// Schema version number.
    pub version: u32,
    /// Human-readable policy name.
    pub name: alloc::string::String,
    /// Ordered list of rules evaluated top-to-bottom.
    pub rules: alloc::vec::Vec<PolicyRule>,
    /// Enforcement posture for this policy. Defaults to `Enforce` when the
    /// field is absent from the source document, preserving pre-feature
    /// behavior for all existing policies.
    #[cfg_attr(feature = "serde", serde(default))]
    pub enforcement_mode: EnforcementMode,
}

/// The outcome of a `PolicyEvaluator::evaluate` call.
///
/// Gated on `alloc` because `Deny::reason` carries a `String`.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum PolicyResult {
    /// The action is permitted.
    Allow,
    /// The action is denied; `reason` explains why.
    Deny {
        /// Human-readable description of why the action was denied.
        reason: alloc::string::String,
    },
    /// Human approval is required within the given timeout.
    RequiresApproval {
        /// Maximum seconds to wait for human approval before the request expires.
        timeout_secs: u32,
    },
}

/// An agent action subject to governance evaluation.
///
/// Gated on `alloc` because all variants carry `String` fields.
#[cfg(feature = "alloc")]
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum GovernanceAction {
    /// Invocation of a named tool with pre-serialized JSON arguments.
    ToolCall {
        /// Registered name of the tool being invoked.
        name: alloc::string::String,
        /// Pre-serialized JSON arguments passed to the tool.
        args: ArgsJson,
    },
    /// Result returned by a tool invocation, evaluated on the response path
    /// before the result is forwarded back to the agent.
    ///
    /// Carries the same shape as `ToolCall.args` — a pre-serialized JSON
    /// string — so the policy engine can apply JSON-pointer-addressed
    /// predicates (e.g. `tool_result.foo`) and credential-pattern scans
    /// against the body the upstream tool emitted.
    ToolResult {
        /// Registered name of the tool that produced the result.
        tool_name: alloc::string::String,
        /// Pre-serialized JSON body of the tool's response.
        result: ArgsJson,
    },
    /// Read or write access to a file path.
    FileAccess {
        /// Absolute or relative path of the file being accessed.
        path: alloc::string::String,
        /// Access mode (read, write, append, or delete).
        mode: FileMode,
    },
    /// Outbound network request.
    NetworkRequest {
        /// Target URL of the outbound request.
        url: alloc::string::String,
        /// HTTP method (e.g., `"GET"`, `"POST"`).
        method: alloc::string::String,
    },
    /// Spawning an external process.
    ProcessExec {
        /// Full shell command string to be executed.
        command: alloc::string::String,
    },
    /// Inter-team message sent through a named channel.
    SendMessage {
        /// Team ID of the sending agent's team. `None` when the sender has no team.
        source_team_id: Option<alloc::string::String>,
        /// Team ID of the intended recipient team. `None` when the target is unresolved.
        target_team_id: Option<alloc::string::String>,
        /// Logical channel identifier through which the message is routed.
        channel_id: Option<alloc::string::String>,
    },
}

/// Pluggable policy evaluation backend.
///
/// Implementors decide whether a given `GovernanceAction` is permitted for
/// a given `AgentContext`. The trait is object-safe: `dyn PolicyEvaluator`
/// is valid because no method has generic parameters or returns `Self`.
///
/// Gated on `alloc` because `GovernanceAction` and `PolicyDocument` require it.
#[cfg(feature = "alloc")]
pub trait PolicyEvaluator {
    /// Evaluate whether `action` is permitted for `ctx`.
    fn evaluate(&self, ctx: &crate::AgentContext, action: &GovernanceAction) -> PolicyResult;

    /// Load a policy document into this evaluator, replacing any prior policy.
    ///
    /// Requires `&mut self`, so callers holding `&dyn PolicyEvaluator` must
    /// upgrade to `&mut dyn PolicyEvaluator` before calling this method.
    fn load_policy(&mut self, policy: &PolicyDocument) -> Result<(), PolicyError>;

    /// Validate a policy document without applying it.
    ///
    /// Returns all validation errors found, or `Ok(())` if the document is valid.
    fn validate_policy(&self, policy: &PolicyDocument) -> Result<(), alloc::vec::Vec<PolicyError>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_mode_clone_and_eq() {
        let m = FileMode::Read;
        assert_eq!(m.clone(), FileMode::Read);
        assert_ne!(FileMode::Write, FileMode::Delete);
    }

    #[test]
    fn file_mode_all_variants() {
        // Verify all variants are constructible and distinct.
        assert_ne!(FileMode::Read, FileMode::Write);
        assert_ne!(FileMode::Append, FileMode::Delete);
        assert_ne!(FileMode::Write, FileMode::Append);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn governance_action_tool_call() {
        let action = GovernanceAction::ToolCall {
            name: alloc::string::String::from("list_files"),
            args: alloc::string::String::from("{\"dir\":\"/tmp\"}"),
        };
        assert_eq!(action.clone(), action);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn governance_action_tool_result() {
        let action = GovernanceAction::ToolResult {
            tool_name: alloc::string::String::from("list_files"),
            result: alloc::string::String::from("{\"entries\":[\"a.txt\"]}"),
        };
        assert_eq!(action.clone(), action);
    }

    #[test]
    #[cfg(all(feature = "alloc", feature = "serde"))]
    fn governance_action_tool_result_serde_round_trip() {
        // The audit pipeline serialises every GovernanceAction it sees; if the
        // new variant fails to round-trip through serde, downstream audit
        // entries silently lose response-side actions.
        let action = GovernanceAction::ToolResult {
            tool_name: alloc::string::String::from("read_file"),
            result: alloc::string::String::from("{\"contents\":\"sk-test-abc\"}"),
        };
        let encoded = serde_json::to_string(&action).expect("serialize");
        let decoded: GovernanceAction = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(decoded, action);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn governance_action_file_access() {
        let action = GovernanceAction::FileAccess {
            path: alloc::string::String::from("/etc/passwd"),
            mode: FileMode::Read,
        };
        let cloned = action.clone();
        assert_eq!(action, cloned);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn governance_action_network_request() {
        let action = GovernanceAction::NetworkRequest {
            url: alloc::string::String::from("https://example.com"),
            method: alloc::string::String::from("GET"),
        };
        assert_eq!(action.clone(), action);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn governance_action_spawn() {
        let action = GovernanceAction::ProcessExec {
            command: alloc::string::String::from("ls -la"),
        };
        assert_eq!(action.clone(), action);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_result_allow() {
        assert_eq!(PolicyResult::Allow, PolicyResult::Allow);
        assert_eq!(PolicyResult::Allow.clone(), PolicyResult::Allow);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_result_deny_reason() {
        let r = PolicyResult::Deny {
            reason: alloc::string::String::from("blocked"),
        };
        if let PolicyResult::Deny { reason } = &r {
            assert_eq!(reason, "blocked");
        } else {
            panic!("expected Deny");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_result_requires_approval() {
        let r = PolicyResult::RequiresApproval { timeout_secs: 30 };
        if let PolicyResult::RequiresApproval { timeout_secs } = r {
            assert_eq!(timeout_secs, 30);
        } else {
            panic!("expected RequiresApproval");
        }
    }

    #[test]
    fn policy_error_variants() {
        assert_eq!(PolicyError::InvalidDocument, PolicyError::InvalidDocument);
        assert_ne!(PolicyError::UnknownAction, PolicyError::EvaluationFailed);
    }

    #[test]
    fn policy_decision_variants() {
        assert_eq!(PolicyDecision::Allow, PolicyDecision::Allow);
        assert_ne!(PolicyDecision::Deny, PolicyDecision::RequireApproval);
    }

    #[test]
    fn enforcement_mode_default_is_enforce() {
        // Pre-feature semantics: omitting the mode anywhere must resolve to Enforce.
        assert_eq!(EnforcementMode::default(), EnforcementMode::Enforce);
    }

    #[test]
    fn enforcement_mode_from_proto_i32_round_trips_known_values() {
        // The proto reserves 0 for UNSPECIFIED — it must NOT silently coerce
        // to Enforce here; only valid 1/2/3 produce Some(_). Server-side
        // resolution is responsible for picking a default for unspecified.
        assert_eq!(EnforcementMode::from_proto_i32(1), Some(EnforcementMode::Enforce));
        assert_eq!(EnforcementMode::from_proto_i32(2), Some(EnforcementMode::Observe));
        assert_eq!(EnforcementMode::from_proto_i32(3), Some(EnforcementMode::Disabled));
        assert_eq!(EnforcementMode::from_proto_i32(0), None);
        assert_eq!(EnforcementMode::from_proto_i32(-1), None);
        assert_eq!(EnforcementMode::from_proto_i32(99), None);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn enforcement_mode_serde_snake_case_round_trip() {
        // The wire / YAML representation must use lowercase tokens — operators
        // type `enforcement_mode: observe`, not `Observe`.
        for (mode, expected) in [
            (EnforcementMode::Enforce, "\"enforce\""),
            (EnforcementMode::Observe, "\"observe\""),
            (EnforcementMode::Disabled, "\"disabled\""),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected, "{mode:?} must serialise as {expected}");
            let back: EnforcementMode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, mode, "{expected} must deserialise back to {mode:?}");
        }
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_rule_field_access_clone_eq() {
        let rule = PolicyRule {
            action_pattern: alloc::string::String::from("tool_call/*"),
            decision: PolicyDecision::Deny,
        };
        let cloned = rule.clone();
        assert_eq!(rule, cloned);
        assert_eq!(rule.action_pattern, "tool_call/*");
        assert_eq!(rule.decision, PolicyDecision::Deny);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_document_field_access_clone_eq() {
        let doc = PolicyDocument {
            version: 1,
            name: alloc::string::String::from("test-policy"),
            rules: alloc::vec![PolicyRule {
                action_pattern: alloc::string::String::from("*"),
                decision: PolicyDecision::Allow,
            }],
            enforcement_mode: EnforcementMode::default(),
        };
        let cloned = doc.clone();
        assert_eq!(doc, cloned);
        assert_eq!(doc.version, 1);
        assert_eq!(doc.name, "test-policy");
        assert_eq!(doc.rules.len(), 1);
        assert_eq!(doc.rules[0].decision, PolicyDecision::Allow);
    }

    #[cfg(all(feature = "alloc", feature = "serde"))]
    #[test]
    fn policy_document_enforcement_mode_parses_observe_from_yaml() {
        // An operator-authored sandbox policy: `enforcement_mode: observe`
        // at the document root must surface as EnforcementMode::Observe.
        let yaml = "version: 1\nname: sandbox-policy\nenforcement_mode: observe\nrules: []\n";
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(doc.enforcement_mode, EnforcementMode::Observe);
    }

    #[cfg(all(feature = "alloc", feature = "serde"))]
    #[test]
    fn policy_document_enforcement_mode_defaults_to_enforce_when_absent() {
        // Backward compatibility: pre-feature YAML / JSON policy documents
        // never had this field, so deserialising one must produce Enforce.
        let yaml = "version: 1\nname: legacy-policy\nrules: []\n";
        let doc: PolicyDocument = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(doc.enforcement_mode, EnforcementMode::Enforce);
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn policy_result_cross_variant_inequality() {
        assert_ne!(
            PolicyResult::Allow,
            PolicyResult::Deny {
                reason: alloc::string::String::from("x")
            }
        );
        assert_ne!(
            PolicyResult::Deny {
                reason: alloc::string::String::from("x")
            },
            PolicyResult::RequiresApproval { timeout_secs: 10 }
        );
    }
}

// ---------------------------------------------------------------------------
// Egress allowlist matcher (AAASM-1943)
// ---------------------------------------------------------------------------

/// Decide whether a host is allowed by an outbound-egress allowlist.
///
/// Semantics:
///
/// * **Empty allowlist** → `true` (allowlist disabled — caller falls back to
///   whatever default policy applies, typically Allow).
/// * **Non-empty allowlist** → `true` only when `host` matches at least one
///   pattern; `false` otherwise.
///
/// Pattern syntax (`aa-proxy` + `aa-gateway` policy DSL share this):
///
/// * **Exact match**: `api.openai.com` matches `api.openai.com` only.
/// * **Leftmost-label wildcard**: `*.openai.com` matches `api.openai.com`,
///   `chat.openai.com`, etc. but NOT `openai.com` itself and NOT
///   `evil.example.com.openai.com.attacker.com`.
/// * **Universal wildcard**: `*` matches every host (escape hatch for
///   "allow everything that isn't otherwise denied"; rarely used).
///
/// Matching is **case-insensitive** for the host portion since DNS labels are
/// case-insensitive (RFC 4343).
///
/// The pattern is intentionally narrow — we don't accept arbitrary glob
/// (`?`, character classes, full-`*` mid-label) because allowlist patterns
/// that look more permissive than they are have historically been the source
/// of egress-rule misconfigurations. The narrow grammar lets operators
/// reason about every pattern at a glance.
#[cfg(feature = "alloc")]
pub fn is_host_allowed_by_egress_allowlist(host: &str, allowlist: &[alloc::string::String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let host_lower = host.to_ascii_lowercase();
    for pattern in allowlist {
        if egress_pattern_matches(pattern, &host_lower) {
            return true;
        }
    }
    false
}

/// Fail-closed egress decision: like [`is_host_allowed_by_egress_allowlist`],
/// but an **empty** allowlist denies all hosts instead of allowing them.
///
/// AAASM-3730: the policy layer (`aa-gateway` cascade + single-file engine, and
/// the `aa-proxy` L2 egress gate) treats the presence of a `network:` clause as
/// "egress is governed". A governed-but-empty allowlist is the most restrictive
/// posture — "permit nothing" — not "permit everything". Defaulting an empty
/// allowlist to allow-all silently disabled the entire egress control whenever
/// an operator wrote an empty list, the canonical fail-open footgun.
///
/// Callers that genuinely mean "no allowlist configured ⇒ no restriction" must
/// gate on the *absence* of the network policy before reaching this matcher, not
/// on the allowlist being empty.
///
/// Non-empty allowlists match identically to
/// [`is_host_allowed_by_egress_allowlist`] (exact, leftmost-label wildcard,
/// universal `*`, case-insensitive).
#[cfg(feature = "alloc")]
pub fn is_host_allowed_by_egress_allowlist_fail_closed(host: &str, allowlist: &[alloc::string::String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    is_host_allowed_by_egress_allowlist(host, allowlist)
}

#[cfg(feature = "alloc")]
fn egress_pattern_matches(pattern: &str, host_lower: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if pattern_lower == "*" {
        return true;
    }
    if let Some(suffix) = pattern_lower.strip_prefix("*.") {
        // *.example.com matches anything ending in `.example.com` AFTER at
        // least one extra label — does NOT match the bare suffix or
        // attacker-crafted subdomains where the suffix is not at the right.
        let required_suffix = alloc::format!(".{suffix}");
        return host_lower.ends_with(&required_suffix) && host_lower.len() > required_suffix.len();
    }
    pattern_lower == host_lower
}

#[cfg(all(test, feature = "alloc"))]
mod egress_tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::is_host_allowed_by_egress_allowlist;

    #[test]
    fn empty_allowlist_is_default_allow() {
        assert!(is_host_allowed_by_egress_allowlist("api.example.com", &[]));
        assert!(is_host_allowed_by_egress_allowlist("evil.attacker.net", &[]));
    }

    #[test]
    fn exact_match_only_matches_exact_host() {
        let list = vec!["api.openai.com".to_string()];
        assert!(is_host_allowed_by_egress_allowlist("api.openai.com", &list));
        assert!(!is_host_allowed_by_egress_allowlist("chat.openai.com", &list));
        assert!(!is_host_allowed_by_egress_allowlist("openai.com", &list));
        assert!(!is_host_allowed_by_egress_allowlist("attackerapi.openai.com", &list));
    }

    #[test]
    fn case_insensitive_host_match() {
        let list = vec!["API.OpenAI.com".to_string()];
        assert!(is_host_allowed_by_egress_allowlist("api.openai.com", &list));
        assert!(is_host_allowed_by_egress_allowlist("API.OPENAI.COM", &list));
    }

    #[test]
    fn leftmost_wildcard_matches_subdomain() {
        let list = vec!["*.openai.com".to_string()];
        assert!(is_host_allowed_by_egress_allowlist("api.openai.com", &list));
        assert!(is_host_allowed_by_egress_allowlist("chat.openai.com", &list));
        assert!(is_host_allowed_by_egress_allowlist("a.b.openai.com", &list));
    }

    #[test]
    fn leftmost_wildcard_does_not_match_bare_suffix() {
        let list = vec!["*.openai.com".to_string()];
        assert!(!is_host_allowed_by_egress_allowlist("openai.com", &list));
    }

    #[test]
    fn leftmost_wildcard_does_not_match_attacker_crafted_suffix() {
        let list = vec!["*.openai.com".to_string()];
        // Classic confusion attack: the attacker hopes a glob would match
        // `evil.openai.com.attacker.net`. Our grammar refuses.
        assert!(!is_host_allowed_by_egress_allowlist(
            "evil.openai.com.attacker.net",
            &list
        ));
    }

    #[test]
    fn universal_wildcard_matches_any_host() {
        let list = vec!["*".to_string()];
        assert!(is_host_allowed_by_egress_allowlist("api.openai.com", &list));
        assert!(is_host_allowed_by_egress_allowlist("evil.attacker.net", &list));
        assert!(is_host_allowed_by_egress_allowlist("anything", &list));
    }

    #[test]
    fn multiple_patterns_any_match_allows() {
        let list = vec!["api.openai.com".to_string(), "*.anthropic.com".to_string()];
        assert!(is_host_allowed_by_egress_allowlist("api.openai.com", &list));
        assert!(is_host_allowed_by_egress_allowlist("api.anthropic.com", &list));
        assert!(!is_host_allowed_by_egress_allowlist("api.cohere.com", &list));
    }

    // AAASM-3730: fail-closed matcher — empty allowlist DENIES all hosts.
    use super::is_host_allowed_by_egress_allowlist_fail_closed as fail_closed;

    #[test]
    fn fail_closed_empty_allowlist_denies_every_host() {
        assert!(!fail_closed("api.openai.com", &[]));
        assert!(!fail_closed("evil.attacker.net", &[]));
    }

    #[test]
    fn fail_closed_non_empty_matches_like_default_matcher() {
        let list = vec!["api.openai.com".to_string(), "*.anthropic.com".to_string()];
        assert!(fail_closed("api.openai.com", &list));
        assert!(fail_closed("chat.anthropic.com", &list));
        assert!(!fail_closed("evil.attacker.net", &list));
    }

    #[test]
    fn fail_closed_universal_wildcard_still_allows_any_host() {
        let list = vec!["*".to_string()];
        assert!(fail_closed("api.openai.com", &list));
        assert!(fail_closed("evil.attacker.net", &list));
    }
}
