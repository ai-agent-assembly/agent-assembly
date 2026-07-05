//! Intermediate policy decision type used by the cascade merge layer.
//!
//! `PolicyDecision` is richer than `aa_core::PolicyResult` — it carries
//! the `source_scope` on `Deny` for audit and debugging. The engine
//! converts to `PolicyResult` before returning `EvaluationResult`.

use std::sync::Arc;

use crate::policy::document::PolicyDocument;
use crate::policy::scope::PolicyScope;

/// The outcome produced by evaluating a single policy document against one action.
///
/// Used by [`merge_decisions`] to combine per-scope outcomes. Convert to
/// [`aa_core::PolicyResult`] via [`PolicyDecision::into_policy_result`]
/// before surfacing through `EvaluationResult`.
#[derive(Debug, Clone, PartialEq)]
pub enum PolicyDecision {
    /// Action is allowed by this policy.
    Allow,
    /// Action requires human approval. Carries the policy's configured timeout.
    RequireApproval { reason: String, timeout_secs: u32 },
    /// Action is denied. `source_scope` identifies which scope triggered the deny.
    Deny { reason: String, source_scope: PolicyScope },
}

impl PolicyDecision {
    /// Convert to `aa_core::PolicyResult`, dropping the `source_scope` audit
    /// field that is not part of the core protocol type.
    pub fn into_policy_result(self) -> aa_core::PolicyResult {
        match self {
            PolicyDecision::Allow => aa_core::PolicyResult::Allow,
            PolicyDecision::RequireApproval { timeout_secs, .. } => {
                aa_core::PolicyResult::RequiresApproval { timeout_secs }
            }
            PolicyDecision::Deny { reason, .. } => aa_core::PolicyResult::Deny { reason },
        }
    }
}

/// Evaluate a single `PolicyDocument` against `(ctx, action)` and return the
/// decision for the *cacheable* stages 2–3 and 5 (network, tool-allow,
/// capability, approval-condition).
///
/// Stage 1 (schedule) is deliberately **excluded** here: it is time-dependent
/// and must be evaluated fresh on every request via [`evaluate_schedule_cascade`]
/// so that a cached `Allow` computed inside an active-hours window cannot be
/// served after the window closes (AAASM-3893). Stages 4 (rate-limit) and 7
/// (budget) are stateful at engine level and are evaluated separately after
/// merging. Stage 6 (credential scan) does not produce a decision — it is
/// handled at the engine level.
///
/// Returns `Deny` on the first matching deny rule, `RequireApproval` for approval
/// conditions, and `Allow` if no rule fires.
pub(crate) fn evaluate_single_doc(
    doc: &PolicyDocument,
    ctx: &aa_core::AgentContext,
    action: &aa_core::GovernanceAction,
    policy_ctx: Option<&dyn crate::policy::context::PolicyContext>,
) -> PolicyDecision {
    if let Some(d) = stage_network(doc, action) {
        return d;
    }
    if let Some(d) = stage_tool_allow(doc, action) {
        return d;
    }
    if let Some(d) = stage_capability(doc, action) {
        return d;
    }
    if let Some(d) = stage_approval(doc, ctx, action, policy_ctx) {
        return d;
    }

    PolicyDecision::Allow
}

/// Stage 1 — Schedule, evaluated **fresh** across the whole cascade.
///
/// Returns the first schedule-based `Deny` (current time outside a doc's
/// active-hours window, or an unparseable timezone), or `None` when every doc's
/// window currently permits the request.
///
/// AAASM-3893: this stage is time-dependent and is intentionally kept out of
/// [`evaluate_single_doc`] (and therefore out of the engine's decision cache).
/// The caller runs it on every request so a cached verdict computed inside an
/// active-hours window cannot outlive that window.
pub(crate) fn evaluate_schedule_cascade(cascade: &[Arc<PolicyDocument>]) -> Option<PolicyDecision> {
    cascade.iter().find_map(|doc| stage_schedule(doc))
}

/// Stage 1 — Schedule: deny when the current time is outside the doc's
/// active-hours window.
fn stage_schedule(doc: &PolicyDocument) -> Option<PolicyDecision> {
    let ah = doc.schedule.as_ref()?.active_hours.as_ref()?;
    use chrono::Timelike;
    // AAASM-3133: an unparseable timezone must fail closed. Silently falling
    // back to UTC let an operator's active-hours window be evaluated in the
    // wrong zone — e.g. a window meant for business hours in `America/New_York`
    // evaluated in UTC could be wide open when it should be shut, bypassing the
    // schedule control. Deny when the configured tz does not parse.
    let Ok(tz) = ah.timezone.parse::<chrono_tz::Tz>() else {
        return Some(PolicyDecision::Deny {
            reason: format!("invalid schedule timezone: {}", ah.timezone),
            source_scope: doc.scope.clone(),
        });
    };
    let now = chrono::Utc::now().with_timezone(&tz);
    let current_hhmm = format!("{:02}:{:02}", now.hour(), now.minute());
    if current_hhmm < ah.start || current_hhmm >= ah.end {
        return Some(PolicyDecision::Deny {
            reason: "outside active hours".into(),
            source_scope: doc.scope.clone(),
        });
    }
    None
}

/// Stage 2 — Network allowlist: deny a `NetworkRequest` whose host is not
/// permitted by the doc's egress allowlist.
///
/// Two correctness fixes over the previous inline matcher (F3/AAASM-3127):
///
/// * **Wildcards** — delegates to
///   [`aa_core::policy::is_host_allowed_by_egress_allowlist`], the same
///   wildcard-aware matcher the `aa-proxy` egress layer uses, so the engine
///   and the proxy no longer disagree on `*.host` patterns. The previous
///   `entry == host` exact-match silently failed to match any wildcard entry,
///   denying legitimate traffic the operator believed they had allowed.
/// * **Empty allowlist = deny-all** — a policy doc that declares a `network`
///   section but leaves the allowlist empty is treated as "deny all egress",
///   not "allow all egress". An empty allowlist is the most restrictive
///   posture; failing open here defeated the whole egress control.
fn stage_network(doc: &PolicyDocument, action: &aa_core::GovernanceAction) -> Option<PolicyDecision> {
    let aa_core::GovernanceAction::NetworkRequest { url, .. } = action else {
        return None;
    };
    let np = doc.network.as_ref()?;
    if !network_request_url_allowed(url, np) {
        return Some(PolicyDecision::Deny {
            reason: "host not in network allowlist".into(),
            source_scope: doc.scope.clone(),
        });
    }
    None
}

/// Shared egress decision for a `NetworkRequest` URL against a [`NetworkPolicy`].
///
/// This is the single source of truth for the gateway's network-stage check:
/// both the cascade path ([`stage_network`]) and the single-file engine path
/// (`PolicyEngine::eval_network_stage`) route through it so they cannot diverge
/// (AAASM-3728).
///
/// * Extracts the authority from `proto://host:port/...` and strips a trailing
///   numeric `:port` (AAASM-3350) — allowlist entries are bare hosts.
/// * Delegates matching to the **fail-closed** matcher
///   ([`aa_core::policy::is_host_allowed_by_egress_allowlist_fail_closed`]):
///   a configured-but-empty allowlist denies all egress, and wildcard patterns
///   (`*.host`, `*`) are honoured (AAASM-3127/AAASM-3730). The previous
///   single-file path used an empty-is-allow-all default and an exact-only
///   compare — a fail-open egress control.
pub(crate) fn network_request_url_allowed(url: &str, np: &crate::policy::NetworkPolicy) -> bool {
    let host_port = url
        .split_once("://")
        .map(|x| x.1)
        .unwrap_or("")
        .split('/')
        .next()
        .unwrap_or("");
    let host = match host_port.rsplit_once(':') {
        Some((h, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => h,
        _ => host_port,
    };
    aa_core::policy::is_host_allowed_by_egress_allowlist_fail_closed(host, &np.allowlist)
}

/// Stage 3 — Tool allow/deny: deny a `ToolCall` whose tool policy is not allowed.
///
/// AAASM-4152: the `"*"` tools key is a wildcard fallback, not a literal tool
/// name. An exact per-tool entry takes precedence; a tool with no explicit
/// entry falls back to the `"*"` policy. This mirrors the network stage's
/// wildcard support and lets `tools: { "*": { allow: false } }` deny unknown
/// tools (fail closed). Previously the exact-only `get(name)` returned `None`
/// for any unlisted tool, so the stage fell through to the engine's
/// allow-by-default — a fail-open tool control.
fn stage_tool_allow(doc: &PolicyDocument, action: &aa_core::GovernanceAction) -> Option<PolicyDecision> {
    let aa_core::GovernanceAction::ToolCall { name, .. } = action else {
        return None;
    };
    let tp = doc.tools.get(name).or_else(|| doc.tools.get("*"))?;
    if !tp.allow {
        return Some(PolicyDecision::Deny {
            reason: "tool denied by policy".into(),
            source_scope: doc.scope.clone(),
        });
    }
    None
}

/// Stage 3.5 — Capability check: deny when this doc's capability set blocks the
/// action's capability (explicit deny, or omitted from a non-empty allow set).
fn stage_capability(doc: &PolicyDocument, action: &aa_core::GovernanceAction) -> Option<PolicyDecision> {
    let caps = doc.capabilities.as_ref()?;
    let cap = aa_core::action_to_capability(action)?;
    if aa_core::capability_is_denied(&caps.deny, &cap) {
        return Some(PolicyDecision::Deny {
            reason: "capability denied by policy".into(),
            source_scope: doc.scope.clone(),
        });
    }
    if !caps.allow.is_empty() && !caps.allow.contains(&cap) {
        return Some(PolicyDecision::Deny {
            reason: "capability not in allow list".into(),
            source_scope: doc.scope.clone(),
        });
    }
    None
}

/// Stages 5 & 5b — Approval condition: require approval when the tool's (or the
/// `message` channel sentinel's) `requires_approval_if` expression evaluates
/// true for the action.
fn stage_approval(
    doc: &PolicyDocument,
    ctx: &aa_core::AgentContext,
    action: &aa_core::GovernanceAction,
    policy_ctx: Option<&dyn crate::policy::context::PolicyContext>,
) -> Option<PolicyDecision> {
    match action {
        aa_core::GovernanceAction::ToolCall { name, .. }
            if approval_condition_met(doc.tools.get(name), ctx, action, policy_ctx) =>
        {
            Some(PolicyDecision::RequireApproval {
                reason: format!("approval required for tool '{name}'"),
                timeout_secs: doc.approval_timeout_secs,
            })
        }
        // The "message" sentinel key carries all inter-team channel rules; the
        // expression evaluator resolves source/target team and channel ids from
        // the SendMessage action fields directly.
        aa_core::GovernanceAction::SendMessage { .. }
            if approval_condition_met(doc.tools.get("message"), ctx, action, policy_ctx) =>
        {
            Some(PolicyDecision::RequireApproval {
                reason: "approval required: cross-team channel policy".into(),
                timeout_secs: doc.approval_timeout_secs,
            })
        }
        _ => None,
    }
}

/// Whether a tool/channel policy has a non-empty `requires_approval_if`
/// expression that evaluates true for `action`.
fn approval_condition_met(
    tool_policy: Option<&crate::policy::document::ToolPolicy>,
    ctx: &aa_core::AgentContext,
    action: &aa_core::GovernanceAction,
    policy_ctx: Option<&dyn crate::policy::context::PolicyContext>,
) -> bool {
    let Some(expr) = tool_policy.and_then(|tp| tp.requires_approval_if.as_ref()) else {
        return false;
    };
    !expr.is_empty() && crate::policy::expr::evaluate(expr, action, Some(ctx.governance_level), policy_ctx)
}

/// Merge a cascade of policy documents into a single `PolicyDecision` using
/// most-restrictive-wins semantics: `Deny > RequireApproval > Allow`.
///
/// Rules:
/// - Any `Deny` from any scope short-circuits immediately and is returned.
/// - If no `Deny` and any `RequireApproval` exists, return the most-specific
///   scope's `RequireApproval` (last one encountered wins — narrower scope
///   overrides broader scope).
/// - If all policies say `Allow`, return `Allow`.
/// - An empty cascade returns a fail-closed `Deny` — never silently allow.
///
/// Stages 4 (rate-limit) and 7 (budget) must be applied by the caller after
/// this function returns `Allow`.
pub fn merge_decisions(
    cascade: &[Arc<PolicyDocument>],
    ctx: &aa_core::AgentContext,
    action: &aa_core::GovernanceAction,
    policy_ctx: Option<&dyn crate::policy::context::PolicyContext>,
) -> PolicyDecision {
    if cascade.is_empty() {
        return PolicyDecision::Deny {
            reason: "no policy — fail-closed".into(),
            source_scope: PolicyScope::Global,
        };
    }

    let mut running = PolicyDecision::Allow;

    for doc in cascade {
        let verdict = evaluate_single_doc(doc, ctx, action, policy_ctx);
        match verdict {
            // Short-circuit: Deny always wins.
            PolicyDecision::Deny { .. } => return verdict,
            // Most-specific scope wins: always overwrite with the narrower scope's decision.
            PolicyDecision::RequireApproval { .. } => {
                running = verdict;
            }
            PolicyDecision::Allow => {}
        }
    }

    running
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::document::PolicyDocument;
    use crate::policy::scope::PolicyScope;
    use aa_core::{
        identity::{AgentId, SessionId},
        time::Timestamp,
        AgentContext, Capability, CapabilitySet, FileMode, GovernanceAction, GovernanceLevel,
    };
    use std::collections::{BTreeMap, BTreeSet, HashMap};

    fn make_ctx() -> AgentContext {
        AgentContext {
            agent_id: AgentId::from_bytes([1u8; 16]),
            session_id: SessionId::from_bytes([2u8; 16]),
            pid: 1,
            started_at: Timestamp::from_nanos(0),
            metadata: BTreeMap::new(),
            governance_level: GovernanceLevel::default(),
            parent_agent_id: None,
            team_id: None,
            depth: 0,
            delegation_reason: None,
            spawned_by_tool: None,
            root_agent_id: None,
        }
    }

    fn minimal_doc(caps: Option<CapabilitySet>) -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: caps,
        }
    }

    fn cap_set(allow: &[Capability], deny: &[Capability]) -> CapabilitySet {
        CapabilitySet {
            allow: allow.iter().cloned().collect::<BTreeSet<_>>(),
            deny: deny.iter().cloned().collect::<BTreeSet<_>>(),
        }
    }

    #[test]
    fn evaluate_single_doc_denies_capability_in_deny_set() {
        let doc = minimal_doc(Some(cap_set(&[], &[Capability::FileRead])));
        let ctx = make_ctx();
        let action = GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: FileMode::Read,
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(
            result,
            PolicyDecision::Deny {
                reason: "capability denied by policy".into(),
                source_scope: PolicyScope::Global,
            }
        );
    }

    #[test]
    fn evaluate_single_doc_denies_capability_not_in_allow_set() {
        // allow = {FileRead} only — FileWrite should be denied
        let doc = minimal_doc(Some(cap_set(&[Capability::FileRead], &[])));
        let ctx = make_ctx();
        let action = GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: FileMode::Write,
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(
            result,
            PolicyDecision::Deny {
                reason: "capability not in allow list".into(),
                source_scope: PolicyScope::Global,
            }
        );
    }

    #[test]
    fn evaluate_single_doc_allows_capability_in_allow_set() {
        // allow = {FileRead} — FileRead should pass the capability stage
        let doc = minimal_doc(Some(cap_set(&[Capability::FileRead], &[])));
        let ctx = make_ctx();
        let action = GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: FileMode::Read,
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(result, PolicyDecision::Allow);
    }

    #[test]
    fn evaluate_single_doc_no_capabilities_field_allows_all() {
        // No capabilities block → no restriction from stage 3.5
        let doc = minimal_doc(None);
        let ctx = make_ctx();
        let action = GovernanceAction::FileAccess {
            path: "/tmp/f".into(),
            mode: FileMode::Write,
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(result, PolicyDecision::Allow);
    }

    #[test]
    fn evaluate_single_doc_mcp_tool_denied_by_name() {
        let doc = minimal_doc(Some(cap_set(&[], &[Capability::McpTool("bash".into())])));
        let ctx = make_ctx();
        let action = GovernanceAction::ToolCall {
            name: "bash".into(),
            args: "{}".into(),
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(
            result,
            PolicyDecision::Deny {
                reason: "capability denied by policy".into(),
                source_scope: PolicyScope::Global,
            }
        );
    }

    #[test]
    fn evaluate_single_doc_mcp_tool_allowed_by_name() {
        let doc = minimal_doc(Some(cap_set(&[Capability::McpTool("bash".into())], &[])));
        let ctx = make_ctx();
        let action = GovernanceAction::ToolCall {
            name: "bash".into(),
            args: "{}".into(),
        };
        let result = evaluate_single_doc(&doc, &ctx, &action, None);
        assert_eq!(result, PolicyDecision::Allow);
    }

    // ── Stage 2: network egress allowlist (F3 / AAASM-3127) ─────────────────

    fn doc_with_allowlist(allowlist: Vec<String>) -> PolicyDocument {
        let mut doc = minimal_doc(None);
        doc.network = Some(crate::policy::document::NetworkPolicy { allowlist });
        doc
    }

    fn net_action(url: &str) -> GovernanceAction {
        GovernanceAction::NetworkRequest {
            url: url.into(),
            method: "GET".into(),
        }
    }

    #[test]
    fn stage_network_wildcard_matches_subdomain() {
        let doc = doc_with_allowlist(vec!["*.openai.com".into()]);
        assert_eq!(stage_network(&doc, &net_action("https://api.openai.com/v1")), None);
    }

    #[test]
    fn stage_network_wildcard_denies_non_matching_host() {
        let doc = doc_with_allowlist(vec!["*.openai.com".into()]);
        let d = stage_network(&doc, &net_action("https://evil.attacker.net/x")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn stage_network_wildcard_denies_bare_apex() {
        // `*.openai.com` must NOT match the bare apex `openai.com`.
        let doc = doc_with_allowlist(vec!["*.openai.com".into()]);
        let d = stage_network(&doc, &net_action("https://openai.com/")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn stage_network_exact_match_allows() {
        let doc = doc_with_allowlist(vec!["api.openai.com".into()]);
        assert_eq!(stage_network(&doc, &net_action("https://api.openai.com/v1")), None);
    }

    #[test]
    fn stage_network_empty_allowlist_denies_all() {
        // F3: an empty allowlist is the most restrictive posture — deny-all,
        // not allow-all.
        let doc = doc_with_allowlist(vec![]);
        let d = stage_network(&doc, &net_action("https://api.openai.com/v1")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn stage_network_no_network_section_is_noop() {
        let doc = minimal_doc(None);
        assert_eq!(stage_network(&doc, &net_action("https://anything.test/")), None);
    }

    #[test]
    fn stage_network_allowlisted_host_with_port_allows() {
        // AAASM-3350: the gateway builds URLs as `proto://host:port`. A bare
        // allowlist entry must still match once the port is stripped.
        let doc = doc_with_allowlist(vec!["api.openai.com".into()]);
        assert_eq!(stage_network(&doc, &net_action("https://api.openai.com:443/v1")), None);
    }

    #[test]
    fn stage_network_wildcard_host_with_port_allows() {
        // AAASM-3350: port stripping must also let wildcard entries match.
        let doc = doc_with_allowlist(vec!["*.openai.com".into()]);
        assert_eq!(stage_network(&doc, &net_action("https://api.openai.com:443/v1")), None);
    }

    #[test]
    fn stage_network_non_allowlisted_host_with_port_denies() {
        // AAASM-3350: stripping the port must not let a non-allowlisted host through.
        let doc = doc_with_allowlist(vec!["api.openai.com".into()]);
        let d = stage_network(&doc, &net_action("https://evil.attacker.net:8443/x")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    // ── Stage 3: tool allow/deny wildcard fail-closed (AAASM-4152) ──────────

    fn tool_action(name: &str) -> GovernanceAction {
        GovernanceAction::ToolCall {
            name: name.into(),
            args: "{}".into(),
        }
    }

    fn doc_with_tools(tools: &[(&str, bool)]) -> PolicyDocument {
        let mut doc = minimal_doc(None);
        doc.tools = tools
            .iter()
            .map(|(name, allow)| {
                (
                    (*name).to_string(),
                    crate::policy::document::ToolPolicy {
                        allow: *allow,
                        limit_per_hour: None,
                        requires_approval_if: None,
                    },
                )
            })
            .collect();
        doc
    }

    #[test]
    fn stage_tool_wildcard_deny_denies_unlisted_tool() {
        // AAASM-4152: `tools: { "*": { allow: false }, read_file: { allow: true } }`
        // must deny an unlisted tool — the `"*"` key is a wildcard fallback, not a
        // literal name. Previously the unlisted tool fell through to allow-by-default.
        let doc = doc_with_tools(&[("*", false), ("read_file", true)]);
        let d = stage_tool_allow(&doc, &tool_action("exfiltrate_secrets")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
    }

    #[test]
    fn stage_tool_wildcard_deny_allows_explicitly_listed_tool() {
        // An explicit per-tool entry takes precedence over the `"*"` fallback.
        let doc = doc_with_tools(&[("*", false), ("read_file", true)]);
        assert_eq!(stage_tool_allow(&doc, &tool_action("read_file")), None);
    }

    #[test]
    fn stage_tool_explicit_entry_overrides_wildcard_allow() {
        // A per-tool deny beats a permissive `"*": allow` fallback.
        let doc = doc_with_tools(&[("*", true), ("dangerous", false)]);
        let d = stage_tool_allow(&doc, &tool_action("dangerous")).expect("deny");
        assert!(matches!(d, PolicyDecision::Deny { .. }));
        // And an unlisted tool falls back to the permissive wildcard → allow.
        assert_eq!(stage_tool_allow(&doc, &tool_action("anything_else")), None);
    }

    #[test]
    fn stage_tool_no_matching_entry_is_noop() {
        // No exact entry and no `"*"` fallback → stage abstains (returns None),
        // deferring to later stages / the engine default.
        let doc = doc_with_tools(&[("read_file", true)]);
        assert_eq!(stage_tool_allow(&doc, &tool_action("write_file")), None);
    }

    // ── Stage 1: schedule timezone fail-closed (AAASM-3133) ─────────────────

    fn doc_with_schedule(tz: &str, start: &str, end: &str) -> PolicyDocument {
        let mut doc = minimal_doc(None);
        doc.schedule = Some(crate::policy::document::SchedulePolicy {
            active_hours: Some(crate::policy::document::ActiveHours {
                start: start.into(),
                end: end.into(),
                timezone: tz.into(),
            }),
        });
        doc
    }

    #[test]
    fn stage_schedule_invalid_timezone_fails_closed() {
        // AAASM-3133: an unparseable tz must DENY, not silently fall back to UTC
        // and risk evaluating the active-hours window in the wrong zone.
        let doc = doc_with_schedule("Mars/Phobos", "00:00", "23:59");
        let d = stage_schedule(&doc).expect("deny");
        match d {
            PolicyDecision::Deny { reason, .. } => {
                assert!(reason.contains("invalid schedule timezone"), "got: {reason}");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn stage_schedule_valid_timezone_full_day_window_allows() {
        // A valid tz with an all-day window must not deny on the tz check.
        let doc = doc_with_schedule("UTC", "00:00", "23:59");
        assert_eq!(stage_schedule(&doc), None);
    }
}
