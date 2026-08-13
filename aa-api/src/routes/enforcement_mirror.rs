//! Read-only mirrors of the gateway's enforcement stages, shared by every
//! projection that reports "what may this agent do?" without evaluating a
//! concrete action.
//!
//! `aa_gateway::engine::decision::evaluate_single_doc` runs its stages in a fixed
//! order and returns on the first `Deny`: `stage_network` → `stage_tool_allow` →
//! `stage_capability` → `stage_approval`. A projection that reads only the merged
//! capability set therefore reports `allow` for everything an *earlier* stage
//! already blocks — the fail-open the capability matrix shipped with
//! (AAASM-5090), which the topology permission panel then repeated (AAASM-5099).
//!
//! Both projections fold the earlier stages in through this module, so there is
//! one implementation to keep in step with the evaluator rather than two that can
//! drift apart. Each mirror names the `stage_*` function it tracks, so grepping
//! for `stage_tool_allow` or `stage_network` finds the evaluator and every mirror
//! of it in the same search.
//!
//! Only stages that a *per-agent* view can decide are mirrored. `stage_network`
//! needs a host and `stage_approval` needs a pending request, so neither can be
//! answered in general here — see [`cascade_denies_all_egress`] for the one
//! network case that is answerable, and note that no approval mirror exists.

use std::sync::Arc;

/// The `tools` key that means "every tool without an explicit entry"
/// (AAASM-4152). It is a fallback pattern, never a tool name, so it must never
/// reach a projection as a tool identifier.
pub(crate) const TOOL_WILDCARD: &str = "*";

/// Whether the cascade's tool stage would deny `tool`.
///
/// **Mirrors `stage_tool_allow` in `aa-gateway/src/engine/decision.rs`** — an
/// exact `tools` entry wins, otherwise the `"*"` fallback applies, and
/// `allow: false` denies. Any deny anywhere in the cascade is final, matching
/// the evaluator's short-circuit on the first `Deny`.
///
/// The capability set alone cannot answer this: a tool denied by
/// `tools: { "*": { allow: false } }` contributes no `mcp_tool:` capability, so
/// reading only the merged capabilities reported `allow` for a tool the gateway
/// blocks — and contradicted the rule rows `capability::project_rules` emits from
/// the very same `tools` map.
pub(crate) fn cascade_denies_tool(cascade: &[Arc<aa_gateway::policy::PolicyDocument>], tool: &str) -> bool {
    cascade.iter().any(|doc| {
        doc.tools
            .get(tool)
            .or_else(|| doc.tools.get(TOOL_WILDCARD))
            .is_some_and(|tp| !tp.allow)
    })
}

/// Whether the cascade's network stage denies *every* outbound host.
///
/// **Mirrors `stage_network` in `aa-gateway/src/engine/decision.rs`** for the one
/// case a per-agent view can state without a concrete URL: a document that
/// declares a `network` section with an empty allowlist is deny-all (the
/// fail-closed matcher — AAASM-3127/AAASM-3730).
///
/// A present, non-empty allowlist is deliberately *not* treated as a deny: egress
/// is permitted, just host-restricted, and there is no host to test. Such an
/// agent keeps its capability-derived decision.
pub(crate) fn cascade_denies_all_egress(cascade: &[Arc<aa_gateway::policy::PolicyDocument>]) -> bool {
    cascade
        .iter()
        .any(|doc| doc.network.as_ref().is_some_and(|np| np.allowlist.is_empty()))
}

/// Every tool name one agent is known to have: what it declared at registration,
/// plus any tool its own cascade names — whether by an `mcp_tool:` grant/deny or
/// by a per-tool policy entry. All three are real declarations about this agent.
///
/// This is the universe [`cascade_denies_tool`] can be asked about. It is
/// necessarily incomplete against `tools: { "*": … }`, which speaks about tools
/// nobody has named yet; callers must not read an absent name as "allowed".
///
/// `"*"` is stripped: it is the tool stage's fallback pattern, not a tool. Left
/// in, it became a resource column literally named `*` whose cell read `allow` —
/// the exact inverse of what `tools: { "*": { allow: false } }` declares.
pub(crate) fn agent_tool_ids(
    record: &aa_gateway::registry::AgentRecord,
    caps: &aa_core::CapabilitySet,
    cascade: &[Arc<aa_gateway::policy::PolicyDocument>],
) -> std::collections::BTreeSet<String> {
    let mut agent_tools: std::collections::BTreeSet<String> = record.tool_names.iter().cloned().collect();
    for cap in caps.allow.iter().chain(caps.deny.iter()) {
        if let aa_core::Capability::McpTool(name) = cap {
            agent_tools.insert(name.clone());
        }
    }
    for doc in cascade {
        agent_tools.extend(doc.tools.keys().cloned());
    }
    agent_tools.remove(TOOL_WILDCARD);
    agent_tools
}
