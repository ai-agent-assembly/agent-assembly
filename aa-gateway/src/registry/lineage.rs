/// Agent lineage resolved from the registry for scope-chain walking.
///
/// `org_id` is the organization the registry bound at Register (the first-class
/// `AgentRecord::org_id`, never the client's request metadata); `team_id` mirrors
/// the `"team_id"` metadata key the lifecycle service writes at registration.
///
/// AAASM-3377 — the delegation fields (`root_agent_id`, `parent_agent_id`,
/// `depth`, `delegation_reason`, `spawned_by_tool`) mirror the first-class
/// fields on `AgentRecord` so audit entries carry the full lineage instead
/// of only the `org_id` / `team_id` scope pair.
#[derive(Debug, Clone, Default)]
pub struct Lineage {
    pub org_id: Option<String>,
    pub team_id: Option<String>,
    /// Root agent identifier at the top of the delegation chain.
    pub root_agent_id: Option<[u8; 16]>,
    /// Identifier of the agent that directly spawned this agent.
    pub parent_agent_id: Option<[u8; 16]>,
    /// Delegation depth from the root agent (`0` = root).
    pub depth: Option<u32>,
    /// Human-readable reason the action was delegated to this agent.
    pub delegation_reason: Option<String>,
    /// Name of the tool or framework that spawned this agent.
    pub spawned_by_tool: Option<String>,
}
