//! Agent-registry storage value types — slim records for persistence.
//!
//! These are deliberately distinct from the richer
//! [`crate::registry::store::AgentRecord`] runtime state: the registry layer
//! owns liveness, heartbeats, and credential tokens; the storage layer
//! persists only the durable identity / configuration fields. Conversion
//! between the two happens at the wiring layer (Epic 18 S-I).

use std::collections::BTreeMap;

use aa_core::identity::AgentId;
use chrono::{DateTime, Utc};

/// Team identifier used by the storage layer.
///
/// Kept as a type alias for now so existing `String` team_ids in the gateway
/// can be passed through unchanged. May be replaced with a newtype later.
pub type TeamId = String;

/// Storage-layer agent record — the durable shape of a registered agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentRecord {
    /// Stable agent identifier.
    pub agent_id: AgentId,
    /// Owning team, if assigned.
    pub team_id: Option<TeamId>,
    /// Owning org, if assigned.
    pub org_id: Option<String>,
    /// Arbitrary metadata (k/v).
    pub metadata: BTreeMap<String, String>,
    /// Initial registration timestamp (UTC).
    pub registered_at: DateTime<Utc>,
    /// Last time the agent was observed (UTC).
    pub last_seen_at: DateTime<Utc>,
    /// Enforcement mode — `"enforce"`, `"shadow"`, `"observe"`, etc.
    pub enforcement_mode: String,
    /// Expiry of a time-limited (shadow) enforcement window, if any.
    ///
    /// `Some(_)` marks `enforcement_mode` as a bounded window that reverts to
    /// the base mode once the deadline passes; `None` means the mode has no
    /// deadline. Persisted so the deadline survives a gateway restart — an
    /// already-expired window must never be silently resurrected as active on
    /// rehydrate (ADR 0021 prerequisite; AAASM-5288).
    pub enforcement_mode_expires_at: Option<DateTime<Utc>>,
}

/// Which tenant a durable agent-registry query may see.
///
/// A struct with a private field rather than a public enum: [`AgentScope::org`]
/// is the only constructor reachable from outside this crate, so a cross-tenant
/// read is not expressible outside `aa-gateway` at all — an unscoped
/// `StorageBackend` call is a compile error for every caller but the one
/// legitimate boot-time replay (AAASM-5648).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentScope(Option<String>);

impl AgentScope {
    /// Scope a query to one org.
    pub fn org(org_id: impl Into<String>) -> Self {
        Self(Some(org_id.into()))
    }

    /// Every tenant — the deployment-wide view.
    ///
    /// Reserved for boot-time registry replay (`AgentRegistry::rehydrate_from_storage`),
    /// the only call site where a cross-tenant read is legitimate: the in-memory
    /// registry it populates is what every tenant-scoped read is later filtered
    /// from. `pub(crate)` and additionally gated by a `clippy::disallowed_methods`
    /// entry in `clippy.toml` so a second call site fails CI, not just review.
    pub(crate) fn entire_deployment() -> Self {
        Self(None)
    }

    /// The org this scope is restricted to, or `None` for [`Self::entire_deployment`].
    pub fn org_id(&self) -> Option<&str> {
        self.0.as_deref()
    }
}

/// Filter applied to agent-registry queries.
///
/// No `Default` impl: `AgentFilter::default()` was the unscoped call this type
/// exists to make unrepresentable (AAASM-5648) — every filter must be built from
/// an explicit [`AgentScope`].
#[derive(Debug, Clone)]
pub struct AgentFilter {
    scope: AgentScope,
    team_id: Option<TeamId>,
    name_contains: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
}

impl AgentFilter {
    /// Start a filter scoped to `scope`, with no further restriction.
    pub fn new(scope: AgentScope) -> Self {
        Self {
            scope,
            team_id: None,
            name_contains: None,
            limit: None,
            offset: None,
        }
    }

    /// The tenant scope this filter enforces.
    pub fn scope(&self) -> &AgentScope {
        &self.scope
    }

    /// Restrict to agents owned by this team.
    #[must_use]
    pub fn with_team(mut self, team_id: impl Into<TeamId>) -> Self {
        self.team_id = Some(team_id.into());
        self
    }

    /// Substring match on agent metadata `name` key.
    #[must_use]
    pub fn with_name_contains(mut self, needle: impl Into<String>) -> Self {
        self.name_contains = Some(needle.into());
        self
    }

    /// Maximum number of agents to return.
    #[must_use]
    pub fn with_limit(mut self, limit: u32) -> Self {
        self.limit = Some(limit);
        self
    }

    /// Offset into the result set.
    #[must_use]
    pub fn with_offset(mut self, offset: u32) -> Self {
        self.offset = Some(offset);
        self
    }

    /// Restrict to agents owned by this team, if any.
    pub fn team_id(&self) -> Option<&str> {
        self.team_id.as_deref()
    }

    /// The name substring to match, if any.
    pub fn name_contains(&self) -> Option<&str> {
        self.name_contains.as_deref()
    }

    /// The maximum number of agents to return, if bounded.
    pub fn limit(&self) -> Option<u32> {
        self.limit
    }

    /// The offset into the result set, if any.
    pub fn offset(&self) -> Option<u32> {
        self.offset
    }
}
