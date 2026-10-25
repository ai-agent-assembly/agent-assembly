//! What, if anything, decides on this runtime's tool calls (AAASM-6384).
//!
//! A runtime started with nothing but `AA_AGENT_ID` allows every call, yet used
//! to log "active enforcement mechanisms" and report `status: "healthy"`. The
//! interception *layers* being present says where a call can be seen; it says
//! nothing about whether anything decides on it. This type is the one place
//! that answers the second question, so the startup log and `GET /health`
//! cannot disagree about it.
//!
//! It only describes. It never changes a verdict: an ungoverned configuration
//! keeps allowing everything, it just no longer looks governed.

/// The governance posture, derived from configuration known at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct GovernancePosture {
    /// `ungoverned`, `policy_only` or `lease_governed`.
    pub state: &'static str,
    /// Governed lease mode (`AA_LEASE_POLICY`) is active.
    pub lease_governed: bool,
    /// Rules loaded from the local policy file.
    pub local_rule_count: usize,
    /// A gateway endpoint is configured to decide on policy checks.
    pub gateway_configured: bool,
}

impl GovernancePosture {
    /// Derive the posture. Lease governance wins: it is the only mode that
    /// enforces a tool's `allow: false` and capability declarations here.
    pub fn new(lease_governed: bool, local_rule_count: usize, gateway_configured: bool) -> Self {
        let state = if lease_governed {
            "lease_governed"
        } else if local_rule_count > 0 || gateway_configured {
            "policy_only"
        } else {
            "ungoverned"
        };
        Self {
            state,
            lease_governed,
            local_rule_count,
            gateway_configured,
        }
    }

    /// Nothing decides on calls: every one is allowed.
    pub fn is_ungoverned(&self) -> bool {
        self.state == "ungoverned"
    }

    /// Say it at startup, at a level matching the consequence.
    pub fn log(&self) {
        match self.state {
            "ungoverned" => tracing::warn!(
                governance = self.state,
                "UNGOVERNED: no lease policy, no local policy rules and no gateway are configured, so \
                 every tool call and action is ALLOWED. To govern, set AA_LEASE_POLICY (with \
                 AA_LEASE_STATE from `aasm lease init`), put rules at AA_POLICY_PATH, or set \
                 AA_GATEWAY_ENDPOINT"
            ),
            "policy_only" => tracing::info!(
                governance = self.state,
                local_rule_count = self.local_rule_count,
                gateway_configured = self.gateway_configured,
                "governance: policy rules and/or a gateway decide, but lease governance is not enabled \
                 (AA_LEASE_POLICY unset), so a tool's allow:false and capability declarations are NOT \
                 enforced by this runtime"
            ),
            _ => tracing::info!(governance = self.state, "governance: capability lease gate active"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_configured_is_ungoverned() {
        let p = GovernancePosture::new(false, 0, false);
        assert_eq!(p.state, "ungoverned");
        assert!(p.is_ungoverned());
    }

    #[test]
    fn rules_or_a_gateway_without_leases_is_policy_only() {
        assert_eq!(GovernancePosture::new(false, 2, false).state, "policy_only");
        assert_eq!(GovernancePosture::new(false, 0, true).state, "policy_only");
        assert!(!GovernancePosture::new(false, 2, false).is_ungoverned());
    }

    #[test]
    fn lease_governance_wins_over_everything_else() {
        assert_eq!(GovernancePosture::new(true, 0, false).state, "lease_governed");
        assert_eq!(GovernancePosture::new(true, 3, true).state, "lease_governed");
    }
}
