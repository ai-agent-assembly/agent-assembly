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

/// The governance posture, derived from configuration known at startup, with
/// the lease gate's own state folded in when `/health` is served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct GovernancePosture {
    /// `ungoverned`, `policy_only`, `lease_governed` or `denied_all` (the lease
    /// gate tripped and is denying every request).
    pub state: &'static str,
    /// Governed lease mode (`AA_LEASE_POLICY`) was started.
    pub lease_governed: bool,
    /// Local rules that can actually decide: a rule that blocks nothing and
    /// requires approval for nothing is not counted.
    pub local_rule_count: usize,
    /// A gateway client is installed. Installed, not reachable: an invalid
    /// `AA_GATEWAY_ENDPOINT` installs none, and a valid but dead one still
    /// counts.
    pub gateway_installed: bool,
    /// The gateway is installed but this runtime was told to fail open
    /// (`AA_GATEWAY_FAIL_CLOSED=false`): when it cannot be reached a call falls
    /// back to the local rules, and with none, is allowed.
    pub gateway_fail_open: bool,
}

impl GovernancePosture {
    /// Derive the posture. Lease governance wins: it is the only mode that
    /// enforces a tool's `allow: false` and capability declarations here.
    pub fn new(
        lease_governed: bool,
        local_rule_count: usize,
        gateway_installed: bool,
        gateway_fail_closed: bool,
    ) -> Self {
        let state = if lease_governed {
            "lease_governed"
        } else if local_rule_count > 0 || gateway_installed {
            "policy_only"
        } else {
            "ungoverned"
        };
        Self {
            state,
            lease_governed,
            local_rule_count,
            gateway_installed,
            gateway_fail_open: gateway_installed && !gateway_fail_closed,
        }
    }

    /// The posture now, given the lease gate's current state (`governed` or
    /// `denied_all`) if there is one. The startup posture is frozen; a gate that
    /// has since tripped is not "governed" to anyone reading `/health`.
    pub fn live(self, lease_state: Option<&str>) -> Self {
        match lease_state {
            Some("denied_all") => Self {
                state: "denied_all",
                ..self
            },
            _ => self,
        }
    }

    /// Nothing decides on calls: this runtime allows every one.
    pub fn is_ungoverned(&self) -> bool {
        self.state == "ungoverned"
    }

    /// Say it at startup, at a level matching the consequence.
    pub fn log(&self) {
        match self.state {
            "ungoverned" => tracing::warn!(
                governance = self.state,
                "UNGOVERNED: no lease policy, no effective local policy rules and no gateway client are \
                 in place, so this runtime evaluates nothing and ALLOWS every tool call and action it \
                 sees. To govern, set AA_LEASE_POLICY (with AA_LEASE_STATE from `aasm lease init`), \
                 put rules at AA_POLICY_PATH, or set a valid AA_GATEWAY_ENDPOINT"
            ),
            "policy_only" => tracing::info!(
                governance = self.state,
                local_rule_count = self.local_rule_count,
                gateway_installed = self.gateway_installed,
                gateway_fail_open = self.gateway_fail_open,
                "governance: policy rules and/or a gateway client decide (installed, not proven \
                 reachable), but lease governance is not enabled (AA_LEASE_POLICY unset), so a tool's \
                 allow:false and capability declarations are NOT enforced by this runtime"
            ),
            _ => tracing::info!(governance = self.state, "governance: capability lease gate active"),
        }
        if self.gateway_fail_open {
            tracing::warn!(
                local_rule_count = self.local_rule_count,
                "gateway fails OPEN (AA_GATEWAY_FAIL_CLOSED=false): when it is unreachable, calls fall \
                 back to the local rules and are allowed if none match"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_installed_is_ungoverned() {
        let p = GovernancePosture::new(false, 0, false, true);
        assert_eq!(p.state, "ungoverned");
        assert!(p.is_ungoverned());
    }

    #[test]
    fn rules_or_a_gateway_without_leases_is_policy_only() {
        assert_eq!(GovernancePosture::new(false, 2, false, true).state, "policy_only");
        assert_eq!(GovernancePosture::new(false, 0, true, true).state, "policy_only");
        assert!(!GovernancePosture::new(false, 2, false, true).is_ungoverned());
    }

    #[test]
    fn lease_governance_wins_over_everything_else() {
        assert_eq!(GovernancePosture::new(true, 0, false, true).state, "lease_governed");
        assert_eq!(GovernancePosture::new(true, 3, true, true).state, "lease_governed");
    }

    #[test]
    fn fail_open_is_only_meaningful_with_an_installed_gateway() {
        assert!(GovernancePosture::new(false, 0, true, false).gateway_fail_open);
        assert!(!GovernancePosture::new(false, 0, true, true).gateway_fail_open);
        assert!(!GovernancePosture::new(false, 0, false, false).gateway_fail_open);
    }

    #[test]
    fn a_tripped_gate_is_denied_all_not_governed() {
        let p = GovernancePosture::new(true, 0, false, true);
        assert_eq!(p.live(Some("governed")).state, "lease_governed");
        assert_eq!(p.live(Some("denied_all")).state, "denied_all");
        assert_eq!(p.live(None).state, "lease_governed");
    }
}
