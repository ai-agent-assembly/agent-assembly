//! Routes an approval request to the appropriate team approver queue.

use aa_runtime::approval::ApprovalRequest;

use super::routing_config::RoutingConfigStore;

// ---------------------------------------------------------------------------
// RoutingOutcome
// ---------------------------------------------------------------------------

/// The result of routing an [`ApprovalRequest`] through the team config.
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingOutcome {
    /// Request routed to the specified approvers.
    Routed {
        /// Team identifier that was matched.
        team_id: String,
        /// Approvers notified for this request.
        approvers: Vec<String>,
        /// Seconds until escalation fires if no decision is made.
        escalation_timeout_secs: u64,
    },
    /// No team config found; request falls through to default handling.
    NoTeamConfig,
    /// Agent has no team affiliation; no routing performed.
    NoTeamId,
}

// ---------------------------------------------------------------------------
// ApprovalRouter
// ---------------------------------------------------------------------------

/// Routes approval requests to team-specific approver lists.
pub struct ApprovalRouter {
    store: RoutingConfigStore,
}

impl ApprovalRouter {
    pub fn new(store: RoutingConfigStore) -> Self {
        Self { store }
    }

    /// Determine the routing outcome for `request`.
    pub fn route(&self, request: &ApprovalRequest) -> RoutingOutcome {
        let team_id = match request.team_id.as_deref() {
            Some(id) if !id.is_empty() => id,
            _ => return RoutingOutcome::NoTeamId,
        };

        match self.store.get(team_id) {
            Some(cfg) => RoutingOutcome::Routed {
                team_id: cfg.team_id.clone(),
                approvers: cfg.approvers.clone(),
                escalation_timeout_secs: cfg.escalation_timeout_secs,
            },
            None => RoutingOutcome::NoTeamConfig,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::approval::routing_config::TeamRoutingConfig;
    use aa_runtime::approval::ApprovalRequest;
    use uuid::Uuid;

    fn store_with_team(team_id: &str) -> RoutingConfigStore {
        let path = {
            let mut p = std::env::temp_dir();
            p.push(format!("router_test_{}.json", Uuid::new_v4()));
            p
        };
        let mut store = RoutingConfigStore::load(&path).unwrap();
        store
            .upsert(TeamRoutingConfig {
                team_id: team_id.to_string(),
                approvers: vec!["alice".to_string()],
                escalation_timeout_secs: 120,
                escalation_approvers: vec!["manager".to_string()],
                approval_kind: None,
            })
            .unwrap();
        store
    }

    fn make_request(team_id: Option<&str>) -> ApprovalRequest {
        ApprovalRequest {
            request_id: Uuid::new_v4(),
            agent_id: "agent-1".to_string(),
            action: "read_file /etc/hosts".to_string(),
            condition_triggered: "sensitive-file-access".to_string(),
            submitted_at: 1_700_000_000,
            timeout_secs: 60,
            fallback: aa_core::PolicyResult::Deny {
                reason: "timed out".to_string(),
            },
            team_id: team_id.map(str::to_string),
        }
    }

    #[test]
    fn route_with_matching_team_returns_routed() {
        let router = ApprovalRouter::new(store_with_team("team-x"));
        let req = make_request(Some("team-x"));
        match router.route(&req) {
            RoutingOutcome::Routed {
                team_id,
                approvers,
                escalation_timeout_secs,
            } => {
                assert_eq!(team_id, "team-x");
                assert_eq!(approvers, vec!["alice"]);
                assert_eq!(escalation_timeout_secs, 120);
            }
            other => panic!("expected Routed, got {other:?}"),
        }
    }

    #[test]
    fn route_with_no_team_id_returns_no_team_id() {
        let router = ApprovalRouter::new(store_with_team("team-x"));
        let req = make_request(None);
        assert_eq!(router.route(&req), RoutingOutcome::NoTeamId);
    }

    #[test]
    fn route_with_empty_team_id_returns_no_team_id() {
        let router = ApprovalRouter::new(store_with_team("team-x"));
        let req = make_request(Some(""));
        assert_eq!(router.route(&req), RoutingOutcome::NoTeamId);
    }

    #[test]
    fn route_with_unknown_team_returns_no_team_config() {
        let router = ApprovalRouter::new(store_with_team("team-x"));
        let req = make_request(Some("team-unknown"));
        assert_eq!(router.route(&req), RoutingOutcome::NoTeamConfig);
    }
}
