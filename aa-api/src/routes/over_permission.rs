//! Over-permission derivation for the capability matrix (AAASM-5175, ADR 0029).
//!
//! An agent is *over-permissioned* when it is effectively granted a destructive
//! / high-blast-radius **system** capability that its declared [`RiskTier`]
//! baseline does not warrant. This is a static, structural comparison of grants
//! against the agent's declared posture — deliberately **not** the behavioural,
//! audit-derived trust score of ADR 0019, and not the topology violation-volume
//! flag. See `docs/src/adr/0029-capability-over-permission-derivation.md`.
//!
//! The rule is **fail-absent**: an agent with no resolvable tier is not
//! evaluated at all (its `flagged` and every `flag` stay absent), and no missing
//! input ever yields a fabricated `true`. The one boolean `false` emitted is for
//! an agent that *was* evaluated (tier resolved) and found within baseline — a
//! real measurement, which is what turns the dashboard's danger-toned tile from
//! "not evaluated" into a count.

use aa_core::{Capability, RiskTier};

/// The destructive / high-blast-radius system capabilities the matrix models and
/// this rule reasons about. `FileRead` is excluded (reading is not destructive);
/// `Model` / `NetworkInbound` / `AgentSpawn` are inert (`Capability::is_enforceable`)
/// and never reach a cell; named MCP tools carry no danger classification, so they
/// are out of the baseline (ADR 0029 Accepted risks).
const HIGH_PRIVILEGE: [Capability; 4] = [
    Capability::FileWrite,
    Capability::FileDelete,
    Capability::TerminalExec,
    Capability::NetworkOutbound,
];

/// Whether a tier's declared baseline permits `cap` without it being
/// over-permission. The baseline is a monotone allow-list that widens with
/// severity (ADR 0029 Decision):
///
/// - `Low` (log-only posture): permits no destructive grant.
/// - `Medium`: routine write + egress.
/// - `High` / `Critical` (always-block, human-review posture): every modelled
///   system verb.
///
/// A capability outside [`HIGH_PRIVILEGE`] is never over-permission, so it is
/// always within baseline.
fn tier_permits(tier: RiskTier, cap: &Capability) -> bool {
    if !HIGH_PRIVILEGE.contains(cap) {
        return true;
    }
    match tier {
        RiskTier::Low => false,
        RiskTier::Medium => matches!(cap, Capability::FileWrite | Capability::NetworkOutbound),
        RiskTier::High | RiskTier::Critical => true,
    }
}

/// Whether granting `cap` to an agent of this tier is over-permission.
///
/// This is a property of the *grant vs. the declared tier*, independent of
/// whether the agent is actually granted the capability — the caller gates on the
/// effective `Decision::Allow` before flagging a cell, so a denied capability is
/// never flagged even though it would be over-baseline if granted.
#[must_use]
pub fn is_over_permission(tier: RiskTier, cap: &Capability) -> bool {
    !tier_permits(tier, cap)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_tier_flags_every_destructive_grant() {
        for cap in &HIGH_PRIVILEGE {
            assert!(is_over_permission(RiskTier::Low, cap), "low should flag {cap}");
        }
    }

    #[test]
    fn low_tier_does_not_flag_file_read() {
        assert!(!is_over_permission(RiskTier::Low, &Capability::FileRead));
    }

    #[test]
    fn medium_permits_write_and_egress_but_not_delete_or_exec() {
        assert!(!is_over_permission(RiskTier::Medium, &Capability::FileWrite));
        assert!(!is_over_permission(RiskTier::Medium, &Capability::NetworkOutbound));
        assert!(is_over_permission(RiskTier::Medium, &Capability::FileDelete));
        assert!(is_over_permission(RiskTier::Medium, &Capability::TerminalExec));
    }

    #[test]
    fn high_and_critical_permit_every_modelled_system_verb() {
        for tier in [RiskTier::High, RiskTier::Critical] {
            for cap in &HIGH_PRIVILEGE {
                assert!(!is_over_permission(tier, cap), "{tier:?} should not flag {cap}");
            }
        }
    }

    #[test]
    fn named_tools_are_never_over_permission() {
        let tool = Capability::McpTool("delete_prod_db".to_string());
        for tier in [RiskTier::Low, RiskTier::Medium, RiskTier::High, RiskTier::Critical] {
            assert!(!is_over_permission(tier, &tool));
        }
    }
}
