//! Network egress policy evaluation (AAASM-1943 — F116 ST-W).
//!
//! Bridges the typed [`NetworkPolicy`] from [`super::document`] to the shared
//! egress-allowlist matcher in [`aa_core::policy::is_host_allowed_by_egress_allowlist`].
//! aa-proxy enforces at the CONNECT level using the same matcher directly;
//! this wrapper exists so other gateway-side consumers (the dashboard,
//! future REST endpoints, CLI dry-run commands) can ask "would this host
//! be allowed by the current policy?" without re-implementing the glob
//! semantics.

use crate::policy::NetworkPolicy;

/// Outcome of evaluating a host against a [`NetworkPolicy`]'s egress
/// allowlist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDecision {
    /// `true` when the host is permitted to receive an outbound connection.
    pub allowed: bool,
    /// Human-readable rationale suitable for logs and audit events.
    pub reason: String,
}

/// Evaluate `host` against the network policy's allowlist.
///
/// When `policy` is `None` (no `network:` clause in the YAML), the host is
/// allowed — the caller's default-open posture wins. When the policy is set
/// but the allowlist is empty, the host is also allowed (an empty list means
/// "no restriction").
///
/// Glob semantics match `aa_core::policy::is_host_allowed_by_egress_allowlist`:
/// exact case-insensitive match, leftmost-label wildcard (`*.example.com`),
/// or universal wildcard (`*`).
pub fn check_network_egress(host: &str, policy: Option<&NetworkPolicy>) -> EgressDecision {
    match policy {
        None => EgressDecision {
            allowed: true,
            reason: "no network policy configured".into(),
        },
        Some(np) if np.allowlist.is_empty() => EgressDecision {
            allowed: true,
            reason: "network allowlist empty (no restriction)".into(),
        },
        Some(np) => {
            if aa_core::policy::is_host_allowed_by_egress_allowlist(host, &np.allowlist) {
                EgressDecision {
                    allowed: true,
                    reason: format!("host matches network allowlist ({} pattern(s))", np.allowlist.len()),
                }
            } else {
                EgressDecision {
                    allowed: false,
                    reason: format!("host not in network allowlist ({} pattern(s))", np.allowlist.len()),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(patterns: &[&str]) -> NetworkPolicy {
        NetworkPolicy {
            allowlist: patterns.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn none_policy_allows_any_host() {
        let d = check_network_egress("api.openai.com", None);
        assert!(d.allowed);
        assert_eq!(d.reason, "no network policy configured");
    }

    #[test]
    fn empty_allowlist_allows_any_host() {
        let np = list(&[]);
        let d = check_network_egress("evil.attacker.net", Some(&np));
        assert!(d.allowed);
        assert!(d.reason.contains("empty"));
    }

    #[test]
    fn matching_host_allowed_with_count_in_reason() {
        let np = list(&["api.openai.com", "*.anthropic.com"]);
        let d = check_network_egress("api.openai.com", Some(&np));
        assert!(d.allowed);
        assert!(d.reason.contains("2 pattern"));
    }

    #[test]
    fn non_matching_host_denied_with_count_in_reason() {
        let np = list(&["api.openai.com"]);
        let d = check_network_egress("evil.attacker.net", Some(&np));
        assert!(!d.allowed);
        assert!(d.reason.contains("not in network allowlist"));
        assert!(d.reason.contains("1 pattern"));
    }

    #[test]
    fn wildcard_subdomain_allowed() {
        let np = list(&["*.openai.com"]);
        let d = check_network_egress("chat.openai.com", Some(&np));
        assert!(d.allowed);
    }
}
