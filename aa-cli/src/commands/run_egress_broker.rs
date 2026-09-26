//! Build this launch's [`aa_isolation::EgressBrokerReport`] from the facts
//! `aasm run` already holds (AAASM-6163).
//!
//! This is the one place an `aa-proxy` fact becomes a statement in
//! `aa-isolation`'s egress-contract vocabulary — pure and unit-testable, no
//! I/O, sibling of [`super::run_no_proxy_guard`] and [`super::run_env_sanitize`].
//! Every mapping below is traceable to a real `aa-proxy` mechanism; see each
//! branch's own comment.

use aa_isolation::{EgressBrokerReport, FailurePosture, MediationDepth, MediationDepthScope, SupportLevel};

/// The built-in LLM hosts `aa-proxy` MitMs under `llm_only` even with no
/// operator `mitm_hosts` entry. Kept in sync by hand with
/// `aa-proxy/src/proxy/mod.rs`'s own `should_mitm` built-in set — this module
/// does not depend on `aa-proxy`, so it cannot import that list directly (see
/// this ticket's publish-graph note: `aa-proxy` publishes, `aa-isolation`
/// does not, and this adapter is the one place that boundary is crossed).
const BUILT_IN_LLM_HOSTS: &[&str] = &[
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
];

/// Build the [`EgressBrokerReport`] for this launch from facts it already
/// holds.
///
/// * `endpoint` — [`super::run::NetworkPlan::endpoint`]. `None` means no
///   dedicated proxy is bound for this launch — `Unavailable`, never "use
///   whatever the shell had" (AAASM-5323's own rule, applied here).
/// * `no_proxy` — the launch explicitly opted out of interception
///   (`--no-proxy`, gated by [`super::run_no_proxy_guard`]).
/// * `llm_only`/`mitm_hosts`/`network_fail_open` — the same
///   `aa_proxy::config::ProxyConfig` facts the spawned proxy itself reads
///   from `AA_PROXY_LLM_ONLY`/`AA_PROXY_MITM_HOSTS`/`AA_PROXY_NETWORK_FAIL_OPEN`.
/// * `gateway_configured` — whether a gateway endpoint is configured for the
///   spawned proxy (`AA_PROXY_GATEWAY_ENDPOINT`/`ProxyGuardOptions::gateway_endpoint`).
///   Does not change *whether* restricted ranges are refused (that is
///   unconditional — see the `with_range_handling` call below) but is
///   reflected in the reported detail, since the mechanism refusing them
///   differs (the gateway's own `policy.network` stage vs. the proxy's local
///   SSRF guard in standalone mode).
pub fn report_for_launch(
    endpoint: Option<&str>,
    no_proxy: bool,
    llm_only: bool,
    mitm_hosts: &[String],
    network_fail_open: bool,
    gateway_configured: bool,
) -> EgressBrokerReport {
    if endpoint.is_none() {
        return EgressBrokerReport::unavailable("no governed egress endpoint is bound for this launch");
    }
    if no_proxy {
        return EgressBrokerReport::unavailable("the launch explicitly opted out of interception (--no-proxy)");
    }

    let failure_posture = if network_fail_open {
        FailurePosture::FailOpen
    } else {
        FailurePosture::FailClosed
    };

    let (depth, scope) = if llm_only {
        let mut patterns: Vec<String> = BUILT_IN_LLM_HOSTS.iter().map(|h| h.to_string()).collect();
        patterns.extend(mitm_hosts.iter().cloned());
        (
            MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string(), "mcp".to_string()],
            },
            MediationDepthScope::NamedDestinationsOnly { patterns },
        )
    } else {
        (
            MediationDepth::PayloadAware {
                protocols: vec!["http/1.1".to_string(), "mcp".to_string()],
            },
            MediationDepthScope::EveryDestination,
        )
    };

    let range_handling_detail = if gateway_configured {
        "the CONNECT-time SSRF literal guard runs unconditionally, ahead of and independent of the \
         gateway's own policy.network stage"
            .to_string()
    } else {
        "the CONNECT-time SSRF literal guard runs unconditionally in standalone mode".to_string()
    };

    EgressBrokerReport::new(depth, scope, failure_posture)
        // AAASM-3130/AAASM-4859: `connect_deny_reason`'s SSRF literal guard
        // refuses a blocked-range CONNECT target regardless of the allowlist
        // or gateway mode — unconditional, so this is never derived from
        // `gateway_configured`.
        .with_range_handling(true, range_handling_detail)
        // No connection/byte/rate accounting exists in `aa-proxy` today —
        // truthful `Unsupported`, not a guess.
        .with_ceiling_support(SupportLevel::Unsupported {
            reason: "this deployment performs no per-run connection, byte or rate accounting for egress".to_string(),
        })
}

#[cfg(test)]
mod tests {
    use aa_isolation::BrokerAvailability;

    use super::*;

    #[test]
    fn no_bound_endpoint_is_unavailable() {
        let report = report_for_launch(None, false, true, &[], false, false);
        assert!(matches!(report.availability(), BrokerAvailability::Unavailable { .. }));
    }

    #[test]
    fn no_proxy_is_unavailable_even_with_a_bound_endpoint() {
        // Control: the same endpoint without `--no-proxy` is available.
        let opted_out = report_for_launch(Some("http://127.0.0.1:9"), true, true, &[], false, false);
        assert!(matches!(
            opted_out.availability(),
            BrokerAvailability::Unavailable { .. }
        ));

        let control = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], false, false);
        assert_eq!(control.availability(), &BrokerAvailability::Available);
    }

    #[test]
    fn llm_only_scopes_payload_aware_depth_to_named_destinations() {
        let report = report_for_launch(
            Some("http://127.0.0.1:9"),
            false,
            true,
            &["custom.example.com".to_string()],
            false,
            false,
        );
        assert!(report.depth().is_payload_aware());
        match report.depth_scope() {
            MediationDepthScope::NamedDestinationsOnly { patterns } => {
                assert!(patterns.iter().any(|p| p == "api.openai.com"));
                assert!(patterns.iter().any(|p| p == "custom.example.com"));
            }
            MediationDepthScope::EveryDestination => panic!("llm_only must scope to named destinations"),
        }
    }

    #[test]
    fn llm_only_false_reaches_every_destination() {
        let report = report_for_launch(Some("http://127.0.0.1:9"), false, false, &[], false, false);
        assert_eq!(report.depth_scope(), &MediationDepthScope::EveryDestination);
    }

    #[test]
    fn network_fail_open_maps_to_fail_open_posture() {
        let open = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], true, false);
        assert_eq!(open.failure_posture(), FailurePosture::FailOpen);

        // Control: the same launch without the env override fails closed.
        let closed = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], false, false);
        assert_eq!(closed.failure_posture(), FailurePosture::FailClosed);
    }

    #[test]
    fn ceiling_support_is_always_unsupported_today_and_says_why() {
        let report = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], false, false);
        match report.ceiling_support() {
            SupportLevel::Unsupported { reason } => assert!(!reason.is_empty()),
            SupportLevel::Full | SupportLevel::Partial { .. } => panic!("no egress accounting exists today"),
        }
    }

    #[test]
    fn restricted_range_refusal_is_unconditional_in_both_gateway_and_standalone_mode() {
        let gateway = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], false, true);
        let standalone = report_for_launch(Some("http://127.0.0.1:9"), false, true, &[], false, false);
        assert!(gateway.refuses_restricted_ranges());
        assert!(standalone.refuses_restricted_ranges());
        // The detail differs by mode even though the boolean does not.
        assert_ne!(gateway.range_handling_detail(), standalone.range_handling_detail());
    }
}
