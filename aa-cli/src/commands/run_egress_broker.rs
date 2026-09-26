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
