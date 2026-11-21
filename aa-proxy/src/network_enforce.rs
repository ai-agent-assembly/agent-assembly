//! Network-egress policy enforcement against the `aa-gateway` PolicyService.
//!
//! AAASM-5851. Mirrors [`crate::mcp_enforce`]'s bridge shape for a second
//! `GovernanceAction` variant the gateway already fully supports
//! (`GovernanceAction::NetworkRequest`, evaluated by
//! `PolicyEngine::eval_network_stage`/`stage_network`): build a
//! `CheckActionRequest{context: NetworkCallContext}`, send it over the same
//! `Arc<Mutex<GatewayClient>>` the proxy already holds for MCP enforcement,
//! and block on the answer before the CONNECT/in-tunnel/plain-HTTP handler
//! dials upstream.
//!
//! ## Why this exists (ADR 0033 §2)
//!
//! Before this module, `aa-proxy`'s CONNECT-time and in-tunnel egress checks
//! consulted only `ProxyConfig::network_allowlist` — a `Vec<String>` sourced
//! exclusively from the local `AA_PROXY_NETWORK_ALLOWLIST` env var. No
//! `aasm run` / `aa-runtime::spawn_proxy` / `aasm proxy start` call site ever
//! set that var, so every managed launch ran with an empty local list, which
//! this proxy's own semantics read as "no allowlist configured" (open) —
//! silently different from the operator's actual gateway `policy.network`
//! configuration, which treats an *empty but present* allowlist as deny-all.
//! Two independently-evolving implementations of the same allowlist grammar
//! is exactly what ADR 0033 §3 forbids for network egress.
//!
//! ## Scope
//!
//! This module answers **only** the allowlist question. The SSRF guard
//! (`ssrf::blocked_ip_literal`) and the `denied_hosts` denylist stay local
//! and unconditional in [`crate::proxy::ProxyServer::connect_deny_reason`] —
//! they are proxy-local safety nets, not policy the gateway holds, and must
//! keep denying even when the gateway (correctly) has nothing to say about a
//! host it never sees because the SSRF/denylist check already refused it.
//!
//! ## Identity: the launch's grant binds this proxy to the registered agent
//!
//! A governed `aasm run` registers one agent with the gateway, has the gateway
//! mint a short-lived **launch grant** for it (`MintLaunchGrant`), and hands the
//! grant to this launch's dedicated proxy on an inherited pipe
//! ([`crate::credentials::LaunchGrant`]). Every check this module sends carries
//! the registered `{org, team, agent}` triple and the grant in
//! `CheckActionRequest.launch_grant`, so the gateway can bind the request to the
//! registered agent (`agent_identity_assurance == BOUND`) and apply that agent's
//! own Org, Team and Agent-scoped policy to it.
//!
//! The agent's registration `credential_token` never reaches this process. A
//! grant is accepted only by `CheckAction`/`BatchCheck`, expires, and dies when
//! the agent deregisters.
//!
//! The proxy **fails closed**: with a grant held, an `Allow` is honoured only when
//! the response says it was bound. A grant that expired or was revoked is refused
//! by the gateway, and an `Allow` that is not bound is refused here.
//!
//! Two properties must not be conflated:
//!
//! * **Proxy identity**: this proxy instance is bound to agent X by a
//!   gateway-validated grant. Delivered, for a launch started by `aasm run`.
//! * **Connection origin**: the process opening a connection to this proxy is the
//!   governed agent. **Not delivered, and not claimed.** The proxy reads no
//!   `Proxy-Authorization`, does no peer-PID lookup and listens on a plain
//!   loopback port, so any process of the same user that can reach the port is
//!   attributed to the launch. A same-user process that obtains the grant itself
//!   can also call `CheckAction` as the agent until the grant expires.
//!
//! A proxy with no grant (standalone `aasm proxy start`) sends a blank
//! `agent_id` and no grant, which the gateway records as unattributed; it never
//! invents a label.

use std::sync::Arc;

use crate::credentials::LaunchGrant;
use crate::mcp_enforce::{claimed_agent_and_grant, response_is_bound};
use aa_proto::assembly::common::v1::{ActionType, Decision};
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, CheckActionResponse, NetworkCallContext,
};
use aa_runtime::gateway_client::GatewayClient;
use tokio::sync::Mutex;

/// Top-level decision the proxy data path branches on after a gateway
/// `CheckAction` response for a network-egress request.
///
/// Unlike [`crate::mcp_enforce::McpDecision`], there is no third `Redact`
/// bucket: at CONNECT / in-tunnel-header / plain-HTTP-header time there is no
/// request body yet to apply redaction instructions to — only a destination.
/// A gateway `Redact` decision therefore has nothing to redact and is treated
/// as [`NetworkDecision::Deny`] (see [`decision_from_response`]), a
/// deliberate choice, not the MCP module's allow-adjacent bucketing inherited
/// by accident.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkDecision {
    /// Permit the CONNECT/in-tunnel-host/plain-HTTP destination.
    Allow,
    /// Refuse it. `reason` is copied from the gateway response (or
    /// synthesised for a decision code the proxy cannot act on) so it can be
    /// surfaced in the deny log line and audit record.
    Deny { reason: String },
}

/// Build a `CheckActionRequest` carrying a `NetworkCallContext` for `host`.
///
/// `port`/`protocol` are informational only: `network_request_url_allowed`
/// (`aa-gateway/src/engine/decision.rs`) strips the port before matching, so
/// they do not affect the allow/deny outcome — callers should still pass the
/// real values they have (CONNECT's authority port, or a sane default) so the
/// gateway's audit trail records an accurate destination.
///
/// `grant` is the launch's grant; `None` claims no identity (blank `agent_id`, no grant).
pub fn build_network_check_action_request(
    host: &str,
    port: u16,
    protocol: &str,
    grant: Option<&LaunchGrant>,
) -> CheckActionRequest {
    let (agent_id, launch_grant) = claimed_agent_and_grant(grant);
    CheckActionRequest {
        agent_id: Some(agent_id),
        credential_token: String::new(),
        trace_id: String::new(),
        span_id: String::new(),
        action_type: ActionType::NetworkCall as i32,
        context: Some(ActionContext {
            action: Some(Action::NetworkCall(NetworkCallContext {
                host: host.to_string(),
                port: i32::from(port),
                protocol: protocol.to_string(),
                in_allowlist: false,
            })),
        }),
        caller_agent_id: None,
        launch_grant,
    }
}

/// Convert a `CheckActionResponse` into a [`NetworkDecision`].
///
/// `Pending`, `Unspecified`, an unrecognised code, and `Redact` (see the
/// module doc) all downgrade to `Deny` — the proxy has no way to act on any
/// of them at a pre-dial network-egress checkpoint.
///
/// `require_bound` is true for a governed launch: an `Allow` the gateway did not
/// bind to the registered agent is refused (see the module doc).
pub fn decision_from_response(response: &CheckActionResponse, require_bound: bool) -> NetworkDecision {
    match Decision::try_from(response.decision) {
        Ok(Decision::Allow) if require_bound && !response_is_bound(response) => NetworkDecision::Deny {
            reason: crate::mcp_enforce::unbound_allow_reason(response),
        },
        Ok(Decision::Allow) => NetworkDecision::Allow,
        Ok(Decision::Deny) => NetworkDecision::Deny {
            reason: response.reason.clone(),
        },
        Ok(Decision::Redact) => NetworkDecision::Deny {
            reason: "policy returned REDACT for a network-egress decision, which has no request body \
                      to redact at this checkpoint — denying (fail-closed)"
                .to_string(),
        },
        Ok(Decision::Pending) => NetworkDecision::Deny {
            reason: format!(
                "policy returned PENDING (approval queue {:?}) — proxy cannot block on human approval",
                response.approval_id,
            ),
        },
        Ok(Decision::Unspecified) | Err(_) => NetworkDecision::Deny {
            reason: format!("unrecognised policy decision code {}", response.decision),
        },
    }
}

/// End-to-end evaluation: build a `CheckActionRequest` for `host`/`port`/
/// `protocol`, forward it over the supplied gateway client, and surface the
/// resulting [`NetworkDecision`].
///
/// Shares the `Arc<Mutex<GatewayClient>>` locking discipline documented on
/// [`crate::mcp_enforce::evaluate_mcp_call`] — concurrent connection tasks
/// queue briefly on the same tonic client rather than racing it. This module
/// adds no proxy-side caching: every call is a fresh RPC, relying entirely on
/// the gateway's own `policy_epoch`-keyed decision cache (60s TTL on the
/// cascade path) for hot-reload correctness, which needs no cooperation from
/// the proxy to stay correct.
///
/// AAASM-5851: bounded by [`CHECK_ACTION_TIMEOUT`], unlike
/// [`crate::mcp_enforce::evaluate_mcp_call`], which has none. A CONNECT is on
/// the latency-critical path of every governed connection an agent opens —
/// a gateway that stopped responding (not merely refused the connection)
/// would otherwise hang the tunnel open indefinitely rather than fail
/// closed, which is a distinct failure mode from an RPC *error* and the
/// caller's fail-open/fail-closed branch never sees it without this timeout.
pub async fn evaluate_network_call(
    gateway: &Arc<Mutex<GatewayClient>>,
    host: &str,
    port: u16,
    protocol: &str,
    grant: Option<&LaunchGrant>,
) -> anyhow::Result<NetworkDecision> {
    let request = build_network_check_action_request(host, port, protocol, grant);
    let response = {
        let mut client = gateway.lock().await;
        tokio::time::timeout(CHECK_ACTION_TIMEOUT, client.check_action(request))
            .await
            .map_err(|_| anyhow::anyhow!("PolicyService.CheckAction timed out after {CHECK_ACTION_TIMEOUT:?}"))?
            .map_err(|e| anyhow::anyhow!("PolicyService.CheckAction failed: {e}"))?
    };
    Ok(decision_from_response(&response, grant.is_some()))
}

/// Bound on a single network-egress `CheckAction` RPC. Chosen to be well
/// under what an interactive CONNECT can tolerate while still generous for a
/// gateway under load — not tuned against a measured p99, so treat this as a
/// conservative starting point, not a calibrated SLO.
const CHECK_ACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;
    use aa_proto::assembly::common::v1::AgentIdentityAssurance;

    #[test]
    fn build_request_populates_network_call_context_fields() {
        let req = build_network_check_action_request("api.anthropic.com", 443, "https", None);
        assert_eq!(req.action_type, ActionType::NetworkCall as i32);

        let action = req.context.expect("context").action.expect("action");
        let nc = match action {
            Action::NetworkCall(nc) => nc,
            other => panic!("expected NetworkCall action, got {other:?}"),
        };
        assert_eq!(nc.host, "api.anthropic.com");
        assert_eq!(nc.port, 443);
        assert_eq!(nc.protocol, "https");
    }

    fn response_with(decision: Decision, reason: &str) -> CheckActionResponse {
        CheckActionResponse {
            decision: decision as i32,
            reason: reason.into(),
            ..Default::default()
        }
    }

    #[test]
    fn decision_allow_maps_to_network_allow() {
        let resp = response_with(Decision::Allow, "ok");
        assert_eq!(decision_from_response(&resp, false), NetworkDecision::Allow);
    }

    #[test]
    fn decision_deny_maps_to_network_deny_with_reason() {
        let resp = response_with(Decision::Deny, "host not in network allowlist");
        match decision_from_response(&resp, false) {
            NetworkDecision::Deny { reason } => assert_eq!(reason, "host not in network allowlist"),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decision_redact_downgrades_to_deny_not_allow() {
        // A network-egress checkpoint has no request body to apply redact
        // instructions to — bucketing Redact with Allow (as mcp_enforce does)
        // would silently forward a destination the gateway did not clear.
        let resp = CheckActionResponse {
            decision: Decision::Redact as i32,
            ..Default::default()
        };
        assert!(matches!(
            decision_from_response(&resp, false),
            NetworkDecision::Deny { .. }
        ));
    }

    #[test]
    fn decision_pending_downgrades_to_deny() {
        let mut resp = response_with(Decision::Pending, "");
        resp.approval_id = "queue-9".into();
        match decision_from_response(&resp, false) {
            NetworkDecision::Deny { reason } => assert!(reason.contains("queue-9") || reason.contains("PENDING")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decision_unspecified_downgrades_to_deny() {
        let resp = response_with(Decision::Unspecified, "");
        assert!(matches!(
            decision_from_response(&resp, false),
            NetworkDecision::Deny { .. }
        ));
    }

    #[test]
    fn unknown_decision_code_downgrades_to_deny() {
        let resp = CheckActionResponse {
            decision: 9999,
            ..Default::default()
        };
        match decision_from_response(&resp, false) {
            NetworkDecision::Deny { reason } => assert!(reason.contains("9999")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    fn grant() -> LaunchGrant {
        LaunchGrant::new(
            String::new(),
            "team-a".into(),
            "did:key:agent-a".into(),
            "grant-a-synthetic".into(),
        )
    }

    #[test]
    fn a_governed_request_carries_the_triple_and_grant_and_never_a_credential_token() {
        let g = grant();
        let req = build_network_check_action_request("api.anthropic.com", 443, "https", Some(&g));
        let id = req.agent_id.expect("agent_id");
        assert_eq!(
            (id.org_id.as_str(), id.team_id.as_str(), id.agent_id.as_str()),
            ("", "team-a", "did:key:agent-a")
        );
        assert_eq!(req.launch_grant, "grant-a-synthetic");
        assert!(req.credential_token.is_empty());
    }

    #[test]
    fn a_standalone_request_claims_no_identity() {
        let req = build_network_check_action_request("api.anthropic.com", 443, "https", None);
        let id = req.agent_id.expect("the field is present but blank");
        assert_eq!(
            (id.org_id.as_str(), id.team_id.as_str(), id.agent_id.as_str()),
            ("", "", ""),
            "no label and no synthetic name such as `aa-proxy`"
        );
        assert!(req.credential_token.is_empty() && req.launch_grant.is_empty());
    }

    fn allow_with(a: AgentIdentityAssurance) -> CheckActionResponse {
        CheckActionResponse {
            decision: Decision::Allow as i32,
            agent_identity_assurance: a as i32,
            ..Default::default()
        }
    }

    #[test]
    fn a_governed_launch_honours_an_allow_only_when_the_gateway_bound_it() {
        assert_eq!(
            decision_from_response(&allow_with(AgentIdentityAssurance::Bound), true),
            NetworkDecision::Allow
        );
        for a in [AgentIdentityAssurance::Asserted, AgentIdentityAssurance::Unattributed] {
            assert!(
                matches!(
                    decision_from_response(&allow_with(a), true),
                    NetworkDecision::Deny { .. }
                ),
                "{a:?} must not be honoured for a governed launch"
            );
        }
        assert_eq!(
            decision_from_response(&allow_with(AgentIdentityAssurance::Unattributed), false),
            NetworkDecision::Allow,
            "a standalone proxy needs no bound answer"
        );
    }
}
