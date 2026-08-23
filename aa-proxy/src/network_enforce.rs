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
//! ## Scope caveat — Global-tier evaluation under a synthetic identity
//!
//! Like [`crate::mcp_enforce`], this module has no real agent identity to
//! attach to the request (the proxy is agent-agnostic — see
//! [`crate::mcp_enforce::PROXY_AGENT_ID`]), so a cascade-scoped gateway
//! (`aa-gateway/src/engine/mod.rs::collect_cascade_with_lineage`) evaluates
//! this request under a synthetic, unregistered identity, which reaches only
//! **Global**-tier network policy — Org/Team/Agent-scoped network rules are
//! not consulted. A single-file `AA_POLICY_PATH` deployment (the common
//! case, routed through uncached `evaluate_primary`) is unaffected by this
//! caveat: its `network:` section applies regardless of identity. Threading
//! a real, credentialed agent identity through to the proxy is tracked
//! separately (a `credential_token` reaching `aa-proxy` would let it act as
//! the agent it mediates — a materially new trust boundary, out of scope
//! here).

use std::sync::Arc;

use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, CheckActionResponse, NetworkCallContext,
};
use aa_runtime::gateway_client::GatewayClient;
use tokio::sync::Mutex;

use crate::mcp_enforce::PROXY_AGENT_ID;

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
pub fn build_network_check_action_request(host: &str, port: u16, protocol: &str) -> CheckActionRequest {
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: String::new(),
            agent_id: PROXY_AGENT_ID.into(),
        }),
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
    }
}

/// Convert a `CheckActionResponse` into a [`NetworkDecision`].
///
/// `Pending`, `Unspecified`, an unrecognised code, and `Redact` (see the
/// module doc) all downgrade to `Deny` — the proxy has no way to act on any
/// of them at a pre-dial network-egress checkpoint.
pub fn decision_from_response(response: &CheckActionResponse) -> NetworkDecision {
    match Decision::try_from(response.decision) {
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
) -> anyhow::Result<NetworkDecision> {
    let request = build_network_check_action_request(host, port, protocol);
    let response = {
        let mut client = gateway.lock().await;
        tokio::time::timeout(CHECK_ACTION_TIMEOUT, client.check_action(request))
            .await
            .map_err(|_| anyhow::anyhow!("PolicyService.CheckAction timed out after {CHECK_ACTION_TIMEOUT:?}"))?
            .map_err(|e| anyhow::anyhow!("PolicyService.CheckAction failed: {e}"))?
    };
    Ok(decision_from_response(&response))
}

/// Bound on a single network-egress `CheckAction` RPC. Chosen to be well
/// under what an interactive CONNECT can tolerate while still generous for a
/// gateway under load — not tuned against a measured p99, so treat this as a
/// conservative starting point, not a calibrated SLO.
const CHECK_ACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_request_populates_network_call_context_fields() {
        let req = build_network_check_action_request("api.anthropic.com", 443, "https");
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
        assert_eq!(decision_from_response(&resp), NetworkDecision::Allow);
    }

    #[test]
    fn decision_deny_maps_to_network_deny_with_reason() {
        let resp = response_with(Decision::Deny, "host not in network allowlist");
        match decision_from_response(&resp) {
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
        assert!(matches!(decision_from_response(&resp), NetworkDecision::Deny { .. }));
    }

    #[test]
    fn decision_pending_downgrades_to_deny() {
        let mut resp = response_with(Decision::Pending, "");
        resp.approval_id = "queue-9".into();
        match decision_from_response(&resp) {
            NetworkDecision::Deny { reason } => assert!(reason.contains("queue-9") || reason.contains("PENDING")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decision_unspecified_downgrades_to_deny() {
        let resp = response_with(Decision::Unspecified, "");
        assert!(matches!(decision_from_response(&resp), NetworkDecision::Deny { .. }));
    }

    #[test]
    fn unknown_decision_code_downgrades_to_deny() {
        let resp = CheckActionResponse {
            decision: 9999,
            ..Default::default()
        };
        match decision_from_response(&resp) {
            NetworkDecision::Deny { reason } => assert!(reason.contains("9999")),
            other => panic!("expected Deny, got {other:?}"),
        }
    }
}
