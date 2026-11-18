//! MCP `tools/call` policy enforcement against the `aa-gateway` PolicyService.
//!
//! This module is the bridge between the proxy's MCP detection primitive
//! (`intercept::mcp::parse_mcp_request`) and the gateway's existing
//! `PolicyService.CheckAction` gRPC RPC.
//!
//! Flow:
//!
//! ```text
//!   client TLS  ──→  parse_mcp_request(body)  ──→  Some(McpToolCall)
//!                                                       │
//!                                                       ▼
//!                                       build_check_action_request(...)
//!                                                       │
//!                                                       ▼
//!                                       GatewayClient::check_action
//!                                                       │
//!                                                       ▼
//!                                       decision_from_response(...)
//!                                                       │
//!                                                       ▼
//!                                       McpDecision::{Allow,Deny,Redact}
//! ```
//!
//! See AAASM-1930.

use std::sync::Arc;

use crate::credentials::LaunchGrant;
use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, AgentIdentityAssurance, Decision};
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, CheckActionResponse, RedactInstructions,
    ToolCallContext, ToolResultContext,
};
use aa_runtime::gateway_client::GatewayClient;
use tokio::sync::Mutex;

use crate::intercept::mcp::McpToolCall;

/// Tool-source label written into `ToolCallContext.tool_source` for every
/// MCP call evaluated by this module. Matches the convention already used
/// in `aa-gateway/tests/edge_langgraph_test.rs` fixtures.
pub const MCP_TOOL_SOURCE: &str = "mcp";

/// The `agent_id` and `launch_grant` a gateway check carries (AAASM-6261).
///
/// A governed launch sends the agent it registered, triple and launch grant, so
/// the gateway can bind the check to it. No grant sends a blank `agent_id` and no
/// grant: the gateway records that as unattributed rather than the proxy
/// inventing a name for itself. One definition for every check the proxy sends
/// (network, MCP call, MCP result), so they cannot disagree about who the launch
/// is. The registration `credential_token` is never sent; the grant travels in
/// its own field.
pub(crate) fn claimed_agent_and_grant(grant: Option<&LaunchGrant>) -> (ProtoAgentId, String) {
    match grant {
        Some(grant) => (grant.proto_agent_id(), grant.grant()),
        None => (ProtoAgentId::default(), String::new()),
    }
}

/// Whether the gateway answered that this check was bound to the registered agent.
///
/// `Bound` means the gateway matched the presented grant to the agent it minted
/// it for: proxy identity. It does not prove which process opened the connection.
pub(crate) fn response_is_bound(response: &CheckActionResponse) -> bool {
    response.agent_identity_assurance == AgentIdentityAssurance::Bound as i32
}

/// Why an `Allow` that the gateway did not bind to the launch's agent is refused.
pub(crate) fn unbound_allow_reason(response: &CheckActionResponse) -> String {
    let assurance = AgentIdentityAssurance::try_from(response.agent_identity_assurance)
        .map(|a| a.as_str_name())
        .unwrap_or("UNKNOWN");
    format!(
        "the gateway did not bind this governed launch's grant (assurance {assurance}) — \
         refusing (fail-closed)"
    )
}

/// Top-level decision the proxy data path branches on after a gateway
/// `CheckAction` response. Maps the proto `Decision` enum onto the
/// proxy's wire-level enforcement choices.
#[derive(Debug, Clone, PartialEq)]
pub enum McpDecision {
    /// Forward the original `tools/call` envelope to the upstream MCP server.
    Allow,
    /// Refuse the call: the proxy writes a JSON-RPC 2.0 error envelope back
    /// to the client and never dials upstream. `reason` is copied from the
    /// gateway response so the client sees the policy rule that fired.
    Deny { reason: String },
    /// The gateway requires the payload to be redacted before it leaves.
    ///
    /// The proxy cannot apply this: it does not replay `instructions` and its
    /// scanner holds built-in patterns only (no gateway `sensitive_patterns` /
    /// locale packs). The data path therefore ALWAYS denies a `Redact` call
    /// fail-closed (AAASM-6353), whatever its own scan finds, mirroring
    /// `network_enforce`. `instructions` is advisory and currently unused.
    /// The response direction is evaluated by the gateway separately
    /// (AAASM-6355) and withholds on `Redact` for the same reason.
    Redact { instructions: RedactInstructions },
}

/// Build a `CheckActionRequest` from a parsed MCP call ready to send over
/// the `PolicyService.CheckAction` gRPC RPC.
///
/// * `tool_name` / `arguments` come from [`McpToolCall`].
/// * `target_url` is the upstream MCP server URL — empty string when the
///   proxy has no host context to attach.
/// * `trace_id` / `span_id` are propagated for distributed-tracing
///   correlation; the proxy may pass empty strings when no parent trace
///   is available.
pub fn build_check_action_request(
    call: &McpToolCall,
    target_url: &str,
    trace_id: &str,
    span_id: &str,
    grant: Option<&LaunchGrant>,
) -> CheckActionRequest {
    let (agent_id, launch_grant) = claimed_agent_and_grant(grant);
    // Serialise arguments back to JSON bytes for `ToolCallContext.args_json`.
    // Failure here is "synthesise an empty payload" rather than propagate —
    // an arguments value that round-trips serde once cannot round-trip
    // serde twice without a programming bug, and an empty args_json still
    // lets the policy engine match against `tool_name` alone.
    let args_json = serde_json::to_vec(&call.arguments).unwrap_or_default();
    CheckActionRequest {
        agent_id: Some(agent_id),
        credential_token: String::new(),
        trace_id: trace_id.into(),
        span_id: span_id.into(),
        action_type: ActionType::ToolCall as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolCall(ToolCallContext {
                tool_name: call.tool_name.clone(),
                tool_source: MCP_TOOL_SOURCE.into(),
                args_json,
                target_url: target_url.into(),
            })),
        }),
        caller_agent_id: None,
        launch_grant,
    }
}

/// Build the response-direction `CheckActionRequest` for an MCP tool result
/// (AAASM-6355): the gateway's `ToolResult` evaluation applies its own policy
/// data (`sensitive_patterns`, locale packs, `tool_result.*` predicates) to the
/// body, which the proxy's built-in-only scanner cannot do.
///
/// The request carries the launch's grant like the request side, so a
/// `SecretAlert` the gateway raises for a response is attributed to the agent
/// whose traffic it was; a launch with no grant stays unattributed.
pub fn build_tool_result_request(
    call: &McpToolCall,
    result_body: &[u8],
    source_url: &str,
    trace_id: &str,
    span_id: &str,
    grant: Option<&LaunchGrant>,
) -> CheckActionRequest {
    let (agent_id, launch_grant) = claimed_agent_and_grant(grant);
    CheckActionRequest {
        agent_id: Some(agent_id),
        credential_token: String::new(),
        trace_id: trace_id.into(),
        span_id: span_id.into(),
        action_type: ActionType::ToolResult as i32,
        context: Some(ActionContext {
            action: Some(Action::ToolResult(ToolResultContext {
                tool_name: call.tool_name.clone(),
                tool_source: MCP_TOOL_SOURCE.into(),
                result_json: result_body.to_vec(),
                source_url: source_url.into(),
            })),
        }),
        caller_agent_id: None,
        launch_grant,
    }
}

/// Ask the gateway to evaluate an upstream MCP response body. Same transport
/// and error shape as [`evaluate_mcp_call`].
pub async fn evaluate_mcp_result(
    gateway: &Arc<Mutex<GatewayClient>>,
    call: &McpToolCall,
    result_body: &[u8],
    source_url: &str,
    trace_id: &str,
    span_id: &str,
    grant: Option<&LaunchGrant>,
) -> anyhow::Result<McpDecision> {
    let request = build_tool_result_request(call, result_body, source_url, trace_id, span_id, grant);
    let response = {
        let mut client = gateway.lock().await;
        client
            .check_action(request)
            .await
            .map_err(|e| anyhow::anyhow!("PolicyService.CheckAction (tool result) failed: {e}"))?
    };
    Ok(decision_from_response(&response, grant.is_some()))
}

/// Convert a `CheckActionResponse` into an [`McpDecision`].
///
/// `Decision::Pending` and `Decision::Unspecified` map to `Deny` with a
/// reason explaining the conservative downgrade — the proxy cannot block
/// on a human approval queue inside the MitM tunnel, so any non-deterministic
/// verdict is treated as a refusal at this layer.
///
/// `require_bound` is true for a governed launch: an `Allow` the gateway did not
/// bind to the registered agent is refused (see [`crate::network_enforce`]).
pub fn decision_from_response(response: &CheckActionResponse, require_bound: bool) -> McpDecision {
    match Decision::try_from(response.decision) {
        Ok(Decision::Allow) if require_bound && !response_is_bound(response) => McpDecision::Deny {
            reason: unbound_allow_reason(response),
        },
        Ok(Decision::Allow) => McpDecision::Allow,
        Ok(Decision::Deny) => McpDecision::Deny {
            reason: response.reason.clone(),
        },
        Ok(Decision::Redact) => McpDecision::Redact {
            instructions: response.redact.clone().unwrap_or_default(),
        },
        Ok(Decision::Pending) => McpDecision::Deny {
            reason: format!(
                "policy returned PENDING (approval queue {:?}) — proxy cannot block on human approval",
                response.approval_id,
            ),
        },
        Ok(Decision::Unspecified) | Err(_) => McpDecision::Deny {
            reason: format!("unrecognised policy decision code {}", response.decision),
        },
    }
}

/// End-to-end evaluation: build a `CheckActionRequest` from the parsed MCP
/// call, forward it over the supplied gateway client, and surface the
/// resulting [`McpDecision`].
///
/// The proxy's data path holds the gateway client inside an
/// `Arc<Mutex<GatewayClient>>` (the tonic-generated client's `check_action`
/// is `&mut self`-keyed). This helper takes the same shape and serialises
/// the RPC behind the mutex — concurrent connection tasks queue up briefly
/// rather than sharing a connection lock-free.
///
/// Wraps the gateway's `tonic::Status` in an `anyhow::Error` (with the
/// status code preserved in the message) so callers can `?`-propagate
/// alongside other proxy data-path errors without taking a direct tonic
/// dependency.
///
/// AAASM-6364: bounded by one [`MCP_CALL_CHECK_TIMEOUT`] deadline covering the
/// shared mutex wait and the RPC. Without it a
/// gateway that stopped answering (not one that refused) would hold the lock
/// and stall every `tools/call` on every connection behind it, indefinitely,
/// before the caller's fail-open/fail-closed branch could ever run. A stalled
/// RPC is an `Err` like any RPC failure; a lock wait that expires is
/// [`GatewayContended`]. Both are `Err`s that `mcp_fail_open` governs.
pub async fn evaluate_mcp_call(
    gateway: &Arc<Mutex<GatewayClient>>,
    call: &McpToolCall,
    target_url: &str,
    trace_id: &str,
    span_id: &str,
    grant: Option<&LaunchGrant>,
) -> anyhow::Result<McpDecision> {
    evaluate_mcp_call_within(
        MCP_CALL_CHECK_TIMEOUT,
        gateway,
        call,
        target_url,
        trace_id,
        span_id,
        grant,
    )
    .await
}

/// [`evaluate_mcp_call`] with the bound as a parameter, so a test can exercise
/// the expiry path without waiting out the production value.
async fn evaluate_mcp_call_within(
    bound: std::time::Duration,
    gateway: &Arc<Mutex<GatewayClient>>,
    call: &McpToolCall,
    target_url: &str,
    trace_id: &str,
    span_id: &str,
    grant: Option<&LaunchGrant>,
) -> anyhow::Result<McpDecision> {
    let request = build_check_action_request(call, target_url, trace_id, span_id, grant);
    // One deadline for the whole evaluation (lock wait plus RPC), so the worst
    // case is `bound`, not twice it, and there is no window at the hand-off
    // between the two stages. The lock wait still fails as `GatewayContended`
    // so the caller can say the call was never sent to the gateway.
    let deadline = tokio::time::Instant::now() + bound;
    let mut client = tokio::time::timeout_at(deadline, gateway.lock())
        .await
        .map_err(|_| anyhow::Error::new(GatewayContended))?;
    let response = tokio::time::timeout_at(deadline, client.check_action(request))
        .await
        .map_err(|_| anyhow::anyhow!("PolicyService.CheckAction timed out after {bound:?}"))?
        .map_err(|e| anyhow::anyhow!("PolicyService.CheckAction failed: {e}"))?;
    drop(client);
    Ok(decision_from_response(&response, grant.is_some()))
}

/// The shared gateway client stayed locked past the bound: this call never
/// reached the gateway. It is an evaluation that did not complete, so it
/// follows `mcp_fail_open` exactly like a stalled RPC; the type exists so the
/// caller can say which of the two happened.
#[derive(Debug)]
pub struct GatewayContended;

impl std::fmt::Display for GatewayContended {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("gateway client busy: evaluation was not sent to the gateway within the bound")
    }
}

impl std::error::Error for GatewayContended {}

/// Client-visible reason for a request-side evaluation that did not complete
/// and was denied (fail-closed). Fixed strings only: the error text can carry
/// gateway or transport detail that must not reach the agent.
pub fn fail_closed_reason(error: &anyhow::Error) -> &'static str {
    if error.is::<GatewayContended>() {
        "MCP enforcement unavailable: gateway client busy, call was not evaluated within 10s (fail-closed)"
    } else {
        "MCP enforcement unavailable: gateway did not return a decision within 10s or failed (fail-closed)"
    }
}

/// Bound on one request-side `tools/call` evaluation (lock wait and RPC share
/// it). Same order as the response-side bound in the proxy
/// (`MCP_GATEWAY_RPC_TIMEOUT`); like it, a conservative starting point rather
/// than a value tuned against a measured p99. The deny reasons in
/// [`fail_closed_reason`] spell this value out as "10s".
const MCP_CALL_CHECK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_call() -> McpToolCall {
        McpToolCall {
            tool_name: "read_file".into(),
            arguments: json!({ "path": "/etc/passwd" }),
        }
    }

    #[test]
    fn build_request_populates_tool_call_context_fields() {
        let call = sample_call();
        let req = build_check_action_request(&call, "https://mcp.example.com/tools", "trace-abc", "span-1", None);

        assert_eq!(req.action_type, ActionType::ToolCall as i32);
        assert_eq!(req.trace_id, "trace-abc");
        assert_eq!(req.span_id, "span-1");

        let action = req.context.expect("context").action.expect("action");
        let tool = match action {
            Action::ToolCall(t) => t,
            other => panic!("expected ToolCall action, got {other:?}"),
        };
        assert_eq!(tool.tool_name, "read_file");
        assert_eq!(tool.tool_source, MCP_TOOL_SOURCE);
        assert_eq!(tool.target_url, "https://mcp.example.com/tools");
        // args_json round-trips back to the original Value.
        let parsed: serde_json::Value = serde_json::from_slice(&tool.args_json).expect("args_json must be valid JSON");
        assert_eq!(parsed, json!({ "path": "/etc/passwd" }));
    }

    /// An in-process `PolicyService` standing in for the gateway, so the
    /// request-side bound is exercised against a real gRPC peer rather than an
    /// unreachable port.
    mod stub {
        use std::pin::Pin;

        use aa_proto::assembly::common::v1::Decision;
        use aa_proto::assembly::policy::v1::policy_service_server::{PolicyService, PolicyServiceServer};
        use aa_proto::assembly::policy::v1::{
            BatchCheckRequest, BatchCheckResponse, CheckActionRequest, CheckActionResponse, OpControlMessage,
            OpControlSubscribeRequest,
        };
        use tonic::codegen::tokio_stream::wrappers::TcpListenerStream;
        use tonic::codegen::tokio_stream::Stream;
        use tonic::{Request, Response, Status};

        #[derive(Clone, Copy)]
        pub enum Mode {
            /// Never answers `CheckAction`: a gateway that stopped responding.
            Hang,
            /// Answers `Allow` immediately.
            Allow,
        }

        struct Stub(Mode);

        #[tonic::async_trait]
        impl PolicyService for Stub {
            async fn check_action(
                &self,
                _req: Request<CheckActionRequest>,
            ) -> Result<Response<CheckActionResponse>, Status> {
                match self.0 {
                    Mode::Hang => std::future::pending().await,
                    Mode::Allow => Ok(Response::new(CheckActionResponse {
                        decision: Decision::Allow as i32,
                        ..Default::default()
                    })),
                }
            }

            async fn batch_check(
                &self,
                _req: Request<BatchCheckRequest>,
            ) -> Result<Response<BatchCheckResponse>, Status> {
                Err(Status::unimplemented("stub"))
            }

            type OpControlStreamStream = Pin<Box<dyn Stream<Item = Result<OpControlMessage, Status>> + Send + 'static>>;

            async fn op_control_stream(
                &self,
                _req: Request<OpControlSubscribeRequest>,
            ) -> Result<Response<Self::OpControlStreamStream>, Status> {
                Err(Status::unimplemented("stub"))
            }
        }

        /// Serve the stub on an already-bound port (no bind/serve race) and
        /// return a client for it.
        pub async fn gateway(mode: Mode) -> super::super::GatewayClient {
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move {
                let _ = tonic::transport::Server::builder()
                    .add_service(PolicyServiceServer::new(Stub(mode)))
                    .serve_with_incoming(TcpListenerStream::new(listener))
                    .await;
            });
            super::super::GatewayClient::connect_lazy_owned(&format!("http://{addr}")).expect("lazy client")
        }
    }

    /// AAASM-6364: a gateway that accepts the call and never answers is a
    /// timeout (the RPC stage), not contention.
    #[tokio::test]
    async fn evaluate_mcp_call_times_out_when_the_gateway_never_answers() {
        let gateway = Arc::new(Mutex::new(stub::gateway(stub::Mode::Hang).await));
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            evaluate_mcp_call_within(
                std::time::Duration::from_millis(50),
                &gateway,
                &sample_call(),
                "https://mcp.example.com/",
                "",
                "",
                None,
            ),
        )
        .await
        .expect("the evaluation itself must be bounded")
        .expect_err("a hung gateway must not be waited on forever");
        assert!(!err.is::<GatewayContended>(), "{err}");
        assert!(err.to_string().contains("timed out"), "{err}");
    }

    /// Positive control for the timeout tests: the same call against a gateway
    /// that answers reaches a real decision, so the `Err`s above come from the
    /// bound and not from the stub or the client being unusable.
    #[tokio::test]
    async fn evaluate_mcp_call_returns_the_gateway_decision_when_it_answers() {
        let gateway = Arc::new(Mutex::new(stub::gateway(stub::Mode::Allow).await));
        let decision = evaluate_mcp_call_within(
            std::time::Duration::from_secs(5),
            &gateway,
            &sample_call(),
            "https://mcp.example.com/",
            "",
            "",
            None,
        )
        .await
        .expect("a live gateway answers");
        assert_eq!(decision, McpDecision::Allow);
    }

    /// AAASM-6364: a gateway lock that is never released (a stalled RPC holds
    /// it) must surface as `GatewayContended` after the bound, not hang the
    /// caller. Once the lock is free the same call reaches a real decision.
    #[tokio::test]
    async fn evaluate_mcp_call_is_bounded_when_the_gateway_lock_is_never_released() {
        let gateway = Arc::new(Mutex::new(stub::gateway(stub::Mode::Allow).await));
        let held = gateway.lock().await;

        // The outer bound makes a regression (an unbounded wait) fail fast
        // instead of hanging the suite.
        let err = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            evaluate_mcp_call_within(
                std::time::Duration::from_millis(50),
                &gateway,
                &sample_call(),
                "https://mcp.example.com/",
                "",
                "",
                None,
            ),
        )
        .await
        .expect("the evaluation itself must be bounded")
        .expect_err("a held lock must not be waited on forever");
        assert!(err.is::<GatewayContended>(), "{err}");
        drop(held);

        let decision = evaluate_mcp_call_within(
            std::time::Duration::from_secs(5),
            &gateway,
            &sample_call(),
            "https://mcp.example.com/",
            "",
            "",
            None,
        )
        .await
        .expect("the lock is free again");
        assert_eq!(decision, McpDecision::Allow);
    }

    /// AAASM-6364: the client-visible reason says which of the two failures
    /// happened, and is a fixed string that never carries the error text.
    #[test]
    fn fail_closed_reason_names_contention_and_gateway_failure_separately() {
        let contended = fail_closed_reason(&anyhow::Error::new(GatewayContended));
        assert_eq!(
            contended,
            "MCP enforcement unavailable: gateway client busy, call was not evaluated within 10s (fail-closed)"
        );
        let failed = fail_closed_reason(&anyhow::anyhow!("PolicyService.CheckAction timed out after 10s"));
        assert_eq!(
            failed,
            "MCP enforcement unavailable: gateway did not return a decision within 10s or failed (fail-closed)"
        );
    }

    /// AAASM-6364: lock wait and RPC share ONE deadline. With separate
    /// timeouts a call that queued for most of the bound would then wait the
    /// whole bound again on the RPC (worst case twice the bound).
    #[tokio::test]
    async fn evaluate_mcp_call_lock_wait_and_rpc_share_one_deadline() {
        let gateway = Arc::new(Mutex::new(stub::gateway(stub::Mode::Hang).await));
        let held = gateway.clone().lock_owned().await;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(700)).await;
            drop(held);
        });

        let started = std::time::Instant::now();
        let err = evaluate_mcp_call_within(
            std::time::Duration::from_secs(1),
            &gateway,
            &sample_call(),
            "https://mcp.example.com/",
            "",
            "",
            None,
        )
        .await
        .expect_err("the gateway never answers");
        let elapsed = started.elapsed();

        // The lock arrived at ~700ms, inside the 1s bound, so the failure is the
        // RPC stage; it must still end at ~1s, not ~1.7s (two separate
        // timeouts). Margins are wide on purpose: 300ms before the deadline for
        // the lock hand-off, 500ms of slack above the bound, still 200ms below
        // the two-timeout outcome.
        assert!(!err.is::<GatewayContended>(), "{err}");
        assert!(elapsed < std::time::Duration::from_millis(1500), "took {elapsed:?}");
    }

    fn response_with(decision: Decision, reason: &str) -> CheckActionResponse {
        CheckActionResponse {
            decision: decision as i32,
            reason: reason.into(),
            ..Default::default()
        }
    }

    #[test]
    fn decision_allow_maps_to_mcp_allow() {
        let resp = response_with(Decision::Allow, "ok");
        assert_eq!(decision_from_response(&resp, false), McpDecision::Allow);
    }

    #[test]
    fn decision_deny_maps_to_mcp_deny_with_reason() {
        let resp = response_with(Decision::Deny, "tool_name read_file blocked on /etc paths");
        match decision_from_response(&resp, false) {
            McpDecision::Deny { reason } => {
                assert_eq!(reason, "tool_name read_file blocked on /etc paths");
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decision_redact_maps_to_mcp_redact_with_instructions() {
        let resp = CheckActionResponse {
            decision: Decision::Redact as i32,
            redact: Some(RedactInstructions::default()),
            ..Default::default()
        };
        assert!(matches!(
            decision_from_response(&resp, false),
            McpDecision::Redact { .. }
        ));
    }

    #[test]
    fn decision_pending_downgrades_to_deny_at_proxy_layer() {
        // The proxy cannot block on a human approval queue inside the MitM
        // tunnel, so PENDING must surface as a wire-level Deny.
        let mut resp = response_with(Decision::Pending, "");
        resp.approval_id = "queue-7".into();
        match decision_from_response(&resp, false) {
            McpDecision::Deny { reason } => {
                assert!(
                    reason.contains("queue-7") || reason.contains("PENDING"),
                    "deny reason should explain the downgrade, got: {reason}",
                );
            }
            other => panic!("expected Deny, got {other:?}"),
        }
    }

    #[test]
    fn decision_unspecified_downgrades_to_deny() {
        let resp = response_with(Decision::Unspecified, "");
        assert!(matches!(decision_from_response(&resp, false), McpDecision::Deny { .. }));
    }

    #[test]
    fn unknown_decision_code_downgrades_to_deny() {
        // Out-of-range proto enum value (e.g. a future Decision variant the
        // proxy was compiled before) must still surface as Deny rather than
        // panic.
        let resp = CheckActionResponse {
            decision: 9999,
            ..Default::default()
        };
        match decision_from_response(&resp, false) {
            McpDecision::Deny { reason } => {
                assert!(
                    reason.contains("9999"),
                    "reason should name the unknown code, got: {reason}"
                );
            }
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

    /// Both MCP requests carry the launch's registered triple and grant, never a
    /// `credential_token`; a launch with no grant claims no identity.
    #[test]
    fn mcp_requests_carry_the_grant_in_its_own_field_or_claim_nothing() {
        let call = sample_call();
        let g = grant();
        for req in [
            build_check_action_request(&call, "https://mcp.example.com/", "", "", Some(&g)),
            build_tool_result_request(&call, b"{}", "https://mcp.example.com/", "", "", Some(&g)),
        ] {
            let id = req.agent_id.expect("agent_id");
            assert_eq!(
                (id.team_id.as_str(), id.agent_id.as_str()),
                ("team-a", "did:key:agent-a")
            );
            assert_eq!(req.launch_grant, "grant-a-synthetic");
            assert!(
                req.credential_token.is_empty(),
                "the registration token must never be sent"
            );
        }
        for req in [
            build_check_action_request(&call, "", "", "", None),
            build_tool_result_request(&call, b"{}", "", "", "", None),
        ] {
            assert_eq!(req.agent_id.expect("agent_id").agent_id, "");
            assert!(req.launch_grant.is_empty() && req.credential_token.is_empty());
        }
    }

    #[test]
    fn a_governed_launch_honours_an_mcp_allow_only_when_the_gateway_bound_it() {
        let allow = |a: AgentIdentityAssurance| CheckActionResponse {
            decision: Decision::Allow as i32,
            agent_identity_assurance: a as i32,
            ..Default::default()
        };
        assert_eq!(
            decision_from_response(&allow(AgentIdentityAssurance::Bound), true),
            McpDecision::Allow
        );
        for a in [AgentIdentityAssurance::Asserted, AgentIdentityAssurance::Unattributed] {
            assert!(
                matches!(decision_from_response(&allow(a), true), McpDecision::Deny { .. }),
                "{a:?}"
            );
        }
        assert_eq!(
            decision_from_response(&allow(AgentIdentityAssurance::Unattributed), false),
            McpDecision::Allow
        );
    }
}
