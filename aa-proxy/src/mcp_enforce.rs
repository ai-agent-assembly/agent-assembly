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

use aa_proto::assembly::common::v1::{ActionType, AgentId as ProtoAgentId, Decision};
use aa_proto::assembly::policy::v1::{
    action_context::Action, ActionContext, CheckActionRequest, CheckActionResponse, RedactInstructions, ToolCallContext,
};

use crate::intercept::mcp::McpToolCall;

/// Tool-source label written into `ToolCallContext.tool_source` for every
/// MCP call evaluated by this module. Matches the convention already used
/// in `aa-gateway/tests/edge_langgraph_test.rs` fixtures.
pub const MCP_TOOL_SOURCE: &str = "mcp";

/// Synthetic `agent_id` the proxy uses when forwarding MCP calls without
/// having registered an agent identity. The proxy is intentionally
/// agent-agnostic at Layer 2 — the gateway evaluates the ToolCallContext
/// directly. Used because `CheckActionRequest.agent_id` is a required
/// field on the proto.
const PROXY_AGENT_ID: &str = "aa-proxy";

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
    /// Forward the call, but rewrite matching fields in the upstream
    /// response before returning it to the client. `instructions` carries
    /// the field-path / replacement rules from the gateway.
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
) -> CheckActionRequest {
    // Serialise arguments back to JSON bytes for `ToolCallContext.args_json`.
    // Failure here is "synthesise an empty payload" rather than propagate —
    // an arguments value that round-trips serde once cannot round-trip
    // serde twice without a programming bug, and an empty args_json still
    // lets the policy engine match against `tool_name` alone.
    let args_json = serde_json::to_vec(&call.arguments).unwrap_or_default();
    CheckActionRequest {
        agent_id: Some(ProtoAgentId {
            org_id: String::new(),
            team_id: String::new(),
            agent_id: PROXY_AGENT_ID.into(),
        }),
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
    }
}

/// Convert a `CheckActionResponse` into an [`McpDecision`].
///
/// `Decision::Pending` and `Decision::Unspecified` map to `Deny` with a
/// reason explaining the conservative downgrade — the proxy cannot block
/// on a human approval queue inside the MitM tunnel, so any non-deterministic
/// verdict is treated as a refusal at this layer.
pub fn decision_from_response(response: &CheckActionResponse) -> McpDecision {
    match Decision::try_from(response.decision) {
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
        let req = build_check_action_request(&call, "https://mcp.example.com/tools", "trace-abc", "span-1");

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
}
