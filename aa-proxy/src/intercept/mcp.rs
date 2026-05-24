//! MCP (Model Context Protocol) `tools/call` JSON-RPC 2.0 request parser.
//!
//! The MCP wire protocol uses JSON-RPC 2.0 envelopes. A `tools/call` request
//! arriving at the proxy looks like:
//!
//! ```json
//! {
//!   "jsonrpc": "2.0",
//!   "id": 1,
//!   "method": "tools/call",
//!   "params": { "name": "read_file", "arguments": { "path": "/etc/passwd" } }
//! }
//! ```
//!
//! This module extracts the semantic `tool_name` and `arguments` fields so a
//! downstream policy engine can match rules like
//! `deny if tool_name == "read_file" and arguments.path starts_with "/etc"` —
//! a precision the raw-bytes credential scanner cannot reach.
//!
//! Scope: pure parser primitive only — see the F116 ST-Q detection slice in
//! `aa-integration-tests/tests/e2e_mcp_interceptor.rs`. The MitM data-path
//! wiring (calling this from inside the TLS tunnel, evaluating policy via the
//! gateway, enforcing allow/deny/redact at the wire, and emitting structured
//! `ToolCall` audit events) is tracked under AAASM-1930.

use serde::Deserialize;

/// Method name for the JSON-RPC 2.0 envelope this parser recognises.
const MCP_TOOLS_CALL_METHOD: &str = "tools/call";

/// JSON-RPC 2.0 protocol version this parser accepts. The MCP spec pins the
/// envelope at exactly `"2.0"`; anything else is rejected so a malformed or
/// non-MCP body cannot accidentally produce a tool-call match.
const JSONRPC_VERSION: &str = "2.0";

/// Semantic view of a single MCP `tools/call` request extracted from the raw
/// request body. The fields here are the inputs a policy engine needs to
/// match structured rules — the parser deliberately discards everything else
/// (jsonrpc version, id, meta) since the proxy data path will pass through
/// the original bytes if the call is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpToolCall {
    /// Tool name from `params.name` — e.g. `"read_file"`, `"execute_bash"`.
    pub tool_name: String,
    /// Tool arguments from `params.arguments` — kept as a raw
    /// `serde_json::Value` so policy expressions can walk nested fields
    /// without this module hard-coding a schema for every possible tool.
    pub arguments: serde_json::Value,
}

/// Try to interpret `body` as a JSON-RPC 2.0 MCP `tools/call` request and
/// extract the [`McpToolCall`].
///
/// Returns `None` when any of the following hold (these are the rejection
/// conditions the policy engine relies on to avoid false-positive matches
/// against arbitrary JSON traffic flowing through the proxy):
///
/// * `body` is not valid JSON.
/// * The top-level object lacks `jsonrpc`, or `jsonrpc != "2.0"`.
/// * `method` is missing or not `"tools/call"`.
/// * `params` is missing.
/// * `params.name` is missing or not a string.
///
/// When `params.arguments` is missing it is normalised to `Value::Null` so
/// callers can always treat it as a structured value.
pub fn parse_mcp_request(body: &[u8]) -> Option<McpToolCall> {
    #[derive(Deserialize)]
    struct Envelope {
        jsonrpc: Option<String>,
        method: Option<String>,
        params: Option<Params>,
    }

    #[derive(Deserialize)]
    struct Params {
        name: Option<String>,
        #[serde(default)]
        arguments: serde_json::Value,
    }

    let envelope: Envelope = serde_json::from_slice(body).ok()?;
    if envelope.jsonrpc.as_deref() != Some(JSONRPC_VERSION) {
        return None;
    }
    if envelope.method.as_deref() != Some(MCP_TOOLS_CALL_METHOD) {
        return None;
    }
    let params = envelope.params?;
    let tool_name = params.name?;
    Some(McpToolCall {
        tool_name,
        arguments: params.arguments,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_tool_name_and_arguments_from_tools_call() {
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": { "path": "/etc/passwd" }
            }
        }"#;
        let call = parse_mcp_request(body).expect("valid tools/call must parse");
        assert_eq!(call.tool_name, "read_file");
        assert_eq!(call.arguments, json!({ "path": "/etc/passwd" }));
    }

    #[test]
    fn returns_none_when_method_is_not_tools_call() {
        // `tools/list`, `initialize`, and other MCP methods must not trip the
        // policy engine — only `tools/call` carries a `tool_name` to match
        // structured rules against.
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }"#;
        assert!(parse_mcp_request(body).is_none());
    }
}
