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

/// Classify a body that [`parse_mcp_request`] could **not** turn into a single
/// [`McpToolCall`], to decide whether it is nonetheless an attempt to invoke
/// `tools/call` that must be fail-closed rather than blindly forwarded upstream.
///
/// Returns `true` when the body is JSON-RPC framing that references a
/// `tools/call` the strict single-object parser cannot fully evaluate:
///
/// * a top-level JSON-RPC **batch** array with any element carrying
///   `method == "tools/call"` — `parse_mcp_request` only deserialises a single
///   object, so a one-element batch `[{…tools/call…}]` returned `None` and was
///   forwarded upstream with no gateway decision (AAASM-4070); or
/// * a top-level object whose `method == "tools/call"` but whose envelope fails
///   strict extraction (wrong/missing `jsonrpc`, missing `params.name`) — a
///   steered agent could malform these to slip a tool call past enforcement.
///
/// Non-JSON bodies, and JSON carrying no `tools/call` method, return `false` so
/// ordinary non-MCP HTTPS traffic on this route still flows through untouched.
/// This is deliberately a *detector*, not a parser: it does not change the
/// `None`-on-false-positive contract [`parse_mcp_request`] relies on.
pub fn is_unenforceable_tool_call(body: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    match &value {
        serde_json::Value::Array(elements) => elements.iter().any(mentions_tools_call),
        serde_json::Value::Object(_) => mentions_tools_call(&value),
        _ => false,
    }
}

/// True when `value` is a JSON object whose `method` field is exactly
/// `"tools/call"` — the marker that a JSON-RPC request intends to invoke a tool.
fn mentions_tools_call(value: &serde_json::Value) -> bool {
    value.get("method").and_then(serde_json::Value::as_str) == Some(MCP_TOOLS_CALL_METHOD)
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

    #[test]
    fn returns_none_when_jsonrpc_version_is_wrong_or_missing() {
        // Wrong version — JSON-RPC 1.0 or unspecified MUST be rejected so a
        // legacy non-MCP payload cannot accidentally be matched.
        let wrong_version = br#"{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        assert!(parse_mcp_request(wrong_version).is_none());

        // Missing entirely — non-MCP JSON-shaped traffic flowing through the
        // proxy must not produce a false-positive McpToolCall.
        let no_version = br#"{"id":1,"method":"tools/call","params":{"name":"x"}}"#;
        assert!(parse_mcp_request(no_version).is_none());
    }

    #[test]
    fn returns_none_when_params_name_is_missing() {
        // A `tools/call` request without a `name` cannot drive any tool — the
        // policy engine would have nothing to match against, so the parser
        // rejects it before any policy evaluation happens.
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "arguments": { "path": "/etc/passwd" } }
        }"#;
        assert!(parse_mcp_request(body).is_none());
    }

    #[test]
    fn returns_none_on_malformed_json() {
        // Garbage bytes, truncated envelopes, and non-JSON traffic must all
        // surface as `None` instead of panicking — the proxy data path will
        // see plenty of non-MCP HTTPS bodies in production.
        assert!(parse_mcp_request(b"not json at all").is_none());
        assert!(parse_mcp_request(b"{\"jsonrpc\":\"2.0\",\"method\":").is_none());
        assert!(parse_mcp_request(b"").is_none());
    }

    #[test]
    fn missing_arguments_defaults_to_json_null() {
        // Tools that take no arguments (e.g. `tools/call` for a
        // `list_workspace_files` no-arg tool) omit the `arguments` field
        // entirely. The parser must accept these and surface
        // `arguments == Value::Null` so callers can treat it uniformly.
        let body = br#"{
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "ping" }
        }"#;
        let call = parse_mcp_request(body).expect("missing arguments must still parse");
        assert_eq!(call.tool_name, "ping");
        assert_eq!(call.arguments, serde_json::Value::Null);
    }

    #[test]
    fn one_element_batch_tools_call_is_flagged_unenforceable() {
        // AAASM-4070 regression: the bypass vector. `parse_mcp_request` only
        // deserialises a single object, so this one-element batch returned
        // `None` and the caller's pre-fix `else` branch forwarded it upstream
        // with NO gateway CheckAction and NO credential/DLP scan. The detector
        // must flag it so the caller fails closed instead of forwarding.
        let body = br#"[
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": "execute_bash", "arguments": { "cmd": "rm -rf /" } }
            }
        ]"#;
        assert!(
            parse_mcp_request(body).is_none(),
            "batch must not parse as a single call"
        );
        assert!(
            is_unenforceable_tool_call(body),
            "a one-element batch tools/call must be flagged so it is fail-closed, not forwarded"
        );
    }

    #[test]
    fn multi_element_batch_with_a_tools_call_is_flagged() {
        // A tool call hidden among benign requests in a batch must still be
        // flagged — any element carrying `method == "tools/call"` taints the
        // whole batch, since the strict parser can enforce none of them.
        let body = br#"[
            {"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}},
            {"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"read_file"}}
        ]"#;
        assert!(is_unenforceable_tool_call(body));
    }

    #[test]
    fn object_tools_call_that_fails_strict_extraction_is_flagged() {
        // `method == "tools/call"` but the envelope fails strict extraction
        // (wrong jsonrpc version, missing `params.name`). `parse_mcp_request`
        // returns `None` for these by contract; the detector must still flag
        // them as tool-call attempts so a malformed envelope cannot slip a call
        // past enforcement via the blind-forward path.
        let wrong_version = br#"{"jsonrpc":"1.0","id":1,"method":"tools/call","params":{"name":"x"}}"#;
        assert!(parse_mcp_request(wrong_version).is_none());
        assert!(is_unenforceable_tool_call(wrong_version));

        let missing_name = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}"#;
        assert!(parse_mcp_request(missing_name).is_none());
        assert!(is_unenforceable_tool_call(missing_name));
    }

    #[test]
    fn non_tool_call_traffic_is_not_flagged() {
        // The detector must NOT fire on ordinary non-MCP HTTPS traffic that
        // happens to flow through this route, or it would break every non-tool
        // request. A single non-tools/call object, a batch of non-tool
        // requests, non-JSON bodies, an empty body, and a plain JSON array of
        // scalars must all pass through untouched (return `false`).
        assert!(!is_unenforceable_tool_call(
            br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#
        ));
        assert!(!is_unenforceable_tool_call(
            br#"[{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}]"#
        ));
        assert!(!is_unenforceable_tool_call(br#"{"hello":"world"}"#));
        assert!(!is_unenforceable_tool_call(b"not json at all"));
        assert!(!is_unenforceable_tool_call(b""));
        assert!(!is_unenforceable_tool_call(b"[1, 2, 3]"));
    }
}
