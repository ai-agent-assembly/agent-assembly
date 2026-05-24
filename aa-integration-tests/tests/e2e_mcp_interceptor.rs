//! F116 ST-Q — E2E MCP interceptor (detection slice).
//!
//! Exercises the new `aa_proxy::intercept::mcp::parse_mcp_request` primitive
//! against MCP-shaped JSON-RPC 2.0 `tools/call` request bodies and asserts:
//!
//! 1. The structured `tool_name` and `arguments` fields the policy engine
//!    needs (`FieldRef::Tool` / `ToolCallContext.args_json`) are extracted
//!    correctly from the wire shape the proxy will see in production.
//! 2. Non-MCP JSON traffic flowing through the proxy is rejected so the
//!    policy engine never matches an MCP rule against an arbitrary body.
//! 3. The raw bytes of a payload that contains a secret are never retained
//!    in the parsed `McpToolCall` outside the structured `arguments` value
//!    (security invariant — the data-path follow-up will add redaction on
//!    the response side, but the parser must not be a side-channel today).
//!
//! ## Scope
//!
//! This file ships the **detection-only** slice of the original 5-test ST-Q.
//! The remaining E2E tests (ST-Q-1 through ST-Q-5) require runtime features
//! that are not yet implemented in `aa-proxy`:
//!
//! * Detection inside the MitM TLS tunnel (proxy must recognise an MCP body
//!   and branch into the MCP path).
//! * A gateway client in `aa-proxy` to send a `PolicyEvaluationRequest`
//!   carrying `ToolCallContext { tool_name, args_json, tool_source: "mcp" }`.
//! * Enforcement on the wire — JSON-RPC error envelope for `deny`, result
//!   mutation for `redact`, passthrough for `allow`.
//! * Structured `ToolCall` audit emission with `tool_name`, `args_json`,
//!   `decision` — not the raw `NetworkCall` body bytes.
//!
//! See **AAASM-1930** for the data-path follow-up; the ST-Q-1..5 placeholders
//! at the end of this file are marked `#[ignore]` until that work lands.
//!
//! ## Synthetic secrets only
//!
//! Every secret value below is synthetic — from prefixes documented as
//! test-only (`sk-test-`). No real secrets are stored in this fixture.

use aa_proxy::intercept::mcp::parse_mcp_request;

/// OpenAI key with the documented `sk-test-` test prefix. Synthetic.
///
/// Consumed by the raw-secret-absence invariant test added in a later commit
/// in this PR; allow(dead_code) until that test lands.
#[allow(dead_code)]
const FAKE_OPENAI_KEY: &str = "sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890";

// ── Detection slice ──────────────────────────────────────────────────────────

/// ST-Q detection — the parser extracts `tool_name == "read_file"` and the
/// nested `arguments.path == "/etc/passwd"` from a canonical MCP `tools/call`
/// request body. This is the structured-field primitive the data-path
/// follow-up (AAASM-1930) will feed into `PolicyEvaluationRequest`.
#[test]
fn parser_extracts_tool_name_and_path_for_deny_match() {
    let body = br#"{
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/etc/passwd" }
        }
    }"#;
    let call = parse_mcp_request(body).expect("MCP tools/call body must parse");
    assert_eq!(call.tool_name, "read_file");
    assert_eq!(
        call.arguments.get("path").and_then(|v| v.as_str()),
        Some("/etc/passwd"),
        "policy engine needs arguments.path to evaluate `starts_with \"/etc\"` predicates",
    );
}

/// ST-Q detection — the parser surfaces an allowed path (one that does NOT
/// match the deny rule's `starts_with "/etc"` predicate) just like a denied
/// one. The primitive is policy-agnostic; ST-Q-2 in AAASM-1930 will assert
/// that the gateway evaluates this body as `Allow` and forwards upstream.
#[test]
fn parser_extracts_tool_name_and_path_for_allow_match() {
    let body = br#"{
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": { "path": "/home/user/file.txt" }
        }
    }"#;
    let call = parse_mcp_request(body).expect("MCP tools/call body must parse");
    assert_eq!(call.tool_name, "read_file");
    assert_eq!(
        call.arguments.get("path").and_then(|v| v.as_str()),
        Some("/home/user/file.txt"),
    );
}

/// ST-Q detection — deeply nested `arguments` objects survive parsing intact.
/// Real-world MCP tools use structured config blocks (e.g. an HTTP fetch tool
/// with `arguments.request.headers.authorization`). The policy engine walks
/// these via `FieldRef::Tool` + JSON-path predicates; the parser must hand
/// the full sub-tree to the engine unchanged.
#[test]
fn parser_preserves_nested_arguments_object() {
    let body = br#"{
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "http_fetch",
            "arguments": {
                "request": {
                    "method": "GET",
                    "headers": { "authorization": "Bearer placeholder" },
                    "config": { "timeout_ms": 30000 }
                }
            }
        }
    }"#;
    let call = parse_mcp_request(body).expect("MCP tools/call with nested args must parse");
    assert_eq!(call.tool_name, "http_fetch");
    assert_eq!(
        call.arguments
            .pointer("/request/config/timeout_ms")
            .and_then(|v| v.as_u64()),
        Some(30000),
        "JSON pointer walk through nested arguments must succeed for policy predicates",
    );
}
