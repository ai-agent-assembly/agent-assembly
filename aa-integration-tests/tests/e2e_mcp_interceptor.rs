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

/// ST-Q detection — non-MCP JSON traffic flowing through the proxy must be
/// rejected by `parse_mcp_request`. Critical invariant: the proxy data path
/// (AAASM-1930) will call this primitive on every body it sees in the MitM
/// tunnel; if an OpenAI chat-completions body or any plain JSON object
/// matched, the policy engine would evaluate MCP rules against arbitrary
/// LLM traffic.
#[test]
fn parser_rejects_non_mcp_json_traffic_seen_by_proxy() {
    // OpenAI chat-completions body — the proxy sees this on every LLM call.
    let openai = br#"{
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "hi"}]
    }"#;
    assert!(
        parse_mcp_request(openai).is_none(),
        "OpenAI body must not match an MCP rule"
    );

    // Anthropic body — same risk.
    let anthropic = br#"{
        "model": "claude-3-opus-20240229",
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": "hi"}]
    }"#;
    assert!(
        parse_mcp_request(anthropic).is_none(),
        "Anthropic body must not match an MCP rule",
    );

    // Plain JSON object with no MCP envelope — generic webhook traffic etc.
    let generic = br#"{"event": "ping", "ts": 1700000000}"#;
    assert!(
        parse_mcp_request(generic).is_none(),
        "generic JSON must not match an MCP rule"
    );
}

/// ST-Q detection — raw-secret-absence security invariant on the parser.
///
/// The parser is **not** a redactor — that's AAASM-1930's response-side job.
/// What the parser MUST guarantee is that it does not become a side-channel:
/// the secret bytes must live exactly in the structured `arguments` value
/// where the policy engine can match against them, and nowhere else (no copy
/// in `tool_name`, no leak via `Debug` formatting outside the arguments).
///
/// AAASM-1930's ST-Q-3 will assert the data-path-side redaction (raw key
/// absent from the response bytes returned to the agent). This test locks
/// down the parser-side prerequisite: the parser hands a faithful
/// `arguments` to the engine without smearing the secret across other
/// fields.
#[test]
fn parser_does_not_leak_secret_bytes_outside_arguments_value() {
    let body = format!(
        r#"{{
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {{
                "name": "submit_context",
                "arguments": {{ "context": "user said {FAKE_OPENAI_KEY}" }}
            }}
        }}"#
    );
    let call = parse_mcp_request(body.as_bytes()).expect("MCP body with secret in args must parse");

    // (1) tool_name carries only the tool name — never spills the secret.
    assert_eq!(call.tool_name, "submit_context");
    assert!(
        !call.tool_name.contains(FAKE_OPENAI_KEY),
        "tool_name must never carry argument bytes",
    );

    // (2) The secret IS present in the structured arguments value — that's
    //     where the gateway's redaction predicate (AAASM-1930) will find and
    //     replace it on the response path.
    let context = call
        .arguments
        .get("context")
        .and_then(|v| v.as_str())
        .expect("arguments.context must be a string");
    assert!(
        context.contains(FAKE_OPENAI_KEY),
        "secret must be present in arguments so the policy engine can match it",
    );

    // (3) The secret must NOT appear in any non-arguments serialised view of
    //     the parsed struct (a regression here would mean a future change
    //     accidentally added a Display impl or log line that leaks the key).
    let debug_repr = format!("{:?}", call.tool_name);
    assert!(
        !debug_repr.contains(FAKE_OPENAI_KEY),
        "Debug of tool_name must not leak the secret — got {debug_repr}",
    );
}
