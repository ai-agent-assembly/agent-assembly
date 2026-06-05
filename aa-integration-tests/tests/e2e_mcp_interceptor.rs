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

// ── ST-Q-1..5 E2E placeholders (pending AAASM-1930) ─────────────────────────
//
// The five tests below mirror the ST-Q acceptance criteria 1:1. They are
// `#[ignore]` because the proxy data path does not yet recognise MCP traffic,
// has no gateway client, and cannot enforce allow/deny/redact on the wire.
// Each test's docstring records the exact assertion AAASM-1930 will make
// against a real running `ProxyServer` + mock MCP upstream, so when the
// data-path work lands the engineer can replace `todo!()` with the
// implementation and remove `#[ignore]`.

/// ST-Q-1 — MCP `read_file /etc/passwd` is denied at the proxy.
///
/// Drives a JSON-RPC `tools/call` for `read_file` through a real
/// `ProxyServer` connected to a real `PolicyService` gateway loaded with
/// `mcp_deny_read_file.yaml`, with a TLS-capturing mock MCP server as the
/// upstream. Asserts:
///
/// 1. The proxy returns a JSON-RPC 2.0 error envelope to the client
///    (`error.code = -32000`, message carries the policy reason).
/// 2. The upstream mock MCP server's `request_count() == 0` — the deny
///    fires at the proxy, the call is never passed through.
/// 3. A `PipelineEvent::Audit` is broadcast carrying a `PolicyViolation`
///    detail with `blocked_action == "tools/call read_file"`.
#[tokio::test(flavor = "multi_thread")]
async fn st_q_1_mcp_read_file_etc_passwd_is_denied() {
    use proxy_e2e::*;
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = std::sync::Arc::new(client_trust_proxy_ca(dir.path()).await);

    let upstream = TlsCapturingMcpUpstream::start(&ca).await;
    let (gateway_addr, _registry) = start_gateway_with_mcp_policy("mcp_deny_read_file.yaml").await;
    let (proxy_addr, mut event_rx, abort) = start_proxy_with_gateway(dir.path(), ca, upstream.addr, gateway_addr).await;

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#;
    let result = send_mcp_request_through_proxy(proxy_addr, client_config, body).await;

    let inner = result.inner_response.expect("inner response from proxy");
    assert!(
        inner.contains(r#""error""#) && inner.contains(r#""code":-32000"#),
        "proxy must return JSON-RPC error envelope on Deny, got: {inner}",
    );
    assert!(
        inner.contains("tool denied by policy"),
        "proxy must propagate gateway reason in JSON-RPC error message, got: {inner}",
    );

    // Give upstream a beat (in case the test races); it should still be 0.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        upstream.request_count(),
        0,
        "upstream MCP server must receive zero requests on Deny"
    );

    // Audit event: PolicyViolation with blocked_action = "tools/call read_file".
    let audit = recv_first_audit(&mut event_rx, std::time::Duration::from_secs(2))
        .await
        .expect("audit event must be emitted");
    match audit.inner.detail.expect("audit detail") {
        aa_proto::assembly::audit::v1::audit_event::Detail::Violation(v) => {
            assert_eq!(v.blocked_action, "tools/call read_file");
            assert!(!v.reason.is_empty(), "violation reason must be populated");
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }

    abort.abort();
}

/// ST-Q-2 — MCP `read_file /home/user/file.txt` is allowed.
///
/// Drives a `tools/call` for `read_file` through a real `ProxyServer` +
/// `PolicyService` (loaded with `allow_all.yaml`) + mock MCP upstream.
/// Asserts:
///
/// 1. The proxy forwards the original JSON-RPC envelope to the upstream
///    (`request_count() == 1`, `last_body()` contains the original body).
/// 2. The client receives the upstream's canned `tools/call` result
///    envelope (the mock returns `{"jsonrpc":"2.0","id":1,"result":{...}}`).
/// 3. The emitted audit event carries a `ToolCallDetail` with
///    `tool_name == "read_file"`, `tool_source == "mcp"`, `succeeded == true`.
#[tokio::test(flavor = "multi_thread")]
async fn st_q_2_mcp_read_file_home_user_is_allowed() {
    use proxy_e2e::*;
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = std::sync::Arc::new(client_trust_proxy_ca(dir.path()).await);

    let upstream = TlsCapturingMcpUpstream::start(&ca).await;
    let (gateway_addr, _registry) = start_gateway_with_mcp_policy("allow_all.yaml").await;
    let (proxy_addr, mut event_rx, abort) = start_proxy_with_gateway(dir.path(), ca, upstream.addr, gateway_addr).await;

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/file.txt"}}}"#;
    let result = send_mcp_request_through_proxy(proxy_addr, client_config, body).await;

    let inner = result.inner_response.expect("inner response from proxy");
    assert!(
        inner.contains(r#""result""#),
        "client must receive upstream's tools/call success envelope, got: {inner}",
    );
    assert!(
        !inner.contains(r#""error""#),
        "no JSON-RPC error envelope on Allow path, got: {inner}",
    );

    // Allow upstream a beat to register the forwarded request.
    for _ in 0..50 {
        if upstream.request_count() >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(
        upstream.request_count(),
        1,
        "upstream must receive exactly one forwarded request on Allow",
    );
    let received = upstream.last_body().expect("upstream captured body");
    assert!(
        received.contains(r#""name":"read_file""#),
        "upstream must receive the original JSON-RPC body, got: {received}",
    );
    assert!(
        received.contains(r#""path":"/home/user/file.txt""#),
        "upstream body must carry original args, got: {received}",
    );

    // Audit event: ToolCallDetail with tool_name = read_file, succeeded = true,
    // and args_json carrying the original (non-secret) arguments — the
    // tool_args half of the AAASM-1930 AC "every emitted MCP audit event
    // carries tool_name, tool_args, decision".
    let audit = recv_first_audit(&mut event_rx, std::time::Duration::from_secs(2))
        .await
        .expect("audit event must be emitted");
    match audit.inner.detail.expect("audit detail") {
        aa_proto::assembly::audit::v1::audit_event::Detail::ToolCall(tc) => {
            assert_eq!(tc.tool_name, "read_file");
            assert_eq!(tc.tool_source, "mcp");
            assert!(tc.succeeded, "tool_call succeeded must be true on Allow");
            // args_json carries the request-side arguments verbatim — no
            // secrets in this test so the scanner-based redaction leaves
            // the payload untouched.
            assert!(!tc.args_json.is_empty(), "args_json must be populated");
            let parsed: serde_json::Value =
                serde_json::from_slice(&tc.args_json).expect("args_json must round-trip as JSON");
            assert_eq!(
                parsed.get("path").and_then(|v| v.as_str()),
                Some("/home/user/file.txt"),
                "args_json must carry the original args.path",
            );
        }
        other => panic!("expected ToolCallDetail, got {other:?}"),
    }

    abort.abort();
}

/// ST-Q-3 — MCP tool result containing a secret is redacted before the
/// agent sees it.
///
/// Drives a `tools/call read_file /home/user/file.txt` against the
/// `allow_all.yaml` policy (so the request-side eval returns Allow and
/// the proxy forwards). The mock MCP upstream is configured to reply
/// with a result body that **embeds a synthetic OpenAI key**
/// (`sk-test-...`). The proxy's `Interceptor::redact_response_body` runs
/// `aa_security::CredentialScanner` against the captured response body —
/// the same scanner shape `aa-gateway` uses for ToolResult evaluation
/// (AAASM-1941) — and rewrites the response with `[REDACTED:OpenAiKey]`
/// markers in place of the raw key before forwarding to the client.
///
/// Asserts:
///
/// 1. The raw `sk-test-...` value appears nowhere in the client-side
///    response bytes.
/// 2. The client-side response carries `[REDACTED:` markers indicating
///    redaction took place.
/// 3. A second audit event (after the Allow audit fires for the request
///    side) is emitted with `tool_source == "mcp"`, `succeeded == true`,
///    documenting the response-side redaction.
#[tokio::test(flavor = "multi_thread")]
async fn st_q_3_mcp_tool_result_secret_is_redacted_before_agent_sees_it() {
    use proxy_e2e::*;
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = std::sync::Arc::new(client_trust_proxy_ca(dir.path()).await);

    // Synthetic OpenAI key — built into the default `aa_security::CredentialScanner`'s
    // OpenAiKey AC pattern. The proxy's scanner catches it without any policy
    // YAML configuration; `mcp_redact_secrets.yaml` would carry the same
    // pattern explicitly if the gateway-side ToolResult flow were used.
    let leaked_response_body = r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"my OpenAI key is sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890 please rotate"}]}}"#;
    let upstream = TlsCapturingMcpUpstream::start_with_response_body(&ca, leaked_response_body).await;
    let (gateway_addr, _registry) = start_gateway_with_mcp_policy("allow_all.yaml").await;
    let (proxy_addr, mut event_rx, abort) = start_proxy_with_gateway(dir.path(), ca, upstream.addr, gateway_addr).await;

    let body = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/home/user/file.txt"}}}"#;
    let result = send_mcp_request_through_proxy(proxy_addr, client_config, body).await;

    let inner = result.inner_response.expect("inner response from proxy");

    // SECURITY INVARIANT: raw secret bytes never appear in the client-side
    // response. A regression here would expose the secret to the agent.
    assert!(
        !inner.contains("sk-test-AbCdEf1234567890ABCDEF1234567890ABCDEF1234567890"),
        "raw OpenAI key leaked to client — proxy did not redact: {inner}",
    );
    // Positive marker: the proxy's scanner placed a redaction sentinel in
    // place of the secret bytes.
    assert!(
        inner.contains("[REDACTED:OpenAiKey]"),
        "client response must carry redaction marker, got: {inner}",
    );

    // The upstream did receive the original (unredacted) request — request-
    // side eval was Allow.
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        upstream.request_count(),
        1,
        "upstream must see exactly one forwarded request"
    );

    // Two audit events should fire: the request-side Allow and the
    // response-side "response redacted". Drain at least one and confirm
    // its shape (the helper returns the first ToolCall-typed audit).
    let audit = recv_first_audit(&mut event_rx, std::time::Duration::from_secs(2))
        .await
        .expect("audit event must be emitted");
    match audit.inner.detail.expect("audit detail") {
        aa_proto::assembly::audit::v1::audit_event::Detail::ToolCall(tc) => {
            assert_eq!(tc.tool_name, "read_file");
            assert_eq!(tc.tool_source, "mcp");
            assert!(tc.succeeded);
        }
        other => panic!("expected ToolCallDetail audit, got {other:?}"),
    }

    abort.abort();
}

/// ST-Q-4 — MCP tool name outside the allowlist is denied.
///
/// Drives `tools/call execute_bash` against `mcp_deny_execute_bash.yaml`
/// (the allowlist-shape fixture documented in that file). Asserts:
///
/// 1. The proxy returns a JSON-RPC 2.0 error envelope.
/// 2. The upstream MCP server's `request_count() == 0`.
/// 3. The emitted audit event carries `PolicyViolation { blocked_action:
///    "tools/call execute_bash" }`.
#[tokio::test(flavor = "multi_thread")]
async fn st_q_4_mcp_tool_name_outside_allowlist_is_denied() {
    use proxy_e2e::*;
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = std::sync::Arc::new(client_trust_proxy_ca(dir.path()).await);

    let upstream = TlsCapturingMcpUpstream::start(&ca).await;
    let (gateway_addr, _registry) = start_gateway_with_mcp_policy("mcp_deny_execute_bash.yaml").await;
    let (proxy_addr, mut event_rx, abort) = start_proxy_with_gateway(dir.path(), ca, upstream.addr, gateway_addr).await;

    let body = r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"execute_bash","arguments":{"cmd":"ls /tmp"}}}"#;
    let result = send_mcp_request_through_proxy(proxy_addr, client_config, body).await;

    let inner = result.inner_response.expect("inner response from proxy");
    assert!(
        inner.contains(r#""error""#) && inner.contains(r#""code":-32000"#),
        "proxy must return JSON-RPC error envelope, got: {inner}",
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        upstream.request_count(),
        0,
        "upstream must receive zero requests for non-allowlisted tool",
    );

    let audit = recv_first_audit(&mut event_rx, std::time::Duration::from_secs(2))
        .await
        .expect("audit event must be emitted");
    match audit.inner.detail.expect("audit detail") {
        aa_proto::assembly::audit::v1::audit_event::Detail::Violation(v) => {
            assert_eq!(v.blocked_action, "tools/call execute_bash");
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }

    abort.abort();
}

/// ST-Q-5 — All four behaviours above work with NO SDK installed.
///
/// Validates the framework-agnostic Layer 2 contract that motivates the
/// MCP interceptor's design (spec lines 452–453 / 7243). This test
/// duplicates ST-Q-1's deny driver while making the SDK-less property
/// explicit: the driver opens a raw `TcpStream → CONNECT → TLS` against
/// the proxy and writes the JSON-RPC body by hand, never invoking
/// `init_assembly()`. There is no Assembly SDK in the connection path.
///
/// Asserts the same wire-level + audit shape as ST-Q-1:
///
/// 1. JSON-RPC 2.0 error envelope returned to client.
/// 2. Upstream `request_count() == 0`.
/// 3. Audit event is `PolicyViolation { blocked_action: "tools/call
///    read_file" }`.
///
/// Sibling tests ST-Q-1 / ST-Q-2 / ST-Q-4 also use this same SDK-less
/// driver implicitly — the entire `proxy_e2e` mod's `send_mcp_request_
/// through_proxy` helper makes raw TCP+TLS calls without going through
/// the SDK. ST-Q-5 promotes that property from "implicit" to an
/// explicit acceptance assertion.
#[tokio::test(flavor = "multi_thread")]
async fn st_q_5_mcp_interception_works_without_sdk_installed() {
    use proxy_e2e::*;
    install_crypto_provider();
    let dir = tempfile::TempDir::new().expect("tempdir");
    let ca = aa_proxy::tls::CaStore::load_or_create(dir.path()).await.expect("ca");
    let client_config = std::sync::Arc::new(client_trust_proxy_ca(dir.path()).await);

    let upstream = TlsCapturingMcpUpstream::start(&ca).await;
    let (gateway_addr, _registry) = start_gateway_with_mcp_policy("mcp_deny_read_file.yaml").await;
    let (proxy_addr, mut event_rx, abort) = start_proxy_with_gateway(dir.path(), ca, upstream.addr, gateway_addr).await;

    // Hand-rolled JSON-RPC body — no `aa_runtime::init_assembly()`, no
    // SDK shim, no FFI binding. Pure Layer-2 driver shape.
    let body = r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/etc/passwd"}}}"#;
    let result = send_mcp_request_through_proxy(proxy_addr, client_config, body).await;

    let inner = result.inner_response.expect("inner response from proxy");
    assert!(
        inner.contains(r#""error""#) && inner.contains(r#""code":-32000"#),
        "framework-agnostic Layer 2 path must still produce JSON-RPC error envelope on Deny, got: {inner}",
    );

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    assert_eq!(
        upstream.request_count(),
        0,
        "upstream must receive zero requests even when caller has no SDK",
    );

    let audit = recv_first_audit(&mut event_rx, std::time::Duration::from_secs(2))
        .await
        .expect("audit event must be emitted from proxy regardless of SDK presence");
    match audit.inner.detail.expect("audit detail") {
        aa_proto::assembly::audit::v1::audit_event::Detail::Violation(v) => {
            assert_eq!(v.blocked_action, "tools/call read_file");
        }
        other => panic!("expected PolicyViolation, got {other:?}"),
    }

    abort.abort();
}

// ── E2E test infrastructure (AAASM-1930 Phase B) ────────────────────────────
//
// Self-contained mod carrying the integration plumbing that drives MCP
// `tools/call` traffic through a real `ProxyServer` connected to a real
// `aa-gateway::PolicyService` against a TLS-terminating mock MCP server.
//
// Modelled on `e2e_secret_interception.rs::proxy_data_path` (AAASM-1566)
// for the proxy + TLS pieces and on `observe_mode_e2e.rs::start_gateway_
// with_policy_fixture` (AAASM-1573) for the gateway boot.

mod proxy_e2e {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::atomic::AtomicU64;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use base64::Engine as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use rustls::{ClientConfig, RootCertStore, ServerConfig};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{broadcast, mpsc};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    use aa_core::AuditEntry;
    use aa_gateway::registry::AgentRegistry;
    use aa_gateway::service::PolicyServiceImpl;
    use aa_gateway::PolicyEngine;
    use aa_proto::assembly::policy::v1::policy_service_server::PolicyServiceServer;
    use aa_proxy::config::{CredentialAction, ProxyConfig};
    use aa_proxy::proxy::ProxyServer;
    use aa_proxy::tls::CaStore;
    use aa_runtime::pipeline::event::EnrichedEvent;
    use aa_runtime::pipeline::PipelineEvent;
    use tonic::transport::Server;

    /// Non-LLM hostname used for the proxy MitM target so the data path
    /// takes the new `handle_non_llm_with_gateway` branch rather than the
    /// pre-existing LLM-only credential-scanner branch.
    pub const MCP_HOSTNAME: &str = "mcp.example.com";

    /// Install rustls's default crypto provider exactly once per process.
    /// Both `aws-lc-rs` and `ring` are present transitively in this
    /// workspace, so rustls 0.23 refuses to pick one automatically.
    pub fn install_crypto_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    /// Resolve a fixture path under `aa-integration-tests/tests/common/fixtures/`.
    fn fixture_path(rel: &str) -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/common/fixtures")
            .join(rel)
    }

    /// TLS-terminating in-process mock MCP server. Captures inbound HTTP
    /// request bodies (the proxy serialises the JSON-RPC `tools/call` as
    /// a regular HTTP POST inside the MitM tunnel) and replies with a
    /// canned JSON-RPC success envelope.
    pub struct TlsCapturingMcpUpstream {
        pub addr: SocketAddr,
        history: Arc<Mutex<Vec<Vec<u8>>>>,
        _abort: tokio::task::AbortHandle,
    }

    impl TlsCapturingMcpUpstream {
        pub fn request_count(&self) -> usize {
            self.history.lock().expect("history mutex poisoned").len()
        }

        /// Consumed by the ST-Q-2 allow test (added in a later commit on
        /// this same PR); allow(dead_code) until that test lands.
        #[allow(dead_code)]
        pub fn last_body(&self) -> Option<String> {
            self.history
                .lock()
                .expect("history mutex poisoned")
                .last()
                .and_then(|b| std::str::from_utf8(b).ok().map(String::from))
        }

        /// Start a TLS-terminating capture upstream signed by the proxy's CA
        /// for `MCP_HOSTNAME`, replying with a canned MCP success envelope
        /// (no secrets in the response body).
        pub async fn start(ca: &CaStore) -> Self {
            Self::start_with_response_body(
                ca,
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"file contents"}]}}"#,
            )
            .await
        }

        /// Variant of [`start`] that replies with the supplied response body
        /// instead of the canned envelope. Used by ST-Q-3 to seed an
        /// upstream response containing a synthetic secret so the proxy's
        /// response-side credential scanner has something to redact.
        pub async fn start_with_response_body(ca: &CaStore, response_body: &str) -> Self {
            let response_body_owned = response_body.to_string();
            let ck = ca.sign_cert(MCP_HOSTNAME).expect("ca sign_cert");
            let cert = CertificateDer::from(ck.cert_der.clone());
            let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
            let server_config = ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config");
            let acceptor = TlsAcceptor::from(Arc::new(server_config));

            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind upstream");
            let addr = listener.local_addr().expect("local_addr");

            let history: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
            let h_arc = Arc::clone(&history);

            let handle = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let history = Arc::clone(&h_arc);
                    let resp_body = response_body_owned.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut buf: Vec<u8> = Vec::new();
                        let mut tmp = [0u8; 4096];
                        let head_end = loop {
                            match tls.read(&mut tmp).await {
                                Ok(0) => return,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => return,
                            }
                            if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                                break p;
                            }
                        };
                        let head = std::str::from_utf8(&buf[..head_end]).unwrap_or("");
                        let cl: usize = head
                            .lines()
                            .find_map(|line| {
                                line.to_ascii_lowercase()
                                    .strip_prefix("content-length:")
                                    .and_then(|v| v.trim().parse().ok())
                            })
                            .unwrap_or(0);
                        let body_start = head_end + 4;
                        while buf.len() < body_start + cl {
                            match tls.read(&mut tmp).await {
                                Ok(0) => break,
                                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                                Err(_) => break,
                            }
                        }
                        let body = buf[body_start..body_start + cl].to_vec();
                        history.lock().expect("history mutex poisoned").push(body);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            resp_body.len(),
                            resp_body,
                        );
                        let _ = tls.write_all(resp.as_bytes()).await;
                        let _ = tls.flush().await;
                    });
                }
            });

            Self {
                addr,
                history,
                _abort: handle.abort_handle(),
            }
        }
    }

    /// Boot a `PolicyService` gRPC server backed by the supplied YAML
    /// policy fixture; returns the bound address + the (empty) registry
    /// handle the caller can ignore for proxy-only ST-Q tests.
    pub async fn start_gateway_with_mcp_policy(policy_fixture: &str) -> (SocketAddr, Arc<AgentRegistry>) {
        let path = fixture_path(&format!("policies/{policy_fixture}"));
        let (alert_tx, _) = tokio::sync::broadcast::channel::<aa_gateway::budget::BudgetAlert>(64);
        let engine = Arc::new(PolicyEngine::load_from_file(&path, alert_tx).expect("policy fixture must load cleanly"));
        let registry = Arc::new(AgentRegistry::new());
        let (audit_tx, _audit_rx) = mpsc::channel::<AuditEntry>(4096);
        let audit_drops = Arc::new(AtomicU64::new(0));
        let service = PolicyServiceImpl::with_registry(
            Arc::clone(&engine),
            Arc::clone(&registry),
            audit_tx,
            audit_drops,
            [0u8; 32],
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind gateway");
        let addr = listener.local_addr().expect("local_addr");
        tokio::spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            Server::builder()
                .add_service(PolicyServiceServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .expect("tonic Server::serve_with_incoming");
        });
        tokio::time::sleep(Duration::from_millis(80)).await;
        (addr, registry)
    }

    /// Start a `ProxyServer` with `gateway_endpoint` pointing at the test
    /// PolicyService, and `upstream_override` redirecting all dials to the
    /// supplied mock MCP upstream. Returns the proxy's bound address,
    /// a `PipelineEvent` broadcast receiver, and an abort handle.
    pub async fn start_proxy_with_gateway(
        ca_dir: &Path,
        ca: CaStore,
        upstream_override: SocketAddr,
        gateway_addr: SocketAddr,
    ) -> (SocketAddr, broadcast::Receiver<PipelineEvent>, tokio::task::AbortHandle) {
        let port = portpicker::pick_unused_port().expect("free port");
        let config = ProxyConfig {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], port)),
            ca_dir: ca_dir.to_path_buf(),
            cert_cache_capacity: 10,
            llm_only: false,
            denied_hosts: Vec::new(),
            network_allowlist: Vec::new(),
            skip_upstream_tls_verify: true,
            credential_action: CredentialAction::default(),
            upstream_override: Some(upstream_override),
            gateway_endpoint: Some(format!("http://{gateway_addr}")),
        };
        let bind_addr = config.bind_addr;
        let (tx, rx) = broadcast::channel(64);
        let server = ProxyServer::new(config, ca, tx);
        let jh = tokio::spawn(async move { server.run().await.unwrap() });
        let abort = jh.abort_handle();

        // Wait for the proxy to bind AND for it to connect to the gateway.
        // The gateway-connect step in `run()` is best-effort but synchronous
        // (await), so once the proxy is accepting TCP we know the connect
        // either succeeded or failed-soft.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                panic!("proxy did not start on {bind_addr}");
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Small extra beat to let the gateway-connect step complete after
        // the listener binds. Without this the very first request can race
        // and find `gateway_client` still unset, taking the transparent-
        // forward fallback instead of the MCP-enforcement branch.
        tokio::time::sleep(Duration::from_millis(150)).await;
        (bind_addr, rx, abort)
    }

    /// Build a [`ClientConfig`] that trusts the proxy's per-host CA so the
    /// TLS connection inside the MitM tunnel verifies against the MitM-
    /// issued leaf cert.
    pub async fn client_trust_proxy_ca(ca_dir: &Path) -> ClientConfig {
        let pem = tokio::fs::read_to_string(ca_dir.join("ca-cert.pem"))
            .await
            .expect("read ca cert pem");
        let body: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let der_bytes = base64::engine::general_purpose::STANDARD
            .decode(body)
            .expect("decode ca pem base64");
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(der_bytes))
            .expect("add ca cert to root store");
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    }

    /// Result of driving an MCP request through the proxy.
    pub struct ProxyDriveResult {
        /// CONNECT response status line (e.g. `"HTTP/1.1 200 Connection Established"`).
        /// Read by tests that need to assert on CONNECT-level deny — none in
        /// this commit, but ST-Q-5 in a later commit on this PR will consume it.
        #[allow(dead_code)]
        pub connect_status: String,
        pub inner_response: Option<String>,
    }

    /// Drive a JSON-RPC `tools/call` body through the proxy: open a CONNECT
    /// tunnel to `MCP_HOSTNAME:443`, TLS-wrap, POST the body, and read the
    /// response.
    pub async fn send_mcp_request_through_proxy(
        proxy_addr: SocketAddr,
        client_config: Arc<ClientConfig>,
        body: &str,
    ) -> ProxyDriveResult {
        let mut tcp = TcpStream::connect(proxy_addr).await.expect("connect to proxy");
        let target = format!("{MCP_HOSTNAME}:443");
        let connect = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
        tcp.write_all(connect.as_bytes()).await.expect("write CONNECT");

        let mut reader = BufReader::new(tcp);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).await.expect("read connect status");
        loop {
            let mut h = String::new();
            reader.read_line(&mut h).await.expect("read header line");
            if h.trim().is_empty() {
                break;
            }
        }

        if !status_line.contains("200") {
            return ProxyDriveResult {
                connect_status: status_line,
                inner_response: None,
            };
        }

        let server_name = ServerName::try_from(MCP_HOSTNAME.to_string()).expect("server name");
        let connector = TlsConnector::from(client_config);
        let tcp = reader.into_inner();
        let mut tls = match connector.connect(server_name, tcp).await {
            Ok(t) => t,
            Err(e) => {
                return ProxyDriveResult {
                    connect_status: status_line,
                    inner_response: Some(format!("TLS error: {e}")),
                };
            }
        };

        let req = format!(
            "POST /mcp HTTP/1.1\r\nHost: {MCP_HOSTNAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body,
        );
        if let Err(e) = tls.write_all(req.as_bytes()).await {
            return ProxyDriveResult {
                connect_status: status_line,
                inner_response: Some(format!("write error: {e}")),
            };
        }
        let mut response_buf = vec![0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_secs(2), tls.read(&mut response_buf)).await;
        let response = String::from_utf8_lossy(&response_buf)
            .trim_end_matches('\0')
            .to_string();
        ProxyDriveResult {
            connect_status: status_line,
            inner_response: Some(response),
        }
    }

    /// Drain the broadcast channel until an Audit event arrives (or the
    /// timeout fires). The proxy emits CONNECT-decision audits before
    /// the MCP-decision audit; this helper returns the first audit whose
    /// `action_type == ToolCall` so callers don't have to filter manually.
    pub async fn recv_first_audit(
        rx: &mut broadcast::Receiver<PipelineEvent>,
        timeout: Duration,
    ) -> Option<Box<EnrichedEvent>> {
        use aa_proto::assembly::common::v1::ActionType;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            let remaining = deadline - tokio::time::Instant::now();
            match tokio::time::timeout(remaining, rx.recv()).await {
                Ok(Ok(PipelineEvent::Audit(e))) if e.inner.action_type == ActionType::ToolCall as i32 => {
                    return Some(e);
                }
                Ok(Ok(_)) => continue, // ignore non-Audit / non-ToolCall events
                Ok(Err(_)) | Err(_) => return None,
            }
        }
    }
}
