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

use std::borrow::Cow;

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

/// The text of `bytes` as a lenient JSON peer reads it: a leading UTF-8 BOM
/// stripped and invalid UTF-8 replaced, rather than the whole body rejected.
///
/// `serde_json::from_slice` refuses both, but Node and Python MCP servers accept
/// a BOM-prefixed body and tolerate a stray byte inside a string. A proxy that
/// is stricter than its peers decides on "not JSON" while the peer runs the
/// call (AAASM-6355 review V2/V4), so every interception decision parses this.
pub fn lenient_json_text(bytes: &[u8]) -> Cow<'_, str> {
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(bytes);
    String::from_utf8_lossy(bytes)
}

/// Parse `bytes` with the peers' leniency (see [`lenient_json_text`]).
pub fn parse_json_lenient(bytes: &[u8]) -> Option<serde_json::Value> {
    serde_json::from_str(&lenient_json_text(bytes)).ok()
}

/// True when `text` is not valid JSON yet looks like a JSON document
/// (`{` / `[`): the shape a fail-closed caller must not treat as "not JSON".
pub fn looks_like_json_document(text: &str) -> bool {
    matches!(text.trim_start().as_bytes().first(), Some(b'{' | b'['))
}

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

/// Upper bound on [`decode_json_strings`] output. Decoding only shrinks escapes,
/// so this is reached only by an input already near the body cap.
const MAX_DECODED_JSON_STRINGS: usize = 64 * 1024 * 1024;

/// Every JSON string token in `text` (object keys and values alike, duplicates
/// kept, in order), each with all escapes decoded and followed by `\n`.
///
/// This is deliberately LEXICAL: it needs no successful parse, so nesting depth,
/// `NaN`, `1e400`, trailing garbage or duplicate keys cannot make the proxy see
/// less than a lenient peer (Node, Python) decodes. Invalid escapes keep the
/// escaped character; unterminated strings end at end of input; time and
/// memory are linear. `None` when the output would exceed `cap`, which callers
/// must treat as "cannot judge" and fail closed on (AAASM-6355 review round 3).
pub fn decode_json_strings_capped(text: &str, cap: usize) -> Option<String> {
    fn hex4(it: &mut std::str::Chars<'_>) -> Option<u32> {
        let mut probe = it.clone();
        let mut v = 0u32;
        for _ in 0..4 {
            v = v * 16 + probe.next()?.to_digit(16)?;
        }
        *it = probe;
        Some(v)
    }
    let mut out = String::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '"' {
            continue;
        }
        loop {
            if out.len() > cap {
                return None;
            }
            match chars.next() {
                None => break,
                Some('"') => break,
                Some('\\') => match chars.next() {
                    None => break,
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some('b') => out.push('\u{8}'),
                    Some('f') => out.push('\u{c}'),
                    Some('u') => match hex4(&mut chars) {
                        None => out.push('u'),
                        Some(hi @ 0xD800..=0xDBFF) => {
                            let mut probe = chars.clone();
                            let low = (probe.next() == Some('\\') && probe.next() == Some('u'))
                                .then(|| hex4(&mut probe))
                                .flatten()
                                .filter(|l| (0xDC00..=0xDFFF).contains(l));
                            match low {
                                Some(lo) => {
                                    chars = probe;
                                    out.push(
                                        char::from_u32(0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00))
                                            .unwrap_or('\u{FFFD}'),
                                    );
                                }
                                None => out.push('\u{FFFD}'),
                            }
                        }
                        Some(cp) => out.push(char::from_u32(cp).unwrap_or('\u{FFFD}')),
                    },
                    // `\"`, `\\`, `\/` and any invalid escape keep the character.
                    Some(other) => out.push(other),
                },
                Some(c) => out.push(c),
            }
        }
        out.push('\n');
    }
    Some(out)
}

/// [`decode_json_strings_capped`] with the production cap.
pub fn decode_json_strings(text: &str) -> Option<String> {
    decode_json_strings_capped(text, MAX_DECODED_JSON_STRINGS)
}

/// Fold a JSON object key the way the most permissive struct decoder does: Go's
/// `encoding/json` matches keys case-insensitively and also folds U+017F (long
/// s) onto `s` and U+212A (Kelvin) onto `k`.
fn fold_key(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{17F}' => 's',
            '\u{212A}' => 'k',
            c => c.to_ascii_lowercase(),
        })
        .collect()
}

/// True when two distinct keys of `obj` are equal after [`fold_key`]: a
/// case-insensitive, last-wins peer would pick one, the proxy another.
fn has_fold_collision(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    let mut seen = std::collections::HashSet::with_capacity(obj.len());
    !obj.keys().all(|k| seen.insert(fold_key(k)))
}

/// `has_fold_collision` anywhere under `value` (recursion is bounded by serde's
/// own nesting limit, since `value` came from a successful parse).
fn has_nested_fold_collision(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => has_fold_collision(map) || map.values().any(has_nested_fold_collision),
        serde_json::Value::Array(items) => items.iter().any(has_nested_fold_collision),
        _ => false,
    }
}

/// A key that is not byte-exact `canonical` yet folds onto it.
fn is_inexact_spelling(key: &str, canonical: &str) -> bool {
    key != canonical && fold_key(key) == canonical
}

/// True when `obj` is a `tools/call` request that a case-insensitive peer could
/// read differently from the exact-key parser the proxy evaluates (AAASM-6355
/// review round 4): a colliding key pair, or an inexact spelling of an envelope
/// field. Applies only to objects that spell `tools/call` as a `method` value,
/// so ordinary JSON with differently-cased keys is untouched. Collisions
/// anywhere inside `params` (including `arguments`) are denied too, so a tool
/// argument such as `{"path":"/ok","PATH":"/etc/passwd"}` cannot differ between
/// the proxy and the tool server.
fn is_case_ambiguous_tools_call(obj: &serde_json::Map<String, serde_json::Value>) -> bool {
    let names_tools_call = obj
        .iter()
        .any(|(k, v)| fold_key(k) == "method" && v.as_str() == Some(MCP_TOOLS_CALL_METHOD));
    if !names_tools_call {
        return false;
    }
    if has_fold_collision(obj)
        || obj.keys().any(|k| {
            ["jsonrpc", "method", "params", "id"]
                .iter()
                .any(|c| is_inexact_spelling(k, c))
        })
    {
        return true;
    }
    obj.iter().filter(|(k, _)| fold_key(k) == "params").any(|(_, params)| {
        has_nested_fold_collision(params)
            || params.as_object().is_some_and(|p| {
                p.keys()
                    .any(|k| ["name", "arguments"].iter().any(|c| is_inexact_spelling(k, c)))
            })
    })
}

/// [`is_case_ambiguous_tools_call`] for a top-level object or each batch element.
fn has_case_ambiguity(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(map) => is_case_ambiguous_tools_call(map),
        serde_json::Value::Array(items) => items
            .iter()
            .any(|v| v.as_object().is_some_and(is_case_ambiguous_tools_call)),
        _ => false,
    }
}

/// True when `body` may be JSON-RPC in an encoding the proxy does not parse but
/// a peer does (AAASM-6355 review round 4): Node's body-parser honours any
/// `utf-*` charset and Python's `json.loads(bytes)` detects UTF-16/32 without a
/// BOM, so a UTF-16 `tools/call` is invisible to a UTF-8 parser.
///
/// * A JSON-looking body whose declared `Content-Type` charset is not UTF-8 is
///   unenforceable.
/// * A body with NUL bytes or a UTF-16/32 BOM is read with the NULs and BOM
///   removed (what remains of ASCII text) and is unenforceable when that reads
///   as JSON carrying a `tools/call` token. Binary bodies and plain UTF-8 or
///   UTF-8-BOM JSON are unaffected; an escaped `\u0000` is not a NUL byte.
pub fn is_unparsed_encoding_tool_call(body: &[u8], content_type: Option<&str>) -> bool {
    let text = nul_stripped_text(body);
    if !looks_like_json_document(&text) {
        return false;
    }
    if content_type
        .and_then(declared_charset)
        .is_some_and(|c| !c.eq_ignore_ascii_case("utf-8") && !c.eq_ignore_ascii_case("utf8"))
    {
        return true;
    }
    has_wide_encoding_markers(body) && has_tools_call_token(&text)
}

/// True for a UTF-16/32 BOM or any NUL byte.
pub fn has_wide_encoding_markers(body: &[u8]) -> bool {
    body.contains(&0) || body.starts_with(&[0xFF, 0xFE]) || body.starts_with(&[0xFE, 0xFF])
}

/// `body` with NUL bytes and a leading UTF-16 / UTF-8 BOM removed, decoded lossily.
pub fn nul_stripped_text(body: &[u8]) -> String {
    let body = body
        .strip_prefix(&[0xFF, 0xFE])
        .or_else(|| body.strip_prefix(&[0xFE, 0xFF]))
        .unwrap_or(body);
    let stripped: Vec<u8> = body.iter().copied().filter(|b| *b != 0).collect();
    lenient_json_text(&stripped).into_owned()
}

fn declared_charset(content_type: &str) -> Option<String> {
    content_type.split(';').skip(1).find_map(|param| {
        let (name, value) = param.split_once('=')?;
        name.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| value.trim().trim_matches('"').to_string())
    })
}

/// True when some decoded string token of `text` is exactly `tools/call`.
fn has_tools_call_token(text: &str) -> bool {
    // Unjudgeable (over the cap) counts as "might be": fail closed.
    decode_json_strings(text).map_or(true, |d| d.lines().any(|t| t == MCP_TOOLS_CALL_METHOD))
}

/// Try to interpret `body` as a JSON-RPC 2.0 MCP `tools/call` request and
/// extract the [`McpToolCall`].
///
/// Returns `None` when any of the following hold (these are the rejection
/// conditions the policy engine relies on to avoid false-positive matches
/// against arbitrary JSON traffic flowing through the proxy):
///
/// * `body` is not valid JSON (after BOM stripping and lossy UTF-8 decoding).
/// * The top-level object lacks `jsonrpc`, or `jsonrpc != "2.0"`.
/// * `method` is missing or not `"tools/call"`.
/// * `params` is missing.
/// * `params.name` is missing or not a string.
///
/// When `params.arguments` is missing it is normalised to `Value::Null` so
/// callers can always treat it as a structured value.
pub fn parse_mcp_request(body: &[u8]) -> Option<McpToolCall> {
    let text = lenient_json_text(body);
    // A case-ambiguous request is left to `is_unenforceable_tool_call`, which denies it.
    if serde_json::from_str::<serde_json::Value>(&text).is_ok_and(|v| has_case_ambiguity(&v)) {
        return None;
    }
    let envelope: Envelope = serde_json::from_str(&text).ok()?;
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
/// Non-JSON bodies (unless JSON-looking and carrying a `tools/call` token), and JSON
/// carrying no `tools/call` method, return `false` so
/// ordinary non-MCP HTTPS traffic on this route still flows through untouched.
/// This is deliberately a *detector*, not a parser: it does not change the
/// `None`-on-false-positive contract [`parse_mcp_request`] relies on.
pub fn is_unenforceable_tool_call(body: &[u8]) -> bool {
    let text = lenient_json_text(body);
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
        // Unparseable even leniently (too deep, NaN, 1e400, ...): the proxy
        // cannot say what a more tolerant peer decodes. A JSON-looking body with
        // a `tools/call` string token, spelled however (`tools\u002fcall`), is
        // denied rather than skipped.
        return looks_like_json_document(&text) && has_tools_call_token(&text);
    };
    if has_case_ambiguity(&value) {
        return true;
    }
    let framing_mentions = match &value {
        serde_json::Value::Array(elements) => elements.iter().any(mentions_tools_call),
        serde_json::Value::Object(_) => mentions_tools_call(&value),
        _ => false,
    };
    if framing_mentions {
        return true;
    }
    // A body serde parses leniently but whose envelope the strict parser
    // rejects (a repeated `method` key: serde keeps the last, a first-wins peer
    // runs the first) is judged by tokens. Well-formed envelopes that merely
    // mention `tools/call` in a string (e.g. a `tools/list` param) pass.
    matches!(&value, serde_json::Value::Array(_) | serde_json::Value::Object(_))
        && serde_json::from_str::<Envelope>(&text).is_err()
        && has_tools_call_token(&text)
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

    // AAASM-6355 review V4: the proxy must be as lenient as the peers it fronts.
    fn tools_call_bytes() -> Vec<u8> {
        br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"a":"x"}}}"#.to_vec()
    }

    #[test]
    fn a_bom_prefixed_tools_call_still_parses() {
        let mut body = b"\xEF\xBB\xBF".to_vec();
        body.extend(tools_call_bytes());
        assert_eq!(parse_mcp_request(&body).expect("BOM is skipped").tool_name, "t");
    }

    #[test]
    fn an_invalid_utf8_byte_in_a_string_still_parses() {
        let mut body = tools_call_bytes();
        let at = body.iter().position(|b| *b == b'x').unwrap();
        body[at] = 0xFF;
        assert!(parse_mcp_request(&body).is_some());
    }

    #[test]
    fn an_unparseable_json_looking_body_naming_tools_call_is_unenforceable() {
        assert!(is_unenforceable_tool_call(br#"{"method":"tools\/call", BROKEN"#));
        assert!(is_unenforceable_tool_call(br#"[{"method":"tools/call" BROKEN"#));
    }

    #[test]
    fn unparseable_bodies_that_do_not_name_tools_call_stay_forwardable() {
        assert!(!is_unenforceable_tool_call(br#"{"method":"tools/list", BROKEN"#));
        assert!(!is_unenforceable_tool_call(b"plain text mentioning tools/call"));
    }

    // ── lexical decoder ──
    #[test]
    fn decoder_handles_escapes_surrogates_keys_and_duplicates() {
        let d = decode_json_strings(r#"{"k\u0041":"a\/b\n","k\u0041":"\ud83d\ude00"}"#).unwrap();
        assert_eq!(d, "kA\na/b\n\nkA\n\u{1F600}\n");
    }

    #[test]
    fn decoder_keeps_invalid_escapes_and_survives_truncation() {
        assert_eq!(
            decode_json_strings(r#"["\q\u12","\ud800x","\udc00"]"#).unwrap(),
            "qu12\n\u{FFFD}x\n\u{FFFD}\n"
        );
        // unterminated string, trailing lone backslash, no panic
        assert_eq!(
            decode_json_strings(r#"{"a":"unterminated\"#).unwrap(),
            "a\nunterminated\n"
        );
        assert_eq!(decode_json_strings("no strings here").unwrap(), "");
    }

    #[test]
    fn decoder_fails_closed_above_its_cap() {
        assert!(decode_json_strings_capped(&format!("\"{}\"", "x".repeat(100)), 10).is_none());
        assert!(decode_json_strings_capped("\"xx\"", 10).is_some());
    }

    // ── round 3: serde-rejected requests a lenient peer still runs ──
    fn deep(n: usize) -> String {
        format!("{}{}", "[".repeat(n), "]".repeat(n))
    }

    #[test]
    fn unparseable_tools_call_is_unenforceable_however_the_method_is_spelled() {
        for method in ["tools/call", r"tools\u002fcall", r"\u0074ools/call", r"tools\/call"] {
            for tail in [
                format!(r#""d":{}"#, deep(200)),
                r#""n":NaN"#.into(),
                r#""n":1e400"#.into(),
            ] {
                let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{"name":"x"}},{tail}}}"#);
                assert!(is_unenforceable_tool_call(body.as_bytes()), "{method} {tail:.12}");
            }
        }
        // controls: same shapes naming another method are not refused
        let other = format!(r#"{{"jsonrpc":"2.0","method":"tools/list","d":{}}}"#, deep(200));
        assert!(!is_unenforceable_tool_call(other.as_bytes()));
    }

    #[test]
    fn a_repeated_method_key_is_unenforceable_in_either_order() {
        for (a, b) in [("tools/call", "tools/list"), ("tools/list", "tools/call")] {
            let body = format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{a}","method":"{b}","params":{{"name":"x"}}}}"#);
            assert!(is_unenforceable_tool_call(body.as_bytes()), "{a} then {b}");
        }
        let both_list = br#"{"jsonrpc":"2.0","method":"tools/list","method":"tools/list"}"#;
        assert!(!is_unenforceable_tool_call(both_list));
    }

    #[test]
    fn a_valid_non_tools_call_request_mentioning_the_string_is_forwardable() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"q":"tools/call"}}"#;
        assert!(parse_mcp_request(body).is_none());
        assert!(!is_unenforceable_tool_call(body));
    }

    // ── round 4 V1: case-insensitive peers (Go encoding/json) ──
    #[test]
    fn case_ambiguous_tools_calls_are_unenforceable() {
        for body in [
            // (a) envelope field spelled differently
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","Method":"tools/call","params":{"name":"evil"}}"#,
            // (b) params / name / arguments collisions and inexact spellings
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe","NAME":"evil"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"},"PARAMS":{"name":"evil"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"safe"},"param\u017f":{"name":"evil"}}"#,
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"p":"ok"},"Arguments":{"p":"/etc/passwd"}}}"#,
            // (c) collision inside arguments
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"path":"/ok","PATH":"/etc/passwd"}}}"#,
            // Kelvin sign folds onto k
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"k":1,"\u212a":2}}}"#,
            // batch element
            r#"[{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","NAME":"e"}}]"#,
        ] {
            assert!(parse_mcp_request(body.as_bytes()).is_none(), "{body}");
            assert!(is_unenforceable_tool_call(body.as_bytes()), "{body}");
        }
    }

    #[test]
    fn non_colliding_differently_cased_keys_still_parse() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tools/call","Meta":1,"params":{"name":"t","arguments":{"Path":"/ok","mode":"r"}}}"#;
        assert_eq!(parse_mcp_request(body).expect("must parse").tool_name, "t");
        // Non-tools/call JSON with colliding keys is not ours to refuse.
        let other = br#"{"jsonrpc":"2.0","method":"tools/list","a":1,"A":2}"#;
        assert!(!is_unenforceable_tool_call(other));
    }

    // ── round 4 V2: wide encodings ──
    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    #[test]
    fn utf16_tools_calls_are_unenforceable_with_or_without_bom_or_content_type() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}"#;
        let plain = utf16le(json);
        let mut bom = vec![0xFF, 0xFE];
        bom.extend(&plain);
        let escaped = utf16le(&json.replace("tools/call", r"tools\u002fcall"));
        assert!(is_unparsed_encoding_tool_call(&plain, None));
        assert!(is_unparsed_encoding_tool_call(
            &plain,
            Some("application/json; charset=utf-16le")
        ));
        assert!(is_unparsed_encoding_tool_call(&bom, None));
        assert!(is_unparsed_encoding_tool_call(&escaped, None));
        // UTF-32LE
        let utf32: Vec<u8> = json.chars().flat_map(|c| (c as u32).to_le_bytes()).collect();
        assert!(is_unparsed_encoding_tool_call(&utf32, None));
        // declared non-UTF-8 charset on a JSON-looking body
        assert!(is_unparsed_encoding_tool_call(
            json.as_bytes(),
            Some("application/json; charset=\"iso-8859-1\"")
        ));
    }

    #[test]
    fn utf8_bodies_and_escaped_nul_are_unaffected_by_the_encoding_check() {
        let json =
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"s":"a\u0000b"}}}"#;
        assert!(!is_unparsed_encoding_tool_call(json.as_bytes(), None));
        assert!(!is_unparsed_encoding_tool_call(
            json.as_bytes(),
            Some("application/json; charset=UTF-8")
        ));
        let mut bom = b"\xEF\xBB\xBF".to_vec();
        bom.extend(json.as_bytes());
        assert!(!is_unparsed_encoding_tool_call(&bom, None));
        // binary with NULs that is not JSON-looking, and UTF-16 JSON without tools/call
        assert!(!is_unparsed_encoding_tool_call(b"\x89PNG\0\0\0tools/call", None));
        assert!(!is_unparsed_encoding_tool_call(&utf16le(r#"{"a":"b"}"#), None));
    }
}
