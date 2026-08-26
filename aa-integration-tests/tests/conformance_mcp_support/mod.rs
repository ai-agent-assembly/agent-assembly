//! AAASM-5930 — the deterministic, non-LLM-dependent conformance upstream.
//!
//! Mocks the one genuinely non-deterministic external dependency (the
//! model's own response) rather than the product path under test: the real
//! `claude` binary talks to this over a real TLS connection through the
//! real per-launch proxy, exactly as it would talk to `api.anthropic.com`
//! and a real remote MCP server.
//!
//! # Why one server, not two
//!
//! `aa-proxy`'s `upstream_override` (`ProxyConfig::upstream_override`) is a
//! single fixed dial target for every MitM'd connection, whatever the
//! original CONNECT host was — the proxy still forwards the original HTTP
//! `Host` header untouched, since that's what carries the real domain to the
//! real upstream in production. [`ConformanceUpstream`] reads that header to
//! dispatch between the two roles this scenario needs (the model API, the
//! MCP server) from one listener, rather than standing up two.
//!
//! # The scripted turn sequence
//!
//! Claude Code resends the full message transcript on every `/v1/messages`
//! call (the Anthropic API is stateless), so [`ConformanceUpstream`] scripts
//! its reply by counting `tool_result` content blocks already in the
//! incoming transcript — 0 → emit a `tool_use` for the allowed tool, 1 →
//! emit a `tool_use` for the denied tool, 2 → emit final text. A parallel,
//! unrelated conversation (Claude Code names each session by asking the
//! model for a short title) would desync a request-count-based script, so
//! the discriminator is a marker string in the scenario's own prompt: only a
//! request whose transcript carries [`TASK_MARKER`] runs the scripted
//! sequence; anything else gets an inert one-line reply.
//!
//! Tool names are the qualified `mcp__<server>__<tool>` form — this was
//! verified empirically against the real `claude` 2.1.238 binary (a bare
//! tool name in the `tool_use` block is silently never invoked; Claude Code
//! only recognises the MCP-qualified name for a tool it discovered via
//! `tools/list` from an MCP server).

use std::collections::HashSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use aa_proxy::tls::CaStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Marker string identifying the scenario's own task prompt, as opposed to
/// any other conversation Claude Code's own runtime opens against the same
/// endpoint (session-title generation, etc.).
pub const TASK_MARKER: &str = "AAASM5930-CONFORMANCE-TASK";

/// The qualified MCP tool name Claude Code must see to recognise a tool as
/// callable — `mcp__<server_name_in_.mcp.json>__<tool_name>`.
pub fn qualified_tool(server_name: &str, tool_name: &str) -> String {
    format!("mcp__{server_name}__{tool_name}")
}

/// One inbound request, recorded for post-hoc assertions independent of the
/// scripted response logic (e.g. "how many `tools/call` actually arrived").
#[derive(Clone, Debug)]
pub struct RecordedRequest {
    pub host: String,
    pub path: String,
    pub body: Vec<u8>,
}

/// A tool call the MCP half of [`ConformanceUpstream`] actually received and
/// answered — i.e. one the proxy's policy adjudication let through. A tool
/// call the policy denies never reaches this server at all; that absence is
/// what the deny half of the scenario asserts on.
#[derive(Clone, Debug)]
pub struct ReceivedToolCall {
    pub name: String,
}

struct Inner {
    requests: Vec<RecordedRequest>,
    tool_calls: Vec<ReceivedToolCall>,
}

/// Combined deterministic model-API + MCP-server upstream.
///
/// `server_name` is the name this scenario's `.mcp.json` registers the MCP
/// server under (needed to build the qualified tool name the script emits).
/// `allow_tool` / `deny_tool` are the two MCP tool names under test; calling
/// either one for real writes a sentinel file under `sentinel_dir` so a
/// tool's actual execution is an observation, not an inference from the
/// model's stated intent.
pub struct ConformanceUpstream {
    pub addr: SocketAddr,
    state: Arc<Mutex<Inner>>,
    _abort: tokio::task::AbortHandle,
}

impl ConformanceUpstream {
    pub async fn start(
        ca: &CaStore,
        cert_hostname: &str,
        server_name: &str,
        allow_tool: &str,
        deny_tool: &str,
        sentinel_dir: &Path,
    ) -> anyhow::Result<Self> {
        let ck = ca
            .sign_cert(cert_hostname)
            .map_err(|e| anyhow::anyhow!("ca sign_cert: {e}"))?;
        let cert = CertificateDer::from(ck.cert_der.clone());
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(ck.key_der.clone()));
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)?;
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;

        let state = Arc::new(Mutex::new(Inner {
            requests: Vec::new(),
            tool_calls: Vec::new(),
        }));

        let allow_qualified = qualified_tool(server_name, allow_tool);
        let deny_qualified = qualified_tool(server_name, deny_tool);
        let sentinel_dir = sentinel_dir.to_path_buf();
        let state_task = Arc::clone(&state);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _peer)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let state = Arc::clone(&state_task);
                let allow_qualified = allow_qualified.clone();
                let deny_qualified = deny_qualified.clone();
                let sentinel_dir = sentinel_dir.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    // A model-host connection serves exactly one
                    // request-response exchange (`Connection: close`,
                    // returns below); an MCP connection stays open for the
                    // whole session and this `loop` reads every subsequent
                    // request on it (`Connection: keep-alive`, `continue`
                    // below) — see the connection-reuse finding on that
                    // decision further down.
                    loop {
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
                        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                        let method = head
                            .lines()
                            .next()
                            .and_then(|l| l.split(' ').next())
                            .unwrap_or("")
                            .to_string();
                        let path = head
                            .lines()
                            .next()
                            .and_then(|l| l.split(' ').nth(1))
                            .unwrap_or("/")
                            .to_string();
                        let host = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
                                    .strip_prefix("host:")
                                    .map(|v| v.trim().to_string())
                            })
                            .unwrap_or_default();
                        let cl: usize = head
                            .lines()
                            .find_map(|l| {
                                l.to_ascii_lowercase()
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
                        let body = buf[body_start..(body_start + cl).min(buf.len())].to_vec();

                        state
                            .lock()
                            .expect("state mutex poisoned")
                            .requests
                            .push(RecordedRequest {
                                host: host.clone(),
                                path: path.clone(),
                                body: body.clone(),
                            });

                        // The MCP Streamable HTTP transport lets a client open a
                        // GET to the same endpoint to receive server-initiated
                        // messages over SSE; a server with nothing to push is
                        // explicitly allowed by the spec to decline with 405
                        // rather than open a stream. This harness never pushes
                        // anything server-initiated, so declining is correct —
                        // and, per the client behaviour observed empirically,
                        // load-bearing: without an explicit reply here Claude
                        // Code's MCP client never proceeds past `initialize`.
                        if method.eq_ignore_ascii_case("GET") && host.to_ascii_lowercase().contains("mcp") {
                            if tls.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n").await.is_err() {
                                return;
                            }
                            if tls.flush().await.is_err() {
                                return;
                            }
                            continue;
                        }

                        let (status, resp_body) = respond(
                            &host,
                            &path,
                            &body,
                            &allow_qualified,
                            &deny_qualified,
                            &sentinel_dir,
                            &state,
                        );

                        // MCP's Streamable HTTP transport (2025-03-26+) mints a
                        // session at `initialize` via this header, and a
                        // compliant client is expected to send it back on every
                        // subsequent request — a fixed value is sufficient for
                        // this harness's single-session scenario. Present on
                        // every MCP response (not just initialize's) since the
                        // client's requirement is "the server sent one at some
                        // point", not "only on the first reply".
                        let session_header = if host.to_ascii_lowercase().contains("mcp") {
                            "Mcp-Session-Id: aaasm5930-conformance-session\r\n"
                        } else {
                            ""
                        };
                        // AAASM-5930 debug finding (supersedes every prior
                        // theory recorded here — those were measured through
                        // a dedicated-proxy debug log that a `guard.rs` fd bug
                        // was silently corrupting, so none of them ever
                        // actually observed what the proxy did). Two things
                        // are now confirmed against the fixed log:
                        //
                        // 1. Every MCP response closing its connection is the
                        //    configuration that lets `deny_test` work: the
                        //    proxy's `mcp_enforce` gate fires, the gateway
                        //    denies, and the proxy answers the client
                        //    directly (`transmission="not_forwarded"`)
                        //    without ever dialling this upstream — correct
                        //    enforcement, and the reason `deny_test` never
                        //    reaching this mock is a pass, not a gap.
                        // 2. `allow_test`'s tools/call never opens a new
                        //    CONNECT tunnel at all (dispatched ~100ms after
                        //    `tools/list`, reusing that connection instead)
                        //    regardless of whether `tools/list`'s own
                        //    response keeps that connection alive or closes
                        //    it — tried both, no change, so this isn't this
                        //    mock's framing to fix. `deny_test` (dispatched
                        //    only after `allow_test`'s 60s client-side
                        //    timeout had already torn the transport down)
                        //    does get a fresh tunnel, which is why deny works
                        //    and allow doesn't. Open: AAASM-5930 tracks the
                        //    allow leg as a known gap pending its own root
                        //    cause.
                        let is_mcp = host.to_ascii_lowercase().contains("mcp");
                        let is_mcp_keep_alive = false;
                        // The model-API host's replies are SSE-framed (see
                        // anthropic_tool_use_sse / anthropic_text_message_sse) —
                        // Claude Code's Anthropic client falls back to a
                        // non-streaming retry, which then hangs, if it doesn't
                        // see `text/event-stream`. MCP responses stay flat JSON.
                        let content_type = if is_mcp {
                            "application/json"
                        } else {
                            "text/event-stream"
                        };
                        // Close after every response rather than keeping the
                        // connection alive for reuse. Empirically load-bearing
                        // for the model host too, not just MCP: with
                        // `Connection: keep-alive` the *first* model exchange
                        // (session-title generation) completes fine, but the
                        // *second* — the real scripted turn — never even
                        // leaves the client (no new proxy connection, no
                        // upstream request, just a client-side stall that
                        // eventually times out at 30s) — consistent with the
                        // client's connection pool treating the still-open
                        // socket as unavailable for a new request rather than
                        // recognizing the prior response as complete.
                        let connection = if is_mcp_keep_alive { "keep-alive" } else { "close" };
                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\n{session_header}Connection: {connection}\r\n\r\n{}",
                            resp_body.len(),
                            resp_body,
                        );
                        if tls.write_all(resp.as_bytes()).await.is_err() {
                            return;
                        }
                        if tls.flush().await.is_err() {
                            return;
                        }
                        if is_mcp_keep_alive {
                            continue;
                        }
                        return;
                    }
                });
            }
        });

        Ok(Self {
            addr,
            state,
            _abort: handle.abort_handle(),
        })
    }

    /// Every request this upstream received, in arrival order — both model
    /// and MCP traffic.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        self.state.lock().expect("state mutex poisoned").requests.clone()
    }

    /// Every `tools/call` this upstream actually answered, in arrival order.
    /// A denied tool call the proxy blocked never adds an entry here.
    pub fn tool_calls(&self) -> Vec<ReceivedToolCall> {
        self.state.lock().expect("state mutex poisoned").tool_calls.clone()
    }

    pub fn tool_call_names(&self) -> HashSet<String> {
        self.tool_calls().into_iter().map(|c| c.name).collect()
    }
}

fn respond(
    host: &str,
    path: &str,
    body: &[u8],
    allow_qualified: &str,
    deny_qualified: &str,
    sentinel_dir: &Path,
    state: &Arc<Mutex<Inner>>,
) -> (&'static str, String) {
    let host_l = host.to_ascii_lowercase();
    if host_l.contains("mcp") {
        return respond_mcp(body, sentinel_dir, state);
    }
    // Claude Code queries Anthropic's own MCP server registry/reputation
    // endpoint before trusting a configured remote MCP server enough to
    // actually invoke its tools — confirmed empirically: `initialize` and
    // `tools/list` both succeed regardless of this endpoint's response, but
    // no `tools/call` is ever attempted while this returns a body shaped
    // for something else (this server previously answered every
    // `api.anthropic.com` path with an Anthropic Messages envelope, which is
    // meaningless here). An empty-but-correctly-shaped list is enough.
    if path.starts_with("/mcp-registry/") {
        return (
            "200 OK",
            serde_json::json!({"servers": [], "has_more": false}).to_string(),
        );
    }
    respond_model(body, allow_qualified, deny_qualified)
}

fn respond_mcp(body: &[u8], sentinel_dir: &Path, state: &Arc<Mutex<Inner>>) -> (&'static str, String) {
    let req: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
    let id = req.get("id").cloned();

    if method == "notifications/initialized" {
        // A notification carries no `id` and expects no JSON-RPC envelope —
        // just a bare 202, per the JSON-RPC-over-HTTP convention Claude
        // Code's MCP client uses.
        return ("202 Accepted", String::new());
    }

    let result = match method {
        "initialize" => {
            // Echo the client's own offered protocolVersion rather than
            // hardcoding one, so this mock never negotiates a version the
            // real client didn't offer.
            let client_version = req
                .get("params")
                .and_then(|p| p.get("protocolVersion"))
                .and_then(|v| v.as_str())
                .unwrap_or("2025-06-18")
                .to_string();
            serde_json::json!({
                "protocolVersion": client_version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "conformance", "version": "0.1.0"},
            })
        }
        "tools/list" => serde_json::json!({
            "tools": [
                {"name": "allow_test", "description": "conformance allow probe", "inputSchema": {"type": "object", "properties": {}, "required": []}},
                {"name": "deny_test", "description": "conformance deny probe", "inputSchema": {"type": "object", "properties": {}, "required": []}},
            ]
        }),
        "tools/call" => {
            let name = req
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            // Reaching here at all means the proxy's policy adjudication let
            // this call through — this is the real observation the harness
            // makes, so the sentinel is written unconditionally rather than
            // special-cased per tool name: if a denied call ever reaches
            // this branch, that is a real enforcement failure the scenario
            // must be able to catch, not something to suppress here.
            let _ = std::fs::create_dir_all(sentinel_dir);
            let _ = std::fs::write(sentinel_dir.join(format!("{name}.sentinel")), b"reached\n");
            state
                .lock()
                .expect("state mutex poisoned")
                .tool_calls
                .push(ReceivedToolCall { name: name.clone() });
            serde_json::json!({"content": [{"type": "text", "text": format!("{name} executed")}]})
        }
        other => {
            return (
                "200 OK",
                serde_json::json!({"jsonrpc": "2.0", "id": id, "error": {"code": -32601, "message": format!("method not found: {other}")}})
                    .to_string(),
            );
        }
    };
    (
        "200 OK",
        serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result}).to_string(),
    )
}

fn respond_model(body: &[u8], allow_qualified: &str, deny_qualified: &str) -> (&'static str, String) {
    let text = String::from_utf8_lossy(body);
    // Claude Code's session-title generation call echoes the user's own
    // prompt verbatim into its own request body — so it carries TASK_MARKER
    // too, and a marker-only check misfires a scripted tool_use onto a
    // title-gen turn instead of the real agent turn (confirmed via
    // ~/.claude/debug: the real turn then never got a reply at all — Claude
    // Code stalled 30s+ waiting on a request our upstream never even saw,
    // because it was busy misinterpreting the title-gen call as turn 0).
    // Title-gen runs on a distinct, cheaper model — `claude-haiku-*` — while
    // the real agent turn does not, so that's the more reliable discriminator
    // than the marker alone.
    let is_title_gen = text.contains("\"model\":\"claude-haiku");
    if is_title_gen || !text.contains(TASK_MARKER) {
        // A side conversation (e.g. session-title generation) — an inert
        // reply so it doesn't desync the scripted turn count below, and
        // doesn't itself attempt a tool call.
        return ("200 OK", anthropic_text_message_sse("msg_side", "ok"));
    }
    let tool_result_count =
        text.matches("\"type\": \"tool_result\"").count() + text.matches("\"type\":\"tool_result\"").count();
    let msg = match tool_result_count {
        0 => anthropic_tool_use_sse("msg_allow", allow_qualified, "toolu_allow"),
        1 => anthropic_tool_use_sse("msg_deny", deny_qualified, "toolu_deny"),
        _ => anthropic_text_message_sse("msg_final", "conformance-done"),
    };
    ("200 OK", msg)
}

/// Anthropic's Messages API is a Server-Sent-Events stream by default for
/// this client, not a single JSON object — confirmed empirically via
/// `~/.claude/debug/<session>.txt`: a flat JSON response produces `[ERROR]
/// Stream completed without receiving message_start event`, the client
/// falls back to a second, non-streaming-flavoured request, and that retry
/// then hangs until the connection is torn down — this harness's earlier
/// flat-JSON replies never actually completed a turn. Assembles the minimal
/// real event sequence (`message_start` → one content block's start/delta/
/// stop → `message_delta` → `message_stop`) framed as `text/event-stream`.
fn sse_frame(event: &str, data: &serde_json::Value) -> String {
    format!("event: {event}\ndata: {}\n\n", data)
}

fn anthropic_tool_use_sse(id: &str, tool_name: &str, tool_use_id: &str) -> String {
    let message_start = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": id, "type": "message", "role": "assistant", "model": "claude-sonnet-4-5",
            "content": [], "stop_reason": null, "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 0},
        }
    });
    let block_start = serde_json::json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "tool_use", "id": tool_use_id, "name": tool_name, "input": {}},
    });
    let block_delta = serde_json::json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "input_json_delta", "partial_json": "{}"},
    });
    let block_stop = serde_json::json!({"type": "content_block_stop", "index": 0});
    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "tool_use", "stop_sequence": null},
        "usage": {"output_tokens": 4},
    });
    let message_stop = serde_json::json!({"type": "message_stop"});
    [
        sse_frame("message_start", &message_start),
        sse_frame("content_block_start", &block_start),
        sse_frame("content_block_delta", &block_delta),
        sse_frame("content_block_stop", &block_stop),
        sse_frame("message_delta", &message_delta),
        sse_frame("message_stop", &message_stop),
    ]
    .concat()
}

fn anthropic_text_message_sse(id: &str, text: &str) -> String {
    let message_start = serde_json::json!({
        "type": "message_start",
        "message": {
            "id": id, "type": "message", "role": "assistant", "model": "claude-sonnet-4-5",
            "content": [], "stop_reason": null, "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 0},
        }
    });
    let block_start = serde_json::json!({
        "type": "content_block_start", "index": 0,
        "content_block": {"type": "text", "text": ""},
    });
    let block_delta = serde_json::json!({
        "type": "content_block_delta", "index": 0,
        "delta": {"type": "text_delta", "text": text},
    });
    let block_stop = serde_json::json!({"type": "content_block_stop", "index": 0});
    let message_delta = serde_json::json!({
        "type": "message_delta",
        "delta": {"stop_reason": "end_turn", "stop_sequence": null},
        "usage": {"output_tokens": 4},
    });
    let message_stop = serde_json::json!({"type": "message_stop"});
    [
        sse_frame("message_start", &message_start),
        sse_frame("content_block_start", &block_start),
        sse_frame("content_block_delta", &block_delta),
        sse_frame("content_block_stop", &block_stop),
        sse_frame("message_delta", &message_delta),
        sse_frame("message_stop", &message_stop),
    ]
    .concat()
    .to_string()
}

/// Write the `.mcp.json` Claude Code reads for remote MCP server config, and
/// the accompanying `.claude/settings.json` enabling it — the adapter's own
/// `apply_settings_at` only ever touches `permissions`/`permissionMode`/
/// `enabledMcpjsonServers`/`disabledMcpjsonServers` (`aa-devtool-claude-code
/// /src/apply.rs::MANAGED_KEYS`) and never an `mcpServers` block, so writing
/// this directly is the supported way to add a server it doesn't manage.
pub fn write_mcp_config(project_dir: &Path, server_name: &str, mcp_host: &str) -> anyhow::Result<()> {
    let mcp_json = serde_json::json!({
        "mcpServers": {
            server_name: {
                "type": "http",
                "url": format!("https://{mcp_host}/mcp"),
            }
        }
    });
    std::fs::write(project_dir.join(".mcp.json"), serde_json::to_string_pretty(&mcp_json)?)?;
    Ok(())
}

/// Enable `server_name` in `<config_dir>/settings.json`'s
/// `enabledMcpjsonServers`, preserving every other key already present (in
/// particular the real `permissions`/`permissionMode` the adapter derived).
/// `config_dir` must be the same directory passed to
/// `ClaudeCodePaths::with_config_dir` / matching the `SettingsScope` the
/// scenario applied under (`SettingsScope::User` resolves to that config
/// dir, not the project directory `.mcp.json` lives in — the two are not
/// the same path).
///
/// Must run **after** `EngineLifecycle::apply` — that step's own
/// `apply_settings_at` splices its plan-derived `enabledMcpjsonServers` over
/// whatever was there (`aa-devtool-claude-code/src/apply.rs::MANAGED_KEYS`),
/// and the plan has no way to know about a server this harness injected
/// out-of-band via `write_mcp_config` — so calling this before `apply` gets
/// silently overwritten back to `[]`. Confirmed empirically: without this
/// ordering, `initialize`/`tools/list` still succeed (Claude Code reads
/// `.mcp.json` directly for discovery) but no `tools/call` is ever attempted
/// — `enabledMcpjsonServers` gates invocation, not discovery.
pub fn enable_mcp_server(config_dir: &Path, server_name: &str) -> anyhow::Result<()> {
    let path = config_dir.join("settings.json");
    let mut settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let obj = settings
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("settings.json is not a JSON object"))?;
    obj.insert("enabledMcpjsonServers".to_string(), serde_json::json!([server_name]));
    std::fs::write(&path, serde_json::to_string_pretty(&settings)?)?;
    Ok(())
}

/// Idempotent variant of [`enable_mcp_server`]: writes only when
/// `enabledMcpjsonServers` doesn't already equal `[server_name]`.
///
/// `aasm run` re-applies its own managed settings keys asynchronously after
/// launch, on a schedule this harness doesn't control, so a single early
/// re-assert (or even a handful within the first ~500ms) can still lose the
/// race and leave the file clobbered back to `[]` for the rest of the
/// launch — discovery (`initialize`/`tools/list`) succeeds regardless since
/// Claude Code reads `.mcp.json` directly for that, but `tools/call` is
/// gated on this key and silently never gets attempted. A caller running
/// this for the whole launch's duration closes that race — but Claude Code
/// live-file-watches `settings.json` and reloads its permission state on
/// every write, so this must skip the write whenever the file already holds
/// the desired value, or a sustained rewrite loop interrupts the client's
/// own in-flight tool-call decision before it ever completes one.
pub fn ensure_mcp_server_enabled(config_dir: &Path, server_name: &str) -> anyhow::Result<()> {
    let path = config_dir.join("settings.json");
    let settings: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let already = settings
        .get("enabledMcpjsonServers")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| arr.len() == 1 && arr[0].as_str() == Some(server_name));
    if already {
        return Ok(());
    }
    enable_mcp_server(config_dir, server_name)
}

/// Sentinel directory helper: the path a given tool's sentinel file would be
/// written to, for assertions (`.exists()` / `!.exists()`).
pub fn sentinel_path(sentinel_dir: &Path, tool_name: &str) -> PathBuf {
    sentinel_dir.join(format!("{tool_name}.sentinel"))
}
