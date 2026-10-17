//! Minimal HTTP/1.1 request parsing for the proxy data path.
//!
//! After TLS termination the proxy needs to read the inbound request line,
//! headers, and body off the TLS stream so the credential scanner can run
//! against the real body bytes (and so the proxy can re-serialise with a
//! modified body when policy is `redact_only`).
//!
//! Scope is intentionally small: only requests with a literal
//! `Content-Length` header are fully supported. Requests using
//! `Transfer-Encoding: chunked` cannot be inspected by this parser, so the
//! request side rejects them (fail-closed, AAASM-3864) rather than forwarding
//! an un-scanned body. The response side decodes a literal `chunked` encoding
//! and reads a close-delimited (no `Content-Length`, no `Transfer-Encoding`)
//! body to EOF (AAASM-5645) — both bounded by [`MAX_BODY_LEN`] — so an MCP
//! response using either framing is captured whole rather than silently
//! emptied. This buffers the full body before scanning: an in-flight SSE
//! stream's events arrive to the client batched with the final result rather
//! than as they occur, a latency/behaviour change rather than data loss, and
//! not the true incremental scan-as-you-stream a future ticket would need.

use std::io::Read;

use flate2::bufread::{DeflateDecoder, MultiGzDecoder, ZlibDecoder};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::error::ProxyError;

/// Maximum accepted HTTP body size, in bytes (64 MiB).
///
/// `Content-Length` is attacker-controlled: a compromised agent can send
/// `Content-Length: 2000000000`, and `vec![0u8; content_length]` would attempt
/// to allocate ~2 GB per connection *before* a single body byte is read — a
/// trivial OOM against the always-on egress proxy, and absurd values abort the
/// task outright (AAASM-3891). The parser rejects any body larger than this
/// bound *before* allocating, mirroring the IPC codec's `MAX_FRAME_LEN`
/// reject-before-alloc guard (AAASM-3132). 64 MiB comfortably exceeds any
/// legitimate LLM request — including multimodal payloads with base64 image
/// data — while keeping one hostile request from exhausting memory.
pub const MAX_BODY_LEN: usize = 64 * 1024 * 1024;

/// Maximum accepted size of a single HTTP line — the request/status line or one
/// header line, in bytes (8 KiB).
///
/// AAASM-3922 (fail-closed): the head was previously read with
/// [`AsyncBufReadExt::read_line`], which grows its target `String` without
/// bound. Only request/response *bodies* were capped (`MAX_BODY_LEN`), so a
/// steered agent could send one multi-GB header line and OOM the always-on
/// proxy *before* a single body byte was read — the same reject-before-alloc gap
/// the body cap already closes, but on the header path. This bounds each line as
/// it is read.
pub const MAX_HEADER_LINE_LEN: usize = 8 * 1024;

/// Maximum accepted total size of an HTTP head — the request/status line plus
/// every header line combined, in bytes (64 KiB) (AAASM-3922). Bounds the head
/// even against many individually-small lines.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Maximum accepted number of header lines in one HTTP head (AAASM-3922).
pub const MAX_HEADER_COUNT: usize = 200;

/// Read a single `\n`-terminated line from `reader`, appending it to `out`,
/// while enforcing both a per-line cap (`max_line`) and the caller's remaining
/// total-head byte budget (`remaining`). Returns the number of bytes consumed
/// (0 on a clean EOF before any byte is read).
///
/// AAASM-3922 (fail-closed): unlike [`AsyncBufReadExt::read_line`], this bounds
/// the line *as it is read* — it pulls bytes through `fill_buf`/`consume` so an
/// oversized line is never materialised in memory — and fails closed with
/// [`ProxyError::Config`] the instant the line would exceed the cap, mirroring
/// the body cap's reject-before-alloc guard.
pub(crate) async fn read_line_capped<R>(
    reader: &mut BufReader<R>,
    out: &mut String,
    max_line: usize,
    remaining: usize,
) -> Result<usize, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let cap = max_line.min(remaining);
    let mut line: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            break; // EOF
        }
        let (chunk_len, done) = match available.iter().position(|&b| b == b'\n') {
            Some(pos) => (pos + 1, true),
            None => (available.len(), false),
        };
        if line.len() + chunk_len > cap {
            return Err(ProxyError::Config(format!(
                "HTTP header line exceeds maximum {cap} bytes; refusing (fail-closed)"
            )));
        }
        line.extend_from_slice(&available[..chunk_len]);
        reader.consume(chunk_len);
        if done {
            break;
        }
    }
    let n = line.len();
    let text = String::from_utf8(line).map_err(|_| ProxyError::Config("invalid UTF-8 in HTTP header line".into()))?;
    out.push_str(&text);
    Ok(n)
}

/// Decompress a MitM'd body carrying a single recognized `Content-Encoding`
/// token, returning the plaintext the DLP scanner should inspect.
///
/// AAASM-4156 (fail-closed): scanning a compressed body scans opaque bytes, so a
/// `gzip`/`deflate`-encoded secret matches no literal/entropy rule and slips past
/// DLP — the same un-inspectable-body gap the chunked-`Transfer-Encoding` path
/// fails closed on (see [`read_http_request`]). This decompresses recognized
/// encodings so the scanner sees the real content, and **fails closed** for
/// anything it cannot decode:
///
/// * `gzip` / `x-gzip` and `deflate` (zlib-wrapped or raw) are decompressed.
/// * Any other token — notably `br` (brotli, which would need a *new*
///   dependency), `zstd`, `compress`, or a layered `a, b` list — returns
///   [`ProxyError::Config`] so the caller withholds the body rather than
///   forwarding one it could not inspect.
///
/// The output is bounded by [`MAX_BODY_LEN`]: decompression is read through a
/// `Read::take` limiter and any output exceeding the cap is rejected, so a
/// small compressed payload cannot expand into a decompression-bomb OOM.
///
/// Callers must handle the `identity` (or absent) encoding themselves — this
/// function is only for a non-identity token and always attempts a decode.
pub fn decompress_content_encoding(encoding: &str, body: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let token = encoding.trim();
    // A comma-separated list is a layered encoding (e.g. `gzip, br`); this
    // parser decodes at most one layer, so refuse rather than half-inspect.
    if token.contains(',') {
        return Err(ProxyError::Config(format!(
            "layered Content-Encoding {token:?} is not inspectable; refusing (fail-closed)"
        )));
    }
    // Every decoder reads from a `&mut &[u8]` so leftover input is observable:
    // a decoder that stops at the end of its first stream would otherwise let
    // trailing bytes (a second gzip member, garbage) go uninspected while the
    // peer's decoder still inflates them (AAASM-6354 review F2).
    if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
        let mut src: &[u8] = body;
        let out = read_bounded(MultiGzDecoder::new(&mut src), token)?;
        require_fully_consumed(src, token)?;
        Ok(out)
    } else if token.eq_ignore_ascii_case("deflate") {
        // HTTP `deflate` is ambiguous: RFC 7230 means zlib-wrapped (RFC 1950),
        // but some servers send raw DEFLATE (RFC 1951). Try zlib first, then
        // fall back to raw; if neither decodes cleanly (or either exceeds the
        // cap), fail closed below.
        let mut src: &[u8] = body;
        match read_bounded(ZlibDecoder::new(&mut src), token) {
            Ok(plain) => {
                require_fully_consumed(src, token)?;
                Ok(plain)
            }
            Err(_) => {
                let mut raw: &[u8] = body;
                let out = read_bounded(DeflateDecoder::new(&mut raw), token)?;
                require_fully_consumed(raw, token)?;
                Ok(out)
            }
        }
    } else {
        Err(ProxyError::Config(format!(
            "unsupported Content-Encoding {token:?} is not inspectable; refusing (fail-closed)"
        )))
    }
}

fn require_fully_consumed(remaining: &[u8], token: &str) -> Result<(), ProxyError> {
    if remaining.is_empty() {
        Ok(())
    } else {
        Err(ProxyError::Config(format!(
            "{} trailing bytes after the {token} stream are not inspectable; refusing (fail-closed)",
            remaining.len()
        )))
    }
}

/// Join every `Content-Encoding` header value (`a`, `b` -> `a, b`) so repeated
/// headers read as the layered encoding a client will apply, which
/// [`decompress_content_encoding`] refuses. Reading only the first header let
/// `gzip` + `gzip` look like one layer (AAASM-6354 review F3).
pub fn joined_content_encoding(headers: &[(String, String)]) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("content-encoding"))
        .map(|(_, v)| v.trim())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// Read a decoder to completion, bounded by [`MAX_BODY_LEN`]. Returns
/// [`ProxyError::Config`] if the decoded stream would exceed the cap (a
/// decompression bomb) or the compressed input is malformed.
fn read_bounded<R: Read>(decoder: R, token: &str) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::new();
    // Read one byte past the cap so an exactly-cap-sized body is accepted while
    // anything larger is detected without buffering the whole expansion.
    let mut limited = decoder.take(MAX_BODY_LEN as u64 + 1);
    limited.read_to_end(&mut out).map_err(|e| {
        ProxyError::Config(format!(
            "failed to decompress {token} body: {e}; refusing (fail-closed)"
        ))
    })?;
    if out.len() > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "decompressed {token} body exceeds maximum {MAX_BODY_LEN} bytes; refusing (fail-closed)"
        )));
    }
    Ok(out)
}

/// A parsed HTTP request from the proxy's MitM tunnel.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    /// HTTP method (e.g. `"POST"`).
    pub method: String,
    /// Request target (e.g. `"/v1/chat/completions"`).
    pub target: String,
    /// HTTP version (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Header lines as `(name, value)` pairs preserving casing.
    pub headers: Vec<(String, String)>,
    /// Request body bytes, captured verbatim.
    pub body: Vec<u8>,
}

impl HttpRequest {
    /// All `Content-Encoding` values joined; see [`joined_content_encoding`].
    pub fn content_encoding(&self) -> Option<String> {
        joined_content_encoding(&self.headers)
    }

    /// Lookup the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Parse a single header line, returning the key-value pair or an error.
fn parse_header_line(trimmed: &str) -> Result<(String, String), ProxyError> {
    trimmed
        .split_once(':')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .ok_or_else(|| ProxyError::Config(format!("malformed header line: {trimmed:?}")))
}

/// Check if headers indicate a chunked transfer encoding (AAASM-3864).
fn has_chunked_transfer_encoding(headers: &[(String, String)]) -> bool {
    headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"))
}

/// Extract and validate Content-Length from headers (AAASM-3891).
fn extract_content_length(headers: &[(String, String)]) -> Result<usize, ProxyError> {
    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    if content_length > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "request Content-Length {content_length} exceeds maximum {MAX_BODY_LEN}; refusing (fail-closed)"
        )));
    }
    Ok(content_length)
}

/// Read and parse an HTTP/1.1 request from `reader`.
///
/// Reads the request line and headers off the stream, then reads exactly
/// `Content-Length` bytes of body. Requests without `Content-Length` are
/// treated as having an empty body.
///
/// A request advertising `Transfer-Encoding: chunked` is **rejected** with a
/// [`ProxyError::Config`] error (AAASM-3864): this parser cannot decode a
/// chunked body, so forwarding it would let an un-scanned body slip past the
/// credential and MCP gates. Failing closed drops the connection instead.
///
/// Returns `Ok(None)` on a clean EOF before any bytes are read — that
/// indicates the peer closed the connection between requests.
pub async fn read_http_request<R>(reader: &mut BufReader<R>) -> Result<Option<HttpRequest>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // AAASM-3922: cap the head (request line + headers) so an unbounded header
    // read cannot OOM the proxy.
    let mut head_budget = MAX_HEADER_BYTES;
    let mut request_line = String::new();
    let n = read_line_capped(reader, &mut request_line, MAX_HEADER_LINE_LEN, head_budget).await?;
    if n == 0 {
        return Ok(None);
    }
    head_budget -= n;

    let trimmed = request_line.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    if parts.len() != 3 {
        return Err(ProxyError::Config(format!("malformed HTTP request line: {trimmed:?}")));
    }
    let method = parts[0].to_string();
    let target = parts[1].to_string();
    let version = parts[2].to_string();

    let headers = read_headers(reader, &mut head_budget).await?;

    if has_chunked_transfer_encoding(&headers) {
        return Err(ProxyError::Config(
            "transfer-encoding: chunked request bodies are not inspectable; refusing (fail-closed)".into(),
        ));
    }

    let content_length = extract_content_length(&headers)?;
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    Ok(Some(HttpRequest {
        method,
        target,
        version,
        headers,
        body,
    }))
}

/// Read HTTP headers from a buffered reader, enforcing size limits.
async fn read_headers<R>(
    reader: &mut BufReader<R>,
    head_budget: &mut usize,
) -> Result<Vec<(String, String)>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        let n = read_line_capped(reader, &mut line, MAX_HEADER_LINE_LEN, *head_budget).await?;
        if n == 0 {
            return Err(ProxyError::Config("unexpected EOF reading headers".into()));
        }
        *head_budget -= n;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ProxyError::Config(format!(
                "HTTP request exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
            )));
        }
        headers.push(parse_header_line(trimmed)?);
    }
    Ok(headers)
}

/// Re-serialise an [`HttpRequest`] with a replacement body, rewriting the
/// `Content-Length` header to match the new body length.
///
/// All other headers are emitted verbatim in their original order; any
/// existing `Content-Length` header is dropped and re-appended with the
/// new value so the upstream sees one — and only one — accurate length.
/// `Transfer-Encoding` is stripped to keep the framing unambiguous.
pub fn serialize_http_request(req: &HttpRequest, new_body: &[u8]) -> Vec<u8> {
    serialize_http_request_with_auth(req, new_body, None)
}

/// Re-serialise an [`HttpRequest`] with a replacement body, optionally
/// **injecting** the real provider auth header at egress.
///
/// Behaves exactly like [`serialize_http_request`] for the request line,
/// `Content-Length`, and `Transfer-Encoding` handling. In addition, when
/// `injected_auth` is `Some((name, value))` (AAASM-3578, header shape made
/// provider-aware in AAASM-5926):
///
/// * every inbound `Authorization` and `x-api-key` header (case-insensitive)
///   the agent supplied is **dropped**, so the agent can never smuggle its own
///   key upstream, and
/// * a single `<name>: <value>` header carrying the real provider credential
///   is appended — `name` is `"Authorization"` for Bearer-style providers or
///   `"x-api-key"` for Anthropic's Messages API, chosen by
///   [`crate::credentials::CredentialStore::authorization_for`].
///
/// The secret bytes are written directly into the outbound buffer and are never
/// copied into an owned `String` or logged — the agent runtime therefore never
/// sees a real provider key.
///
/// When `injected_auth` is `None` the agent's own headers are forwarded
/// verbatim (the historical, backward-compatible behaviour).
///
/// AAASM-3864: any inbound `Connection` header is dropped and a single
/// `Connection: close` is emitted so the upstream tears the connection down
/// after one request/response. Combined with the proxy's single-exchange
/// relay this prevents a second request being pipelined onto the same tunnel
/// and reaching upstream un-inspected.
pub fn serialize_http_request_with_auth(
    req: &HttpRequest,
    new_body: &[u8],
    injected_auth: Option<(&str, &[u8])>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(req.body.len() + new_body.len() + 256);
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.version.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("content-length")
            || k.eq_ignore_ascii_case("transfer-encoding")
            || k.eq_ignore_ascii_case("connection")
        {
            continue;
        }
        // When injecting, strip any agent-supplied credential header so it
        // cannot reach upstream — the real key is appended below instead.
        if injected_auth.is_some() && (k.eq_ignore_ascii_case("authorization") || k.eq_ignore_ascii_case("x-api-key")) {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if let Some((name, value)) = injected_auth {
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
    // AAASM-3864 (a): force a single request/response per upstream connection so
    // a follow-up request cannot be pipelined onto the tunnel un-inspected.
    out.extend_from_slice(b"Connection: close\r\n");
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(new_body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(new_body);
    out
}

/// A parsed HTTP response from the proxy's MitM tunnel (upstream side).
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP version (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Status code (e.g. `"200"`).
    pub status_code: String,
    /// Reason phrase (e.g. `"OK"`).
    pub reason: String,
    /// Header lines as `(name, value)` pairs preserving casing.
    pub headers: Vec<(String, String)>,
    /// Response body bytes, captured verbatim.
    pub body: Vec<u8>,
}

/// The status line and headers of an upstream response, before any body byte
/// is read, plus the exact bytes they were parsed from.
///
/// Split from [`HttpResponse`] (AAASM-6356) so a caller can decide what to do
/// with the response — relay it verbatim, withhold it, or buffer and inspect
/// it — from the head alone, before committing to reading (or forwarding) the
/// body.
#[derive(Debug, Clone)]
pub struct HttpResponseHead {
    /// HTTP version (e.g. `"HTTP/1.1"`).
    pub version: String,
    /// Status code (e.g. `"200"`).
    pub status_code: String,
    /// Reason phrase (e.g. `"OK"`).
    pub reason: String,
    /// Header lines as `(name, value)` pairs preserving casing.
    pub headers: Vec<(String, String)>,
    /// The head exactly as received, through the blank line. Relaying these
    /// bytes keeps the original framing headers, which a re-serialised head
    /// would rewrite.
    pub raw: Vec<u8>,
}

impl HttpResponseHead {
    /// Whether the response is a Server-Sent Events stream: `text/event-stream`
    /// appears (case-insensitively) anywhere in ANY `Content-Type` value, so a
    /// list such as `application/json, text/event-stream` is caught too.
    pub fn is_event_stream(&self) -> bool {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .any(|(_, v)| v.to_ascii_lowercase().contains(EVENT_STREAM_TYPE))
    }
}

/// Media type of a Server-Sent Events stream.
const EVENT_STREAM_TYPE: &str = "text/event-stream";

/// Largest raw response head [`read_raw_response_head`] will buffer. Far above
/// the parser's own caps ([`MAX_HEADER_BYTES`]) on purpose: ordinary non-MCP
/// responses the parser would refuse must still be relayed, and the only
/// question asked of them is "is this an event stream".
pub const MAX_RAW_HEAD_BYTES: usize = 1024 * 1024;

/// Read the response head as raw bytes through the blank line (`CRLF CRLF`, or
/// the bare-`LF` form), leaving the body unread in `reader`. No UTF-8, header
/// count or line-length rule is applied: this is what lets an unrecognised
/// exchange be relayed byte-for-byte when its head is odd. `Ok(None)` is a
/// clean EOF before any byte; EOF mid-head returns the bytes read. Errors only
/// when the head exceeds `cap` (the caller then fails closed).
pub async fn read_raw_response_head<R>(reader: &mut BufReader<R>, cap: usize) -> Result<Option<Vec<u8>>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut head: Vec<u8> = Vec::new();
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok((!head.is_empty()).then_some(head));
        }
        // Consume byte-wise up to the terminator so the body stays in `reader`.
        let mut used = 0;
        let mut done = false;
        for &b in available {
            used += 1;
            head.push(b);
            if b == b'\n' && (head.ends_with(b"\r\n\r\n") || head.ends_with(b"\n\n")) {
                done = true;
                break;
            }
            if head.len() > cap {
                break;
            }
        }
        reader.consume(used);
        if head.len() > cap && !done {
            return Err(ProxyError::Config(format!(
                "HTTP response head exceeds maximum {cap} bytes; refusing (fail-closed)"
            )));
        }
        if done {
            return Ok(Some(head));
        }
    }
}

/// Lenient BYTE-level check whether a raw response head declares an event
/// stream: any `Content-Type` header line (name ASCII-case-insensitive, an
/// obs-fold continuation counted as part of its header, non-UTF-8 bytes
/// tolerated) whose value contains `text/event-stream` in any case.
pub fn raw_head_is_event_stream(raw: &[u8]) -> bool {
    let mut in_content_type = false;
    for line in raw.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let value: &[u8] = if line.first().is_some_and(|b| matches!(b, b' ' | b'\t')) {
            if !in_content_type {
                continue;
            }
            line
        } else {
            match line.iter().position(|&b| b == b':') {
                Some(colon) if trim_ows(&line[..colon]).eq_ignore_ascii_case(b"content-type") => {
                    in_content_type = true;
                    &line[colon + 1..]
                }
                _ => {
                    in_content_type = false;
                    continue;
                }
            }
        };
        if value
            .windows(EVENT_STREAM_TYPE.len())
            .any(|w| w.eq_ignore_ascii_case(EVENT_STREAM_TYPE.as_bytes()))
        {
            return true;
        }
    }
    false
}

/// `bytes` without leading/trailing space or tab (`<[u8]>::trim_ascii` is above the MSRV).
fn trim_ows(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t'))
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|b| !matches!(b, b' ' | b'\t'))
        .map_or(start, |i| i + 1);
    &bytes[start..end]
}

/// True when the raw head's status line is an interim `1xx` response other than
/// `101` (`100 Continue`, `103 Early Hints`): a head that precedes the real
/// response on the same connection.
pub fn raw_head_is_interim(raw: &[u8]) -> bool {
    let first = raw.split(|&b| b == b'\n').next().unwrap_or(&[]);
    let first = first.strip_suffix(b"\r").unwrap_or(first);
    let mut parts = first.split(|&b| b == b' ').filter(|p| !p.is_empty());
    let (_version, status) = (parts.next(), parts.next());
    matches!(status, Some(code) if code.len() == 3 && code[0] == b'1' && code != b"101"
        && code.iter().all(u8::is_ascii_digit))
}

/// Parse a raw head (as returned by [`read_raw_response_head`]) with the same
/// caps and strictness as [`read_http_response_head`].
pub fn parse_raw_response_head(raw: &[u8]) -> Result<HttpResponseHead, ProxyError> {
    let text = std::str::from_utf8(raw)
        .map_err(|_| ProxyError::Config("invalid UTF-8 in HTTP response head; refusing (fail-closed)".into()))?;
    if raw.len() > MAX_HEADER_BYTES {
        return Err(ProxyError::Config(format!(
            "HTTP response head exceeds maximum {MAX_HEADER_BYTES} bytes; refusing (fail-closed)"
        )));
    }
    let mut lines = text.split_inclusive('\n');
    let status_line = lines.next().unwrap_or("");
    let mut terminated = false;
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in std::iter::once(status_line).chain(lines.clone()) {
        if line.len() > MAX_HEADER_LINE_LEN {
            return Err(ProxyError::Config(format!(
                "HTTP header line exceeds maximum {MAX_HEADER_LINE_LEN} bytes; refusing (fail-closed)"
            )));
        }
    }
    let trimmed = status_line.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyError::Config(format!("malformed HTTP status line: {trimmed:?}")));
    }
    for line in lines {
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            terminated = true;
            break;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ProxyError::Config(format!(
                "HTTP response exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
            )));
        }
        let Some((k, v)) = trimmed.split_once(':') else {
            return Err(ProxyError::Config(format!(
                "malformed response header line: {trimmed:?}"
            )));
        };
        headers.push((k.trim().to_string(), v.trim().to_string()));
    }
    if !terminated {
        return Err(ProxyError::Config("unexpected EOF reading response headers".into()));
    }
    Ok(HttpResponseHead {
        version: parts[0].to_string(),
        status_code: parts[1].to_string(),
        reason: parts.get(2).copied().unwrap_or("").to_string(),
        headers,
        raw: raw.to_vec(),
    })
}

/// Read and parse an HTTP/1.1 response from `reader`.
///
/// Companion to [`read_http_request`] but for the upstream side of the
/// MitM tunnel. Reads exactly `Content-Length` bytes of body when present; a
/// literal `Transfer-Encoding: chunked` is decoded via [`read_chunked_body`]
/// (AAASM-5645); a response with neither header is close-delimited and read
/// to EOF, bounded by [`MAX_BODY_LEN`] (`204`/`304` are exempted — they are
/// body-less by definition and must not wait for the connection to close).
/// Any other `Transfer-Encoding` token (e.g. a layered `gzip, chunked`) is
/// rejected rather than guessed at, mirroring the request side's fail-closed
/// stance on an un-inspectable body.
///
/// Used by the AAASM-1930 MCP path to capture upstream responses for
/// credential scanning before the bytes reach the client.
pub async fn read_http_response<R>(reader: &mut BufReader<R>) -> Result<Option<HttpResponse>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let Some(head) = read_http_response_head(reader).await? else {
        return Ok(None);
    };
    let body = read_http_response_body(&head, reader).await?;
    Ok(Some(HttpResponse {
        version: head.version,
        status_code: head.status_code,
        reason: head.reason,
        headers: head.headers,
        body,
    }))
}

/// Read and parse only the status line and headers of an HTTP/1.1 response,
/// with the same caps as [`read_http_response`]. Leaves the body unread in
/// `reader`. `Ok(None)` is a clean EOF before any byte.
pub async fn read_http_response_head<R>(reader: &mut BufReader<R>) -> Result<Option<HttpResponseHead>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    // AAASM-3922: bound the response head the same way as the request head so a
    // hostile upstream cannot OOM the proxy with an unbounded header read.
    let mut head_budget = MAX_HEADER_BYTES;
    let mut status_line = String::new();
    let n = read_line_capped(reader, &mut status_line, MAX_HEADER_LINE_LEN, head_budget).await?;
    if n == 0 {
        return Ok(None);
    }
    head_budget -= n;
    let mut raw = status_line.clone().into_bytes();
    let trimmed = status_line.trim_end_matches(['\r', '\n']);
    let parts: Vec<&str> = trimmed.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return Err(ProxyError::Config(format!("malformed HTTP status line: {trimmed:?}")));
    }
    let version = parts[0].to_string();
    let status_code = parts[1].to_string();
    let reason = parts.get(2).copied().unwrap_or("").to_string();

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        let n = read_line_capped(reader, &mut line, MAX_HEADER_LINE_LEN, head_budget).await?;
        if n == 0 {
            return Err(ProxyError::Config("unexpected EOF reading response headers".into()));
        }
        head_budget -= n;
        raw.extend_from_slice(line.as_bytes());
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ProxyError::Config(format!(
                "HTTP response exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
            )));
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            return Err(ProxyError::Config(format!(
                "malformed response header line: {trimmed:?}"
            )));
        }
    }

    Ok(Some(HttpResponseHead {
        version,
        status_code,
        reason,
        headers,
        raw,
    }))
}

/// Read the body that follows `head`, under the framing and caps documented on
/// [`read_http_response`].
pub async fn read_http_response_body<R>(
    head: &HttpResponseHead,
    reader: &mut BufReader<R>,
) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let headers = &head.headers;
    let status_code = head.status_code.as_str();
    let content_length_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .map(|(_, v)| v.as_str());
    let transfer_encoding = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("transfer-encoding"))
        .map(|(_, v)| v.trim().to_ascii_lowercase());

    let body = match (content_length_header, transfer_encoding.as_deref()) {
        // A literal `chunked` encoding is decoded in full (AAASM-5645). Any
        // other token — including a layered `gzip, chunked` — cannot be
        // decoded by this parser (chunk-framing is not the only thing a
        // second token could mean), so it fails closed rather than guessing.
        (_, Some("chunked")) => read_chunked_body(reader).await?,
        (_, Some(other)) => {
            return Err(ProxyError::Config(format!(
                "response Transfer-Encoding {other:?} is not inspectable; refusing (fail-closed)"
            )));
        }
        (Some(raw), None) => {
            let content_length: usize = raw
                .parse()
                .map_err(|_| ProxyError::Config(format!("malformed response Content-Length {raw:?}")))?;
            // AAASM-3891 (fail-closed): reject an over-cap Content-Length
            // *before* allocating, so a hostile upstream response cannot OOM
            // the proxy the same way a hostile request could.
            if content_length > MAX_BODY_LEN {
                return Err(ProxyError::Config(format!(
                    "response Content-Length {content_length} exceeds maximum {MAX_BODY_LEN}; refusing (fail-closed)"
                )));
            }
            let mut body = vec![0u8; content_length];
            if content_length > 0 {
                reader.read_exact(&mut body).await?;
            }
            body
        }
        // Neither header: close-delimited framing (AAASM-5645). `204 No
        // Content` and `304 Not Modified` are body-less by definition and
        // must not block waiting for a connection close that a
        // `Connection: close`-forcing client (this proxy) will itself cause
        // only *after* the response is read — reading to EOF here would
        // deadlock against our own request-side framing.
        (None, None) if status_code == "204" || status_code == "304" => Vec::new(),
        (None, None) => read_to_eof_capped(reader).await?,
    };

    Ok(body)
}

/// Decode a `Transfer-Encoding: chunked` body from `reader` (AAASM-5645).
///
/// Reads chunk-size lines (bounded the same way as a header line, via
/// [`read_line_capped`], so a hostile chunk-size line cannot itself OOM the
/// proxy), splits off any chunk extension (`;`-delimited — accepted but
/// ignored, per RFC 7230 §4.1.1), and copies each chunk's data followed by
/// its trailing CRLF-consuming (not data-appending) delimiter. The running
/// total is checked against [`MAX_BODY_LEN`] *before* each chunk is appended
/// — reject-before-alloc, mirroring [`extract_content_length`] — so a chunked
/// body cannot exceed the same cap a `Content-Length` body is held to.
///
/// After the terminating zero-length chunk, any trailer header lines are
/// consumed and discarded (they are not merged into the response's own
/// headers) up to the final blank line. An EOF at any point before the
/// terminating chunk is a [`ProxyError::Config`] — a truncated chunked body
/// must fail closed, never silently return whatever was read so far.
async fn read_chunked_body<R>(reader: &mut BufReader<R>) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    loop {
        let mut size_line = String::new();
        let n = read_line_capped(reader, &mut size_line, MAX_HEADER_LINE_LEN, MAX_HEADER_LINE_LEN).await?;
        if n == 0 {
            return Err(ProxyError::Config(
                "unexpected EOF reading chunk size; refusing (fail-closed)".into(),
            ));
        }
        let size_text = size_line.trim_end_matches(['\r', '\n']);
        let size_hex = size_text.split(';').next().unwrap_or("").trim();
        let chunk_size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| ProxyError::Config(format!("malformed chunk size: {size_text:?}")))?;

        if chunk_size == 0 {
            // Terminating chunk: consume trailer lines (discarded, not merged
            // into the response headers) through the final blank line.
            loop {
                let mut trailer_line = String::new();
                let n = read_line_capped(reader, &mut trailer_line, MAX_HEADER_LINE_LEN, MAX_HEADER_LINE_LEN).await?;
                if n == 0 {
                    return Err(ProxyError::Config(
                        "unexpected EOF reading chunked trailer; refusing (fail-closed)".into(),
                    ));
                }
                if trailer_line.trim_end_matches(['\r', '\n']).is_empty() {
                    break;
                }
            }
            return Ok(body);
        }

        if body.len() + chunk_size > MAX_BODY_LEN {
            return Err(ProxyError::Config(format!(
                "chunked response body exceeds maximum {MAX_BODY_LEN} bytes; refusing (fail-closed)"
            )));
        }

        let start = body.len();
        body.resize(start + chunk_size, 0);
        reader.read_exact(&mut body[start..]).await?;

        // Each chunk's data is followed by a CRLF that is part of the framing,
        // not the payload — consume and discard it.
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(ProxyError::Config(
                "malformed chunk terminator; refusing (fail-closed)".into(),
            ));
        }
    }
}

/// Read a close-delimited response body (no `Content-Length`, no
/// `Transfer-Encoding`) to EOF, bounded by [`MAX_BODY_LEN`] (AAASM-5645).
///
/// Reads one byte past the cap so an exactly-cap-sized body is accepted while
/// anything larger is detected without buffering the full excess, mirroring
/// [`read_bounded`]'s over-cap detection shape.
async fn read_to_eof_capped<R>(reader: &mut BufReader<R>) -> Result<Vec<u8>, ProxyError>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut body = Vec::new();
    let mut limited = reader.take(MAX_BODY_LEN as u64 + 1);
    limited.read_to_end(&mut body).await?;
    if body.len() > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "close-delimited response body exceeds maximum {MAX_BODY_LEN} bytes; refusing (fail-closed)"
        )));
    }
    Ok(body)
}

/// Re-serialise an [`HttpResponse`] with a replacement body, rewriting the
/// `Content-Length` header to match the new body length.
///
/// Mirrors [`serialize_http_request`]'s contract for the upstream side:
/// existing `Content-Length` and `Transfer-Encoding` headers are dropped
/// and replaced with a single fresh `Content-Length`, so the client sees
/// unambiguous framing.
pub fn serialize_http_response(resp: &HttpResponse, new_body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(resp.body.len() + new_body.len() + 256);
    out.extend_from_slice(resp.version.as_bytes());
    out.push(b' ');
    out.extend_from_slice(resp.status_code.as_bytes());
    if !resp.reason.is_empty() {
        out.push(b' ');
        out.extend_from_slice(resp.reason.as_bytes());
    }
    out.extend_from_slice(b"\r\n");

    for (k, v) in &resp.headers {
        if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("transfer-encoding") {
            continue;
        }
        out.extend_from_slice(k.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(v.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"Content-Length: ");
    out.extend_from_slice(new_body.len().to_string().as_bytes());
    out.extend_from_slice(b"\r\n\r\n");
    out.extend_from_slice(new_body);
    out
}

/// Largest piece [`BodyStream::next_piece`] returns, so a long chunk or a fast
/// close-delimited body is handed to the caller in bounded steps.
const BODY_STREAM_PIECE: usize = 8 * 1024;

/// Incremental reader of a response body, for streams that cannot be buffered
/// (AAASM-6356 PR2: Server-Sent Events). Yields the *decoded* payload — chunk
/// framing is removed — in bounded pieces, with the same fail-closed framing
/// rules as [`read_http_response_body`]: a literal `chunked` encoding, a
/// `Content-Length`, or close-delimited. Any other `Transfer-Encoding` is
/// refused when the stream is opened, and a truncated chunked body is an error
/// rather than a quiet end.
#[derive(Debug)]
pub struct BodyStream {
    framing: BodyFraming,
}

#[derive(Debug)]
enum BodyFraming {
    /// Inside a chunked body; `remaining` payload bytes are left in the current
    /// chunk (0 means the next thing on the wire is a chunk-size line).
    Chunked {
        remaining: usize,
    },
    Length {
        remaining: usize,
    },
    UntilClose,
    Done,
}

impl BodyStream {
    /// Pick the framing from `head`.
    pub fn new(head: &HttpResponseHead) -> Result<Self, ProxyError> {
        let find = |name: &str| {
            head.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.trim().to_ascii_lowercase())
        };
        let framing = match (find("content-length"), find("transfer-encoding").as_deref()) {
            (_, Some("chunked")) => BodyFraming::Chunked { remaining: 0 },
            (_, Some(other)) => {
                return Err(ProxyError::Config(format!(
                    "response Transfer-Encoding {other:?} is not inspectable; refusing (fail-closed)"
                )));
            }
            (Some(raw), None) => BodyFraming::Length {
                remaining: raw
                    .parse()
                    .map_err(|_| ProxyError::Config(format!("malformed response Content-Length {raw:?}")))?,
            },
            (None, None) => BodyFraming::UntilClose,
        };
        Ok(Self { framing })
    }

    /// The next decoded piece, or `None` once the body has ended cleanly.
    pub async fn next_piece<R>(&mut self, reader: &mut BufReader<R>) -> Result<Option<Vec<u8>>, ProxyError>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        loop {
            match &mut self.framing {
                BodyFraming::Done => return Ok(None),
                BodyFraming::UntilClose => {
                    let mut piece = vec![0u8; BODY_STREAM_PIECE];
                    let n = reader.read(&mut piece).await?;
                    if n == 0 {
                        self.framing = BodyFraming::Done;
                        return Ok(None);
                    }
                    piece.truncate(n);
                    return Ok(Some(piece));
                }
                BodyFraming::Length { remaining } => {
                    if *remaining == 0 {
                        self.framing = BodyFraming::Done;
                        return Ok(None);
                    }
                    let mut piece = vec![0u8; (*remaining).min(BODY_STREAM_PIECE)];
                    let n = reader.read(&mut piece).await?;
                    if n == 0 {
                        return Err(ProxyError::Config(
                            "response body ended before Content-Length; refusing (fail-closed)".into(),
                        ));
                    }
                    *remaining -= n;
                    piece.truncate(n);
                    return Ok(Some(piece));
                }
                BodyFraming::Chunked { remaining } => {
                    if *remaining > 0 {
                        let mut piece = vec![0u8; (*remaining).min(BODY_STREAM_PIECE)];
                        let n = reader.read(&mut piece).await?;
                        if n == 0 {
                            return Err(ProxyError::Config(
                                "unexpected EOF inside a chunk; refusing (fail-closed)".into(),
                            ));
                        }
                        *remaining -= n;
                        piece.truncate(n);
                        if *remaining == 0 {
                            let mut crlf = [0u8; 2];
                            reader.read_exact(&mut crlf).await?;
                            if &crlf != b"\r\n" {
                                return Err(ProxyError::Config(
                                    "malformed chunk terminator; refusing (fail-closed)".into(),
                                ));
                            }
                        }
                        return Ok(Some(piece));
                    }
                    let mut size_line = String::new();
                    let n = read_line_capped(reader, &mut size_line, MAX_HEADER_LINE_LEN, MAX_HEADER_LINE_LEN).await?;
                    if n == 0 {
                        return Err(ProxyError::Config(
                            "unexpected EOF reading chunk size; refusing (fail-closed)".into(),
                        ));
                    }
                    let size_text = size_line.trim_end_matches(['\r', '\n']);
                    let size_hex = size_text.split(';').next().unwrap_or("").trim();
                    let chunk_size = usize::from_str_radix(size_hex, 16)
                        .map_err(|_| ProxyError::Config(format!("malformed chunk size: {size_text:?}")))?;
                    if chunk_size == 0 {
                        loop {
                            let mut trailer = String::new();
                            let n = read_line_capped(reader, &mut trailer, MAX_HEADER_LINE_LEN, MAX_HEADER_LINE_LEN)
                                .await?;
                            if n == 0 {
                                return Err(ProxyError::Config(
                                    "unexpected EOF reading chunked trailer; refusing (fail-closed)".into(),
                                ));
                            }
                            if trailer.trim_end_matches(['\r', '\n']).is_empty() {
                                break;
                            }
                        }
                        self.framing = BodyFraming::Done;
                        return Ok(None);
                    }
                    *remaining = chunk_size;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn make_reader(bytes: &[u8]) -> BufReader<Cursor<Vec<u8>>> {
        BufReader::new(Cursor::new(bytes.to_vec()))
    }

    #[tokio::test]
    async fn parses_post_with_content_length_body() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 13\r\n\
                    \r\n\
                    {\"hello\":1}\r\n";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().expect("request present");
        assert_eq!(req.method, "POST");
        assert_eq!(req.target, "/v1/chat/completions");
        assert_eq!(req.version, "HTTP/1.1");
        assert_eq!(req.header("host"), Some("api.openai.com"));
        assert_eq!(req.body.len(), 13);
        assert_eq!(&req.body, b"{\"hello\":1}\r\n");
    }

    #[tokio::test]
    async fn parses_get_with_no_body() {
        let raw = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().expect("request present");
        assert_eq!(req.method, "GET");
        assert!(req.body.is_empty());
    }

    #[tokio::test]
    async fn returns_none_on_clean_eof() {
        let mut reader = make_reader(b"");
        let req = read_http_request(&mut reader).await.unwrap();
        assert!(req.is_none(), "EOF before request line must return None");
    }

    #[tokio::test]
    async fn header_lookup_is_case_insensitive() {
        let raw = b"GET / HTTP/1.1\r\nX-Custom: v\r\n\r\n";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();
        assert_eq!(req.header("x-custom"), Some("v"));
        assert_eq!(req.header("X-CUSTOM"), Some("v"));
    }

    #[tokio::test]
    async fn serialize_rewrites_content_length_for_smaller_body() {
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 20\r\n\
                    \r\n\
                    01234567890123456789";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();

        let new_body = b"short";
        let wire = serialize_http_request(&req, new_body);
        let text = std::str::from_utf8(&wire).unwrap();

        assert!(text.starts_with("POST /v1/chat/completions HTTP/1.1\r\n"));
        assert!(text.contains("Host: api.openai.com\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        // Old length is dropped; only the new value appears, exactly once.
        assert_eq!(text.matches("Content-Length: 5\r\n").count(), 1);
        assert!(!text.contains("Content-Length: 20"));
        // Body is the new bytes after the blank line.
        assert!(text.ends_with("\r\n\r\nshort"));
    }

    #[test]
    fn serialize_drops_transfer_encoding_header() {
        // `read_http_request` now rejects chunked requests (AAASM-3864), so the
        // serializer's Transfer-Encoding stripping is exercised by constructing
        // the request directly — it remains defence-in-depth for any caller that
        // hands the serializer a request carrying a stale framing header.
        let req = HttpRequest {
            method: "POST".into(),
            target: "/".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "x.example.com".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
            ],
            body: Vec::new(),
        };
        let wire = serialize_http_request(&req, b"hi");
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(
            !text.to_ascii_lowercase().contains("transfer-encoding"),
            "serialized request must drop Transfer-Encoding when replacing body, got: {text}",
        );
        assert!(text.contains("Content-Length: 2\r\n"));
    }

    #[test]
    fn serialize_forces_connection_close_and_strips_inbound_connection() {
        // AAASM-3864 (a): every forwarded request must carry exactly one
        // `Connection: close` so upstream tears the tunnel down after one
        // exchange, and any inbound Connection header the agent supplied (e.g.
        // keep-alive) must be dropped.
        let req = HttpRequest {
            method: "POST".into(),
            target: "/v1/x".into(),
            version: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "api.openai.com".into()),
                ("Connection".into(), "keep-alive".into()),
            ],
            body: Vec::new(),
        };
        let wire = serialize_http_request(&req, b"hi");
        let text = std::str::from_utf8(&wire).unwrap();
        assert_eq!(
            text.to_ascii_lowercase().matches("connection:").count(),
            1,
            "exactly one Connection header expected: {text}"
        );
        assert!(
            text.contains("Connection: close\r\n"),
            "must force Connection: close: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("keep-alive"),
            "inbound keep-alive Connection header must be dropped: {text}"
        );
    }

    #[tokio::test]
    async fn inject_auth_strips_agent_header_and_appends_real_key() {
        // AAASM-3578: an agent request carrying its own (bogus) Authorization
        // and x-api-key must reach upstream with both stripped and the injected
        // real key appended exactly once.
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Authorization: Bearer agent-bogus-token\r\n\
                    x-api-key: agent-bogus-key\r\n\
                    Content-Length: 2\r\n\
                    \r\n\
                    hi";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();

        let wire =
            serialize_http_request_with_auth(&req, &req.body, Some(("Authorization", b"Bearer sk-REAL-PROVIDER-KEY")));
        let text = std::str::from_utf8(&wire).unwrap();

        assert!(
            !text.contains("agent-bogus-token"),
            "agent Authorization must be stripped: {text}"
        );
        assert!(
            !text.contains("agent-bogus-key"),
            "agent x-api-key must be stripped: {text}"
        );
        assert_eq!(
            text.matches("Authorization: Bearer sk-REAL-PROVIDER-KEY\r\n").count(),
            1,
            "injected Authorization must appear exactly once: {text}"
        );
        assert!(
            text.contains("Host: api.openai.com\r\n"),
            "non-credential headers preserved"
        );
    }

    #[tokio::test]
    async fn inject_auth_x_api_key_writes_that_header_not_authorization() {
        // AAASM-5926: an Anthropic-classified credential is handed to the
        // serializer as an ("x-api-key", <key>) pair; the wire header name
        // must follow that pair, not default to Authorization.
        let raw = b"POST /v1/messages HTTP/1.1\r\n\
                    Host: api.anthropic.com\r\n\
                    x-api-key: agent-bogus-key\r\n\
                    Content-Length: 2\r\n\
                    \r\n\
                    hi";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();

        let wire = serialize_http_request_with_auth(&req, &req.body, Some(("x-api-key", b"sk-ant-REAL-KEY")));
        let text = std::str::from_utf8(&wire).unwrap();

        assert!(
            !text.contains("agent-bogus-key"),
            "agent x-api-key must be stripped: {text}"
        );
        assert_eq!(
            text.matches("x-api-key: sk-ant-REAL-KEY\r\n").count(),
            1,
            "injected x-api-key must appear exactly once: {text}"
        );
        assert!(
            !text.to_ascii_lowercase().contains("authorization:"),
            "no Authorization header should be emitted for x-api-key injection: {text}"
        );
    }

    #[tokio::test]
    async fn inject_auth_none_forwards_agent_header_verbatim() {
        // Backward compatibility: with no injected key the agent's own
        // Authorization passes through unchanged (historical behaviour).
        let raw = b"POST / HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Authorization: Bearer agent-token\r\n\
                    Content-Length: 2\r\n\
                    \r\n\
                    hi";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();
        let wire = serialize_http_request_with_auth(&req, &req.body, None);
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(
            text.contains("Authorization: Bearer agent-token\r\n"),
            "agent header forwarded: {text}"
        );
    }

    // ── request-side error branches ─────────────────────────────────────────

    #[tokio::test]
    async fn malformed_request_line_is_config_error() {
        // A request line that does not split into method/target/version must be
        // rejected rather than silently mis-parsed.
        let mut reader = make_reader(b"GET-ONLY\r\n\r\n");
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn malformed_header_line_is_config_error() {
        // A header line with no colon separator is malformed.
        let mut reader = make_reader(b"GET / HTTP/1.1\r\nNoColonHere\r\n\r\n");
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_chunked_transfer_encoding_request() {
        // AAASM-3864: a request advertising a chunked body cannot be inspected
        // by this Content-Length-only parser, so it must fail closed rather than
        // yield an empty body that forwards an un-scanned payload upstream.
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    5\r\nhello\r\n0\r\n\r\n";
        let mut reader = make_reader(raw);
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("chunked")),
            "expected fail-closed chunked rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_request_content_length_over_cap_without_allocating() {
        // AAASM-3891: a Content-Length far above MAX_BODY_LEN (here ~2 GB, the
        // exploit value) must be rejected at the header stage — before any
        // `vec![0u8; content_length]` allocation — so a single hostile request
        // cannot OOM the proxy. The reader holds only the header bytes, proving
        // the rejection happens before the (absent) 2 GB body is touched.
        let raw = b"POST /v1/chat/completions HTTP/1.1\r\n\
                    Host: api.openai.com\r\n\
                    Content-Length: 2000000000\r\n\
                    \r\n";
        let mut reader = make_reader(raw);
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("exceeds maximum")),
            "expected over-cap rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn accepts_request_content_length_at_cap_boundary() {
        // A Content-Length exactly at the cap is allowed (the boundary is
        // inclusive); only values strictly greater are rejected. The body bytes
        // are absent here, so the parse fails on EOF *after* passing the cap
        // check — proving the cap itself did not reject the boundary value.
        let raw = format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Length: {MAX_BODY_LEN}\r\n\r\n");
        let mut reader = make_reader(raw.as_bytes());
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            !matches!(&err, ProxyError::Config(msg) if msg.contains("exceeds maximum")),
            "cap boundary must not be rejected by the cap check, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_response_content_length_over_cap_without_allocating() {
        // AAASM-3891: the response side applies the same reject-before-alloc cap
        // so a hostile upstream response cannot OOM the proxy.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Length: 2000000000\r\n\
                    \r\n";
        let mut reader = make_reader(raw);
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("exceeds maximum")),
            "expected over-cap rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn unexpected_eof_reading_request_headers_is_error() {
        // Stream ends after the request line, before the header-terminating
        // blank line — this is a truncated request, not a clean inter-request
        // EOF, so it must surface as an error.
        let mut reader = make_reader(b"GET / HTTP/1.1\r\n");
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    // ── response-side parsing ───────────────────────────────────────────────

    #[tokio::test]
    async fn parses_response_with_content_length_body() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Content-Length: 11\r\n\
                    \r\n\
                    {\"ok\":true}";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert_eq!(resp.version, "HTTP/1.1");
        assert_eq!(resp.status_code, "200");
        assert_eq!(resp.reason, "OK");
        assert_eq!(&resp.body, b"{\"ok\":true}");
    }

    #[tokio::test]
    async fn response_returns_none_on_clean_eof() {
        let mut reader = make_reader(b"");
        assert!(read_http_response(&mut reader).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn response_with_no_reason_phrase_parses() {
        // A status line with only version + code (no reason phrase) is valid;
        // the reason is captured as an empty string.
        let raw = b"HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader).await.unwrap().unwrap();
        assert_eq!(resp.status_code, "204");
        assert_eq!(resp.reason, "");
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn malformed_status_line_is_config_error() {
        // Fewer than two whitespace-separated parts is not a status line.
        let mut reader = make_reader(b"GARBAGE\r\n\r\n");
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn malformed_response_header_line_is_config_error() {
        let mut reader = make_reader(b"HTTP/1.1 200 OK\r\nNoColonHeader\r\n\r\n");
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn unexpected_eof_reading_response_headers_is_error() {
        let mut reader = make_reader(b"HTTP/1.1 200 OK\r\n");
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    // ── response-side re-serialisation ──────────────────────────────────────

    #[test]
    fn serialize_response_rewrites_content_length_and_drops_transfer_encoding() {
        // Built directly (AAASM-5645): a response cannot validly carry both a
        // literal Content-Length and a chunked Transfer-Encoding at once
        // (RFC 7230 §3.3.3), and `read_http_response` now decodes a genuine
        // `chunked` body rather than falling back to Content-Length — so this
        // stays a serializer-only test, exercising `serialize_http_response`'s
        // stale-header stripping the same way `serialize_drops_transfer_encoding_header`
        // does on the request side.
        let resp = HttpResponse {
            version: "HTTP/1.1".into(),
            status_code: "200".into(),
            reason: "OK".into(),
            headers: vec![
                ("Content-Type".into(), "application/json".into()),
                ("Transfer-Encoding".into(), "chunked".into()),
                ("Content-Length".into(), "3".into()),
            ],
            body: b"old".to_vec(),
        };

        let new_body = b"redacted";
        let wire = serialize_http_response(&resp, new_body);
        let text = std::str::from_utf8(&wire).unwrap();

        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        // Stale framing headers are dropped and replaced by one accurate length.
        assert!(
            !text.to_ascii_lowercase().contains("transfer-encoding"),
            "Transfer-Encoding must be stripped: {text}"
        );
        // The original Content-Length: 3 is dropped; only the new value remains.
        assert_eq!(text.matches("Content-Length:").count(), 1);
        assert_eq!(text.matches("Content-Length: 8\r\n").count(), 1);
        assert!(text.ends_with("\r\n\r\nredacted"));
    }

    #[tokio::test]
    async fn serialize_response_omits_empty_reason_phrase() {
        // When the parsed response carried no reason phrase, the re-serialised
        // status line must not emit a trailing space after the code.
        let raw = b"HTTP/1.1 204\r\nContent-Length: 0\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader).await.unwrap().unwrap();
        let wire = serialize_http_response(&resp, b"");
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(
            text.starts_with("HTTP/1.1 204\r\n"),
            "no trailing reason space: {text:?}"
        );
    }

    // ── header-cap (OOM) guards (AAASM-3922) ────────────────────────────────

    #[tokio::test]
    async fn rejects_oversized_request_header_line_before_oom() {
        // AAASM-3922: a single header line larger than MAX_HEADER_LINE_LEN must
        // be rejected *as it is read* — before the old unbounded read_line could
        // buffer a multi-GB line and OOM the proxy. The over-cap line here is
        // ~8 KiB+1; the reader holds only the head, proving the cap fires at the
        // header stage rather than after a giant allocation.
        let big_value = "a".repeat(MAX_HEADER_LINE_LEN + 1);
        let raw = format!("GET / HTTP/1.1\r\nX-Big: {big_value}\r\n\r\n");
        let mut reader = make_reader(raw.as_bytes());
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("exceeds maximum")),
            "expected over-cap header rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_request_with_too_many_headers() {
        // AAASM-3922: more than MAX_HEADER_COUNT header lines is refused,
        // bounding the head against a flood of individually-small lines.
        let mut raw = String::from("GET / HTTP/1.1\r\n");
        for i in 0..=MAX_HEADER_COUNT {
            raw.push_str(&format!("X-H{i}: v\r\n"));
        }
        raw.push_str("\r\n");
        let mut reader = make_reader(raw.as_bytes());
        let err = read_http_request(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("header lines")),
            "expected too-many-headers rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn header_within_caps_still_parses() {
        // Regression: a normal-sized header well under every cap must still
        // parse — the OOM guard must not reject legitimate traffic.
        let raw = b"POST / HTTP/1.1\r\nHost: api.openai.com\r\nContent-Length: 2\r\n\r\nhi";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().expect("request present");
        assert_eq!(req.header("host"), Some("api.openai.com"));
        assert_eq!(&req.body, b"hi");
    }

    #[tokio::test]
    async fn rejects_oversized_response_header_line_before_oom() {
        // AAASM-3922: the response side applies the same per-line cap so a
        // hostile upstream cannot OOM the proxy with an unbounded header read.
        let big_value = "a".repeat(MAX_HEADER_LINE_LEN + 1);
        let raw = format!("HTTP/1.1 200 OK\r\nX-Big: {big_value}\r\n\r\n");
        let mut reader = make_reader(raw.as_bytes());
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(msg) if msg.contains("exceeds maximum")),
            "expected over-cap header rejection, got: {err:?}"
        );
    }

    // ── Content-Encoding decompression (AAASM-4156) ─────────────────────────

    use std::io::Write;

    use flate2::write::{DeflateEncoder, GzEncoder, ZlibEncoder};
    use flate2::Compression;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn raw_deflate(data: &[u8]) -> Vec<u8> {
        let mut e = DeflateEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn decompress_gzip_roundtrips_plaintext() {
        let plain = b"a secret sk-TESTONLY-NOT-REAL body the scanner must see";
        let out = decompress_content_encoding("gzip", &gzip(plain)).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn decompress_encoding_token_is_case_insensitive_and_trimmed() {
        let plain = b"hello";
        assert_eq!(decompress_content_encoding("  GZip  ", &gzip(plain)).unwrap(), plain);
    }

    #[test]
    fn decompress_deflate_accepts_zlib_wrapped() {
        let plain = b"zlib-wrapped deflate body";
        assert_eq!(decompress_content_encoding("deflate", &zlib(plain)).unwrap(), plain);
    }

    #[test]
    fn decompress_deflate_accepts_raw_stream() {
        // Some servers send raw RFC-1951 DEFLATE for `Content-Encoding: deflate`;
        // the zlib-then-raw fallback must decode it too.
        let plain = b"raw deflate body";
        assert_eq!(
            decompress_content_encoding("deflate", &raw_deflate(plain)).unwrap(),
            plain
        );
    }

    #[test]
    fn decompress_unsupported_brotli_fails_closed() {
        // `br` would need a new dependency, so it is intentionally refused rather
        // than forwarded un-inspected.
        let err = decompress_content_encoding("br", b"\x1b\x00\x00").unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("unsupported") && m.contains("fail-closed")),
            "expected unsupported-encoding fail-closed, got: {err:?}"
        );
    }

    #[test]
    fn decompress_layered_encoding_fails_closed() {
        // A comma-separated list is a layered encoding this one-layer decoder
        // cannot fully invert, so it must fail closed.
        let err = decompress_content_encoding("gzip, br", &gzip(b"x")).unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("layered")),
            "expected layered-encoding fail-closed, got: {err:?}"
        );
    }

    #[test]
    fn decompress_malformed_stream_fails_closed() {
        // Bytes that are not a valid gzip stream must error rather than yield a
        // partial/empty body the scanner would treat as clean.
        let err = decompress_content_encoding("gzip", b"this is not a gzip stream").unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got: {err:?}"
        );
    }

    #[test]
    fn decompress_bomb_is_bounded_by_max_body_len() {
        // A tiny gzip stream that expands past MAX_BODY_LEN must be rejected —
        // the Read::take limiter caps the expansion so a decompression bomb
        // cannot OOM the proxy.
        let bomb = gzip(&vec![0u8; MAX_BODY_LEN + 1024]);
        assert!(
            bomb.len() < 1024 * 1024,
            "a highly-compressible bomb is tiny on the wire ({} bytes)",
            bomb.len()
        );
        let err = decompress_content_encoding("gzip", &bomb).unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("exceeds maximum")),
            "expected decompression-bomb rejection, got: {err:?}"
        );
    }

    #[test]
    fn decompress_at_cap_boundary_is_accepted() {
        // A body that decompresses to exactly MAX_BODY_LEN is allowed (the cap is
        // inclusive); only strictly-larger expansions are rejected.
        let plain = vec![0u8; MAX_BODY_LEN];
        let out = decompress_content_encoding("gzip", &gzip(&plain)).unwrap();
        assert_eq!(out.len(), MAX_BODY_LEN);
    }

    // ── response-side chunked / close-delimited framing (AAASM-5645) ────────

    #[tokio::test]
    async fn chunked_response_is_decoded_whole() {
        // The bug this closes: `Content-Length` was the only framing this
        // parser understood, so a chunked response's body defaulted to empty.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    5\r\nhello\r\n\
                    7\r\n, world\r\n\
                    0\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert_eq!(&resp.body, b"hello, world");
    }

    #[tokio::test]
    async fn chunked_response_decodes_chunk_extensions() {
        // RFC 7230 §4.1.1: a `;`-delimited chunk extension is accepted and
        // ignored, not treated as part of the hex size.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    5;foo=bar\r\nhello\r\n\
                    0\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert_eq!(&resp.body, b"hello");
    }

    #[tokio::test]
    async fn chunked_response_discards_trailers() {
        // Trailer header lines after the terminating chunk are consumed (so
        // parsing doesn't stop early) but must not be merged into the
        // response's own headers.
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n\
                    5\r\nhello\r\n\
                    0\r\nX-Trailer: should-not-appear\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert_eq!(&resp.body, b"hello");
        assert!(
            !resp.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("x-trailer")),
            "a chunked trailer must not be merged into the response headers"
        );
    }

    #[tokio::test]
    async fn chunked_response_over_cap_is_rejected_without_forwarding() {
        // The running total is checked before each chunk is appended
        // (reject-before-alloc), so an over-cap chunked body fails closed the
        // same way an over-cap Content-Length body does.
        let mut raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        // One chunk already larger than MAX_BODY_LEN.
        let chunk_len = MAX_BODY_LEN + 1024;
        raw.extend_from_slice(format!("{chunk_len:x}\r\n").as_bytes());
        raw.extend(std::iter::repeat_n(b'a', chunk_len));
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let mut reader = make_reader(&raw);
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("exceeds maximum")),
            "expected over-cap rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn unterminated_chunked_response_is_config_error() {
        // EOF before the terminating zero-length chunk must fail closed, never
        // return a truncated `Ok` body.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        let mut reader = make_reader(raw);
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(err, ProxyError::Config(_)),
            "expected Config error, got {err:?}"
        );
    }

    #[tokio::test]
    async fn layered_chunked_transfer_encoding_is_rejected() {
        // `gzip, chunked` cannot be decoded by this parser's single-layer
        // chunk decoder, and de-chunking it would hand still-gzipped bytes to
        // the credential scanner (which decompresses on Content-Encoding, not
        // Transfer-Encoding) — scanning opaque bytes and forwarding them
        // (AAASM-4156's gap, on a new axis). Only a literal `chunked` decodes;
        // anything else fails closed.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\nirrelevant";
        let mut reader = make_reader(raw);
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("not inspectable")),
            "expected fail-closed rejection of a layered Transfer-Encoding, got: {err:?}"
        );
    }

    // ── incremental body reading (AAASM-6356 PR2) ───────────────────────────

    async fn stream_all(raw: &[u8]) -> Result<Vec<u8>, ProxyError> {
        let mut reader = make_reader(raw);
        let head = read_http_response_head(&mut reader).await?.expect("head present");
        let mut stream = BodyStream::new(&head)?;
        let mut out = Vec::new();
        while let Some(piece) = stream.next_piece(&mut reader).await? {
            out.extend_from_slice(&piece);
        }
        Ok(out)
    }

    #[tokio::test]
    async fn body_stream_decodes_chunks_to_the_same_bytes_as_the_buffered_reader() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;ext=1\r\nhello\r\n7\r\n, world\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(stream_all(raw).await.unwrap(), b"hello, world");
    }

    #[tokio::test]
    async fn body_stream_honours_content_length_and_close_delimited_framing() {
        let sized = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello-trailing-bytes-are-not-ours";
        assert_eq!(stream_all(sized).await.unwrap(), b"hello");
        let open = b"HTTP/1.1 200 OK\r\n\r\nuntil close";
        assert_eq!(stream_all(open).await.unwrap(), b"until close");
    }

    #[tokio::test]
    async fn body_stream_fails_closed_on_truncation_and_layered_encodings() {
        let cut_chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n";
        assert!(stream_all(cut_chunked).await.is_err());
        let cut_inside_chunk = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\nhel";
        assert!(stream_all(cut_inside_chunk).await.is_err());
        let short_length = b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nhel";
        assert!(stream_all(short_length).await.is_err());
        let layered = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\nx";
        assert!(stream_all(layered).await.is_err());
    }

    #[tokio::test]
    async fn close_delimited_response_is_read_to_eof() {
        // Neither Content-Length nor Transfer-Encoding present: the body is
        // whatever remains on the connection.
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nwhatever remains";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert_eq!(&resp.body, b"whatever remains");
    }

    #[tokio::test]
    async fn close_delimited_response_over_cap_is_rejected() {
        let mut raw = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'a', MAX_BODY_LEN + 1));
        let mut reader = make_reader(&raw);
        let err = read_http_response(&mut reader).await.unwrap_err();
        assert!(
            matches!(&err, ProxyError::Config(m) if m.contains("exceeds maximum")),
            "expected over-cap rejection, got: {err:?}"
        );
    }

    #[tokio::test]
    async fn no_content_204_response_does_not_wait_for_eof() {
        // A body-less status must not block waiting for a connection close
        // that (in production) only happens after this read returns.
        let raw = b"HTTP/1.1 204 No Content\r\n\r\n";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader)
            .await
            .unwrap()
            .expect("response present");
        assert!(resp.body.is_empty());
    }

    #[tokio::test]
    async fn response_head_keeps_exact_raw_bytes_and_leaves_body_unread() {
        let head = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\ncontent-LENGTH: 5\r\n\r\n";
        let raw = format!("{head}hello");
        let mut reader = make_reader(raw.as_bytes());
        let parsed = read_http_response_head(&mut reader).await.unwrap().expect("head");
        assert_eq!(parsed.raw, head.as_bytes());
        assert_eq!(parsed.status_code, "200");
        let body = read_http_response_body(&parsed, &mut reader).await.unwrap();
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn response_head_then_body_matches_read_http_response() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let whole = read_http_response(&mut make_reader(raw)).await.unwrap().unwrap();
        let mut reader = make_reader(raw);
        let head = read_http_response_head(&mut reader).await.unwrap().unwrap();
        let body = read_http_response_body(&head, &mut reader).await.unwrap();
        assert_eq!(whole.body, body);
        assert_eq!(whole.headers, head.headers);
    }

    #[tokio::test]
    async fn event_stream_detection_is_a_case_insensitive_substring_match() {
        let cases: &[(&str, bool)] = &[
            ("text/event-stream", true),
            ("Text/Event-Stream; charset=utf-8", true),
            ("application/json", false),
            ("application/json, text/event-stream", true),
            // Substring matching over-matches on purpose: withholding a lookalike
            // is the fail-closed side of an interim rule, missing a list is not.
            ("text/event-streamx", true),
            ("application/x-ndjson; note=text/event-stream", true),
        ];
        for (ct, want) in cases {
            let raw = format!("HTTP/1.1 200 OK\r\nContent-Type: {ct}\r\nContent-Length: 0\r\n\r\n");
            let head = read_http_response_head(&mut make_reader(raw.as_bytes()))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(head.is_event_stream(), *want, "content-type: {ct}");
        }
    }

    // ── Raw response head (AAASM-6356 review F2/F4) ────────────────────────

    #[test]
    fn raw_head_event_stream_scan_is_lenient_and_case_insensitive() {
        let hit = |h: &[u8]| raw_head_is_event_stream(h);
        assert!(hit(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n"));
        assert!(hit(
            b"HTTP/1.1 200 OK\r\ncontent-type : Application/JSON, TEXT/Event-Stream; q=1\r\n\r\n"
        ));
        assert!(hit(
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Type: text/event-stream\r\n\r\n"
        ));
        // obs-fold continuation of Content-Type, and a non-UTF-8 byte elsewhere
        assert!(hit(
            b"HTTP/1.1 200 OK\r\nX-A: \xE9\r\nContent-Type: application/json,\r\n text/event-stream\r\n\r\n"
        ));
        // controls
        assert!(!hit(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n"));
        assert!(!hit(b"HTTP/1.1 200 OK\r\nX-Note: text/event-stream\r\n\r\n"));
        assert!(!hit(
            b"HTTP/1.1 200 OK\r\nX-Note: a\r\n text/event-stream\r\nContent-Type: text/plain\r\n\r\n"
        ));
        assert!(!hit(b"text/event-stream"));
    }

    #[test]
    fn raw_head_interim_detection() {
        assert!(raw_head_is_interim(b"HTTP/1.1 100 Continue\r\n\r\n"));
        assert!(raw_head_is_interim(b"HTTP/1.1 103\r\n\r\n"));
        assert!(!raw_head_is_interim(b"HTTP/1.1 101 Switching Protocols\r\n\r\n"));
        assert!(!raw_head_is_interim(b"HTTP/1.1 200 OK\r\n\r\n"));
        assert!(!raw_head_is_interim(b"HTTP/1.1\r\n\r\n"));
    }

    #[tokio::test]
    async fn read_raw_response_head_stops_at_the_blank_line_and_leaves_the_body() {
        let mut r = BufReader::new(&b"HTTP/1.1 200 OK\r\nX: \xFF\r\n\r\nBODY"[..]);
        let head = read_raw_response_head(&mut r, 1024).await.unwrap().unwrap();
        assert_eq!(head, b"HTTP/1.1 200 OK\r\nX: \xFF\r\n\r\n");
        let mut rest = Vec::new();
        r.read_to_end(&mut rest).await.unwrap();
        assert_eq!(rest, b"BODY");
        // EOF before any byte is a clean None; an over-cap head is an error
        let mut empty = BufReader::new(&b""[..]);
        assert!(read_raw_response_head(&mut empty, 16).await.unwrap().is_none());
        let mut big = BufReader::new(&b"HTTP/1.1 200 OK\r\nX: aaaaaaaaaaaaaaaaaaaaaaaa\r\n\r\n"[..]);
        assert!(read_raw_response_head(&mut big, 16).await.is_err());
    }

    #[test]
    fn parse_raw_response_head_keeps_the_strict_caps() {
        assert!(parse_raw_response_head(b"HTTP/1.1 200 OK\r\nA: b\r\n\r\n").is_ok());
        assert!(parse_raw_response_head(b"HTTP/1.1\r\n\r\n").is_err());
        assert!(parse_raw_response_head(b"HTTP/1.1 200 OK\r\nA: \xE9\r\n\r\n").is_err());
        let long = format!("HTTP/1.1 200 OK\r\nA: {}\r\n\r\n", "a".repeat(MAX_HEADER_LINE_LEN));
        assert!(parse_raw_response_head(long.as_bytes()).is_err());
        let many = format!("HTTP/1.1 200 OK\r\n{}\r\n", "A: b\r\n".repeat(MAX_HEADER_COUNT + 1));
        assert!(parse_raw_response_head(many.as_bytes()).is_err());
        assert!(parse_raw_response_head(b"HTTP/1.1 200 OK\r\nA: b\r\n").is_err());
    }

    #[test]
    fn parsed_head_event_stream_matches_any_content_type_value() {
        let head = |ct: &[(&str, &str)]| HttpResponseHead {
            version: "HTTP/1.1".into(),
            status_code: "200".into(),
            reason: "OK".into(),
            headers: ct.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            raw: Vec::new(),
        };
        assert!(head(&[("Content-Type", "application/json, text/event-stream")]).is_event_stream());
        assert!(head(&[("content-type", "a/b"), ("Content-Type", "TEXT/EVENT-STREAM")]).is_event_stream());
        assert!(!head(&[("Content-Type", "application/json")]).is_event_stream());
    }
}
