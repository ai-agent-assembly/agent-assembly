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
//! an un-scanned body. The response side still parses the head and leaves a
//! chunked body empty (the MCP path falls back to a transparent relay).

use std::io::Read;

use flate2::read::{DeflateDecoder, GzDecoder, ZlibDecoder};
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
    if token.eq_ignore_ascii_case("gzip") || token.eq_ignore_ascii_case("x-gzip") {
        read_bounded(GzDecoder::new(body), token)
    } else if token.eq_ignore_ascii_case("deflate") {
        // HTTP `deflate` is ambiguous: RFC 7230 means zlib-wrapped (RFC 1950),
        // but some servers send raw DEFLATE (RFC 1951). Try zlib first, then
        // fall back to raw; if neither decodes cleanly (or either exceeds the
        // cap), fail closed below.
        match read_bounded(ZlibDecoder::new(body), token) {
            Ok(plain) => Ok(plain),
            Err(_) => read_bounded(DeflateDecoder::new(body), token),
        }
    } else {
        Err(ProxyError::Config(format!(
            "unsupported Content-Encoding {token:?} is not inspectable; refusing (fail-closed)"
        )))
    }
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
    /// Lookup the first header value matching `name` (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
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
    // read cannot OOM the proxy. `head_budget` tracks the remaining total-head
    // allowance; each line is additionally bounded by `MAX_HEADER_LINE_LEN`.
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

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        let n = read_line_capped(reader, &mut line, MAX_HEADER_LINE_LEN, head_budget).await?;
        if n == 0 {
            return Err(ProxyError::Config("unexpected EOF reading headers".into()));
        }
        head_budget -= n;
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(ProxyError::Config(format!(
                "HTTP request exceeds maximum {MAX_HEADER_COUNT} header lines; refusing (fail-closed)"
            )));
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            return Err(ProxyError::Config(format!("malformed header line: {trimmed:?}")));
        }
    }

    // AAASM-3864 (fail-closed): a chunked body cannot be parsed here, so the
    // credential scanner and `parse_mcp_request` would see an empty body while
    // the real payload was forwarded un-inspected. Refuse such requests rather
    // than silently passing an un-scanned body upstream.
    if headers
        .iter()
        .any(|(k, v)| k.eq_ignore_ascii_case("transfer-encoding") && v.to_ascii_lowercase().contains("chunked"))
    {
        return Err(ProxyError::Config(
            "transfer-encoding: chunked request bodies are not inspectable; refusing (fail-closed)".into(),
        ));
    }

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    // AAASM-3891 (fail-closed): reject an over-cap Content-Length *before*
    // allocating. The header is attacker-controlled, so allocating a buffer
    // sized to it lets a single request OOM the proxy.
    if content_length > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "request Content-Length {content_length} exceeds maximum {MAX_BODY_LEN}; refusing (fail-closed)"
        )));
    }

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
/// **injecting** the real provider `Authorization` header at egress.
///
/// Behaves exactly like [`serialize_http_request`] for the request line,
/// `Content-Length`, and `Transfer-Encoding` handling. In addition, when
/// `injected_auth` is `Some(bytes)` (AAASM-3578):
///
/// * every inbound `Authorization` and `x-api-key` header (case-insensitive)
///   the agent supplied is **dropped**, so the agent can never smuggle its own
///   key upstream, and
/// * a single `Authorization: <bytes>` header carrying the real provider
///   credential is appended.
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
pub fn serialize_http_request_with_auth(req: &HttpRequest, new_body: &[u8], injected_auth: Option<&[u8]>) -> Vec<u8> {
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
    if let Some(auth) = injected_auth {
        out.extend_from_slice(b"Authorization: ");
        out.extend_from_slice(auth);
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

/// Read and parse an HTTP/1.1 response from `reader`.
///
/// Companion to [`read_http_request`] but for the upstream side of the
/// MitM tunnel. Reads exactly `Content-Length` bytes of body; responses
/// using `Transfer-Encoding: chunked` parse the head but leave the body
/// empty (consistent with the request-side scope note above).
///
/// Used by the AAASM-1930 MCP path to capture upstream responses for
/// credential scanning before the bytes reach the client.
pub async fn read_http_response<R>(reader: &mut BufReader<R>) -> Result<Option<HttpResponse>, ProxyError>
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

    let content_length: usize = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);

    // AAASM-3891 (fail-closed): reject an over-cap Content-Length *before*
    // allocating, so a hostile upstream response cannot OOM the proxy the same
    // way a hostile request could.
    if content_length > MAX_BODY_LEN {
        return Err(ProxyError::Config(format!(
            "response Content-Length {content_length} exceeds maximum {MAX_BODY_LEN}; refusing (fail-closed)"
        )));
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).await?;
    }

    Ok(Some(HttpResponse {
        version,
        status_code,
        reason,
        headers,
        body,
    }))
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

        let wire = serialize_http_request_with_auth(&req, &req.body, Some(b"Bearer sk-REAL-PROVIDER-KEY"));
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

    #[tokio::test]
    async fn serialize_response_rewrites_content_length_and_drops_transfer_encoding() {
        let raw = b"HTTP/1.1 200 OK\r\n\
                    Content-Type: application/json\r\n\
                    Transfer-Encoding: chunked\r\n\
                    Content-Length: 3\r\n\
                    \r\n\
                    old";
        let mut reader = make_reader(raw);
        let resp = read_http_response(&mut reader).await.unwrap().unwrap();

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
}
