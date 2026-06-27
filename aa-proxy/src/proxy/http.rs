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

use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

use crate::error::ProxyError;

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
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(None);
    }
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
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(ProxyError::Config("unexpected EOF reading headers".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
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
    let mut status_line = String::new();
    let n = reader.read_line(&mut status_line).await?;
    if n == 0 {
        return Ok(None);
    }
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
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            return Err(ProxyError::Config("unexpected EOF reading response headers".into()));
        }
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
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
}
