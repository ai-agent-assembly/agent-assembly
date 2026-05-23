//! Minimal HTTP/1.1 request parsing for the proxy data path.
//!
//! After TLS termination the proxy needs to read the inbound request line,
//! headers, and body off the TLS stream so the credential scanner can run
//! against the real body bytes (and so the proxy can re-serialise with a
//! modified body when policy is `redact_only`).
//!
//! Scope is intentionally small: only requests with a literal
//! `Content-Length` header are fully supported. Requests using
//! `Transfer-Encoding: chunked` parse the head but leave the body empty —
//! that variant is rare for LLM POSTs and can be added when needed without
//! breaking this API.

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
/// `Content-Length` bytes of body. Requests without `Content-Length` and
/// without `Transfer-Encoding: chunked` are treated as having an empty body.
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
    let mut out = Vec::with_capacity(req.body.len() + new_body.len() + 256);
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.target.as_bytes());
    out.push(b' ');
    out.extend_from_slice(req.version.as_bytes());
    out.extend_from_slice(b"\r\n");

    for (k, v) in &req.headers {
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

    #[tokio::test]
    async fn serialize_drops_transfer_encoding_header() {
        let raw = b"POST / HTTP/1.1\r\n\
                    Host: x.example.com\r\n\
                    Transfer-Encoding: chunked\r\n\
                    \r\n";
        let mut reader = make_reader(raw);
        let req = read_http_request(&mut reader).await.unwrap().unwrap();
        let wire = serialize_http_request(&req, b"hi");
        let text = std::str::from_utf8(&wire).unwrap();
        assert!(
            !text.to_ascii_lowercase().contains("transfer-encoding"),
            "serialized request must drop Transfer-Encoding when replacing body, got: {text}",
        );
        assert!(text.contains("Content-Length: 2\r\n"));
    }
}
