//! Traffic interception: detect LLM API calls and emit structured events.

pub mod detect;
pub mod event;
pub mod extract;
pub mod mcp;

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use aa_proto::assembly::audit::v1::{
    audit_event, AuditEvent, LlmCallDetail, NetworkCallDetail, PolicyViolation, ToolCallDetail,
};
use aa_proto::assembly::common::v1::ActionType;
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource};
use aa_runtime::pipeline::PipelineEvent;

use aa_security::{CredentialFinding, CredentialScanner};
use bytes::Bytes;

use std::borrow::Cow;

use crate::config::CredentialAction;
use crate::error::ProxyError;
use crate::intercept::detect::LlmApiPattern;
use crate::intercept::extract::{extract_anthropic, extract_cohere, extract_openai, ExtractionError, LlmFields};
use crate::proxy::http::decompress_content_encoding;

/// What the proxy should do with an intercepted request body after the
/// scanner has run.
///
/// Returned by [`Interceptor::intercept_request`]; the data path branches on
/// `decision` and uses `redacted_body` when applicable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerdictDecision {
    /// No findings — forward the original body unmodified.
    Forward,
    /// Findings detected and policy is `redact_only` — forward the bytes in
    /// the `redacted_body` field instead of the original.
    ForwardRedacted,
    /// Findings detected and policy is `block` — return 403 to the client,
    /// do not dial upstream.
    Block,
    /// Findings detected and policy is `alert_only` — forward the original
    /// body and emit a critical alert side-effect.
    AlertAndForward,
}

/// Output of [`Interceptor::intercept_request`].
///
/// Carries the policy-driven decision, the per-match scanner output (empty
/// when clean), and the post-scan body (only populated when redaction took
/// place). The data path consumes this to drive both upstream forwarding
/// and audit emission.
#[derive(Debug, Clone)]
pub struct InterceptVerdict {
    /// What the proxy should do with this request.
    pub decision: VerdictDecision,
    /// Per-match output from the credential scanner. Empty when no
    /// credentials were detected.
    pub findings: Vec<CredentialFinding>,
    /// Post-scan body. `Some` only when `decision == ForwardRedacted` so the
    /// data path can forward these bytes verbatim.
    pub redacted_body: Option<Bytes>,
}

/// Outcome of [`Interceptor::redact_response_body`] for an upstream response
/// body the MCP data path is about to relay to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResponseScan {
    /// Forward the original upstream body unchanged — the scanner is disabled
    /// or the (decoded) payload is clean.
    Forward,
    /// Forward these bytes in place of the original: findings were replaced with
    /// the scanner's `[REDACTED:<kind>]` markers.
    Redact(Vec<u8>),
    /// The body could not be inspected — an undecodable `Content-Encoding`, or a
    /// compressed body carrying findings that cannot be safely re-encoded here.
    /// The caller must withhold the upstream body and fail closed (AAASM-4156).
    Withhold,
}

/// The bytes the credential/DLP scanner should inspect for a body that may
/// carry a `Content-Encoding`, or a signal that the body is un-inspectable.
///
/// AAASM-4156: a `gzip`/`deflate` body must be decompressed before scanning —
/// scanning the compressed bytes lets an encoded secret slip past. An encoding
/// the proxy cannot decode yields [`ScanSource::Uninspectable`] so the caller
/// fails closed (refuse the request / withhold the response) rather than
/// forwarding a body it never inspected.
enum ScanSource<'a> {
    /// Scan these bytes. `encoded` is `true` when they were decompressed from a
    /// non-identity `Content-Encoding` (the original wire body is compressed).
    Plaintext { bytes: Cow<'a, [u8]>, encoded: bool },
    /// The `Content-Encoding` cannot be decoded here — fail closed.
    Uninspectable,
}

/// Resolve the [`ScanSource`] for `body` given its `Content-Encoding` header
/// value (if any). An absent or `identity` encoding is scanned verbatim; a
/// recognized encoding is decompressed (bounded by `MAX_BODY_LEN`); anything
/// else is [`ScanSource::Uninspectable`].
fn scan_source<'a>(body: &'a [u8], content_encoding: Option<&str>) -> ScanSource<'a> {
    let token = content_encoding.map(str::trim).filter(|s| !s.is_empty());
    match token {
        None => ScanSource::Plaintext {
            bytes: Cow::Borrowed(body),
            encoded: false,
        },
        Some(enc) if enc.eq_ignore_ascii_case("identity") => ScanSource::Plaintext {
            bytes: Cow::Borrowed(body),
            encoded: false,
        },
        Some(enc) => match decompress_content_encoding(enc, body) {
            Ok(decoded) => ScanSource::Plaintext {
                bytes: Cow::Owned(decoded),
                encoded: true,
            },
            Err(_) => ScanSource::Uninspectable,
        },
    }
}

/// Inspects a decrypted HTTP request/response pair, decides whether it is an
/// LLM API call, and extracts audit-relevant fields from the body.
///
/// Holds a [`broadcast::Sender`] to emit [`PipelineEvent`]s for intercepted
/// LLM calls into the runtime event pipeline.
pub struct Interceptor {
    event_tx: broadcast::Sender<PipelineEvent>,
    scanner: Option<CredentialScanner>,
}

impl Interceptor {
    /// Run the credential scanner against a flowing request body and decide
    /// the data-path verdict according to the supplied [`CredentialAction`].
    ///
    /// Findings drive `decision`:
    ///
    /// * No findings → [`VerdictDecision::Forward`] (no redaction performed).
    /// * Findings + [`CredentialAction::Block`] → [`VerdictDecision::Block`].
    /// * Findings + [`CredentialAction::RedactOnly`] →
    ///   [`VerdictDecision::ForwardRedacted`] with the redacted bytes
    ///   populated.
    /// * Findings + [`CredentialAction::AlertOnly`] →
    ///   [`VerdictDecision::AlertAndForward`].
    ///
    /// When the proxy's scanner is disabled (constructed via
    /// `with_scanner(None)`) this returns `Forward` with no findings.
    ///
    /// `content_encoding` is the request's `Content-Encoding` header value (if
    /// present). A non-identity encoding is decompressed before scanning
    /// (AAASM-4156) so a `gzip`/`deflate`-encoded secret cannot slip past the
    /// scanner as opaque compressed bytes. Two fail-closed cases return
    /// [`VerdictDecision::Block`] with no findings — mirroring the chunked-TE
    /// stance of refusing an un-inspectable body rather than forwarding it:
    ///
    /// * an encoding the proxy cannot decode (`br`, `zstd`, layered lists, or a
    ///   malformed/oversized stream), and
    /// * `RedactOnly` findings inside a compressed body — the redacted plaintext
    ///   cannot be re-encoded to the declared encoding here, and forwarding the
    ///   original compressed bytes would leak the secret, so the request is
    ///   blocked. Identity bodies still redact and forward as before.
    pub fn intercept_request(
        &self,
        body: &[u8],
        content_encoding: Option<&str>,
        action: CredentialAction,
    ) -> InterceptVerdict {
        let Some(scanner) = self.scanner.as_ref() else {
            return InterceptVerdict {
                decision: VerdictDecision::Forward,
                findings: Vec::new(),
                redacted_body: None,
            };
        };

        let (bytes, encoded) = match scan_source(body, content_encoding) {
            ScanSource::Plaintext { bytes, encoded } => (bytes, encoded),
            ScanSource::Uninspectable => {
                // Fail closed: the body's Content-Encoding cannot be decoded, so
                // the scanner never saw the real content. Refuse the forward.
                return InterceptVerdict {
                    decision: VerdictDecision::Block,
                    findings: Vec::new(),
                    redacted_body: None,
                };
            }
        };

        let text = String::from_utf8_lossy(&bytes);
        let scan = scanner.scan(&text);
        if scan.is_clean() {
            return InterceptVerdict {
                decision: VerdictDecision::Forward,
                findings: Vec::new(),
                redacted_body: None,
            };
        }

        match action {
            CredentialAction::Block => InterceptVerdict {
                decision: VerdictDecision::Block,
                findings: scan.findings,
                redacted_body: None,
            },
            CredentialAction::RedactOnly if encoded => {
                // Cannot re-encode the redacted plaintext to the declared
                // Content-Encoding, and forwarding the original compressed bytes
                // would relay the secret. Fail closed rather than leak.
                InterceptVerdict {
                    decision: VerdictDecision::Block,
                    findings: scan.findings,
                    redacted_body: None,
                }
            }
            CredentialAction::RedactOnly => {
                let redacted = scan.redact(&text);
                InterceptVerdict {
                    decision: VerdictDecision::ForwardRedacted,
                    findings: scan.findings,
                    redacted_body: Some(Bytes::from(redacted)),
                }
            }
            CredentialAction::AlertOnly => InterceptVerdict {
                decision: VerdictDecision::AlertAndForward,
                findings: scan.findings,
                redacted_body: None,
            },
        }
    }

    /// Create a new `Interceptor` with default credential scanning enabled.
    pub fn new(event_tx: broadcast::Sender<PipelineEvent>) -> Self {
        Self {
            event_tx,
            scanner: Some(CredentialScanner::new()),
        }
    }

    /// Create a new `Interceptor` with an explicit scanner configuration.
    ///
    /// Pass `None` to disable credential scanning entirely, or `Some(scanner)`
    /// to use a custom-configured [`CredentialScanner`].
    pub fn with_scanner(event_tx: broadcast::Sender<PipelineEvent>, scanner: Option<CredentialScanner>) -> Self {
        Self { event_tx, scanner }
    }

    /// Emit an audit event recording the policy decision for a CONNECT tunnel.
    ///
    /// - `host`: the target hostname from the CONNECT request line.
    /// - `denied`: `true` if the connection was blocked (403 returned),
    ///   `false` if the connection was allowed through.
    ///
    /// The event is emitted on the broadcast channel; if there are no receivers
    /// (standalone proxy with no runtime attached) the send is silently ignored.
    pub async fn emit_policy_decision(&self, host: &str, denied: bool) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let (action_type, detail) = if denied {
            let violation = PolicyViolation {
                blocked_action: format!("CONNECT {host}"),
                reason: "host is on the deny list".into(),
                ..Default::default()
            };
            (ActionType::NetworkCall, audit_event::Detail::Violation(violation))
        } else {
            let network = NetworkCallDetail {
                host: host.to_string(),
                protocol: "https".into(),
                succeeded: true,
                ..Default::default()
            };
            (ActionType::NetworkCall, audit_event::Detail::Network(network))
        };

        let audit = AuditEvent {
            action_type: action_type.into(),
            detail: Some(detail),
            ..Default::default()
        };

        let enriched = EnrichedEvent {
            inner: audit,
            received_at_ms: now_ms,
            source: EventSource::Proxy,
            agent_id: String::new(),
            connection_id: 0,
            sequence_number: 0,
            // Proxy-sourced events carry no SDK identity claim.
            observed_sdk_identity: aa_security::sdk_identity::ObservedSdkIdentity::missing(),
            tamper: None,
        };

        // send() returns Err only when there are zero receivers — normal for
        // standalone proxy operation (no runtime attached).
        let _ = self.event_tx.send(PipelineEvent::Audit(Box::new(enriched)));
    }

    /// Scan a response-side payload for credentials and return the redacted
    /// form when findings are present.
    ///
    /// Returns [`ResponseScan::Forward`] when the scanner is disabled or the
    /// (decoded) payload is clean; [`ResponseScan::Redact`] with the redacted
    /// bytes when findings are replaced with `[REDACTED:<kind>]` markers; and
    /// [`ResponseScan::Withhold`] when the body cannot be inspected and the
    /// caller must fail closed.
    ///
    /// `content_encoding` is the response's `Content-Encoding` header value (if
    /// present). A non-identity encoding is decompressed before scanning
    /// (AAASM-4156) so a `gzip`/`deflate`-encoded secret in an upstream response
    /// is inspected as plaintext rather than relayed as opaque compressed bytes.
    /// An encoding the proxy cannot decode, and findings inside a compressed body
    /// (which cannot be re-encoded to the declared encoding without leaking the
    /// secret), both return [`ResponseScan::Withhold`].
    ///
    /// Used by the AAASM-1930 MCP data path to redact upstream response
    /// bodies before they reach the client (ST-Q-3). The proxy's default
    /// scanner carries the same `aa_security::CredentialScanner` patterns the
    /// gateway uses for ToolResult evaluation, so the redaction shape
    /// matches what `mcp_redact_secrets.yaml` would produce gateway-side.
    pub fn redact_response_body(&self, body: &[u8], content_encoding: Option<&str>) -> ResponseScan {
        let Some(scanner) = self.scanner.as_ref() else {
            return ResponseScan::Forward;
        };
        let (bytes, encoded) = match scan_source(body, content_encoding) {
            ScanSource::Plaintext { bytes, encoded } => (bytes, encoded),
            ScanSource::Uninspectable => return ResponseScan::Withhold,
        };
        let text = String::from_utf8_lossy(&bytes);
        let scan = scanner.scan(&text);
        if scan.is_clean() {
            return ResponseScan::Forward;
        }
        if encoded {
            // Findings inside a compressed body cannot be re-encoded to the
            // declared Content-Encoding here, and forwarding the original
            // compressed bytes would relay the secret. Withhold (fail closed).
            return ResponseScan::Withhold;
        }
        ResponseScan::Redact(scan.redact(&text).into_bytes())
    }

    /// Emit an audit event recording the gateway's decision for an MCP
    /// `tools/call` intercept.
    ///
    /// * `tool_name` is copied verbatim from the parsed [`crate::intercept::mcp::McpToolCall`].
    /// * `args_json` is the JSON-encoded arguments the agent passed to the
    ///   tool. Run through the `CredentialScanner` here so the audit
    ///   `ToolCallDetail.args_json` carries the **redacted** form when
    ///   findings are present — the audit chain never sees raw secrets.
    /// * `denied` distinguishes the two audit shapes:
    ///   * `false` → `audit_event::Detail::ToolCall(ToolCallDetail { tool_name,
    ///     tool_source: "mcp", succeeded: true, args_json: <maybe redacted>, .. })`
    ///     for Allow / Redact (the proxy forwarded the request).
    ///   * `true` → `audit_event::Detail::Violation(PolicyViolation {
    ///     blocked_action: "tools/call <tool_name>", reason })` for Deny.
    /// * `reason` is the policy's human-readable explanation for the deny
    ///   path; ignored on Allow.
    ///
    /// The event is emitted on the broadcast channel; send failures are
    /// silently dropped (no-receivers is normal for standalone proxy mode).
    pub async fn emit_mcp_decision(&self, tool_name: &str, args_json: &[u8], denied: bool, reason: &str) {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let detail = if denied {
            let violation = PolicyViolation {
                blocked_action: format!("tools/call {tool_name}"),
                reason: reason.to_string(),
                ..Default::default()
            };
            audit_event::Detail::Violation(violation)
        } else {
            // Scan the args for credentials before recording them in the
            // audit chain. The producer-side scrub keeps raw secrets out
            // of every downstream audit subscriber (JSONL writer, dashboard
            // ws, etc.) without requiring each subscriber to re-scan.
            let safe_args = self
                .scanner
                .as_ref()
                .and_then(|s| {
                    let text = String::from_utf8_lossy(args_json);
                    let scan = s.scan(&text);
                    if scan.is_clean() {
                        None
                    } else {
                        Some(scan.redact(&text).into_bytes())
                    }
                })
                .unwrap_or_else(|| args_json.to_vec());

            let tool_call = ToolCallDetail {
                tool_name: tool_name.to_string(),
                tool_source: "mcp".into(),
                succeeded: true,
                args_json: safe_args,
                ..Default::default()
            };
            audit_event::Detail::ToolCall(tool_call)
        };

        let audit = AuditEvent {
            action_type: ActionType::ToolCall.into(),
            detail: Some(detail),
            ..Default::default()
        };

        let enriched = EnrichedEvent {
            inner: audit,
            received_at_ms: now_ms,
            source: EventSource::Proxy,
            agent_id: String::new(),
            connection_id: 0,
            sequence_number: 0,
            // Proxy-sourced events carry no SDK identity claim.
            observed_sdk_identity: aa_security::sdk_identity::ObservedSdkIdentity::missing(),
            tamper: None,
        };

        let _ = self.event_tx.send(PipelineEvent::Audit(Box::new(enriched)));
    }

    /// Inspect an intercepted exchange, extract LLM fields from the body,
    /// and emit a [`PipelineEvent::Audit`] on the broadcast channel.
    ///
    /// Returns the extracted [`LlmFields`] (or `None` for non-LLM traffic
    /// and extraction failures).
    pub async fn intercept(&self, event: &event::ProxyEvent) -> Result<Option<LlmFields>, ProxyError> {
        // Non-LLM traffic is passed through without extraction.
        if event.pattern == LlmApiPattern::Unknown {
            tracing::debug!(method = %event.method, path = %event.path, "non-LLM traffic, skipping");
            return Ok(None);
        }

        // Pick the body to extract from: prefer response (has usage stats),
        // fall back to request.
        let raw_body = event.response_body.as_ref().or(event.request_body.as_ref());

        // Scan for credentials and redact before any further processing so
        // that secrets never appear in audit events or log output.
        let body: Option<bytes::Bytes> = raw_body.map(|b| {
            if let Some(scanner) = &self.scanner {
                let text = String::from_utf8_lossy(b);
                let result = scanner.scan(&text);
                if result.is_clean() {
                    b.clone()
                } else {
                    tracing::warn!(
                        findings = result.findings.len(),
                        agent_id = event.agent_id.as_deref().unwrap_or("<unknown>"),
                        "credentials detected in LLM body, redacting before audit"
                    );
                    bytes::Bytes::from(result.redact(&text))
                }
            } else {
                b.clone()
            }
        });

        let fields = match body.as_ref() {
            Some(bytes) => match Self::extract_for_pattern(&event.pattern, bytes) {
                Ok(f) => Some(f),
                Err(e) => {
                    tracing::warn!(
                        pattern = ?event.pattern,
                        error = %e,
                        "failed to extract LLM fields from body"
                    );
                    None
                }
            },
            None => None,
        };

        tracing::info!(
            agent_id = event.agent_id.as_deref().unwrap_or("<unknown>"),
            pattern = ?event.pattern,
            method = %event.method,
            path = %event.path,
            model = fields.as_ref().map(|f| f.model.as_str()).unwrap_or("<unknown>"),
            messages = fields.as_ref().map(|f| f.messages_count).unwrap_or(0),
            "intercepted LLM API call"
        );

        // Emit a PipelineEvent for every detected LLM call (even when body
        // extraction failed — the audit record still captures the call).
        let pipeline_event = Self::build_pipeline_event(event, fields.as_ref());
        // send() returns Err only when there are zero receivers — that is
        // normal during standalone proxy operation (no runtime attached).
        let _ = self.event_tx.send(pipeline_event);

        Ok(fields)
    }

    /// Build a [`PipelineEvent::Audit`] from a proxy event and optional extracted fields.
    fn build_pipeline_event(event: &event::ProxyEvent, fields: Option<&LlmFields>) -> PipelineEvent {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let llm_detail = LlmCallDetail {
            model: fields.map(|f| f.model.clone()).unwrap_or_default(),
            prompt_tokens: fields.and_then(|f| f.prompt_tokens).unwrap_or(0) as i32,
            completion_tokens: fields.and_then(|f| f.completion_tokens).unwrap_or(0) as i32,
            provider: Self::provider_name(&event.pattern).into(),
            ..Default::default()
        };

        let audit = AuditEvent {
            action_type: ActionType::LlmCall.into(),
            detail: Some(audit_event::Detail::LlmCall(llm_detail)),
            ..Default::default()
        };

        let enriched = EnrichedEvent {
            inner: audit,
            received_at_ms: now_ms,
            source: EventSource::Proxy,
            agent_id: event.agent_id.clone().unwrap_or_default(),
            connection_id: 0,
            sequence_number: 0,
            // Proxy-sourced events carry no SDK identity claim.
            observed_sdk_identity: aa_security::sdk_identity::ObservedSdkIdentity::missing(),
            tamper: None,
        };

        PipelineEvent::Audit(Box::new(enriched))
    }

    /// Map a detected API pattern to the provider name stored in the audit record.
    fn provider_name(pattern: &LlmApiPattern) -> &'static str {
        match pattern {
            LlmApiPattern::OpenAi => "openai",
            LlmApiPattern::Anthropic => "anthropic",
            LlmApiPattern::Cohere => "cohere",
            LlmApiPattern::Unknown => "unknown",
        }
    }

    /// Select the correct extractor based on the detected API pattern.
    fn extract_for_pattern(pattern: &LlmApiPattern, body: &[u8]) -> Result<LlmFields, ExtractionError> {
        match pattern {
            LlmApiPattern::OpenAi => extract_openai(body),
            LlmApiPattern::Anthropic => extract_anthropic(body),
            LlmApiPattern::Cohere => extract_cohere(body),
            LlmApiPattern::Unknown => Err(ExtractionError::UnrecognizedFormat {
                reason: "unknown provider".into(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use bytes::Bytes;

    use super::*;
    use crate::intercept::detect::LlmApiPattern;
    use crate::intercept::event::ProxyEvent;

    /// Create a dummy `Interceptor` with a broadcast sender whose receiver is
    /// dropped — sends silently fail, which is correct for unit tests that
    /// only verify extraction logic.
    fn make_interceptor() -> Interceptor {
        let (tx, _rx) = broadcast::channel(16);
        Interceptor::new(tx)
    }

    fn make_event(pattern: LlmApiPattern) -> ProxyEvent {
        ProxyEvent {
            agent_id: Some("test-agent".into()),
            pattern,
            method: "POST".into(),
            path: "/v1/chat/completions".into(),
            request_body: None,
            response_body: None,
            timestamp: SystemTime::now(),
        }
    }

    #[tokio::test]
    async fn intercept_openai_event_succeeds() {
        let interceptor = make_interceptor();
        let result = interceptor.intercept(&make_event(LlmApiPattern::OpenAi)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn intercept_anthropic_event_succeeds() {
        let interceptor = make_interceptor();
        let result = interceptor.intercept(&make_event(LlmApiPattern::Anthropic)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn intercept_unknown_returns_none() {
        let interceptor = make_interceptor();
        let result = interceptor
            .intercept(&make_event(LlmApiPattern::Unknown))
            .await
            .unwrap();
        assert!(result.is_none(), "unknown pattern should skip extraction");
    }

    #[tokio::test]
    async fn intercept_with_no_agent_id_succeeds() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.agent_id = None;
        assert!(interceptor.intercept(&event).await.is_ok());
    }

    #[tokio::test]
    async fn intercept_openai_with_body_extracts_fields() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.response_body = Some(Bytes::from(
            r#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":20}}"#,
        ));
        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.prompt_tokens, Some(10));
        assert_eq!(fields.completion_tokens, Some(20));
    }

    #[tokio::test]
    async fn intercept_anthropic_with_body_extracts_fields() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::Anthropic);
        event.response_body = Some(Bytes::from(
            r#"{"model":"claude-3-opus-20240229","usage":{"input_tokens":15,"output_tokens":30}}"#,
        ));
        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "claude-3-opus-20240229");
        assert_eq!(fields.prompt_tokens, Some(15));
        assert_eq!(fields.completion_tokens, Some(30));
    }

    #[tokio::test]
    async fn intercept_cohere_with_body_extracts_fields() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::Cohere);
        event.response_body = Some(Bytes::from(
            r#"{"model":"command-r-plus","message":"hello","meta":{"tokens":{"input_tokens":5,"output_tokens":12}}}"#,
        ));
        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "command-r-plus");
        assert_eq!(fields.prompt_tokens, Some(5));
        assert_eq!(fields.completion_tokens, Some(12));
        assert_eq!(fields.messages_count, 1);
    }

    #[tokio::test]
    async fn intercept_prefers_response_body_over_request() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.request_body = Some(Bytes::from(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
        ));
        event.response_body = Some(Bytes::from(
            r#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":20}}"#,
        ));
        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        // Response body was used — it has usage stats, not messages
        assert_eq!(fields.prompt_tokens, Some(10));
        assert_eq!(fields.completion_tokens, Some(20));
        assert_eq!(fields.messages_count, 0);
    }

    #[tokio::test]
    async fn intercept_falls_back_to_request_body() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.request_body = Some(Bytes::from(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}"#,
        ));
        event.response_body = None;
        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);
        assert_eq!(fields.prompt_tokens, None);
    }

    #[tokio::test]
    async fn intercept_with_none_body_returns_none() {
        let interceptor = make_interceptor();
        let event = make_event(LlmApiPattern::OpenAi);
        // Both request_body and response_body are None
        let result = interceptor.intercept(&event).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn intercept_with_malformed_body_returns_none() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.response_body = Some(Bytes::from("not json"));
        // Malformed body logs a warning and returns None (not an error)
        let result = interceptor.intercept(&event).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn non_llm_traffic_emits_no_pipeline_event() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let event = make_event(LlmApiPattern::Unknown);

        interceptor.intercept(&event).await.unwrap();

        // Channel should be empty — Unknown pattern skips emission.
        assert!(rx.try_recv().is_err(), "non-LLM traffic must not emit a pipeline event");
    }

    #[tokio::test]
    async fn llm_traffic_emits_pipeline_event_with_correct_fields() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let mut event = make_event(LlmApiPattern::OpenAi);
        event.response_body = Some(Bytes::from(
            r#"{"model":"gpt-4","usage":{"prompt_tokens":10,"completion_tokens":20}}"#,
        ));

        interceptor.intercept(&event).await.unwrap();

        let pipeline_event = rx.try_recv().expect("should have received a pipeline event");
        match pipeline_event {
            PipelineEvent::Audit(enriched) => {
                assert_eq!(enriched.source, EventSource::Proxy);
                assert_eq!(enriched.agent_id, "test-agent");
                // Verify the LlmCallDetail inside the AuditEvent.
                let detail = enriched.inner.detail.expect("detail must be set");
                match detail {
                    aa_proto::assembly::audit::v1::audit_event::Detail::LlmCall(llm) => {
                        assert_eq!(llm.model, "gpt-4");
                        assert_eq!(llm.prompt_tokens, 10);
                        assert_eq!(llm.completion_tokens, 20);
                        assert_eq!(llm.provider, "openai");
                    }
                    other => panic!("expected LlmCall detail, got {other:?}"),
                }
            }
            other => panic!("expected Audit event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn intercept_redacts_credentials_from_body() {
        let interceptor = make_interceptor();
        let mut event = make_event(LlmApiPattern::OpenAi);
        // Embed a well-known OpenAI API key pattern in a message content field.
        event.request_body = Some(Bytes::from(
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"my key is sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab"}]}"#,
        ));
        event.response_body = None;

        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        // Extraction still succeeds — model and message count are preserved.
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.messages_count, 1);
    }

    #[tokio::test]
    async fn intercept_credential_body_emits_redacted_event() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let mut event = make_event(LlmApiPattern::OpenAi);
        // Response body with a credential embedded in a field.
        event.response_body = Some(Bytes::from(
            r#"{"model":"gpt-4","usage":{"prompt_tokens":5,"completion_tokens":8},"debug":"sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab"}"#,
        ));

        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.prompt_tokens, Some(5));

        // The pipeline event should not contain the raw credential.
        let pipeline_event = rx.try_recv().expect("should receive pipeline event");
        let event_str = format!("{pipeline_event:?}");
        assert!(
            !event_str.contains("TESTONLY-NOT-REAL"),
            "pipeline event must not contain raw credential"
        );
    }

    #[tokio::test]
    async fn intercept_with_scanner_disabled_skips_redaction() {
        let (tx, _rx) = broadcast::channel(16);
        let interceptor = Interceptor::with_scanner(tx, None);
        let mut event = make_event(LlmApiPattern::OpenAi);
        // Body contains a credential — but scanner is disabled.
        event.response_body = Some(Bytes::from(
            r#"{"model":"gpt-4","usage":{"prompt_tokens":5,"completion_tokens":8},"debug":"sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab"}"#,
        ));

        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        // Fields are still extracted — scanning is off, not extraction.
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.prompt_tokens, Some(5));
    }

    // ── intercept_request verdict matrix ────────────────────────────────────
    //
    // The request-side credential gate maps (findings × CredentialAction) onto
    // the data-path VerdictDecision. These tests pin every arm.

    /// A synthetic OpenAI key that the default scanner detects. Not a real key.
    const CRED_BODY: &[u8] = b"leaking sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab here";

    #[test]
    fn intercept_request_disabled_scanner_forwards_even_with_credential() {
        let (tx, _rx) = broadcast::channel(16);
        let interceptor = Interceptor::with_scanner(tx, None);
        let verdict = interceptor.intercept_request(CRED_BODY, None, CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Forward);
        assert!(verdict.findings.is_empty());
        assert!(verdict.redacted_body.is_none());
    }

    #[test]
    fn intercept_request_clean_body_forwards() {
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(b"nothing secret here", None, CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Forward);
        assert!(verdict.findings.is_empty());
        assert!(verdict.redacted_body.is_none());
    }

    #[test]
    fn intercept_request_block_action_blocks_on_finding() {
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(CRED_BODY, None, CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Block);
        assert!(!verdict.findings.is_empty(), "a finding must be reported");
        // Block never forwards bytes, so no redacted body is produced.
        assert!(verdict.redacted_body.is_none());
    }

    #[test]
    fn intercept_request_redact_only_returns_redacted_bytes() {
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(CRED_BODY, None, CredentialAction::RedactOnly);
        assert_eq!(verdict.decision, VerdictDecision::ForwardRedacted);
        assert!(!verdict.findings.is_empty());
        let redacted = verdict.redacted_body.expect("redact_only must populate the body");
        assert!(
            !redacted
                .windows(b"TESTONLY-NOT-REAL".len())
                .any(|w| w == b"TESTONLY-NOT-REAL"),
            "redacted body must not contain the raw secret"
        );
    }

    #[test]
    fn intercept_request_alert_only_forwards_original_with_findings() {
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(CRED_BODY, None, CredentialAction::AlertOnly);
        assert_eq!(verdict.decision, VerdictDecision::AlertAndForward);
        assert!(!verdict.findings.is_empty());
        // alert_only forwards the original body unmodified, so no redaction.
        assert!(verdict.redacted_body.is_none());
    }

    // ── Content-Encoding request-body DLP (AAASM-4156) ──────────────────────

    /// gzip-compress `data` for building encoded test bodies.
    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;

        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn intercept_request_gzip_credential_is_blocked_not_forwarded() {
        // The headline gap: a gzip'd secret was scanned compressed (matching
        // nothing) and forwarded. It must now be decompressed, detected, and
        // blocked.
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(&gzip(CRED_BODY), Some("gzip"), CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Block);
        assert!(!verdict.findings.is_empty(), "decompressed secret must be detected");
    }

    #[test]
    fn intercept_request_gzip_clean_body_forwards() {
        // A clean gzip'd body decompresses to clean plaintext and forwards
        // (the original compressed bytes) unchanged.
        let interceptor = make_interceptor();
        let verdict =
            interceptor.intercept_request(&gzip(b"nothing secret here"), Some("gzip"), CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Forward);
        assert!(verdict.findings.is_empty());
    }

    #[test]
    fn intercept_request_unsupported_encoding_fails_closed() {
        // An encoding the proxy cannot decode is un-inspectable, so the request
        // is blocked even though no secret was (or could be) seen.
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(b"\x1b\x00\x00brotli", Some("br"), CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Block);
        assert!(
            verdict.findings.is_empty(),
            "fail-closed block reports no findings (the body was never inspected)"
        );
    }

    #[test]
    fn intercept_request_identity_encoding_is_unchanged() {
        // An explicit `identity` (and the absent-header path) scans the raw body
        // exactly as before — a clean plaintext body forwards.
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(b"nothing secret here", Some("identity"), CredentialAction::Block);
        assert_eq!(verdict.decision, VerdictDecision::Forward);
        assert!(verdict.findings.is_empty());
    }

    #[test]
    fn intercept_request_redact_only_compressed_fails_closed() {
        // RedactOnly cannot re-encode a redacted plaintext to the declared
        // encoding, and forwarding the original compressed bytes would leak the
        // secret — so it escalates to a fail-closed Block rather than forwarding.
        let interceptor = make_interceptor();
        let verdict = interceptor.intercept_request(&gzip(CRED_BODY), Some("gzip"), CredentialAction::RedactOnly);
        assert_eq!(verdict.decision, VerdictDecision::Block);
        assert!(!verdict.findings.is_empty());
        assert!(verdict.redacted_body.is_none());
    }

    // ── redact_response_body ────────────────────────────────────────────────

    #[test]
    fn redact_response_body_disabled_scanner_forwards() {
        let (tx, _rx) = broadcast::channel(16);
        let interceptor = Interceptor::with_scanner(tx, None);
        assert_eq!(interceptor.redact_response_body(CRED_BODY, None), ResponseScan::Forward);
    }

    #[test]
    fn redact_response_body_clean_payload_forwards() {
        let interceptor = make_interceptor();
        assert_eq!(
            interceptor.redact_response_body(b"clean upstream response", None),
            ResponseScan::Forward
        );
    }

    #[test]
    fn redact_response_body_with_credential_returns_redacted() {
        let interceptor = make_interceptor();
        let ResponseScan::Redact(redacted) = interceptor.redact_response_body(CRED_BODY, None) else {
            panic!("a credential payload must yield redacted bytes");
        };
        assert!(
            !redacted
                .windows(b"TESTONLY-NOT-REAL".len())
                .any(|w| w == b"TESTONLY-NOT-REAL"),
            "redacted response must not contain the raw secret"
        );
    }

    // ── emit_policy_decision (CONNECT tunnel audit) ─────────────────────────

    #[tokio::test]
    async fn emit_policy_decision_denied_emits_violation() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        interceptor.emit_policy_decision("evil.example.com", true).await;

        let event = rx.try_recv().expect("a pipeline event must be emitted");
        let PipelineEvent::Audit(enriched) = event else {
            panic!("expected Audit event");
        };
        assert_eq!(enriched.source, EventSource::Proxy);
        match enriched.inner.detail.expect("detail") {
            audit_event::Detail::Violation(v) => {
                assert_eq!(v.blocked_action, "CONNECT evil.example.com");
            }
            other => panic!("expected Violation detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_policy_decision_allowed_emits_network_detail() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        interceptor.emit_policy_decision("api.openai.com", false).await;

        let PipelineEvent::Audit(enriched) = rx.try_recv().expect("event") else {
            panic!("expected Audit event");
        };
        match enriched.inner.detail.expect("detail") {
            audit_event::Detail::Network(n) => {
                assert_eq!(n.host, "api.openai.com");
                assert_eq!(n.protocol, "https");
                assert!(n.succeeded);
            }
            other => panic!("expected Network detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_policy_decision_with_no_receiver_does_not_panic() {
        // Standalone proxy mode: the broadcast send returns Err with no
        // receivers, which the method must swallow.
        let (tx, rx) = broadcast::channel(16);
        drop(rx);
        let interceptor = Interceptor::new(tx);
        interceptor.emit_policy_decision("api.openai.com", true).await;
    }

    // ── emit_mcp_decision (tools/call audit) ────────────────────────────────

    #[tokio::test]
    async fn emit_mcp_decision_denied_emits_violation_with_blocked_action() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        interceptor
            .emit_mcp_decision("read_file", b"{}", true, "blocked on /etc paths")
            .await;

        let PipelineEvent::Audit(enriched) = rx.try_recv().expect("event") else {
            panic!("expected Audit event");
        };
        match enriched.inner.detail.expect("detail") {
            audit_event::Detail::Violation(v) => {
                assert_eq!(v.blocked_action, "tools/call read_file");
                assert_eq!(v.reason, "blocked on /etc paths");
            }
            other => panic!("expected Violation detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_mcp_decision_allowed_redacts_credentials_in_args() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let args = br#"{"token":"sk-TESTONLY-NOT-REAL-1234567890abcdef1234567890ab"}"#;
        interceptor.emit_mcp_decision("call_api", args, false, "").await;

        let PipelineEvent::Audit(enriched) = rx.try_recv().expect("event") else {
            panic!("expected Audit event");
        };
        match enriched.inner.detail.expect("detail") {
            audit_event::Detail::ToolCall(tc) => {
                assert_eq!(tc.tool_name, "call_api");
                assert_eq!(tc.tool_source, "mcp");
                assert!(tc.succeeded);
                // Producer-side scrub: the raw secret never enters the audit chain.
                assert!(
                    !tc.args_json
                        .windows(b"TESTONLY-NOT-REAL".len())
                        .any(|w| w == b"TESTONLY-NOT-REAL"),
                    "args_json must be redacted in the audit record"
                );
            }
            other => panic!("expected ToolCall detail, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn emit_mcp_decision_allowed_clean_args_pass_through() {
        let (tx, mut rx) = broadcast::channel(16);
        let interceptor = Interceptor::new(tx);
        let args = br#"{"path":"/tmp/readme.txt"}"#;
        interceptor.emit_mcp_decision("read_file", args, false, "").await;

        let PipelineEvent::Audit(enriched) = rx.try_recv().expect("event") else {
            panic!("expected Audit event");
        };
        match enriched.inner.detail.expect("detail") {
            audit_event::Detail::ToolCall(tc) => {
                // No findings → the original args bytes are preserved verbatim.
                assert_eq!(tc.args_json, args);
            }
            other => panic!("expected ToolCall detail, got {other:?}"),
        }
    }
}
