//! Traffic interception: detect LLM API calls and emit structured events.

pub mod detect;
pub mod event;
pub mod extract;

use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::broadcast;

use aa_proto::assembly::audit::v1::{audit_event, AuditEvent, LlmCallDetail, NetworkCallDetail, PolicyViolation};
use aa_proto::assembly::common::v1::ActionType;
use aa_runtime::pipeline::event::{EnrichedEvent, EventSource};
use aa_runtime::pipeline::PipelineEvent;

use aa_core::CredentialScanner;

use crate::error::ProxyError;
use crate::intercept::detect::LlmApiPattern;
use crate::intercept::extract::{extract_anthropic, extract_cohere, extract_openai, ExtractionError, LlmFields};

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
        };

        // send() returns Err only when there are zero receivers — normal for
        // standalone proxy operation (no runtime attached).
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
            r#"{"model":"gpt-4","messages":[{"role":"user","content":"my key is sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab"}]}"#,
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
            r#"{"model":"gpt-4","usage":{"prompt_tokens":5,"completion_tokens":8},"debug":"sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab"}"#,
        ));

        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.prompt_tokens, Some(5));

        // The pipeline event should not contain the raw credential.
        let pipeline_event = rx.try_recv().expect("should receive pipeline event");
        let event_str = format!("{pipeline_event:?}");
        assert!(
            !event_str.contains("sk-proj-"),
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
            r#"{"model":"gpt-4","usage":{"prompt_tokens":5,"completion_tokens":8},"debug":"sk-proj-aBcDeFgHiJkLmNoPqRsT1234567890abcdef1234567890ab"}"#,
        ));

        let fields = interceptor.intercept(&event).await.unwrap().unwrap();
        // Fields are still extracted — scanning is off, not extraction.
        assert_eq!(fields.model, "gpt-4");
        assert_eq!(fields.prompt_tokens, Some(5));
    }
}
