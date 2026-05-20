//! RFC 7807 Problem Details error responses.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// RFC 7807 Problem Details JSON body.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[schema(example = json!({
    "type": "about:blank",
    "title": "Not Found",
    "status": 404,
    "detail": "No route matched: /unknown",
    "instance": "/unknown"
}))]
pub struct ProblemDetail {
    /// URI reference identifying the problem type.
    #[serde(rename = "type")]
    pub type_uri: String,
    /// Short human-readable summary.
    pub title: String,
    /// HTTP status code.
    pub status: u16,
    /// Human-readable explanation specific to this occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// URI reference identifying the specific occurrence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// Stable machine-readable error code (e.g. `"invalid_threshold"`)
    /// for clients that need to branch on the specific failure
    /// without parsing the human-readable `detail`. Omitted from the
    /// wire when unset so existing endpoints stay byte-identical.
    ///
    /// Codes are static identifiers — `&'static str` keeps the struct
    /// small enough that handlers returning `Result<_, ProblemDetail>`
    /// stay under clippy's `result_large_err` threshold.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<&'static str>,
}

impl ProblemDetail {
    /// Create a `ProblemDetail` from an HTTP status code.
    pub fn from_status(status: StatusCode) -> Self {
        Self {
            type_uri: "about:blank".to_string(),
            title: status.canonical_reason().unwrap_or("Unknown Error").to_string(),
            status: status.as_u16(),
            detail: None,
            instance: None,
            error_code: None,
        }
    }

    /// Attach a human-readable detail message.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    /// Attach the request URI as the instance identifier.
    #[must_use]
    pub fn with_instance(mut self, instance: impl Into<String>) -> Self {
        self.instance = Some(instance.into());
        self
    }

    /// Attach a stable machine-readable error code.
    #[must_use]
    pub fn with_error_code(mut self, code: &'static str) -> Self {
        self.error_code = Some(code);
        self
    }
}

impl IntoResponse for ProblemDetail {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = serde_json::to_string(&self)
            .unwrap_or_else(|_| r#"{"type":"about:blank","title":"Internal Server Error","status":500}"#.to_string());

        (
            status,
            [(axum::http::header::CONTENT_TYPE, "application/problem+json")],
            body,
        )
            .into_response()
    }
}
