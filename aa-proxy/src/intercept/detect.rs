//! LLM API pattern detection from HTTPS request host headers.
//!
//! The proxy only intercepts traffic destined for known LLM providers when
//! `ProxyConfig::llm_only` is `true`. This module provides the detection logic.

/// Identifies which LLM provider an intercepted request is targeting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlmApiPattern {
    /// `api.openai.com`
    OpenAi,
    /// `api.anthropic.com`
    Anthropic,
    /// `api.cohere.com`
    Cohere,
    /// Host does not match any known LLM API.
    Unknown,
}

/// Classify `host` (the CONNECT tunnel target hostname) as an [`LlmApiPattern`].
///
/// Comparison is case-insensitive. A host like `api.openai.com:443` is
/// normalised by stripping the port before matching. A single trailing dot is
/// also stripped (AAASM-3983): `api.openai.com.` is a valid, equivalent FQDN
/// for `api.openai.com`, so without this it would classify as `Unknown` and —
/// under `llm_only` — take the transparent raw-tunnel path, reaching the
/// provider with no scan/redact/audit.
pub fn detect_api(host: &str) -> LlmApiPattern {
    let hostname = host.split(':').next().unwrap_or(host);
    let hostname = hostname.strip_suffix('.').unwrap_or(hostname);
    match hostname.to_ascii_lowercase().as_str() {
        "api.openai.com" => LlmApiPattern::OpenAi,
        "api.anthropic.com" => LlmApiPattern::Anthropic,
        "api.cohere.com" => LlmApiPattern::Cohere,
        _ => LlmApiPattern::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_openai() {
        assert_eq!(detect_api("api.openai.com"), LlmApiPattern::OpenAi);
    }

    #[test]
    fn detects_anthropic() {
        assert_eq!(detect_api("api.anthropic.com"), LlmApiPattern::Anthropic);
    }

    #[test]
    fn detects_cohere() {
        assert_eq!(detect_api("api.cohere.com"), LlmApiPattern::Cohere);
    }

    #[test]
    fn unknown_host_returns_unknown() {
        assert_eq!(detect_api("example.com"), LlmApiPattern::Unknown);
    }

    #[test]
    fn strips_port_before_matching() {
        assert_eq!(detect_api("api.openai.com:443"), LlmApiPattern::OpenAi);
    }

    #[test]
    fn case_insensitive_matching() {
        assert_eq!(detect_api("API.OPENAI.COM"), LlmApiPattern::OpenAi);
        assert_eq!(detect_api("Api.Anthropic.Com"), LlmApiPattern::Anthropic);
    }

    #[test]
    fn subdomain_does_not_match() {
        assert_eq!(detect_api("cdn.api.openai.com"), LlmApiPattern::Unknown);
    }
}
