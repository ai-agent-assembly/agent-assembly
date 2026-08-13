//! LLM provider and model identifiers shared across the workspace.
//!
//! These types and the [`Model::infer_from_name`] helper were originally
//! introduced inside `aa-gateway::budget::types` (AAASM-3353). They are
//! relocated here (AAASM-3362) so that SDKs and other crates can reuse the
//! provider/model taxonomy and the model-name → `(Provider, Model)` inference
//! without taking a dependency on `aa-gateway`. Pricing tables remain in
//! `aa-gateway` — only the enums and the inference logic are core-appropriate.

/// LLM provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Provider {
    /// OpenAI (GPT-* models).
    OpenAi,
    /// Anthropic (Claude models).
    Anthropic,
    /// Cohere (Command models).
    Cohere,
}

/// LLM model identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum Model {
    /// OpenAI GPT-4o.
    Gpt4o,
    /// OpenAI GPT-4.
    Gpt4,
    /// OpenAI GPT-3.5 Turbo.
    Gpt35Turbo,
    /// Anthropic Claude 3 Opus.
    Claude3Opus,
    /// Anthropic Claude 3 Sonnet.
    Claude3Sonnet,
    /// Anthropic Claude 3 Haiku.
    Claude3Haiku,
    /// Cohere Command R+.
    CommandRPlus,
    /// Cohere Command R.
    CommandR,
}

impl Model {
    /// Infer the `(Provider, Model)` pair from a free-form model name string.
    ///
    /// AAASM-3353 — the live `CheckAction` proto (`LlmCallContext`) carries only
    /// the model name string; it does NOT carry a provider field. Rather than
    /// change `proto/` (out of scope), the provider is inferred here from the
    /// model name. The match is a case-insensitive substring test against the
    /// known model families, ordered most-specific-first so that e.g.
    /// `gpt-4o-2024-08-06` maps to `Gpt4o` (not `Gpt4`) and
    /// `command-r-plus` maps to `CommandRPlus` (not `CommandR`).
    ///
    /// Returns `None` for an unrecognised model name. Callers must decide how
    /// to price an unknown model — the gateway budget stage fails closed at a
    /// conservative fallback rate (AAASM-4069) rather than treating it as free.
    pub fn infer_from_name(name: &str) -> Option<(Provider, Self)> {
        let n = name.to_ascii_lowercase();
        // Most-specific patterns first; substrings of others must come earlier.
        if n.contains("gpt-4o") || n.contains("gpt4o") {
            Some((Provider::OpenAi, Model::Gpt4o))
        } else if n.contains("gpt-3.5") || n.contains("gpt35") || n.contains("gpt-35") {
            Some((Provider::OpenAi, Model::Gpt35Turbo))
        } else if n.contains("gpt-4") || n.contains("gpt4") {
            Some((Provider::OpenAi, Model::Gpt4))
        } else if n.contains("opus") {
            Some((Provider::Anthropic, Model::Claude3Opus))
        } else if n.contains("sonnet") {
            Some((Provider::Anthropic, Model::Claude3Sonnet))
        } else if n.contains("haiku") {
            Some((Provider::Anthropic, Model::Claude3Haiku))
        } else if n.contains("command-r-plus") || n.contains("command-r+") {
            Some((Provider::Cohere, Model::CommandRPlus))
        } else if n.contains("command-r") {
            Some((Provider::Cohere, Model::CommandR))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_variants_are_distinct() {
        assert_eq!(Provider::OpenAi, Provider::OpenAi);
        assert_ne!(Provider::OpenAi, Provider::Anthropic);
        assert_ne!(Provider::OpenAi, Provider::Cohere);
        assert_ne!(Provider::Anthropic, Provider::Cohere);
    }

    #[test]
    fn model_variants_are_distinct() {
        assert_eq!(Model::Gpt4o, Model::Gpt4o);
        assert_ne!(Model::Gpt4o, Model::Gpt4);
        assert_ne!(Model::Claude3Opus, Model::Claude3Haiku);
        assert_ne!(Model::CommandRPlus, Model::CommandR);
    }

    #[test]
    fn infer_openai_gpt4o_most_specific() {
        assert_eq!(
            Model::infer_from_name("gpt-4o-2024-08-06"),
            Some((Provider::OpenAi, Model::Gpt4o))
        );
        assert_eq!(Model::infer_from_name("GPT4O"), Some((Provider::OpenAi, Model::Gpt4o)));
    }

    #[test]
    fn infer_openai_gpt35_before_gpt4() {
        assert_eq!(
            Model::infer_from_name("gpt-3.5-turbo"),
            Some((Provider::OpenAi, Model::Gpt35Turbo))
        );
    }

    #[test]
    fn infer_openai_gpt4() {
        assert_eq!(Model::infer_from_name("gpt-4"), Some((Provider::OpenAi, Model::Gpt4)));
    }

    #[test]
    fn infer_anthropic_family() {
        assert_eq!(
            Model::infer_from_name("claude-3-opus-20240229"),
            Some((Provider::Anthropic, Model::Claude3Opus))
        );
        assert_eq!(
            Model::infer_from_name("claude-3-5-sonnet"),
            Some((Provider::Anthropic, Model::Claude3Sonnet))
        );
        assert_eq!(
            Model::infer_from_name("claude-3-haiku"),
            Some((Provider::Anthropic, Model::Claude3Haiku))
        );
    }

    #[test]
    fn infer_cohere_command_r_plus_before_command_r() {
        assert_eq!(
            Model::infer_from_name("command-r-plus"),
            Some((Provider::Cohere, Model::CommandRPlus))
        );
        assert_eq!(
            Model::infer_from_name("command-r"),
            Some((Provider::Cohere, Model::CommandR))
        );
    }

    #[test]
    fn infer_unknown_returns_none() {
        assert_eq!(Model::infer_from_name("mystery-model-v9"), None);
        assert_eq!(Model::infer_from_name(""), None);
    }
}
