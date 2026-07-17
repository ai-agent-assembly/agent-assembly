//! LLM pricing table — per-model USD cost per 1,000 tokens.

use rust_decimal::Decimal;

/// USD cost per 1,000 tokens for one direction (input or output).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PricingEntry {
    /// USD per 1,000 input tokens.
    #[serde(with = "rust_decimal::serde::str")]
    pub input_per_1k_usd: Decimal,
    /// USD per 1,000 output tokens.
    #[serde(with = "rust_decimal::serde::str")]
    pub output_per_1k_usd: Decimal,
}

/// Flat JSON record used only for deserialization.
#[derive(serde::Deserialize)]
struct PricingJsonRow {
    provider: crate::budget::types::Provider,
    model: crate::budget::types::Model,
    #[serde(with = "rust_decimal::serde::str")]
    input_per_1k_usd: Decimal,
    #[serde(with = "rust_decimal::serde::str")]
    output_per_1k_usd: Decimal,
}

/// In-memory table mapping `(Provider, Model)` to pricing.
#[derive(Debug, Clone)]
pub struct PricingTable {
    entries: std::collections::HashMap<(crate::budget::types::Provider, crate::budget::types::Model), PricingEntry>,
    /// Conservative price applied to a call whose model name does not resolve
    /// to a known `(Provider, Model)` pair (AAASM-4069). Set to the most
    /// expensive known rate so an unrecognized model can never be cheaper than
    /// a metered one — the budget cap fails closed instead of open.
    fallback: PricingEntry,
}

impl PricingTable {
    /// Build the default embedded pricing table (2024 list prices).
    pub fn default_table() -> Self {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> Decimal {
            s.parse().expect("embedded literal")
        }

        let rows: &[(Provider, Model, &str, &str)] = &[
            (Provider::OpenAi, Model::Gpt4o, "0.005", "0.015"),
            (Provider::OpenAi, Model::Gpt4, "0.03", "0.06"),
            (Provider::OpenAi, Model::Gpt35Turbo, "0.0005", "0.0015"),
            (Provider::Anthropic, Model::Claude3Opus, "0.015", "0.075"),
            (Provider::Anthropic, Model::Claude3Sonnet, "0.003", "0.015"),
            (Provider::Anthropic, Model::Claude3Haiku, "0.00025", "0.00125"),
            (Provider::Cohere, Model::CommandRPlus, "0.003", "0.015"),
            (Provider::Cohere, Model::CommandR, "0.0005", "0.0015"),
        ];

        let entries = rows
            .iter()
            .map(|(prov, model, inp, out)| {
                (
                    (*prov, *model),
                    PricingEntry {
                        input_per_1k_usd: d(inp),
                        output_per_1k_usd: d(out),
                    },
                )
            })
            .collect();

        Self {
            entries,
            // AAASM-4069 fail-closed fallback: mirror the costliest default
            // entry (Claude 3 Opus, "0.015"/"0.075") so a model outside the
            // table is priced at least as high as any known model. Priced
            // through `fallback_cost_usd`, this keeps unknown-model spend
            // metered and the budget reservation reachable.
            fallback: PricingEntry {
                input_per_1k_usd: d("0.015"),
                output_per_1k_usd: d("0.075"),
            },
        }
    }

    /// Load pricing overrides from a JSON string, merging on top of the defaults.
    pub fn load_from_json_str(json: &str) -> Result<Self, PricingLoadError> {
        let rows: Vec<PricingJsonRow> = serde_json::from_str(json).map_err(PricingLoadError::Json)?;
        let mut table = Self::default_table();
        for row in rows {
            table.entries.insert(
                (row.provider, row.model),
                PricingEntry {
                    input_per_1k_usd: row.input_per_1k_usd,
                    output_per_1k_usd: row.output_per_1k_usd,
                },
            );
        }
        Ok(table)
    }

    /// Load from a file path. Returns `default_table()` silently on any I/O or parse error.
    pub fn load_from_file(path: &std::path::Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(json) => Self::load_from_json_str(&json).unwrap_or_else(|e| {
                eprintln!(
                    "aa-gateway: failed to parse pricing file {} ({e}); using defaults",
                    path.display()
                );
                Self::default_table()
            }),
            Err(_) => Self::default_table(),
        }
    }

    /// Compute USD cost for a completed LLM call.
    ///
    /// Fail-closed (AAASM-4744): a `(provider, model)` pair absent from the table
    /// is priced through [`fallback_cost_usd`](Self::fallback_cost_usd) at the
    /// costliest-known rate, never `$0`. A partial custom pricing table (an
    /// override JSON that lists only some models) must not silently zero-price
    /// the models it omits — a `$0` cost would trip the `cost <= 0` accrual
    /// short-circuit in the gateway and bypass the budget cap entirely.
    pub fn cost_usd(
        &self,
        provider: crate::budget::types::Provider,
        model: crate::budget::types::Model,
        input_tokens: u64,
        output_tokens: u64,
    ) -> Decimal {
        match self.entries.get(&(provider, model)) {
            Some(entry) => {
                let input_cost = entry.input_per_1k_usd * Decimal::from(input_tokens) / Decimal::from(1_000u64);
                let output_cost = entry.output_per_1k_usd * Decimal::from(output_tokens) / Decimal::from(1_000u64);
                input_cost + output_cost
            }
            None => self.fallback_cost_usd(input_tokens, output_tokens),
        }
    }

    /// Price a call whose model did not resolve to a known `(Provider, Model)`
    /// pair, using the conservative fallback rate (AAASM-4069).
    ///
    /// Fail-closed: an unrecognized model name must NOT price to `$0`, or the
    /// `cost <= 0.0` accrual short-circuit in the gateway skips the budget
    /// reservation entirely and the daily/monthly cap is bypassed. Charging the
    /// costliest-known rate keeps spend accruing so the cap still engages for
    /// any current model outside the built-in table (o1/o3, gemini-*, llama-*,
    /// "gpt-5", …). Cost is token-proportional, so a genuinely empty call
    /// (0 tokens) still prices to zero — the token count is trusted separately.
    pub fn fallback_cost_usd(&self, input_tokens: u64, output_tokens: u64) -> Decimal {
        let input_cost = self.fallback.input_per_1k_usd * Decimal::from(input_tokens) / Decimal::from(1_000u64);
        let output_cost = self.fallback.output_per_1k_usd * Decimal::from(output_tokens) / Decimal::from(1_000u64);
        input_cost + output_cost
    }

    /// The conservative fallback pricing entry applied to unrecognized models.
    pub fn fallback_entry(&self) -> &PricingEntry {
        &self.fallback
    }

    /// Look up pricing for a `(provider, model)` pair.
    pub fn entry(
        &self,
        provider: crate::budget::types::Provider,
        model: crate::budget::types::Model,
    ) -> Option<&PricingEntry> {
        self.entries.get(&(provider, model))
    }
}

/// Error loading the pricing JSON config.
#[derive(Debug)]
pub enum PricingLoadError {
    Json(serde_json::Error),
}

impl std::fmt::Display for PricingLoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PricingLoadError::Json(e) => write!(f, "pricing JSON error: {e}"),
        }
    }
}

impl std::error::Error for PricingLoadError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cost_usd_gpt4o_input_only() {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let table = PricingTable::default_table();
        // 1,000 input tokens × $0.005/1k = $0.005
        assert_eq!(table.cost_usd(Provider::OpenAi, Model::Gpt4o, 1_000, 0), d("0.005"));
    }

    #[test]
    fn cost_usd_gpt4o_mixed_tokens() {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let table = PricingTable::default_table();
        // 100k input ($0.50) + 20k output ($0.30) = $0.80
        assert_eq!(
            table.cost_usd(Provider::OpenAi, Model::Gpt4o, 100_000, 20_000),
            d("0.80")
        );
    }

    #[test]
    fn cost_usd_unknown_pair_prices_via_fail_closed_fallback() {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let table = PricingTable::default_table();
        // AAASM-4744: Anthropic + CommandR is not a tabled pair. It must price
        // through the costliest-known fallback (Opus: $0.015 in + $0.075 out),
        // never $0 — a zero cost would bypass the budget cap.
        assert_eq!(
            table.cost_usd(Provider::Anthropic, Model::CommandR, 1_000, 1_000),
            d("0.09"),
        );
        assert_eq!(
            table.cost_usd(Provider::Anthropic, Model::CommandR, 1_000, 1_000),
            table.fallback_cost_usd(1_000, 1_000),
        );
    }

    #[test]
    fn fallback_cost_usd_is_nonzero_and_uses_costliest_rate() {
        // AAASM-4069: an unknown model must price at the costliest known rate
        // (Claude 3 Opus) so it can never be cheaper than a metered call.
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let table = PricingTable::default_table();
        // 10,000 input tokens × $0.015/1k = $0.15 (Opus input rate).
        assert_eq!(table.fallback_cost_usd(10_000, 0), d("0.15"));
        // 1,000 input + 1,000 output = $0.015 + $0.075 = $0.09.
        assert_eq!(table.fallback_cost_usd(1_000, 1_000), d("0.09"));
        // The fallback rate matches the most expensive default entry.
        let opus = table
            .entry(
                crate::budget::types::Provider::Anthropic,
                crate::budget::types::Model::Claude3Opus,
            )
            .unwrap();
        assert_eq!(table.fallback_entry().input_per_1k_usd, opus.input_per_1k_usd);
        assert_eq!(table.fallback_entry().output_per_1k_usd, opus.output_per_1k_usd);
    }

    #[test]
    fn load_from_file_falls_back_to_defaults_on_missing_file() {
        let path = std::path::Path::new("/nonexistent/path/pricing.json");
        let table = PricingTable::load_from_file(path);
        use crate::budget::types::{Model, Provider};
        assert!(table.entry(Provider::OpenAi, Model::Gpt4o).is_some());
    }

    #[test]
    fn load_from_json_str_overrides_gpt4o_input_price() {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let json = r#"[
          { "provider": "open_ai", "model": "gpt4o",
            "input_per_1k_usd": "0.999", "output_per_1k_usd": "0.015" }
        ]"#;
        let table = PricingTable::load_from_json_str(json).unwrap();
        let entry = table.entry(Provider::OpenAi, Model::Gpt4o).unwrap();
        assert_eq!(entry.input_per_1k_usd, d("0.999"));
        // Non-overridden models keep defaults
        assert!(table.entry(Provider::Anthropic, Model::Claude3Opus).is_some());
    }

    #[test]
    fn default_table_contains_all_eight_models() {
        use crate::budget::types::{Model, Provider};
        let table = PricingTable::default_table();
        for (prov, model) in [
            (Provider::OpenAi, Model::Gpt4o),
            (Provider::OpenAi, Model::Gpt4),
            (Provider::OpenAi, Model::Gpt35Turbo),
            (Provider::Anthropic, Model::Claude3Opus),
            (Provider::Anthropic, Model::Claude3Sonnet),
            (Provider::Anthropic, Model::Claude3Haiku),
            (Provider::Cohere, Model::CommandRPlus),
            (Provider::Cohere, Model::CommandR),
        ] {
            assert!(table.entry(prov, model).is_some(), "{prov:?}/{model:?} missing");
        }
    }

    #[test]
    fn default_table_gpt4o_has_correct_rates() {
        use crate::budget::types::{Model, Provider};
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let table = PricingTable::default_table();
        let entry = table.entry(Provider::OpenAi, Model::Gpt4o).unwrap();
        assert_eq!(entry.input_per_1k_usd, d("0.005"));
        assert_eq!(entry.output_per_1k_usd, d("0.015"));
    }

    #[test]
    fn pricing_load_error_displays_message() {
        let raw = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = PricingLoadError::Json(raw);
        assert!(err.to_string().contains("pricing JSON error"));
    }

    #[test]
    fn pricing_entry_stores_rates() {
        fn d(s: &str) -> rust_decimal::Decimal {
            s.parse().unwrap()
        }
        let entry = PricingEntry {
            input_per_1k_usd: d("0.005"),
            output_per_1k_usd: d("0.015"),
        };
        assert_eq!(entry.input_per_1k_usd, d("0.005"));
        assert_eq!(entry.output_per_1k_usd, d("0.015"));
    }
}
