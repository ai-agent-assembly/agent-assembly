//! Core domain types for the budget tracking engine.

use chrono::Datelike;

/// LLM provider identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provider {
    /// OpenAI (GPT-* models).
    OpenAi,
    /// Anthropic (Claude models).
    Anthropic,
    /// Cohere (Command models).
    Cohere,
}

/// LLM model identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Model {
    // OpenAI
    Gpt4o,
    Gpt4,
    Gpt35Turbo,
    // Anthropic
    Claude3Opus,
    Claude3Sonnet,
    Claude3Haiku,
    // Cohere
    CommandRPlus,
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
    /// Returns `None` for an unrecognised model name — the caller treats an
    /// unknown model as zero cost (no spend accrued) rather than guessing.
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

/// Discriminates which budget window a limit or check applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetKind {
    /// Per-calendar-day spend window, reset at midnight in the configured timezone.
    Daily,
    /// Per-calendar-month spend window, reset on the first of each month.
    Monthly,
    /// Aggregate across all windows (used for subtree-level checks).
    Global,
}

/// Rollover strategy for [`super::tracker::BudgetTracker`].
///
/// `Daily` (the default) zeroes accumulated spend at the calendar-day
/// boundary in the tracker's configured timezone — historical behaviour
/// preserved for every existing deployment.
///
/// `Duration` zeroes accumulated spend every elapsed wall-clock interval —
/// driven by [`BudgetState::last_reset_at`]. Intended for test fixtures and
/// short-cycle staging environments that need sub-day rollover (e.g. a
/// 200 ms window for the `budget_resets_after_daily_window` integration
/// test gated by AAASM-1600).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BudgetWindow {
    /// Reset at midnight in the configured timezone.
    #[default]
    Daily,
    /// Reset every `interval` of wall-clock time.
    Duration(std::time::Duration),
}

/// Error returned by [`super::tracker::BudgetTracker::check_and_decrement`].
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BudgetError {
    /// An ancestor agent's budget is exhausted; the spend was not applied to any node.
    #[error("ancestor {ancestor_id:?} budget exhausted ({kind:?})")]
    AncestorBudgetExhausted {
        /// The ancestor agent whose budget was exceeded.
        ancestor_id: [u8; 16],
        /// Which window (daily/monthly/global) was exhausted.
        kind: BudgetKind,
    },
}

/// Result returned by [`super::tracker::BudgetTracker::record_usage`].
#[derive(Debug, Clone, PartialEq)]
pub enum BudgetStatus {
    /// Spend is below the 80% alert threshold.
    WithinBudget { spent_usd: f64, remaining_usd: f64 },
    /// Spend crossed 80% or 95% of the daily limit.
    ThresholdAlert { pct: u8 },
    /// Daily limit reached or exceeded — caller should block the LLM call.
    LimitExceeded,
}

/// Per-agent accumulated spend for daily and monthly windows.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudgetState {
    /// Total USD spent today using exact decimal arithmetic.
    #[serde(with = "rust_decimal::serde::str")]
    pub spent_usd: rust_decimal::Decimal,
    /// UTC calendar date this state is valid for.
    pub date: chrono::NaiveDate,
    /// Current month as `YYYYMM` (e.g. `202604`). Used for monthly reset.
    #[serde(default)]
    pub month: u32,
    /// Total USD spent this calendar month. `None` when monthly tracking is unused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_spent_usd: Option<rust_decimal::Decimal>,
    /// Wall-clock instant of the last sub-day reset.
    ///
    /// `None` preserves the historical date-only reset path (and the
    /// back-compat for `budget.json` files written before AAASM-1600);
    /// `Some(t)` is populated by [`maybe_reset_window`] when the tracker
    /// is configured with [`BudgetWindow::Duration`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reset_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl BudgetState {
    /// Compute the `YYYYMM` month tag for a given date.
    fn month_tag(date: chrono::NaiveDate) -> u32 {
        date.year() as u32 * 100 + date.month()
    }

    /// Create a fresh zero-spend state stamped with today's UTC date.
    pub fn new_today() -> Self {
        let date = chrono::Utc::now().date_naive();
        Self {
            spent_usd: rust_decimal::Decimal::ZERO,
            date,
            month: Self::month_tag(date),
            monthly_spent_usd: None,
            last_reset_at: None,
        }
    }

    /// Create a fresh zero-spend state stamped with the given date.
    pub fn new_for_date(date: chrono::NaiveDate) -> Self {
        Self {
            spent_usd: rust_decimal::Decimal::ZERO,
            date,
            month: Self::month_tag(date),
            monthly_spent_usd: None,
            last_reset_at: None,
        }
    }

    /// Reset daily spend if the day changed; reset monthly spend if the month changed.
    pub fn maybe_reset(&mut self, today: chrono::NaiveDate) {
        let current_month = Self::month_tag(today);
        if current_month != self.month {
            self.monthly_spent_usd = self.monthly_spent_usd.map(|_| rust_decimal::Decimal::ZERO);
            self.month = current_month;
        }
        if self.date < today {
            self.spent_usd = rust_decimal::Decimal::ZERO;
            self.date = today;
        }
    }

    /// Window-aware reset.
    ///
    /// For [`BudgetWindow::Daily`] this is equivalent to [`maybe_reset`] using
    /// the calendar date of `now` in the supplied timezone.
    ///
    /// For [`BudgetWindow::Duration`] the daily accumulator is zeroed each time
    /// `now - last_reset_at >= interval`. On the first call under a fresh state
    /// `last_reset_at` is `None`, so we seed the anchor without zeroing —
    /// existing spend (loaded from disk) is preserved across the upgrade path.
    pub fn maybe_reset_window(&mut self, now: chrono::DateTime<chrono::Utc>, window: BudgetWindow, tz: chrono_tz::Tz) {
        match window {
            BudgetWindow::Daily => {
                self.maybe_reset(now.with_timezone(&tz).date_naive());
            }
            BudgetWindow::Duration(interval) => {
                let today = now.with_timezone(&tz).date_naive();
                let current_month = Self::month_tag(today);
                if current_month != self.month {
                    self.monthly_spent_usd = self.monthly_spent_usd.map(|_| rust_decimal::Decimal::ZERO);
                    self.month = current_month;
                }
                match self.last_reset_at {
                    None => {
                        // Seed the anchor on first observation under the
                        // Duration window. Existing `spent_usd` (legacy or
                        // mid-window) stays as-is — the rollover triggers only
                        // once we have a baseline.
                        self.last_reset_at = Some(now);
                    }
                    Some(anchor) => {
                        let elapsed = now
                            .signed_duration_since(anchor)
                            .to_std()
                            .unwrap_or(std::time::Duration::ZERO);
                        if elapsed >= interval {
                            self.spent_usd = rust_decimal::Decimal::ZERO;
                            self.last_reset_at = Some(now);
                            self.date = today;
                        }
                    }
                }
            }
        }
    }
}

/// Aggregate spend summary for an agent and its entire descendant subtree.
#[derive(Debug, Clone, PartialEq)]
pub struct SubtreeSpend {
    /// Total input + output tokens across the subtree for today's window.
    pub tokens: u64,
    /// Total USD spend across the subtree for today's window.
    pub usd: rust_decimal::Decimal,
    /// Number of distinct agents in the subtree that have recorded spend today.
    pub agents_counted: usize,
}

/// Alert emitted via broadcast when spend crosses 80% or 95% of a daily or monthly limit.
#[derive(Debug, Clone)]
pub struct BudgetAlert {
    /// The agent whose spend triggered the alert.
    pub agent_id: aa_core::AgentId,
    /// Team whose budget triggered the alert, if this is a team-level alert.
    pub team_id: Option<String>,
    /// Threshold percentage crossed: 80 or 95.
    pub threshold_pct: u8,
    /// Current total spend in USD.
    pub spent_usd: f64,
    /// Configured daily limit in USD.
    pub limit_usd: f64,
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
    fn budget_status_within_budget_holds_values() {
        let s = BudgetStatus::WithinBudget {
            spent_usd: 5.0,
            remaining_usd: 45.0,
        };
        match s {
            BudgetStatus::WithinBudget {
                spent_usd,
                remaining_usd,
            } => {
                assert!((spent_usd - 5.0).abs() < f64::EPSILON);
                assert!((remaining_usd - 45.0).abs() < f64::EPSILON);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn budget_status_threshold_alert_holds_pct() {
        let s = BudgetStatus::ThresholdAlert { pct: 80 };
        assert_eq!(s, BudgetStatus::ThresholdAlert { pct: 80 });
        assert_ne!(s, BudgetStatus::ThresholdAlert { pct: 95 });
    }

    #[test]
    fn budget_state_new_today_has_zero_spend() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let state = BudgetState::new_today();
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.date, Utc::now().date_naive());
    }

    #[test]
    fn budget_state_maybe_reset_clears_old_date() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let yesterday = Utc::now().date_naive() - chrono::Duration::days(1);
        let mut state = BudgetState {
            spent_usd: Decimal::new(500, 2), // 5.00
            date: yesterday,
            month: BudgetState::month_tag(yesterday),
            monthly_spent_usd: None,
            last_reset_at: None,
        };
        state.maybe_reset(Utc::now().date_naive());
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.date, Utc::now().date_naive());
    }

    #[test]
    fn budget_state_maybe_reset_same_day_is_noop() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let amount = Decimal::new(500, 2); // 5.00
        let today = Utc::now().date_naive();
        let mut state = BudgetState {
            spent_usd: amount,
            date: today,
            month: BudgetState::month_tag(today),
            monthly_spent_usd: None,
            last_reset_at: None,
        };
        state.maybe_reset(Utc::now().date_naive());
        assert_eq!(state.spent_usd, amount);
    }

    #[test]
    fn budget_state_maybe_reset_uses_injected_date() {
        use chrono::NaiveDate;
        use rust_decimal::Decimal;
        let jan1 = NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let mut state = BudgetState {
            spent_usd: Decimal::new(500, 2), // 5.00
            date: jan1,
            month: BudgetState::month_tag(jan1),
            monthly_spent_usd: None,
            last_reset_at: None,
        };
        // Inject a specific "today" that is after state.date
        let injected_today = NaiveDate::from_ymd_opt(2024, 1, 2).unwrap();
        state.maybe_reset(injected_today);
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.date, injected_today);
    }

    #[test]
    fn monthly_reset_clears_monthly_spend_on_month_change() {
        use chrono::NaiveDate;
        use rust_decimal::Decimal;
        let jan31 = NaiveDate::from_ymd_opt(2024, 1, 31).unwrap();
        let mut state = BudgetState {
            spent_usd: Decimal::new(500, 2),
            date: jan31,
            month: BudgetState::month_tag(jan31),
            monthly_spent_usd: Some(Decimal::new(10000, 2)), // 100.00
            last_reset_at: None,
        };
        let feb1 = NaiveDate::from_ymd_opt(2024, 2, 1).unwrap();
        state.maybe_reset(feb1);
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.monthly_spent_usd, Some(Decimal::ZERO));
        assert_eq!(state.month, 202402);
        assert_eq!(state.date, feb1);
    }

    #[test]
    fn monthly_no_reset_within_same_month() {
        use chrono::NaiveDate;
        use rust_decimal::Decimal;
        let jan1 = NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
        let monthly = Decimal::new(5000, 2); // 50.00
        let mut state = BudgetState {
            spent_usd: Decimal::new(500, 2),
            date: jan1,
            month: BudgetState::month_tag(jan1),
            monthly_spent_usd: Some(monthly),
            last_reset_at: None,
        };
        let jan2 = NaiveDate::from_ymd_opt(2024, 1, 2).unwrap();
        state.maybe_reset(jan2);
        // Daily resets, monthly does not
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.monthly_spent_usd, Some(monthly));
        assert_eq!(state.month, 202401);
    }

    #[test]
    fn monthly_none_stays_none_on_month_change() {
        use chrono::NaiveDate;
        use rust_decimal::Decimal;
        let dec31 = NaiveDate::from_ymd_opt(2024, 12, 31).unwrap();
        let mut state = BudgetState {
            spent_usd: Decimal::new(100, 2),
            date: dec31,
            month: BudgetState::month_tag(dec31),
            monthly_spent_usd: None,
            last_reset_at: None,
        };
        let jan1 = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
        state.maybe_reset(jan1);
        assert!(state.monthly_spent_usd.is_none());
        assert_eq!(state.month, 202501);
    }

    #[test]
    fn month_tag_computes_correctly() {
        use chrono::NaiveDate;
        assert_eq!(
            BudgetState::month_tag(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap()),
            202401
        );
        assert_eq!(
            BudgetState::month_tag(NaiveDate::from_ymd_opt(2024, 12, 31).unwrap()),
            202412
        );
        assert_eq!(
            BudgetState::month_tag(NaiveDate::from_ymd_opt(2026, 4, 29).unwrap()),
            202604
        );
    }

    #[test]
    fn budget_alert_stores_fields() {
        use aa_core::AgentId;
        let id = AgentId::from_bytes([1u8; 16]);
        let alert = BudgetAlert {
            agent_id: id,
            team_id: None,
            threshold_pct: 80,
            spent_usd: 8.0,
            limit_usd: 10.0,
        };
        assert_eq!(alert.threshold_pct, 80);
        assert!((alert.spent_usd - 8.0).abs() < f64::EPSILON);
    }

    #[test]
    fn maybe_reset_window_daily_matches_maybe_reset() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let yesterday = Utc::now().date_naive() - chrono::Duration::days(1);
        let mut a = BudgetState::new_for_date(yesterday);
        a.spent_usd = Decimal::new(500, 2);
        let mut b = a.clone();
        a.maybe_reset(Utc::now().date_naive());
        b.maybe_reset_window(Utc::now(), BudgetWindow::Daily, chrono_tz::UTC);
        assert_eq!(a.spent_usd, b.spent_usd);
        assert_eq!(a.date, b.date);
    }

    #[test]
    fn maybe_reset_window_duration_seeds_anchor_without_zeroing() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let mut state = BudgetState::new_today();
        state.spent_usd = Decimal::new(500, 2);
        let before = state.spent_usd;
        let now = Utc::now();
        state.maybe_reset_window(
            now,
            BudgetWindow::Duration(std::time::Duration::from_secs(60)),
            chrono_tz::UTC,
        );
        // First observation under Duration: anchor seeded, spend preserved.
        assert_eq!(state.spent_usd, before);
        assert_eq!(state.last_reset_at, Some(now));
    }

    #[test]
    fn maybe_reset_window_duration_keeps_spend_inside_interval() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let now = Utc::now();
        let mut state = BudgetState::new_today();
        state.spent_usd = Decimal::new(250, 2);
        state.last_reset_at = Some(now);
        // 100 ms later — well inside the 5 s window.
        state.maybe_reset_window(
            now + chrono::Duration::milliseconds(100),
            BudgetWindow::Duration(std::time::Duration::from_secs(5)),
            chrono_tz::UTC,
        );
        assert_eq!(state.spent_usd, Decimal::new(250, 2));
        assert_eq!(state.last_reset_at, Some(now));
    }

    #[test]
    fn maybe_reset_window_duration_zeroes_after_interval() {
        use chrono::Utc;
        use rust_decimal::Decimal;
        let now = Utc::now();
        let mut state = BudgetState::new_today();
        state.spent_usd = Decimal::new(250, 2);
        state.last_reset_at = Some(now);
        // 200 ms later — well past the 100 ms window.
        let later = now + chrono::Duration::milliseconds(200);
        state.maybe_reset_window(
            later,
            BudgetWindow::Duration(std::time::Duration::from_millis(100)),
            chrono_tz::UTC,
        );
        assert_eq!(state.spent_usd, Decimal::ZERO);
        assert_eq!(state.last_reset_at, Some(later));
    }

    #[test]
    fn budget_window_default_is_daily() {
        assert_eq!(BudgetWindow::default(), BudgetWindow::Daily);
    }
}
