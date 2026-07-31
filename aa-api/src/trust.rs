//! Per-tenant trust-score configuration and the Option-A clean-rate formula
//! (AAASM-5083, ADR 0019 Option D).
//!
//! ADR 0019 accepted **Option D**: Option A's clean-rate trust formula ships as
//! the product-owned default, and each of the three penalty signals is
//! operator-configurable **at the tenant layer** — a signal may be toggled
//! on/off and reweighted. The bucket thresholds (60/80) and window (`7d`) are
//! fixed in v1 and are deliberately *not* tenant-tunable.
//!
//! Two binding guardrails from the ADR are enforced by [`compute_trust`]:
//!
//! 1. **The score is labelled with the weight-set that produced it.** A `78`
//!    under tenant A's weights is not comparable to a `78` under tenant B's, so
//!    the endpoint reports the effective [`TrustWeights`] alongside the score.
//! 2. **Configurability never manufactures certainty.** Cold start
//!    (`D < min_actions`) returns `None` *regardless of weights*; disabling every
//!    signal yields a constant `100` only once `D >= min_actions`. Truncation is
//!    handled by the caller (the audit window is capped) and also yields `None`.
//!
//! The config store is the tenant layer: it is keyed by the tenant `org_id` —
//! the same confinement dimension `scope_entries` uses for the audit read — so a
//! caller reads the trust config for exactly the tenant whose audit entries it
//! is allowed to see. There is no durable per-tenant config subsystem in aa-api
//! today (Postgres is optional and not wired into the analytics read path), so
//! this store follows the established in-memory pattern of the other aa-api
//! per-tenant stores (`alert_rule_store`, `destination_store`, `capability_store`);
//! it resets on restart, matching the budget tracker and approval queue the
//! sibling analytics routes already read.

use std::collections::HashMap;
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// The minimum number of governed actions (`D`) before a trust score is
/// computed. Below this floor the score is `null` — the honest "not enough
/// data" answer the `—` placeholder already renders. Fixed in v1, not
/// tenant-tunable (ADR 0019 Decision §2).
pub const MIN_ACTIONS: u64 = 20;

/// Default weight for the `policy_violation` penalty signal (ADR 0019 Option A).
pub const DEFAULT_WEIGHT_VIOLATION: f64 = 1.0;
/// Default weight for the `credential_redaction` penalty signal.
pub const DEFAULT_WEIGHT_REDACTION: f64 = 1.5;
/// Default weight for the `approval_rejection` penalty signal.
pub const DEFAULT_WEIGHT_APPROVAL_REJECT: f64 = 0.5;

/// One operator-configurable penalty signal: whether it contributes to the
/// score at all, and the weight it carries when enabled (ADR 0019 Option D).
///
/// A disabled signal drops its penalty term entirely (`penalty += 0`); it does
/// **not** change `D` (total governed actions stays the denominator), matching
/// the ADR's `penalty = Σ(weight_i × count_i) for each ENABLED signal i`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct SignalConfig {
    /// Whether this signal contributes to the penalty. When `false` the signal's
    /// count is excluded from the penalty sum (its term becomes 0) but `D` is
    /// unchanged.
    pub enabled: bool,
    /// The weight applied to this signal's count when `enabled`. Ignored when
    /// the signal is disabled.
    pub weight: f64,
}

/// A tenant's effective trust-score weight-set: the three penalty signals and
/// their enabled/weight state (ADR 0019 Option D).
///
/// This is the "weight-set that produced the score" the response echoes back
/// (Guardrail 1). Every tenant inherits [`TrustWeights::default`] (the Option A
/// defaults) until it changes its own config.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, ToSchema)]
pub struct TrustWeights {
    /// Penalty for a `PolicyViolation` (a denied action). Default weight `1.0`.
    pub policy_violation: SignalConfig,
    /// Penalty for a `CredentialLeakBlocked` (a successful DLP redaction).
    /// Default weight `1.5`. A tenant whose thesis is "the DLP layer doing its
    /// job is not a demerit" may disable this — the ADR's motivating example.
    pub credential_redaction: SignalConfig,
    /// Penalty for an approval rejection (`ApprovalDenied` + `ApprovalTimedOut`).
    /// Default weight `0.5`.
    pub approval_rejection: SignalConfig,
}

impl Default for TrustWeights {
    /// The product-owned Option A defaults every tenant inherits: all three
    /// signals enabled at weights 1.0 / 1.5 / 0.5.
    fn default() -> Self {
        Self {
            policy_violation: SignalConfig {
                enabled: true,
                weight: DEFAULT_WEIGHT_VIOLATION,
            },
            credential_redaction: SignalConfig {
                enabled: true,
                weight: DEFAULT_WEIGHT_REDACTION,
            },
            approval_rejection: SignalConfig {
                enabled: true,
                weight: DEFAULT_WEIGHT_APPROVAL_REJECT,
            },
        }
    }
}

/// The raw per-agent signal counts pulled from the audit window, before any
/// weighting (ADR 0019 Option A vocabulary).
///
/// `D` (total governed actions) is `intercepted + violations + redactions +
/// approvals_requested` — every governed action, whether or not its signal is
/// enabled. The penalty numerator is assembled from `violations`, `redactions`,
/// and `approval_rejections` under the tenant's [`TrustWeights`].
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SignalCounts {
    /// `I` — `ToolCallIntercepted` events (allowed governed actions).
    pub intercepted: u64,
    /// `V` — `PolicyViolation` events (denials).
    pub violations: u64,
    /// `S` — `CredentialLeakBlocked` events (redactions).
    pub redactions: u64,
    /// The count of `ApprovalRequested` events. Part of `D`; not itself a penalty.
    pub approvals_requested: u64,
    /// `R` — `ApprovalDenied` + `ApprovalTimedOut` events (approval rejections).
    pub approval_rejections: u64,
}

impl SignalCounts {
    /// `D` — total governed actions, the denominator of the clean rate. Every
    /// governed action counts toward `D` regardless of which signals are
    /// enabled (ADR 0019: disabling a signal drops its penalty term, not its
    /// contribution to `D`).
    pub fn total_governed(&self) -> u64 {
        self.intercepted
            .saturating_add(self.violations)
            .saturating_add(self.redactions)
            .saturating_add(self.approvals_requested)
    }
}

/// Compute the clamped 0–100 trust score for one agent under a tenant's weights,
/// or `None` when the score would be dishonest (ADR 0019 Option D).
///
/// Returns `None` when `counts.total_governed() < min_actions` — the cold-start
/// floor (Guardrail 2): no weight configuration can turn "not enough data" into
/// a number. Truncation of the audit window is handled by the caller, which
/// passes `None` through without calling this.
///
/// `penalty = Σ(weight_i × count_i)` over the **enabled** signals only; a
/// disabled signal contributes `0`. `trust = clamp(round(100 * (1 - penalty /
/// D)), 0, 100)`. Disabling every signal makes `penalty == 0`, yielding a
/// constant `100` — labelled by the UI as "no penalty signals enabled", not as
/// "fully trusted".
pub fn compute_trust(counts: &SignalCounts, weights: &TrustWeights, min_actions: u64) -> Option<u8> {
    let d = counts.total_governed();
    if d < min_actions {
        // Cold start: honest null, regardless of the configured weights.
        return None;
    }

    let mut penalty = 0.0_f64;
    if weights.policy_violation.enabled {
        penalty += weights.policy_violation.weight * counts.violations as f64;
    }
    if weights.credential_redaction.enabled {
        penalty += weights.credential_redaction.weight * counts.redactions as f64;
    }
    if weights.approval_rejection.enabled {
        penalty += weights.approval_rejection.weight * counts.approval_rejections as f64;
    }

    let raw = 100.0 * (1.0 - penalty / d as f64);
    let clamped = raw.round().clamp(0.0, 100.0);
    Some(clamped as u8)
}

/// Thread-safe in-memory per-tenant [`TrustWeights`] store (ADR 0019 Option D).
///
/// Keyed by tenant `org_id` — the confinement dimension `scope_entries` uses —
/// so a caller's trust config and its visible audit entries share one tenant
/// boundary. A tenant with no stored override reads [`TrustWeights::default`]
/// (the Option A defaults), so every deployment gets a working score on day one
/// and configuration is opt-in.
///
/// In-memory by design: aa-api has no durable per-tenant config subsystem, and
/// this follows the same in-memory pattern as the other per-tenant aa-api stores
/// (`alert_rule_store`, `destination_store`). It resets on restart, consistent
/// with the budget tracker and approval queue the sibling analytics routes read.
#[derive(Debug, Default)]
pub struct TrustConfigStore {
    weights: RwLock<HashMap<String, TrustWeights>>,
}

impl TrustConfigStore {
    /// Create an empty store — every tenant reads the defaults until it sets a
    /// config.
    pub fn new() -> Self {
        Self::default()
    }

    /// The effective weight-set for a tenant: its stored override, or the
    /// Option A defaults when it has none. `org` is the tenant `org_id`; a
    /// caller with no org tenant (`None`) reads the defaults.
    pub fn get(&self, org: Option<&str>) -> TrustWeights {
        let Some(org) = org else {
            return TrustWeights::default();
        };
        let map = self.weights.read().unwrap_or_else(|e| e.into_inner());
        map.get(org).copied().unwrap_or_default()
    }

    /// Store (replace) a tenant's weight-set. `org` is the tenant `org_id`,
    /// resolved from the authenticated caller — never from client input — so a
    /// caller can only write its own tenant's config.
    pub fn set(&self, org: &str, weights: TrustWeights) {
        let mut map = self.weights.write().unwrap_or_else(|e| e.into_inner());
        map.insert(org.to_string(), weights);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default weights reproduce Option A's arithmetic exactly (ADR 0019
    /// validation requirement). Worked example: I=90, V=5, S=3, approvals
    /// requested=2, R=1 → D=100; penalty = 1.0*5 + 1.5*3 + 0.5*1 = 10.0;
    /// trust = round(100*(1-0.1)) = 90.
    #[test]
    fn default_weights_reproduce_option_a_arithmetic() {
        let counts = SignalCounts {
            intercepted: 90,
            violations: 5,
            redactions: 3,
            approvals_requested: 2,
            approval_rejections: 1,
        };
        assert_eq!(counts.total_governed(), 100);
        let score = compute_trust(&counts, &TrustWeights::default(), MIN_ACTIONS);
        assert_eq!(score, Some(90));
    }

    /// Guardrail 2 — cold start (`D < MIN_ACTIONS`) is `null`, not 0 and not 50,
    /// regardless of the configured weights.
    #[test]
    fn cold_start_below_min_actions_is_null_regardless_of_weights() {
        // 19 governed actions, all clean — still below the floor.
        let counts = SignalCounts {
            intercepted: 19,
            ..Default::default()
        };
        assert!(counts.total_governed() < MIN_ACTIONS);
        // Default weights → null.
        assert_eq!(compute_trust(&counts, &TrustWeights::default(), MIN_ACTIONS), None);
        // A tenant that disabled every signal still gets null below the floor —
        // configurability cannot manufacture certainty.
        let all_off = TrustWeights {
            policy_violation: SignalConfig {
                enabled: false,
                weight: 1.0,
            },
            credential_redaction: SignalConfig {
                enabled: false,
                weight: 1.5,
            },
            approval_rejection: SignalConfig {
                enabled: false,
                weight: 0.5,
            },
        };
        assert_eq!(compute_trust(&counts, &all_off, MIN_ACTIONS), None);
    }

    /// Disabling a signal drops its penalty term (raising the score) while `D`
    /// stays the total governed actions (ADR 0019 Option D delta).
    #[test]
    fn disabling_a_signal_changes_the_score() {
        // I=80, V=0, S=20, no approvals → D=100. With redaction enabled at 1.5:
        // penalty = 1.5*20 = 30 → trust = 70. With redaction disabled: penalty =
        // 0 → trust = 100. D is 100 in both cases.
        let counts = SignalCounts {
            intercepted: 80,
            redactions: 20,
            ..Default::default()
        };
        assert_eq!(counts.total_governed(), 100);
        let enabled = TrustWeights::default();
        assert_eq!(compute_trust(&counts, &enabled, MIN_ACTIONS), Some(70));

        let redaction_off = TrustWeights {
            credential_redaction: SignalConfig {
                enabled: false,
                weight: 1.5,
            },
            ..TrustWeights::default()
        };
        assert_eq!(compute_trust(&counts, &redaction_off, MIN_ACTIONS), Some(100));
    }

    /// Disabling every signal yields a constant 100 once `D >= MIN_ACTIONS`
    /// (ADR 0019 Guardrail 2 — "no penalty signals enabled", not "fully trusted").
    #[test]
    fn all_signals_disabled_yields_100_only_at_or_above_min_actions() {
        let all_off = TrustWeights {
            policy_violation: SignalConfig {
                enabled: false,
                weight: 1.0,
            },
            credential_redaction: SignalConfig {
                enabled: false,
                weight: 1.5,
            },
            approval_rejection: SignalConfig {
                enabled: false,
                weight: 0.5,
            },
        };
        // Above the floor with heavy violations, disabling everything → 100.
        let counts = SignalCounts {
            intercepted: 10,
            violations: 40,
            approvals_requested: 0,
            ..Default::default()
        };
        assert_eq!(counts.total_governed(), 50);
        assert_eq!(compute_trust(&counts, &all_off, MIN_ACTIONS), Some(100));
    }

    /// The score is clamped into `[0, 100]` — a penalty exceeding `D` cannot
    /// produce a negative score.
    #[test]
    fn score_is_clamped_to_zero_floor() {
        // D=20 (at the floor), V=20 at weight 1.0 → penalty 20, raw = 0.
        let counts = SignalCounts {
            violations: 20,
            ..Default::default()
        };
        assert_eq!(counts.total_governed(), 20);
        assert_eq!(compute_trust(&counts, &TrustWeights::default(), MIN_ACTIONS), Some(0));
    }

    /// A tenant reads the Option A defaults until it sets an override; a caller
    /// with no org tenant always reads the defaults.
    #[test]
    fn store_returns_defaults_until_overridden_and_is_tenant_keyed() {
        let store = TrustConfigStore::new();
        assert_eq!(store.get(Some("acme")), TrustWeights::default());
        assert_eq!(store.get(None), TrustWeights::default());

        let custom = TrustWeights {
            credential_redaction: SignalConfig {
                enabled: false,
                weight: 1.5,
            },
            ..TrustWeights::default()
        };
        store.set("acme", custom);
        assert_eq!(store.get(Some("acme")), custom, "acme reads its override");
        assert_eq!(
            store.get(Some("other")),
            TrustWeights::default(),
            "another tenant is unaffected by acme's config"
        );
    }
}
