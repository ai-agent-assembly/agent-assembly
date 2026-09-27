//! The policy-default slot's structural anti-bypass mechanism (HORO-1375
//! design amendment §4.1).
//!
//! This file is deliberately a **submodule-free leaf** re-exported from
//! [`crate::engine`], not declared inline in `engine/mod.rs`. A private field
//! is module-scoped in Rust: had these types been declared in `mod.rs`, every
//! descendant module (`engine::decision`, `engine::cache`, …) would be able to
//! construct them freely, defeating the invariant below. Declaring them in
//! their own leaf module — one with no `mod` declarations of its own — makes
//! "this module" and "the exact scope of the invariant" the same one file.
//! The ADR for this ticket must say so rather than claiming a crate-wide
//! guarantee.
//!
//! Two newtypes gate the two ends of the policy-default slot:
//!
//! * [`PolicyDefaultMode`] gates **construction** of the default — its only
//!   `Observe`-yielding constructor requires a
//!   [`aa_core::observation::PersonalObserveGrant`], which is itself only
//!   mintable by `aa_core::observation::authorize_personal_observe` (the boot
//!   gate).
//! * [`EffectiveMode`] gates **consumption** of the resolved result —
//!   [`transform_for_observe_mode`](super::transform_for_observe_mode) now
//!   only accepts an `EffectiveMode`, and the only way to produce one is
//!   [`resolve_enforcement_mode`], which always checks the 72h-capped
//!   per-agent override column first.
//!
//! Gating only the input would leave
//! `transform_for_observe_mode(eval, EnforcementMode::Observe)` directly
//! callable — exactly the "future code path added carelessly" this
//! constraint targets. Narrowing the *consumer* closes that: there is no
//! `EffectiveMode` constructor, no `From<EnforcementMode>` impl, and no
//! `Default` that yields `Observe`.

/// The policy-default slot. Private field — the only way to obtain a value
/// that resolves to `Observe` is [`PolicyDefaultMode::personal_observe`],
/// which requires a
/// [`PersonalObserveGrant`](aa_core::observation::PersonalObserveGrant).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyDefaultMode(aa_core::EnforcementMode);

impl PolicyDefaultMode {
    /// The server-wide default for every deployment that has not been
    /// granted personal-observe. Matches the hardcoded `Enforce` default the
    /// two production `CheckAction` / `BatchCheck` call sites used before
    /// this ticket.
    pub const fn enforce() -> Self {
        Self(aa_core::EnforcementMode::Enforce)
    }

    /// The **only** constructor that can yield `Observe`. Requires proof
    /// that the personal-observe boot gate ran and found no enterprise
    /// coupling signal.
    pub fn personal_observe(_grant: &aa_core::observation::PersonalObserveGrant) -> Self {
        Self(aa_core::EnforcementMode::Observe)
    }
}

impl Default for PolicyDefaultMode {
    fn default() -> Self {
        Self::enforce()
    }
}

/// The resolved effective enforcement mode. Private field; the **only**
/// constructor is [`resolve_enforcement_mode`], which always consults the
/// 72h-capped per-agent override column before falling back to a
/// [`PolicyDefaultMode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveMode(aa_core::EnforcementMode);

impl EffectiveMode {
    /// Unwrap the resolved mode for use by the transform / audit paths.
    pub fn get(self) -> aa_core::EnforcementMode {
        self.0
    }
}

/// Resolve the effective enforcement mode for a given agent.
///
/// Lookup order (first match wins):
///
/// 1. `AgentRecord.enforcement_mode` — the agent's per-record override (set
///    via `RegisterRequest.enforcement_mode` or the enforcement-mode admin
///    endpoint). This is the 72h-capped shadow-window column; it **always**
///    wins over the policy default, including over a personal-observe
///    default.
/// 2. `policy_default` — the server-wide fallback. `PolicyDefaultMode::enforce()`
///    for every deployment; `PolicyDefaultMode::personal_observe(&grant)` only
///    on a deployment that passed the personal-observe boot gate.
///
/// `PolicyDocument.enforcement_mode` is deliberately NOT consulted here: it
/// is dead on the `CheckAction` hot path today (both production callers
/// hardcode a `PolicyDefaultMode`), and wiring it without routing through the
/// same gate would create a second, ungated `Observe` source
/// (`// KNOWN GAP (HORO-1491)`).
///
/// Both inputs are `Copy` so this is a cheap pure function callable from the
/// `CheckAction` hot path without locks or allocations.
pub fn resolve_enforcement_mode(
    agent_override: Option<aa_core::EnforcementMode>,
    policy_default: PolicyDefaultMode,
) -> EffectiveMode {
    EffectiveMode(agent_override.unwrap_or(policy_default.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::EnforcementMode;

    #[test]
    fn agent_override_always_wins_over_policy_default() {
        let default = PolicyDefaultMode::enforce();
        assert_eq!(
            resolve_enforcement_mode(Some(EnforcementMode::Observe), default).get(),
            EnforcementMode::Observe
        );
        assert_eq!(
            resolve_enforcement_mode(Some(EnforcementMode::Enforce), default).get(),
            EnforcementMode::Enforce
        );
        assert_eq!(
            resolve_enforcement_mode(Some(EnforcementMode::Disabled), default).get(),
            EnforcementMode::Disabled
        );
    }

    #[test]
    fn none_falls_through_to_policy_default() {
        assert_eq!(
            resolve_enforcement_mode(None, PolicyDefaultMode::enforce()).get(),
            EnforcementMode::Enforce
        );
    }

    #[test]
    fn default_impl_is_enforce() {
        assert_eq!(PolicyDefaultMode::default(), PolicyDefaultMode::enforce());
    }

    // ── HORO-1375 AC-3 N5 (compile-fail intent, documented `#[test]` form) ──
    //
    // trybuild is not a dependency of this workspace (global policy: no new
    // dependency without asking first) and this design doc's own text
    // sanctions the fallback used here: a documented `#[test]` asserting the
    // absence of a constructor, in place of an automated compile-fail
    // harness. This test is therefore NOT a mechanically-enforced guarantee
    // — a reviewer changing `transform_for_observe_mode`'s signature back to
    // a bare `aa_core::EnforcementMode`, or adding a public constructor to
    // `EffectiveMode`/`PolicyDefaultMode` that can yield `Observe` without a
    // grant, will not be caught by `cargo test`. It IS mechanically checked
    // by ordinary compilation of this file: the line below only compiles
    // because `transform_for_observe_mode` takes an `EffectiveMode`, not a
    // bare `EnforcementMode` — if a future change widened its parameter type
    // back to `aa_core::EnforcementMode`, the DIRECT-CALL form in the
    // commented block below would start compiling, which is the regression
    // this test exists to name.
    //
    // The following, if it compiled, would demonstrate the exact bypass
    // §4.1 exists to prevent — an ungated Observe reaching the transform
    // directly, with no `resolve_enforcement_mode` call and no grant:
    //
    // ```rust,compile_fail
    // # use aa_gateway::engine::transform_for_observe_mode;
    // # let eval: aa_gateway::engine::EvaluationResult = unimplemented!();
    // let (_out, _shadow) = transform_for_observe_mode(eval, aa_core::EnforcementMode::Observe);
    // ```
    //
    // This does NOT compile today because `transform_for_observe_mode`'s
    // second parameter is `effective_mode::EffectiveMode`, which has no
    // public constructor and no `From<aa_core::EnforcementMode>` impl — the
    // only way to obtain one is `resolve_enforcement_mode`, asserted below.
    #[test]
    fn n5_transform_for_observe_mode_only_accepts_a_resolved_effective_mode() {
        // This compiling at all is the positive half of N5: the ONLY way to
        // construct the second argument `transform_for_observe_mode` accepts
        // is through `resolve_enforcement_mode`. There is no
        // `EffectiveMode::new`, no `From<aa_core::EnforcementMode>`, and no
        // `Default` — grep confirms zero other constructors in this file.
        let mode = resolve_enforcement_mode(Some(EnforcementMode::Observe), PolicyDefaultMode::enforce());
        assert_eq!(mode.get(), EnforcementMode::Observe);
    }

    /// HORO-1375 AC-3 N9 (partial, aa-gateway half — see `aa-core::observation`
    /// tests for the `PersonalObserveGrant` half): `PolicyDefaultMode` and
    /// `EffectiveMode` are declared in this leaf file, which declares no
    /// `mod` items of its own other than `#[cfg(test)] mod tests` (test code
    /// is not shipped, so it does not reach the invariant's threat model —
    /// only PRODUCTION descendant modules would defeat module-scoped
    /// privacy, and this file has none). Absence of `Deserialize`, `From`,
    /// and a `Default` that yields `Observe` are compile-time facts this
    /// crate's `cargo test` cannot assert positively without an unstable
    /// negative-trait-bound feature or a compile-fail harness (see N5) —
    /// reviewed by eye instead: neither type derives `serde::Deserialize`
    /// anywhere in this file, and the only `Default` impl is
    /// `PolicyDefaultMode::default() -> Self::enforce()`, asserted above.
    #[test]
    fn n9_effective_mode_default_construction_paths_are_all_enforce() {
        assert_eq!(PolicyDefaultMode::default().0, EnforcementMode::Enforce);
        assert_eq!(
            resolve_enforcement_mode(None, PolicyDefaultMode::default()).get(),
            EnforcementMode::Enforce
        );
    }
}
