//! What the *caller* stated about its own launch environment — never what the
//! long-lived service process happens to see in its own.
//!
//! # Why this exists (AAASM-5993)
//!
//! A bypass check that reads `std::env::var(...)` inside the lifecycle service
//! reads the **daemon's** process environment, not the environment a launch the
//! service is being asked about would actually inherit. The daemon is
//! long-lived and shared by every client on the host — its own environment is
//! whatever it happened to be spawned with, not any particular caller's launch
//! environment. Reading it produces both directions of wrong answer: a caller
//! whose launch is bypassed reads as clean because the daemon's own environment
//! is clean (the dangerous false negative — reported fully protected when it is
//! not), and a caller whose launch is clean reads as bypassed because the
//! daemon's environment happens to carry one of the watched variables (the
//! false positive). [`CallerEnvironment`] is the type that lets a caller state
//! its own launch environment instead, so detection is a pure function of what
//! was actually asked about.
//!
//! # Why two sets, not one
//!
//! A single "here is what was set" set cannot distinguish "the caller looked
//! and found nothing" from "the caller said nothing at all" — an empty set
//! reads as both, and treating them the same reintroduces the false negative
//! one layer up: a caller that never examined its environment would look
//! identical to one that examined it and found it clean, and the honest answer
//! for the first is "unknown", not "clean". [`CallerEnvironment`] therefore
//! tracks `examined` (every name the caller looked at) separately from
//! `present` (the subset that were actually set and non-empty), so
//! [`state_of`](CallerEnvironment::state_of) can return three answers —
//! [`Set`](EnvVarState::Set), [`Unset`](EnvVarState::Unset) and
//! [`NotStated`](EnvVarState::NotStated) — instead of collapsing "examined and
//! absent" into the same bucket as "never asked about".
//!
//! # Why no value ever crosses this boundary
//!
//! [`CallerEnvironment`] carries variable *names* only, never values. The
//! variables this type exists to report on (`ANTHROPIC_BASE_URL`,
//! `NODE_TLS_REJECT_UNAUTHORIZED` and similar) commonly carry credentials or
//! endpoints that redirect a model's traffic, and a bypass report is exactly
//! the kind of artifact — logged, displayed, sometimes pasted into a ticket —
//! that a value must never end up inside. Restricting the type to presence
//! bits, not a `BTreeMap<String, String>`, makes "a bypass report cannot leak a
//! credential" a property of the type rather than a discipline every caller has
//! to remember to uphold.

use std::collections::BTreeSet;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Environment variable names known, today, to change whether a governed
/// launch is actually governed once the tool itself is running.
///
/// Lives here rather than in `aa-devtool-claude-code` (the only adapter that
/// currently checks any of them) because the caller that states this — the
/// `aa-cli` binary, over the DI-API wire (AAASM-5993) — links `aa-core` but
/// not any one adapter crate: the DI-API is spoken to a `tool_id`, not to a
/// linked-in adapter type, so the client that builds a
/// [`CallerEnvironment`] cannot import an adapter-specific constant without
/// either linking every adapter or picking one arbitrarily. A future
/// adapter with its own bypass-relevant names extends this list (or adds a
/// sibling one referenced from here) rather than inventing a second, parallel
/// channel for the same kind of fact.
///
/// `aa_devtool_claude_code::bypass::BYPASS_ENV_VARS` re-exports this constant
/// rather than duplicating it, so the two can never drift apart.
pub const KNOWN_LAUNCH_BYPASS_ENV_VARS: [&str; 5] = [
    "ANTHROPIC_BASE_URL",
    "CLAUDE_CODE_API_BASE_URL",
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "NODE_TLS_REJECT_UNAUTHORIZED",
];

/// What a caller stated about one environment variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EnvVarState {
    /// The caller examined this variable and it was set to a non-empty value.
    Set,
    /// The caller examined this variable and it was unset or empty.
    Unset,
    /// The caller said nothing about this variable at all.
    NotStated,
}

/// What a caller stated about its own launch environment, presence-only.
///
/// See the module docs for why this carries two sets and never a value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CallerEnvironment {
    /// Every variable name the caller looked at, whether or not it was set.
    examined: BTreeSet<String>,
    /// The subset of `examined` that were set to a non-empty value.
    present: BTreeSet<String>,
}

impl CallerEnvironment {
    /// A caller that examined exactly `names`, none of them (yet) present.
    ///
    /// Chain [`present`](Self::present) for each variable found to actually be
    /// set — seeding `examined` up front is what makes an unset variable
    /// distinguishable from one the caller never looked at.
    pub fn stating(names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        Self {
            examined: names.into_iter().map(Into::into).collect(),
            present: BTreeSet::new(),
        }
    }

    /// Record that `name` was examined and found set to a non-empty value.
    ///
    /// Also inserts `name` into the examined set, so a caller need not name a
    /// variable in [`stating`](Self::stating) before marking it present.
    #[must_use]
    pub fn present(mut self, name: impl Into<String>) -> Self {
        let name = name.into();
        self.examined.insert(name.clone());
        self.present.insert(name);
        self
    }

    /// What the caller stated about `name`.
    ///
    /// Checks `present` first: it is a subset of `examined` by construction, so
    /// membership there is sufficient on its own. A name in `examined` but not
    /// `present` means the caller looked and found it unset; a name in neither
    /// means the caller said nothing about it.
    pub fn state_of(&self, name: &str) -> EnvVarState {
        if self.present.contains(name) {
            EnvVarState::Set
        } else if self.examined.contains(name) {
            EnvVarState::Unset
        } else {
            EnvVarState::NotStated
        }
    }

    /// Every name the caller examined, whether or not it was set.
    ///
    /// For a wire encoder (AAASM-5993's `TargetArgs.caller_env_examined`) that
    /// needs to carry the same two-set shape this type holds internally,
    /// without exposing `present` as a way to reconstruct `examined` (a name
    /// can be present without appearing here only if the caller never called
    /// [`stating`](Self::stating) or [`present`](Self::present) for it, which
    /// this type's constructors do not allow — so this and
    /// [`present_names`](Self::present_names) together are always sufficient
    /// to round-trip a value built through the public API).
    pub fn examined_names(&self) -> impl Iterator<Item = &str> {
        self.examined.iter().map(String::as_str)
    }

    /// The subset of [`examined_names`](Self::examined_names) that were set to
    /// a non-empty value. See [`examined_names`](Self::examined_names) for why
    /// this exists.
    pub fn present_names(&self) -> impl Iterator<Item = &str> {
        self.present.iter().map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_never_stated_is_not_stated() {
        let env = CallerEnvironment::default();
        assert_eq!(env.state_of("ANTHROPIC_BASE_URL"), EnvVarState::NotStated);
    }

    #[test]
    fn a_name_stated_but_never_marked_present_is_unset() {
        let env = CallerEnvironment::stating(["ANTHROPIC_BASE_URL"]);
        assert_eq!(env.state_of("ANTHROPIC_BASE_URL"), EnvVarState::Unset);
    }

    #[test]
    fn a_name_marked_present_is_set() {
        let env = CallerEnvironment::stating(["ANTHROPIC_BASE_URL"]).present("ANTHROPIC_BASE_URL");
        assert_eq!(env.state_of("ANTHROPIC_BASE_URL"), EnvVarState::Set);
    }

    #[test]
    fn present_implies_examined_even_without_stating_first() {
        let env = CallerEnvironment::default().present("ANTHROPIC_BASE_URL");
        assert_eq!(env.state_of("ANTHROPIC_BASE_URL"), EnvVarState::Set);
    }

    #[test]
    fn an_empty_present_set_is_distinguishable_from_no_statement_at_all() {
        // The whole point of two sets: "examined, found nothing" must not read
        // the same as "examined nothing".
        let examined_and_clean = CallerEnvironment::stating(["ANTHROPIC_BASE_URL", "NODE_TLS_REJECT_UNAUTHORIZED"]);
        let said_nothing = CallerEnvironment::default();
        assert_eq!(examined_and_clean.state_of("ANTHROPIC_BASE_URL"), EnvVarState::Unset);
        assert_eq!(said_nothing.state_of("ANTHROPIC_BASE_URL"), EnvVarState::NotStated);
    }
}
