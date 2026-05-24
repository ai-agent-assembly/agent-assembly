//! Placeholder resolver — walks a JSON value and substitutes `${NAME}`
//! tokens with their registered credential values from a [`SecretsStore`].
//!
//! The resolver is the only consumer of [`SecretsStore::lookup`] in the
//! request path. It returns a [`SubstitutionResult`] that records which
//! placeholder *names* were resolved so the caller can emit an audit
//! entry with the placeholder-form args while forwarding the resolved
//! form to the tool sink (AAASM-1920 audit-shape contract).
//!
//! Unregistered placeholders surface as
//! [`SecretInjectionError::UnknownPlaceholder`]. The resolver **never**
//! silently passes a literal `${UNKNOWN}` token through to the tool sink
//! — that would mask a typo into an arbitrary-string injection at
//! downstream parser layer.

/// Outcome of a successful [`resolve_placeholders`] call.
///
/// `resolved` is the post-substitution JSON value the caller should forward
/// to the tool sink. `names_substituted` is the list of placeholder *names*
/// that were replaced — names only, never the resolved credential values.
///
/// Callers emit an audit entry from the *pre*-resolution args and forward
/// the *post*-resolution args downstream; this struct keeps the two views
/// disambiguated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstitutionResult {
    /// The resolved JSON value, with every matched `${NAME}` token replaced
    /// by its registered credential value.
    pub resolved: serde_json::Value,
    /// The placeholder names that were resolved, in encounter order.
    /// Names appear once per occurrence — a string with two references to
    /// `${DB_PASSWORD}` produces two entries.
    pub names_substituted: Vec<String>,
}

use std::sync::OnceLock;

use regex::Regex;

/// Lazy-compiled regex for the `${NAME}` token. `NAME` is uppercase +
/// digits + underscore and starts with a letter — matches the convention
/// pinned in the `e2e_secret_injection.rs` scaffold (`${DB_PASSWORD}`,
/// `${UNKNOWN_SECRET}`).
///
/// `OnceLock` (rather than `LazyLock`) keeps the workspace MSRV at 1.75.
#[allow(dead_code)]
fn placeholder_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\$\{([A-Z][A-Z0-9_]*)\}").expect("placeholder regex is valid"))
}
