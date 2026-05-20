//! Storage backend for [`AlertRule`] records (AAASM-1386).
//!
//! Today the only implementation is the in-memory
//! [`InMemoryAlertRuleStore`] — a persisted store (e.g. SQLite) is
//! deferred per the Story's acceptance criteria.

use super::types::AlertRule;

/// Errors surfaced from [`AlertRuleStore`] mutations.
///
/// Each variant maps onto a Story-defined HTTP error code that the
/// handler in AAASM-1620 will return in the RFC 7807 response.
#[derive(Debug, Clone, PartialEq)]
pub enum AlertRuleStoreError {
    /// A rule with this `name` already exists (POST only). Maps to
    /// 409 with `error: "rule_name_conflict"`.
    NameConflict {
        /// The conflicting rule name.
        name: String,
    },
    /// No rule was found with the given id (GET / PUT / DELETE).
    /// Maps to 404 with `error: "rule_not_found"`.
    NotFound,
}

impl AlertRuleStoreError {
    /// Stable error code returned in the RFC 7807 response.
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::NameConflict { .. } => "rule_name_conflict",
            Self::NotFound => "rule_not_found",
        }
    }
}

impl std::fmt::Display for AlertRuleStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameConflict { name } => write!(f, "rule name already exists: {name}"),
            Self::NotFound => write!(f, "rule not found"),
        }
    }
}

impl std::error::Error for AlertRuleStoreError {}

/// Read-write storage abstraction over [`AlertRule`] records.
///
/// Implementations must be thread-safe (`Send + Sync`).
pub trait AlertRuleStore: Send + Sync {
    /// Persist a new rule, returning the fully-populated record.
    ///
    /// The store assigns `id`, `created_at`, and `updated_at` —
    /// callers may leave them empty on input. Returns
    /// [`AlertRuleStoreError::NameConflict`] when `rule.name`
    /// duplicates an existing entry.
    fn create(&self, rule: AlertRule) -> Result<AlertRule, AlertRuleStoreError>;

    /// Fetch a rule by id, or `None` if no such rule exists.
    fn get(&self, id: &str) -> Option<AlertRule>;

    /// List all rules, optionally filtering by the `enabled` flag.
    /// `enabled_filter = None` returns every rule.
    fn list(&self, enabled_filter: Option<bool>) -> Vec<AlertRule>;

    /// Replace the rule with id `id`. The stored record's `id` and
    /// `created_at` are preserved; the rest of the fields are taken
    /// from `rule`; `updated_at` is bumped to now. Returns
    /// [`AlertRuleStoreError::NotFound`] when `id` is unknown.
    fn update(&self, id: &str, rule: AlertRule) -> Result<AlertRule, AlertRuleStoreError>;

    /// Remove the rule with id `id`. Returns true when a record was
    /// removed, false when `id` was unknown.
    fn delete(&self, id: &str) -> bool;

    /// Find a rule by exact name match, or `None` if no such rule
    /// exists. Used by the handler to surface
    /// [`AlertRuleStoreError::NameConflict`] before re-inserting on
    /// PUT requests that change the name.
    fn find_by_name(&self, name: &str) -> Option<AlertRule>;
}
