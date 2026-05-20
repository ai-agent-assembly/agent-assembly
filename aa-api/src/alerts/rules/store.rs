//! Storage backend for [`AlertRule`] records (AAASM-1386).
//!
//! Today the only implementation is the in-memory
//! [`InMemoryAlertRuleStore`] — a persisted store (e.g. SQLite) is
//! deferred per the Story's acceptance criteria.

use std::collections::HashMap;
use std::sync::RwLock;

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

/// Thread-safe in-memory [`AlertRuleStore`].
///
/// Backed by an `RwLock<HashMap<id, AlertRule>>`. Suitable for
/// development and tests; a durable backend (e.g. SQLite) is tracked
/// as a follow-up under AAASM-1386.
pub struct InMemoryAlertRuleStore {
    rules: RwLock<HashMap<String, AlertRule>>,
}

impl InMemoryAlertRuleStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self {
            rules: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryAlertRuleStore {
    fn default() -> Self {
        Self::new()
    }
}

impl AlertRuleStore for InMemoryAlertRuleStore {
    fn create(&self, mut rule: AlertRule) -> Result<AlertRule, AlertRuleStoreError> {
        let mut rules = self.rules.write().expect("alert rule store lock poisoned");

        if rules.values().any(|r| r.name == rule.name) {
            return Err(AlertRuleStoreError::NameConflict { name: rule.name });
        }

        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        rule.id = id.clone();
        rule.created_at = now.clone();
        rule.updated_at = now;
        rules.insert(id, rule.clone());
        Ok(rule)
    }

    fn get(&self, id: &str) -> Option<AlertRule> {
        let rules = self.rules.read().expect("alert rule store lock poisoned");
        rules.get(id).cloned()
    }

    fn list(&self, enabled_filter: Option<bool>) -> Vec<AlertRule> {
        let rules = self.rules.read().expect("alert rule store lock poisoned");
        rules
            .values()
            .filter(|r| match enabled_filter {
                Some(want) => r.enabled == want,
                None => true,
            })
            .cloned()
            .collect()
    }

    fn update(&self, _id: &str, _rule: AlertRule) -> Result<AlertRule, AlertRuleStoreError> {
        unimplemented!("AAASM-1616: update lands next")
    }

    fn delete(&self, _id: &str) -> bool {
        unimplemented!("AAASM-1616: delete lands next")
    }

    fn find_by_name(&self, _name: &str) -> Option<AlertRule> {
        unimplemented!("AAASM-1616: find_by_name lands next")
    }
}
