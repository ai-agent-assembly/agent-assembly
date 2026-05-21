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

    fn update(&self, id: &str, mut rule: AlertRule) -> Result<AlertRule, AlertRuleStoreError> {
        let mut rules = self.rules.write().expect("alert rule store lock poisoned");
        let existing = rules.get(id).ok_or(AlertRuleStoreError::NotFound)?;

        // Reject the update when the new name collides with another
        // rule. Same-id same-name (i.e. unchanged name) is allowed.
        if rule.name != existing.name && rules.values().any(|r| r.id != id && r.name == rule.name) {
            return Err(AlertRuleStoreError::NameConflict { name: rule.name });
        }

        rule.id = existing.id.clone();
        rule.created_at = existing.created_at.clone();
        rule.updated_at = chrono::Utc::now().to_rfc3339();
        rules.insert(id.to_string(), rule.clone());
        Ok(rule)
    }

    fn delete(&self, id: &str) -> bool {
        let mut rules = self.rules.write().expect("alert rule store lock poisoned");
        rules.remove(id).is_some()
    }

    fn find_by_name(&self, name: &str) -> Option<AlertRule> {
        let rules = self.rules.read().expect("alert rule store lock poisoned");
        rules.values().find(|r| r.name == name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::alerts::rules::types::{RuleMetric, RuleOperator, RuleSeverity};
    use std::collections::HashMap;

    /// Build a rule with the given name but otherwise default values.
    /// `id`, `created_at`, `updated_at` are left empty — the store
    /// overwrites them on `create`.
    fn rule_named(name: &str) -> AlertRule {
        AlertRule {
            id: String::new(),
            name: name.to_string(),
            description: format!("desc for {name}"),
            metric: RuleMetric::BudgetSpentPct,
            operator: RuleOperator::Gt,
            threshold: 90.0,
            evaluation_window_seconds: 300,
            severity: RuleSeverity::Critical,
            destination_ids: vec!["slack-ops".to_string()],
            dedup_window_seconds: 600,
            suppression_labels: HashMap::new(),
            enabled: true,
            created_at: String::new(),
            updated_at: String::new(),
        }
    }

    #[test]
    fn create_assigns_id_and_timestamps() {
        let store = InMemoryAlertRuleStore::new();
        let created = store.create(rule_named("r1")).expect("create");
        assert!(!created.id.is_empty(), "id must be assigned");
        assert!(!created.created_at.is_empty(), "created_at must be assigned");
        assert_eq!(created.created_at, created.updated_at);
    }

    #[test]
    fn create_rejects_duplicate_name() {
        let store = InMemoryAlertRuleStore::new();
        store.create(rule_named("dup")).expect("first create");
        let err = store.create(rule_named("dup")).expect_err("duplicate name must fail");
        assert!(matches!(err, AlertRuleStoreError::NameConflict { ref name } if name == "dup"));
        assert_eq!(err.error_code(), "rule_name_conflict");
    }

    #[test]
    fn get_returns_some_for_known_id_and_none_otherwise() {
        let store = InMemoryAlertRuleStore::new();
        let created = store.create(rule_named("r1")).expect("create");
        assert_eq!(store.get(&created.id).map(|r| r.name), Some("r1".to_string()));
        assert!(store.get("does-not-exist").is_none());
    }

    #[test]
    fn list_returns_all_rules_when_filter_is_none() {
        let store = InMemoryAlertRuleStore::new();
        store.create(rule_named("a")).expect("a");
        store.create(rule_named("b")).expect("b");
        store.create(rule_named("c")).expect("c");
        let mut names: Vec<String> = store.list(None).into_iter().map(|r| r.name).collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string(), "c".to_string()]);
    }

    #[test]
    fn list_filter_true_returns_only_enabled_rules() {
        let store = InMemoryAlertRuleStore::new();
        store.create(rule_named("on")).expect("on");
        store
            .create(AlertRule {
                enabled: false,
                ..rule_named("off")
            })
            .expect("off");
        let names: Vec<String> = store.list(Some(true)).into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["on".to_string()]);
    }

    #[test]
    fn list_filter_false_returns_only_disabled_rules() {
        let store = InMemoryAlertRuleStore::new();
        store.create(rule_named("on")).expect("on");
        store
            .create(AlertRule {
                enabled: false,
                ..rule_named("off")
            })
            .expect("off");
        let names: Vec<String> = store.list(Some(false)).into_iter().map(|r| r.name).collect();
        assert_eq!(names, vec!["off".to_string()]);
    }

    #[test]
    fn update_preserves_id_and_created_at_and_bumps_updated_at() {
        let store = InMemoryAlertRuleStore::new();
        let created = store.create(rule_named("r1")).expect("create");
        // Force a measurable delta so updated_at != created_at.
        std::thread::sleep(std::time::Duration::from_millis(5));
        let updated = store
            .update(
                &created.id,
                AlertRule {
                    threshold: 95.0,
                    ..rule_named("r1")
                },
            )
            .expect("update");
        assert_eq!(updated.id, created.id, "id must be preserved");
        assert_eq!(updated.created_at, created.created_at, "created_at must be preserved",);
        assert!(
            updated.updated_at > created.updated_at,
            "updated_at must be bumped: {} > {}",
            updated.updated_at,
            created.updated_at,
        );
        assert_eq!(updated.threshold, 95.0);
    }

    #[test]
    fn update_returns_not_found_for_unknown_id() {
        let store = InMemoryAlertRuleStore::new();
        let err = store
            .update("missing", rule_named("r1"))
            .expect_err("unknown id must fail");
        assert_eq!(err, AlertRuleStoreError::NotFound);
        assert_eq!(err.error_code(), "rule_not_found");
    }

    #[test]
    fn update_rejects_name_conflict_with_other_rule() {
        let store = InMemoryAlertRuleStore::new();
        let a = store.create(rule_named("a")).expect("a");
        store.create(rule_named("b")).expect("b");
        let err = store
            .update(&a.id, rule_named("b"))
            .expect_err("renaming a -> b must collide with the existing b");
        assert!(matches!(err, AlertRuleStoreError::NameConflict { ref name } if name == "b"));
    }

    #[test]
    fn delete_removes_existing_rule_and_returns_true() {
        let store = InMemoryAlertRuleStore::new();
        let created = store.create(rule_named("r1")).expect("create");
        assert!(store.delete(&created.id), "delete must return true for known id");
        assert!(store.get(&created.id).is_none(), "rule must be gone");
    }

    #[test]
    fn delete_returns_false_for_unknown_id() {
        let store = InMemoryAlertRuleStore::new();
        assert!(!store.delete("missing"));
    }

    #[test]
    fn find_by_name_returns_some_for_known_and_none_otherwise() {
        let store = InMemoryAlertRuleStore::new();
        store.create(rule_named("r1")).expect("create");
        assert!(store.find_by_name("r1").is_some());
        assert!(store.find_by_name("not-there").is_none());
    }
}
