//! In-memory store for notification destinations (AAASM-1388).
//!
//! The store is concurrent-safe via `dashmap` and exposes a small trait so
//! tests can substitute in a stub `RuleReferenceChecker` to drive the
//! `destination_in_use` 409 path.

use std::sync::Arc;

use chrono::Utc;
use dashmap::DashMap;

use crate::destinations::types::{Destination, DestinationConfig, DestinationKind};

/// Asks whether any alert-routing rule still references a destination id.
///
/// The HTTP layer consults this before deleting a destination so an in-use
/// destination returns 409 instead of silently being removed.
pub trait RuleReferenceChecker: Send + Sync {
    /// Return true if any rule references `destination_id`.
    fn is_referenced(&self, destination_id: &str) -> bool;
}

/// Default `RuleReferenceChecker` for environments where no rule store is
/// wired up yet — never reports a reference, so deletes always succeed.
pub struct NoopRuleReferenceChecker;

impl RuleReferenceChecker for NoopRuleReferenceChecker {
    fn is_referenced(&self, _destination_id: &str) -> bool {
        false
    }
}

/// Errors returned by store mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreError {
    /// No destination with the given id exists.
    NotFound,
    /// Destination exists but a rule still references it.
    InUse,
}

/// Storage abstraction for notification destinations.
pub trait DestinationStore: Send + Sync {
    /// List all destinations, optionally filtered by kind, sorted by
    /// `created_at` ascending so list output is stable.
    fn list(&self, kind: Option<DestinationKind>) -> Vec<Destination>;
    /// Fetch a single destination by id.
    fn get(&self, id: &str) -> Option<Destination>;
    /// Insert a new destination and return the persisted record.
    fn create(&self, name: String, config: DestinationConfig, enabled: bool) -> Destination;
    /// Mutate any subset of `name`/`config`/`enabled` and bump `updated_at`.
    fn update(
        &self,
        id: &str,
        name: Option<String>,
        config: Option<DestinationConfig>,
        enabled: Option<bool>,
    ) -> Result<Destination, StoreError>;
    /// Remove a destination. Returns `InUse` if a rule still references it.
    fn delete(&self, id: &str) -> Result<(), StoreError>;
}

/// In-memory `DestinationStore` backed by `dashmap::DashMap`.
pub struct InMemoryDestinationStore {
    items: DashMap<String, Destination>,
    rule_checker: Arc<dyn RuleReferenceChecker>,
}

impl InMemoryDestinationStore {
    /// Construct a fresh store with the given rule-reference checker.
    pub fn new(rule_checker: Arc<dyn RuleReferenceChecker>) -> Self {
        Self {
            items: DashMap::new(),
            rule_checker,
        }
    }

    /// Generate a `dst_`-prefixed identifier. Uses uuid v4 simple-form so
    /// the id is `dst_` + 32 hex characters (no dashes) — sortable enough
    /// for our purposes without pulling in a separate ULID dep.
    fn generate_id() -> String {
        format!("dst_{}", uuid::Uuid::new_v4().simple())
    }
}

impl DestinationStore for InMemoryDestinationStore {
    fn list(&self, kind: Option<DestinationKind>) -> Vec<Destination> {
        let mut out: Vec<Destination> = self
            .items
            .iter()
            .filter(|e| kind.map_or(true, |k| e.value().config.kind() == k))
            .map(|e| e.value().clone())
            .collect();
        out.sort_by(|a, b| a.created_at.cmp(&b.created_at));
        out
    }

    fn get(&self, id: &str) -> Option<Destination> {
        self.items.get(id).map(|e| e.value().clone())
    }

    fn create(&self, name: String, config: DestinationConfig, enabled: bool) -> Destination {
        let now = Utc::now().to_rfc3339();
        let d = Destination {
            id: Self::generate_id(),
            name,
            config,
            enabled,
            created_at: now.clone(),
            updated_at: now,
        };
        self.items.insert(d.id.clone(), d.clone());
        d
    }

    fn update(
        &self,
        id: &str,
        name: Option<String>,
        config: Option<DestinationConfig>,
        enabled: Option<bool>,
    ) -> Result<Destination, StoreError> {
        let mut entry = self.items.get_mut(id).ok_or(StoreError::NotFound)?;
        if let Some(n) = name {
            entry.name = n;
        }
        if let Some(c) = config {
            entry.config = c;
        }
        if let Some(e) = enabled {
            entry.enabled = e;
        }
        entry.updated_at = Utc::now().to_rfc3339();
        Ok(entry.clone())
    }

    fn delete(&self, id: &str) -> Result<(), StoreError> {
        if !self.items.contains_key(id) {
            return Err(StoreError::NotFound);
        }
        if self.rule_checker.is_referenced(id) {
            return Err(StoreError::InUse);
        }
        self.items.remove(id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn webhook(url: &str) -> DestinationConfig {
        DestinationConfig::Webhook {
            url: url.to_string(),
            secret_header: None,
        }
    }

    fn slack(url: &str) -> DestinationConfig {
        DestinationConfig::Slack {
            webhook_url: url.to_string(),
            channel_override: None,
        }
    }

    fn store() -> InMemoryDestinationStore {
        InMemoryDestinationStore::new(Arc::new(NoopRuleReferenceChecker))
    }

    #[test]
    fn create_then_get() {
        let s = store();
        let d = s.create("hook".into(), webhook("https://example.com/hook"), true);
        assert!(d.id.starts_with("dst_"));
        assert_eq!(d.id.len(), 4 + 32);
        let fetched = s.get(&d.id).unwrap();
        assert_eq!(fetched.id, d.id);
        assert_eq!(fetched.name, "hook");
    }

    #[test]
    fn list_filters_by_kind() {
        let s = store();
        s.create("h1".into(), webhook("https://example.com/h1"), true);
        s.create("s1".into(), slack("https://hooks.slack.com/x"), true);
        s.create("h2".into(), webhook("https://example.com/h2"), false);

        assert_eq!(s.list(None).len(), 3);
        assert_eq!(s.list(Some(DestinationKind::Webhook)).len(), 2);
        let slack_only = s.list(Some(DestinationKind::Slack));
        assert_eq!(slack_only.len(), 1);
        assert_eq!(slack_only[0].name, "s1");
    }

    #[test]
    fn update_preserves_created_at_and_bumps_updated_at() {
        let s = store();
        let d = s.create("hook".into(), webhook("https://example.com/hook"), true);
        let orig_created = d.created_at.clone();
        let orig_updated = d.updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(15));

        let updated = s.update(&d.id, Some("renamed".into()), None, None).unwrap();
        assert_eq!(updated.created_at, orig_created);
        assert_ne!(updated.updated_at, orig_updated);
        assert_eq!(updated.name, "renamed");
    }

    #[test]
    fn update_unknown_returns_not_found() {
        let s = store();
        let err = s
            .update("dst_does_not_exist", Some("x".into()), None, None)
            .unwrap_err();
        assert_eq!(err, StoreError::NotFound);
    }

    #[test]
    fn delete_returns_not_found() {
        let s = store();
        assert_eq!(s.delete("dst_missing"), Err(StoreError::NotFound));
    }

    /// Stub checker that pretends every destination is referenced.
    struct AlwaysReferenced;
    impl RuleReferenceChecker for AlwaysReferenced {
        fn is_referenced(&self, _id: &str) -> bool {
            true
        }
    }

    #[test]
    fn delete_returns_in_use_when_checker_says_yes() {
        let s = InMemoryDestinationStore::new(Arc::new(AlwaysReferenced));
        let d = s.create("hook".into(), webhook("https://example.com/hook"), true);
        assert_eq!(s.delete(&d.id), Err(StoreError::InUse));
        // still present after the failed delete
        assert!(s.get(&d.id).is_some());
    }
}
