//! In-memory registry of known alert-rule destinations (AAASM-1386).
//!
//! The Story's `destination_ids` validation needs *some* backing source
//! of truth. A full destination management surface (with delivery
//! adapters per type) is out of scope for AAASM-1386; this stub ships
//! a fixed allow-set so `destination_unknown` rejections work
//! end-to-end. Future work can swap this for a persisted registry
//! behind the same [`DestinationRegistryLookup`] trait.

use std::collections::HashSet;

use super::types::DestinationRegistryLookup;

/// Seed entries returned by [`DestinationRegistry::seeded`]. Kept as a
/// `const` so dashboard / docs can render the same allow-list without
/// pulling in the runtime registry.
pub const SEEDED_DESTINATIONS: &[&str] = &["slack-ops", "pagerduty-oncall", "email-team"];

/// Allow-set of destination ids that alert rules may target.
pub struct DestinationRegistry {
    ids: HashSet<String>,
}

impl DestinationRegistry {
    /// Empty registry — useful only in tests that want to assert
    /// `destination_unknown` rejections without seed noise.
    pub fn empty() -> Self {
        Self { ids: HashSet::new() }
    }

    /// Pre-populated registry containing [`SEEDED_DESTINATIONS`].
    pub fn seeded() -> Self {
        Self {
            ids: SEEDED_DESTINATIONS.iter().map(|s| (*s).to_string()).collect(),
        }
    }

    /// Add `id` to the allow-set. Intended for tests / future
    /// destination-management endpoints.
    pub fn register(&mut self, id: impl Into<String>) {
        self.ids.insert(id.into());
    }
}

impl Default for DestinationRegistry {
    fn default() -> Self {
        Self::seeded()
    }
}

impl DestinationRegistryLookup for DestinationRegistry {
    fn contains(&self, id: &str) -> bool {
        self.ids.contains(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeded_registry_contains_every_seed_entry() {
        let registry = DestinationRegistry::seeded();
        for id in SEEDED_DESTINATIONS {
            assert!(registry.contains(id), "expected seeded id {id} to be present");
        }
    }

    #[test]
    fn empty_registry_rejects_all_lookups() {
        let registry = DestinationRegistry::empty();
        assert!(!registry.contains("slack-ops"));
        assert!(!registry.contains("anything"));
    }

    #[test]
    fn register_extends_the_allow_set() {
        let mut registry = DestinationRegistry::empty();
        registry.register("custom-webhook");
        assert!(registry.contains("custom-webhook"));
        assert!(!registry.contains("missing"));
    }
}
