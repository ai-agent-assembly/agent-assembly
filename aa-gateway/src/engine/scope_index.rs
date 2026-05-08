//! Scope-keyed index of loaded policies (`PolicyId` ↔ `PolicyScope`).
//!
//! Built for AAASM-951 (F92 Phase B). Stores policy documents alongside a
//! map from each [`crate::policy::PolicyScope`] to the list of policy ids
//! loaded under that scope, in insertion order, so the cascading evaluator
//! added by AAASM-220 (F93) can resolve applicable policies in O(1).

use std::collections::HashMap;
use std::sync::Arc;

use crate::policy::{PolicyDocument, PolicyScope};

/// Opaque identifier returned by [`ScopeIndex::insert`] (and by
/// [`crate::engine::PolicyEngine::load_policy`] in turn).
///
/// Monotonically increasing within a single `ScopeIndex` instance, but
/// callers must treat the inner value as opaque — it is not stable
/// across processes and not suitable as a database key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PolicyId(u64);

impl PolicyId {
    /// Construct a `PolicyId` from a raw counter value. Intended for tests
    /// and for `ScopeIndex` itself; production callers should obtain ids
    /// from `ScopeIndex::insert`.
    #[inline]
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Return the raw counter value of this id.
    #[inline]
    pub const fn as_raw(&self) -> u64 {
        self.0
    }
}

/// Owns loaded policy documents and a secondary index from
/// [`PolicyScope`] to the list of [`PolicyId`]s registered under that
/// scope, preserving insertion order within each bucket.
///
/// Phase B (this Sub-task) only populates the index; the cascading
/// evaluator that *consumes* it lands in F93 (AAASM-220).
///
/// # Invariants
///
/// * Every id in any `by_scope` bucket points to a live entry in
///   `policies`. [`Self::remove`] preserves this by editing both
///   collections atomically.
/// * Empty buckets are not retained — once the last id under a scope
///   is removed, the scope itself is dropped from `by_scope`.
///   [`Self::policies_for_scope`] therefore returns `&[]` both for
///   "scope was never used" and "scope is now empty"; callers cannot
///   distinguish these two states (and shouldn't need to).
/// * Buckets preserve **insertion order**: ids appear in the order
///   their corresponding documents were passed to [`Self::insert`].
///   Documents inserted under unrelated scopes between two same-scope
///   inserts do not affect the relative order of the same-scope ids.
#[derive(Debug, Default)]
pub struct ScopeIndex {
    /// Owned policy documents keyed by their assigned id.
    policies: HashMap<PolicyId, Arc<PolicyDocument>>,
    /// Per-scope insertion-ordered list of policy ids.
    by_scope: HashMap<PolicyScope, Vec<PolicyId>>,
    /// Monotonic counter feeding new [`PolicyId`] values.
    next_id: u64,
}

impl ScopeIndex {
    /// Construct an empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register `doc` under its declared `scope`, returning the freshly
    /// allocated [`PolicyId`].
    ///
    /// The id is appended to the scope's bucket so subsequent
    /// [`Self::policies_for_scope`] calls observe insertion order.
    pub fn insert(&mut self, doc: PolicyDocument) -> PolicyId {
        let id = PolicyId(self.next_id);
        self.next_id += 1;

        let scope = doc.scope.clone();
        self.policies.insert(id, Arc::new(doc));
        self.by_scope.entry(scope).or_default().push(id);
        id
    }

    /// Look up a stored document by id.
    pub fn policy(&self, id: PolicyId) -> Option<&Arc<PolicyDocument>> {
        self.policies.get(&id)
    }

    /// Remove the policy registered under `id`, keeping `by_scope` in sync.
    ///
    /// Returns the dropped `Arc<PolicyDocument>` if the id was present, or
    /// `None` if it had already been removed (or was never inserted). When
    /// the affected scope bucket becomes empty it is dropped from the map
    /// so callers can rely on the bucket's presence implying at least one
    /// live policy.
    pub fn remove(&mut self, id: PolicyId) -> Option<Arc<PolicyDocument>> {
        let doc = self.policies.remove(&id)?;
        if let Some(bucket) = self.by_scope.get_mut(&doc.scope) {
            bucket.retain(|existing| *existing != id);
            if bucket.is_empty() {
                self.by_scope.remove(&doc.scope);
            }
        }
        Some(doc)
    }

    /// Total number of policies currently indexed.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether the index holds any policies.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Return the ids of every policy registered under `scope`, in
    /// insertion order. Returns an empty slice when no policy has ever
    /// been registered (or all of them have since been removed).
    ///
    /// Cheap — backed directly by the index `Vec`, no allocation.
    pub fn policies_for_scope(&self, scope: &PolicyScope) -> &[PolicyId] {
        self.by_scope.get(scope).map(Vec::as_slice).unwrap_or(&[])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// Build an empty `PolicyDocument` carrying just the requested scope.
    /// Keeps tests focused on the index, not on policy validation.
    fn doc_with_scope(scope: PolicyScope) -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: None,
        }
    }

    #[test]
    fn empty_index_reports_no_policies() {
        let idx = ScopeIndex::new();
        assert_eq!(idx.len(), 0);
        assert!(idx.is_empty());
        assert!(idx.policies_for_scope(&PolicyScope::Global).is_empty());
    }

    #[test]
    fn insert_returns_distinct_ids_in_order() {
        let mut idx = ScopeIndex::new();
        let id_a = idx.insert(doc_with_scope(PolicyScope::Global));
        let id_b = idx.insert(doc_with_scope(PolicyScope::Global));
        assert_ne!(id_a, id_b, "ids must be unique within an index");
        assert!(id_b.as_raw() > id_a.as_raw(), "ids must be monotonic");
    }

    #[test]
    fn policies_for_scope_returns_load_order() {
        let mut idx = ScopeIndex::new();
        let team = PolicyScope::Team("platform".to_owned());
        let id1 = idx.insert(doc_with_scope(team.clone()));
        idx.insert(doc_with_scope(PolicyScope::Global));
        let id3 = idx.insert(doc_with_scope(team.clone()));

        assert_eq!(
            idx.policies_for_scope(&team),
            &[id1, id3],
            "team bucket must hold ids in insertion order, with the global \
             policy that landed in between excluded",
        );
    }

    #[test]
    fn policies_for_scope_groups_by_distinct_scopes() {
        let mut idx = ScopeIndex::new();
        let id_g = idx.insert(doc_with_scope(PolicyScope::Global));
        let id_org = idx.insert(doc_with_scope(PolicyScope::Org("acme".to_owned())));
        let id_team = idx.insert(doc_with_scope(PolicyScope::Team("platform".to_owned())));

        assert_eq!(idx.policies_for_scope(&PolicyScope::Global), &[id_g]);
        assert_eq!(idx.policies_for_scope(&PolicyScope::Org("acme".to_owned())), &[id_org]);
        assert_eq!(
            idx.policies_for_scope(&PolicyScope::Team("platform".to_owned())),
            &[id_team],
        );
    }

    #[test]
    fn remove_drops_doc_and_strips_id_from_scope_bucket() {
        let mut idx = ScopeIndex::new();
        let team = PolicyScope::Team("platform".to_owned());
        let id_a = idx.insert(doc_with_scope(team.clone()));
        let id_b = idx.insert(doc_with_scope(team.clone()));

        let removed = idx.remove(id_a);
        assert!(removed.is_some(), "remove returns the dropped doc");
        assert_eq!(idx.policies_for_scope(&team), &[id_b]);
        assert!(idx.policy(id_a).is_none(), "doc lookup must miss after removal");
    }

    #[test]
    fn remove_drops_empty_scope_bucket_entirely() {
        let mut idx = ScopeIndex::new();
        let team = PolicyScope::Team("platform".to_owned());
        let id = idx.insert(doc_with_scope(team.clone()));

        idx.remove(id);
        assert!(
            idx.policies_for_scope(&team).is_empty(),
            "lookup must report empty for a fully-emptied bucket",
        );
    }

    #[test]
    fn remove_unknown_id_returns_none() {
        let mut idx = ScopeIndex::new();
        let bogus = PolicyId::from_raw(9_999);
        assert!(idx.remove(bogus).is_none());
    }

    #[test]
    fn policy_lookup_returns_inserted_document() {
        let mut idx = ScopeIndex::new();
        let id = idx.insert(doc_with_scope(PolicyScope::Org("acme".to_owned())));
        let stored = idx.policy(id).expect("inserted doc must be retrievable");
        assert_eq!(stored.scope, PolicyScope::Org("acme".to_owned()));
    }
}
