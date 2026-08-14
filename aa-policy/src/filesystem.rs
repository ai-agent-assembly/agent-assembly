//! Cascade merge for the filesystem path-scope node (AAASM-5751).
//!
//! The gateway evaluates an agent against a *cascade* of documents — Global →
//! Org → Team → Agent → Tool, broadest first. [`merge_cascade`] folds the
//! `filesystem:` node across that cascade under **most-restrictive-wins**: the
//! effective permitted set is the intersection of every tier that declared one,
//! so a narrower tier can only ever shrink a broader one and never widen it.
//!
//! # Three outcomes, and why an `Option` cannot carry them
//!
//! [`CascadeFilesystemScope`] has three variants because the cascade can fail
//! to produce a scope for two entirely different reasons, and they oblige
//! opposite responses:
//!
//! * [`Stated`](CascadeFilesystemScope::Stated) — at least one tier declared
//!   the node. The intersection is the effective scope.
//! * [`NotStated`](CascadeFilesystemScope::NotStated) — documents were present
//!   and none declared it. The operator has policies and did not scope paths;
//!   the remedy is to edit one, and there is one to edit.
//! * [`EmptyCascade`](CascadeFilesystemScope::EmptyCascade) — **no documents at
//!   all**. ADR 0024 §6(2) settled that an empty or unavailable cascade is
//!   *Unconfigured* and never permission. This is a refusal, and
//!   [`into_effective`](CascadeFilesystemScope::into_effective) makes it one:
//!   it returns an error rather than `None`, so a caller cannot reach a
//!   permissive path by pattern-matching the absence.
//!
//! Folding the last two into a single `None` is precisely the accidental
//! answer ADR 0024 exists to overturn — `collect_merged_capabilities` folds an
//! empty slice into an empty (unrestricted) `CapabilitySet`, and every cell of
//! the capability matrix rendered `allow` as a result.

use aa_security::policy::FilesystemPolicy;

use crate::document::PolicyDocument;

/// The result of folding the `filesystem:` node across a policy cascade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CascadeFilesystemScope {
    /// The cascade carried no documents at all — fail closed.
    EmptyCascade,
    /// Documents were present and none declared a `filesystem:` node.
    ///
    /// **Not a grant.** No path restriction was requested; whether the domain
    /// is otherwise restricted is decided by the capability node, and the
    /// `aa-isolation` lowering reports the path dimension as
    /// `DomainCoverage::NotStated`.
    NotStated,
    /// The most-restrictive-wins intersection of every tier that declared one.
    Stated(FilesystemPolicy),
}

/// A cascade that carried no documents, so nothing could be merged.
///
/// Distinct from a merge that produced an empty scope: there, an operator wrote
/// tiers whose intersection is empty and the answer is a deliberate deny-all.
/// Here nobody wrote anything, and the two must not be reported as one fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyCascadeRefusal;

impl core::fmt::Display for EmptyCascadeRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(
            "refusing to resolve a filesystem path scope from an empty policy cascade: no policy \
             document is in force, and an absent cascade is unconfigured, not permission (ADR 0024)",
        )
    }
}

impl std::error::Error for EmptyCascadeRefusal {}

impl CascadeFilesystemScope {
    /// The merged node, or a refusal when the cascade was empty.
    ///
    /// `Ok(None)` is [`NotStated`](Self::NotStated) — documents exist and none
    /// scoped paths. The empty cascade is deliberately **not** representable as
    /// `Ok(None)`: a caller that treats "no scope" as "no restriction" would
    /// then treat "no policy at all" the same way, which is the fail-open this
    /// type exists to prevent.
    ///
    /// # Errors
    ///
    /// [`EmptyCascadeRefusal`] when the cascade carried no documents.
    pub fn into_effective(self) -> Result<Option<FilesystemPolicy>, EmptyCascadeRefusal> {
        match self {
            Self::EmptyCascade => Err(EmptyCascadeRefusal),
            Self::NotStated => Ok(None),
            Self::Stated(node) => Ok(Some(node)),
        }
    }

    /// Whether this outcome refuses rather than resolves.
    pub fn is_fail_closed(&self) -> bool {
        matches!(self, Self::EmptyCascade)
    }

    /// A stable lowercase identifier for reports and logs, so the three states
    /// are told apart by reading a token rather than by inferring from which
    /// fields are missing.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::EmptyCascade => "empty_cascade",
            Self::NotStated => "not_stated",
            Self::Stated(_) => "stated",
        }
    }
}

/// Fold the `filesystem:` node across a policy cascade, most-restrictive-wins.
///
/// Tiers are expected broadest-first, but the merge is order-independent
/// (intersection is commutative and associative), so a mis-ordered cascade
/// cannot silently widen the result.
///
/// A tier that declares no node contributes nothing — it cannot widen a scope
/// another tier declared, for the same reason `aa_core::merge_capabilities`
/// keeps a non-empty `allow` when the other side declares none. Silence is
/// never permission, so it is never grounds to drop a restriction either.
pub fn merge_cascade<'a, I>(cascade: I) -> CascadeFilesystemScope
where
    I: IntoIterator<Item = &'a PolicyDocument>,
{
    let mut merged: Option<FilesystemPolicy> = None;
    let mut saw_document = false;
    for doc in cascade {
        saw_document = true;
        let Some(node) = doc.filesystem.as_ref() else { continue };
        merged = Some(match merged {
            None => node.clone(),
            Some(acc) => acc.intersect(node),
        });
    }
    match (saw_document, merged) {
        (false, _) => CascadeFilesystemScope::EmptyCascade,
        (true, None) => CascadeFilesystemScope::NotStated,
        (true, Some(node)) => CascadeFilesystemScope::Stated(node),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use aa_security::policy::PathScope;

    use super::*;
    use crate::scope::PolicyScope;

    fn doc(filesystem: Option<FilesystemPolicy>) -> PolicyDocument {
        PolicyDocument {
            name: None,
            policy_version: None,
            version: None,
            scope: PolicyScope::Global,
            network: None,
            schedule: None,
            budget: None,
            data: None,
            approval_timeout_secs: 300,
            approval_policy: None,
            tools: HashMap::new(),
            capabilities: None,
            filesystem,
        }
    }

    fn reads(paths: &[&str]) -> Option<FilesystemPolicy> {
        Some(FilesystemPolicy {
            read: Some(PathScope::from_paths(paths).expect("fixture paths are valid")),
            write: None,
        })
    }

    fn merged_reads(scope: &CascadeFilesystemScope) -> &PathScope {
        let CascadeFilesystemScope::Stated(node) = scope else {
            panic!("expected a stated scope, got {}", scope.as_str());
        };
        node.read.as_ref().expect("the read verb was stated")
    }

    /// The Epic's founding property, at cascade level: an empty cascade is a
    /// refusal, not an unrestricted scope. The three-way control beside it is
    /// what makes the assertion meaningful — `NotStated` and `Stated` both
    /// resolve, so the refusal is attributable to emptiness and not to
    /// `into_effective` refusing unconditionally.
    #[test]
    fn an_empty_cascade_refuses_where_a_populated_one_resolves() {
        let empty = merge_cascade(std::iter::empty());
        assert_eq!(empty, CascadeFilesystemScope::EmptyCascade);
        assert!(empty.is_fail_closed());
        assert_eq!(empty.as_str(), "empty_cascade");
        let refusal = empty.into_effective().expect_err("an empty cascade must refuse");
        assert!(refusal.to_string().contains("not permission"));

        // Control 1: one document that scopes nothing resolves to "nobody
        // said" — no refusal, and no scope either.
        let silent = merge_cascade([&doc(None)]);
        assert_eq!(silent, CascadeFilesystemScope::NotStated);
        assert!(!silent.is_fail_closed());
        assert_eq!(silent.into_effective().expect("a populated cascade resolves"), None);

        // Control 2: one document that scopes paths resolves to that scope.
        let stated = merge_cascade([&doc(reads(&["/workspace"]))]);
        assert!(!stated.is_fail_closed());
        assert!(stated.into_effective().expect("resolves").is_some());
    }

    /// `EmptyCascade` and `NotStated` are both "no scope came out" and they are
    /// not the same fact. Distinguishing them by token — not by an
    /// `Option::is_none()` both share — is the whole reason this is an enum.
    #[test]
    fn no_documents_and_no_declaration_are_distinguishable() {
        assert_ne!(
            merge_cascade(std::iter::empty()),
            merge_cascade([&doc(None)]),
            "an absent cascade collapsed onto a silent one"
        );
        assert_eq!(merge_cascade(std::iter::empty()).as_str(), "empty_cascade");
        assert_eq!(merge_cascade([&doc(None)]).as_str(), "not_stated");
    }

    /// Most-restrictive-wins across tiers. The fixture is chosen so the
    /// candidate merges disagree: a union yields `/workspace` (widening the
    /// narrow tier), keeping the last tier yields `/workspace/src` **and**
    /// `/tmp` (permitting a subtree the broad tier never allowed), and the
    /// intersection this asserts yields `/workspace/src` alone.
    #[test]
    fn a_narrower_tier_shrinks_a_broader_one_and_cannot_add_to_it() {
        let global = doc(reads(&["/workspace"]));
        let team = doc(reads(&["/workspace/src", "/tmp"]));
        let scope = merge_cascade([&global, &team]);

        let read = merged_reads(&scope);
        assert!(read.permits("/workspace/src/main.rs"));
        assert!(
            !read.permits("/workspace/docs/readme.md"),
            "the narrower tier must shrink the broader one"
        );
        assert!(
            !read.permits("/tmp/scratch"),
            "a narrower tier must not add a subtree the broader one never permitted"
        );
    }

    #[test]
    fn the_merge_is_order_independent() {
        let global = doc(reads(&["/workspace", "/var/log"]));
        let team = doc(reads(&["/workspace/src", "/tmp"]));
        assert_eq!(merge_cascade([&global, &team]), merge_cascade([&team, &global]));
    }

    /// A tier that declares nothing must not widen a tier that does. If the
    /// fold treated an absent node as "everything permitted" and intersected
    /// with it, the restriction would survive; if it treated it as a *reset*,
    /// the restriction would vanish. This pins the surviving case.
    #[test]
    fn a_silent_tier_does_not_erase_a_stated_one() {
        let global = doc(reads(&["/workspace"]));
        let silent = doc(None);
        let scope = merge_cascade([&global, &silent]);
        assert!(merged_reads(&scope).permits("/workspace/src"));
        assert!(!merged_reads(&scope).permits("/etc"));
        assert_eq!(merge_cascade([&silent, &global]), scope);
    }

    /// Disjoint tiers intersect to nothing, and nothing is deny-all — the
    /// AAASM-4154 case for capabilities, reached here through paths. It must
    /// not read as "no restriction is in force": the node is still `Stated`,
    /// and the scope still permits nothing.
    #[test]
    fn disjoint_tiers_collapse_to_a_stated_deny_all_not_to_silence() {
        let scope = merge_cascade([&doc(reads(&["/workspace"])), &doc(reads(&["/opt"]))]);
        assert_eq!(scope.as_str(), "stated", "a collapse must not be reported as silence");
        let read = merged_reads(&scope);
        assert!(read.permits_nothing());
        assert!(!read.permits("/workspace"));
        assert!(!read.permits("/opt"));

        // The control: overlapping tiers do not collapse, so the deny-all is
        // attributable to disjointness rather than to the fold emptying always.
        let overlapping = merge_cascade([&doc(reads(&["/workspace"])), &doc(reads(&["/workspace/src"]))]);
        assert!(!merged_reads(&overlapping).permits_nothing());
    }

    /// A five-tier cascade folds monotonically: each added tier can only
    /// remove permitted paths.
    #[test]
    fn every_added_tier_can_only_narrow_the_result() {
        let tiers = [
            doc(reads(&["/"])),
            doc(reads(&["/workspace", "/tmp"])),
            doc(reads(&["/workspace"])),
            doc(None),
            doc(reads(&["/workspace/src", "/workspace/tests"])),
        ];
        let mut previously_permitted = usize::MAX;
        let probes = [
            "/etc/passwd",
            "/tmp/scratch",
            "/workspace/docs/x",
            "/workspace/src/main.rs",
            "/workspace/tests/t.rs",
        ];
        for prefix_len in 1..=tiers.len() {
            let scope = merge_cascade(tiers[..prefix_len].iter());
            let read = merged_reads(&scope);
            let permitted = probes.iter().filter(|p| read.permits(p)).count();
            assert!(
                permitted <= previously_permitted,
                "tier {prefix_len} widened the scope from {previously_permitted} to {permitted} permitted probes"
            );
            previously_permitted = permitted;
        }
        // It genuinely narrowed rather than staying constant, so the assertion
        // above is not vacuously satisfied by a fold that ignores every tier.
        assert_eq!(previously_permitted, 2);
    }

    /// Verbs merge independently across the cascade: a tier that scopes only
    /// writes must not leave reads unscoped when another tier scoped them.
    #[test]
    fn verbs_merge_independently_across_tiers() {
        let read_tier = doc(reads(&["/workspace"]));
        let write_tier = doc(Some(FilesystemPolicy {
            read: None,
            write: Some(PathScope::from_paths(["/workspace/build"]).unwrap()),
        }));
        let CascadeFilesystemScope::Stated(node) = merge_cascade([&read_tier, &write_tier]) else {
            panic!("two stated tiers merge to a stated node");
        };
        assert!(node.read.as_ref().unwrap().permits("/workspace/src"));
        assert!(node.write.as_ref().unwrap().permits("/workspace/build/out.o"));
        assert!(!node.write.as_ref().unwrap().permits("/workspace/src"));
    }
}
