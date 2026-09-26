//! Real per-domain [`ScopeOrder`] comparators (AAASM-6161, ADR 0038 amendment).
//!
//! [`UndefinedScopeOrder`](crate::lease::UndefinedScopeOrder) is the only
//! comparator AAASM-6160 shipped, and it refuses every delegation by
//! construction — the honest answer until a comparator could actually reason
//! about a domain's own scope semantics. This module is that follow-up: one
//! comparator per domain family, built by **reusing** the matching engines
//! that already decide the same question elsewhere in the workspace
//! (`aa_security::policy::filesystem::PathScope` for paths,
//! `aa_core::policy::is_host_allowed_by_egress_allowlist` for hostnames,
//! `crate::lease::limits_cover` for numeric ceilings) rather than hand-rolling
//! a second matcher that could silently diverge from `aa-proxy`, `aa-gateway`
//! or the eBPF probes.
//!
//! # Fail-closed on unknown selector grammar
//!
//! Every comparator here operates only on selectors that pass
//! [`crate::lowering::permitted_selector`] — the `permit-only:` grammar policy
//! lowering emits. A selector that does not carry that prefix is reachable in
//! practice (`aa-isolation/src/lease.rs` itself builds one raw string in a
//! test fixture), and falling through to a raw-string subset check for it
//! would silently reintroduce the exact prefix-matching bug
//! (`"/work".starts_with` admitting `/workspace`) that
//! [`aa_security::policy::filesystem::PathScope`] exists to prevent. So every
//! comparator below returns [`ScopeOrdering::Incomparable`] the moment any
//! selector on either side fails to parse as `permit-only:<item>` — fails
//! closed exactly like [`UndefinedScopeOrder`](crate::lease::UndefinedScopeOrder)
//! does for every pair, just narrower in when it applies.

use std::collections::BTreeSet;

use aa_security::policy::filesystem::PathScope;

use crate::capability::CapabilityDomain;
use crate::lease::{limits_narrower_or_equal, ScopeOrder, ScopeOrdering, UndefinedScopeOrder};
use crate::lowering::permitted_selector;
use crate::spec::RequirementScope;

/// Strip the `permit-only:` prefix from every selector, or `None` if any one
/// of them does not carry it.
///
/// A partial strip (some selectors valid, one not) is never returned: a
/// caller that got `Some` back knows every selector was interpretable, which
/// is the property [`ScopeOrdering::Incomparable`]'s fail-closed contract
/// depends on.
fn strip_permit_only(selectors: &[String]) -> Option<Vec<String>> {
    selectors
        .iter()
        .map(|s| permitted_selector(s).map(str::to_string))
        .collect()
}

/// Filesystem path-prefix containment, over `permit-only:` selectors.
///
/// Delegates entirely to [`PathScope`] — normalization, `..`-rejection and
/// containment are exactly the questions that type already answers for the
/// policy layer, and a second implementation here would only be a chance to
/// disagree with it.
#[derive(Debug, Clone, Copy, Default)]
pub struct PathPrefixOrder;

impl ScopeOrder for PathPrefixOrder {
    fn compare(&self, parent: &RequirementScope, child: &RequirementScope) -> ScopeOrdering {
        match (parent, child) {
            (RequirementScope::Whole, RequirementScope::Whole) => ScopeOrdering::Equal,
            (RequirementScope::Whole, RequirementScope::Selectors(_)) => ScopeOrdering::Narrower,
            (RequirementScope::Selectors(_), RequirementScope::Whole) => ScopeOrdering::Wider,
            (RequirementScope::Selectors(p), RequirementScope::Selectors(c)) => compare_path_selectors(p, c),
            _ => ScopeOrdering::Incomparable,
        }
    }
}

fn compare_path_selectors(parent: &[String], child: &[String]) -> ScopeOrdering {
    let Some(parent_raw) = strip_permit_only(parent) else {
        return ScopeOrdering::Incomparable;
    };
    let Some(child_raw) = strip_permit_only(child) else {
        return ScopeOrdering::Incomparable;
    };
    let Ok(parent_scope) = PathScope::from_paths(parent_raw) else {
        return ScopeOrdering::Incomparable;
    };
    let Ok(child_scope) = PathScope::from_paths(child_raw) else {
        return ScopeOrdering::Incomparable;
    };

    if parent_scope == child_scope {
        return ScopeOrdering::Equal;
    }
    // Narrower iff every child prefix is already inside the parent's set —
    // which is exactly what `intersect` reduces to when the child is the
    // narrower side, per `PathScope::intersect`'s own documentation.
    if parent_scope.intersect(&child_scope) == child_scope {
        ScopeOrdering::Narrower
    } else {
        ScopeOrdering::Wider
    }
}

/// Egress/DNS host-pattern containment, over `permit-only:` selectors.
///
/// Reuses [`aa_core::policy::is_host_allowed_by_egress_allowlist`] for the
/// literal-host case so this comparator can never disagree with the matcher
/// `aa-proxy`/`aa-gateway`/the eBPF probes already enforce against. A
/// **wildcard child pattern** (`*.a.com`) is never fed to that matcher as if
/// it were a hostname — it isn't one — and is instead compared against the
/// parent's own wildcard reach directly.
#[derive(Debug, Clone, Copy, Default)]
pub struct HostPatternOrder;

impl ScopeOrder for HostPatternOrder {
    fn compare(&self, parent: &RequirementScope, child: &RequirementScope) -> ScopeOrdering {
        match (parent, child) {
            (RequirementScope::Whole, RequirementScope::Whole) => ScopeOrdering::Equal,
            (RequirementScope::Whole, RequirementScope::Selectors(_)) => ScopeOrdering::Narrower,
            (RequirementScope::Selectors(_), RequirementScope::Whole) => ScopeOrdering::Wider,
            (RequirementScope::Selectors(p), RequirementScope::Selectors(c)) => compare_host_selectors(p, c),
            _ => ScopeOrdering::Incomparable,
        }
    }
}

/// Whether `pattern` is a grammar this comparator understands: an exact host,
/// the universal `*`, or a leftmost wildcard `*.suffix` with no further glob
/// metacharacters. Anything else (`?`, a mid-label `*`) is unknown grammar and
/// must fail closed rather than be guessed at.
fn is_valid_host_pattern(pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return !suffix.is_empty() && !suffix.contains('*') && !suffix.contains('?');
    }
    !pattern.contains('*') && !pattern.contains('?')
}

/// Whether parent pattern `p` covers child pattern `c`.
///
/// `c == p`, or `p == "*"`, or (`p == "*.S"` and `c` is a literal host inside
/// `S`, or `c == "*.T"` where `T` ends in `.S` with at least one extra label)
/// — everything else is `false` (read by the caller as `Wider`, since grammar
/// validity was already established before this is called).
fn host_pattern_covered(child: &str, parent: &str) -> bool {
    if child == parent || parent == "*" {
        return true;
    }
    let Some(p_suffix) = parent.strip_prefix("*.") else {
        // `parent` is a literal host: only an identical child pattern covers,
        // and that was already handled by the `child == parent` check above.
        return false;
    };
    if let Some(c_suffix) = child.strip_prefix("*.") {
        // Child is itself a wildcard: covered only by a broader-or-equal
        // parent wildcard whose suffix `c_suffix` ends in `.p_suffix` with at
        // least one extra label — `c_suffix == p_suffix` is the `Equal` case,
        // already handled above.
        return c_suffix != p_suffix && c_suffix.ends_with(&format!(".{p_suffix}"));
    }
    // Child is a literal host: this is the one case where reusing the
    // canonical egress matcher is safe, because `child` really is a hostname
    // here.
    aa_core::policy::is_host_allowed_by_egress_allowlist(child, std::slice::from_ref(&parent.to_string()))
}

fn compare_host_selectors(parent: &[String], child: &[String]) -> ScopeOrdering {
    let Some(parent_patterns) = strip_permit_only(parent) else {
        return ScopeOrdering::Incomparable;
    };
    let Some(child_patterns) = strip_permit_only(child) else {
        return ScopeOrdering::Incomparable;
    };
    if !parent_patterns
        .iter()
        .chain(child_patterns.iter())
        .all(|p| is_valid_host_pattern(p))
    {
        return ScopeOrdering::Incomparable;
    }

    let parent_set: BTreeSet<&str> = parent_patterns.iter().map(String::as_str).collect();
    let child_set: BTreeSet<&str> = child_patterns.iter().map(String::as_str).collect();
    if parent_set == child_set {
        return ScopeOrdering::Equal;
    }
    let narrower = child_patterns
        .iter()
        .all(|c| parent_patterns.iter().any(|p| host_pattern_covered(c, p)));
    if narrower {
        ScopeOrdering::Narrower
    } else {
        ScopeOrdering::Wider
    }
}

/// Opaque exact-token subset — syscall names, environment-variable names.
///
/// Neither vocabulary has a meaningful "narrower than" relation beyond set
/// containment: a syscall name is not a prefix of another, and neither is an
/// env-var name, so exact-set comparison is the whole (and correct) answer.
#[derive(Debug, Clone, Copy, Default)]
pub struct ExactTokenOrder;

impl ScopeOrder for ExactTokenOrder {
    fn compare(&self, parent: &RequirementScope, child: &RequirementScope) -> ScopeOrdering {
        match (parent, child) {
            (RequirementScope::Whole, RequirementScope::Whole) => ScopeOrdering::Equal,
            (RequirementScope::Whole, RequirementScope::Selectors(_)) => ScopeOrdering::Narrower,
            (RequirementScope::Selectors(_), RequirementScope::Whole) => ScopeOrdering::Wider,
            (RequirementScope::Selectors(p), RequirementScope::Selectors(c)) => compare_token_selectors(p, c),
            _ => ScopeOrdering::Incomparable,
        }
    }
}

fn compare_token_selectors(parent: &[String], child: &[String]) -> ScopeOrdering {
    let Some(parent_raw) = strip_permit_only(parent) else {
        return ScopeOrdering::Incomparable;
    };
    let Some(child_raw) = strip_permit_only(child) else {
        return ScopeOrdering::Incomparable;
    };
    let parent_set: BTreeSet<&str> = parent_raw.iter().map(String::as_str).collect();
    let child_set: BTreeSet<&str> = child_raw.iter().map(String::as_str).collect();
    if parent_set == child_set {
        ScopeOrdering::Equal
    } else if child_set.is_subset(&parent_set) {
        ScopeOrdering::Narrower
    } else {
        ScopeOrdering::Wider
    }
}

/// Field-wise numeric ceiling ordering over [`RequirementScope::Limits`].
///
/// Delegates to [`limits_narrower_or_equal`] — **not**
/// [`crate::lease::CapabilityLease::covers`]'s own `limits_cover`, which
/// answers a different question (see that function's own documentation for
/// the asymmetry: a field a *requirement* never mentions is vacuously
/// satisfied, whereas a field a *child* leaves unbounded is wider than any
/// bounded parent ceiling, not narrower).
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceCeilingOrder;

impl ScopeOrder for ResourceCeilingOrder {
    fn compare(&self, parent: &RequirementScope, child: &RequirementScope) -> ScopeOrdering {
        match (parent, child) {
            (RequirementScope::Limits(p), RequirementScope::Limits(c)) => {
                if p == c {
                    ScopeOrdering::Equal
                } else if limits_narrower_or_equal(p, c) {
                    ScopeOrdering::Narrower
                } else {
                    ScopeOrdering::Wider
                }
            }
            _ => ScopeOrdering::Incomparable,
        }
    }
}

/// The domain-total comparator registry.
///
/// Exhaustive `match` over every [`CapabilityDomain`] variant with **no
/// wildcard arm** — a domain added to the enum without a row here is a
/// compile error, not a silent fall-through to a default. The three domains
/// that never carry anything but [`RequirementScope::Whole`] from lowering
/// (`ProcessCreation`, `Ipc`, `WorkspaceTransaction`) get
/// [`UndefinedScopeOrder`]: there is nothing to narrow, so `Incomparable` is
/// the honest answer rather than a comparator pretending to reason about a
/// scope shape that never occurs.
pub fn order_for(domain: CapabilityDomain) -> &'static dyn ScopeOrder {
    match domain {
        CapabilityDomain::FilesystemRead | CapabilityDomain::FilesystemWrite => &PathPrefixOrder,
        CapabilityDomain::NetworkEgress | CapabilityDomain::NameResolution => &HostPatternOrder,
        CapabilityDomain::Syscall | CapabilityDomain::Credential => &ExactTokenOrder,
        CapabilityDomain::Resource => &ResourceCeilingOrder,
        CapabilityDomain::ProcessCreation | CapabilityDomain::Ipc | CapabilityDomain::WorkspaceTransaction => {
            &UndefinedScopeOrder
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::ResourceLimits;

    fn selectors(paths: &[&str]) -> RequirementScope {
        RequirementScope::Selectors(paths.iter().map(|p| crate::lowering::permit_only_selector(p)).collect())
    }

    fn raw_selectors(paths: &[&str]) -> RequirementScope {
        RequirementScope::Selectors(paths.iter().map(|p| p.to_string()).collect())
    }

    /// Positive control, and the pinned regression for the `starts_with` bug:
    /// `/workspace/sub` is genuinely inside `/workspace`, and `/work` is a
    /// sibling that a naive string-prefix check would wrongly admit.
    #[test]
    fn path_prefix_order_admits_a_contained_subtree_and_rejects_a_sibling() {
        let parent = selectors(&["/workspace"]);
        assert_eq!(
            PathPrefixOrder.compare(&parent, &selectors(&["/workspace/sub"])),
            ScopeOrdering::Narrower
        );
        assert_eq!(
            PathPrefixOrder.compare(&parent, &selectors(&["/work"])),
            ScopeOrdering::Wider
        );
    }

    #[test]
    fn path_prefix_order_is_incomparable_on_a_relative_or_dotdot_selector() {
        let parent = selectors(&["/workspace"]);
        assert_eq!(
            PathPrefixOrder.compare(&parent, &selectors(&["/workspace/../etc"])),
            ScopeOrdering::Incomparable
        );
        assert_eq!(
            PathPrefixOrder.compare(&parent, &raw_selectors(&["relative/path"])),
            ScopeOrdering::Incomparable
        );
    }

    #[test]
    fn host_pattern_order_admits_an_exact_host_under_a_leftmost_wildcard() {
        let parent = selectors(&["*.openai.com"]);
        assert_eq!(
            HostPatternOrder.compare(&parent, &selectors(&["api.openai.com"])),
            ScopeOrdering::Narrower
        );
    }

    #[test]
    fn host_pattern_order_rejects_the_bare_suffix() {
        let parent = selectors(&["*.openai.com"]);
        assert_eq!(
            HostPatternOrder.compare(&parent, &selectors(&["openai.com"])),
            ScopeOrdering::Wider
        );
    }

    #[test]
    fn host_pattern_order_rejects_an_attacker_crafted_suffix() {
        let parent = selectors(&["*.openai.com"]);
        assert_eq!(
            HostPatternOrder.compare(&parent, &selectors(&["attackeropenai.com"])),
            ScopeOrdering::Wider
        );
    }

    #[test]
    fn host_pattern_order_never_admits_a_child_wildcard_under_a_narrower_parent() {
        let parent = selectors(&["api.x.com"]);
        assert_eq!(
            HostPatternOrder.compare(&parent, &selectors(&["*"])),
            ScopeOrdering::Wider
        );
    }

    #[test]
    fn host_pattern_order_admits_a_strictly_narrower_child_wildcard() {
        let parent = selectors(&["*.x.com"]);
        assert_eq!(
            HostPatternOrder.compare(&parent, &selectors(&["*.api.x.com"])),
            ScopeOrdering::Narrower
        );
    }

    #[test]
    fn a_selector_without_the_permit_only_prefix_is_incomparable_for_every_comparator() {
        let parent = selectors(&["/workspace"]);
        let raw_child = raw_selectors(&["/workspace"]);
        assert_eq!(
            PathPrefixOrder.compare(&parent, &raw_child),
            ScopeOrdering::Incomparable
        );

        let host_parent = selectors(&["*.x.com"]);
        assert_eq!(
            HostPatternOrder.compare(&host_parent, &raw_selectors(&["a.x.com"])),
            ScopeOrdering::Incomparable
        );

        let token_parent = selectors(&["read"]);
        assert_eq!(
            ExactTokenOrder.compare(&token_parent, &raw_selectors(&["read"])),
            ScopeOrdering::Incomparable
        );
    }

    #[test]
    fn exact_token_order_admits_a_subset_and_rejects_a_superset() {
        let parent = selectors(&["read", "write"]);
        assert_eq!(
            ExactTokenOrder.compare(&parent, &selectors(&["read"])),
            ScopeOrdering::Narrower
        );
        assert_eq!(
            ExactTokenOrder.compare(&parent, &selectors(&["read", "write", "ptrace"])),
            ScopeOrdering::Wider
        );
    }

    #[test]
    fn resource_ceiling_order_treats_an_unbounded_child_field_as_wider() {
        let parent = RequirementScope::Limits(ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });
        let child = RequirementScope::Limits(ResourceLimits {
            max_memory_bytes: None,
            ..Default::default()
        });
        assert_eq!(ResourceCeilingOrder.compare(&parent, &child), ScopeOrdering::Wider);
    }

    #[test]
    fn resource_ceiling_order_admits_a_lower_ceiling() {
        let parent = RequirementScope::Limits(ResourceLimits {
            max_memory_bytes: Some(1_000),
            ..Default::default()
        });
        let child = RequirementScope::Limits(ResourceLimits {
            max_memory_bytes: Some(500),
            ..Default::default()
        });
        assert_eq!(ResourceCeilingOrder.compare(&parent, &child), ScopeOrdering::Narrower);
    }

    /// Compile-time-adjacent totality check: every domain must resolve to
    /// *some* comparator. The real totality guarantee is the exhaustive
    /// `match` in `order_for` itself (a new domain fails to compile), but this
    /// pins the runtime behavior too.
    #[test]
    fn order_for_is_total_over_every_capability_domain() {
        for &domain in CapabilityDomain::ALL {
            // Exercising `compare` (rather than merely calling `order_for`) is
            // what proves the returned reference is a real, callable
            // comparator and not e.g. a dangling default.
            let _ = order_for(domain).compare(&RequirementScope::Whole, &RequirementScope::Whole);
        }
    }
}
