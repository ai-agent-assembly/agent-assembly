//! Filesystem path-scope node for the canonical policy AST (AAASM-5751).
//!
//! A [`FilesystemPolicy`] is the operator-authored answer to *which paths* an
//! agent may read and write. It lives on the same
//! [`PolicyDocument`](super::document::PolicyDocument) as the capability,
//! egress and syscall nodes so there is ONE policy source; the AAASM-5707
//! lowering in `aa-isolation` consumes it to scope a filesystem control at
//! `ScopeGranularity::Enumerated` instead of the whole-domain boolean the
//! `capabilities` node could express on its own.
//!
//! Authority: ADR 0035 (`Backend capability examples` requires the vocabulary
//! to distinguish filesystem read/write/create/delete **scope**) and its
//! AAASM-5751 amendment, which records this node.
//!
//! # Three states that must not collapse into one
//!
//! | Authored form | Meaning |
//! | --- | --- |
//! | The verb's node is absent (`None`) | The operator stated nothing. **Not a grant** |
//! | [`PathScope`] with a non-empty `allow` | Only these subtrees may be reached |
//! | [`PathScope`] with an empty `allow` | A restriction is in force and permits nothing — deny-all |
//!
//! The third is the one that is easy to get wrong, and getting it wrong is
//! fail-open. `Some(PathScope { allow: {} })` is the *most* restrictive posture
//! an author can write, not the absence of one — the same reading
//! `aa_policy::check_network_egress` gives an empty egress allowlist
//! (AAASM-3728 / AAASM-3730). Presence of the node IS the "a restriction is in
//! force" flag, which is why no separate boolean is needed here (contrast
//! `aa_core::CapabilitySet::allow_restricted`, whose struct is always present
//! and therefore cannot use presence to mean anything).
//!
//! # No backend vocabulary
//!
//! Paths are absolute prefixes and nothing else. Nothing here names Landlock
//! rulesets, seccomp filters, bind mounts or any other mechanism — ADR 0035 §2
//! keeps mechanism names out of the policy language, and a backend that cannot
//! realize a prefix says so through its own capability report rather than by
//! having the policy speak its dialect.

use std::collections::BTreeSet;

/// Why a path could not be admitted to a [`PathScope`].
///
/// Every variant is a fail-closed rejection at authoring time rather than a
/// silent normalization, because each one has a reading under which the
/// authored prefix would permit strictly more than the operator meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathScopeError {
    /// The entry was empty or whitespace-only.
    Empty,
    /// The entry was not absolute.
    ///
    /// A relative prefix has no meaning without a working directory, and the
    /// working directory of a confined agent is not a policy input. Resolving
    /// one at load time would make the same document mean different things on
    /// two machines.
    NotAbsolute(String),
    /// The entry contained a `..` component.
    ///
    /// `/workspace/../etc` is `/etc`. Accepting it would let a prefix that
    /// *reads* as scoped to the workspace silently permit anything, so it is
    /// rejected rather than normalized — an operator who means `/etc` must
    /// write `/etc`.
    ParentTraversal(String),
    /// The entry contained an interior NUL byte, which no path can carry and
    /// which truncates when handed to a C API.
    InteriorNul(String),
}

impl core::fmt::Display for PathScopeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Empty => write!(f, "path entry must not be empty"),
            Self::NotAbsolute(p) => write!(
                f,
                "path {p:?} must be absolute (start with '/'); a relative prefix has no \
                 machine-independent meaning"
            ),
            Self::ParentTraversal(p) => write!(
                f,
                "path {p:?} contains a '..' component; a traversing prefix would permit more than \
                 it reads as permitting"
            ),
            Self::InteriorNul(p) => write!(f, "path {p:?} contains an interior NUL byte"),
        }
    }
}

impl std::error::Error for PathScopeError {}

/// Normalize an absolute path into its canonical component form.
///
/// Purely lexical: no filesystem is touched, so the result is identical on
/// every host and reproducible in a test. `.` components and repeated or
/// trailing separators are removed (they are pure notation and carry no
/// meaning), `..` is rejected rather than resolved. The root is `/`.
fn normalize(raw: &str) -> Result<String, PathScopeError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(PathScopeError::Empty);
    }
    if trimmed.contains('\0') {
        return Err(PathScopeError::InteriorNul(trimmed.to_string()));
    }
    if !trimmed.starts_with('/') {
        return Err(PathScopeError::NotAbsolute(trimmed.to_string()));
    }
    let mut components: Vec<&str> = Vec::new();
    for component in trimmed.split('/') {
        match component {
            "" | "." => {}
            ".." => return Err(PathScopeError::ParentTraversal(trimmed.to_string())),
            other => components.push(other),
        }
    }
    if components.is_empty() {
        return Ok("/".to_string());
    }
    Ok(format!("/{}", components.join("/")))
}

/// Whether `ancestor` contains `path` — equal, or a proper directory prefix.
///
/// Both arguments must already be normalized. The comparison is
/// component-aware on purpose: a byte-prefix test would make `/workspace`
/// permit `/workspace-of-someone-else`, which is the classic prefix-matching
/// widening and is exactly the bug a path allow-list exists to prevent.
fn contains(ancestor: &str, path: &str) -> bool {
    if ancestor == "/" {
        return true;
    }
    if path == ancestor {
        return true;
    }
    path.len() > ancestor.len() && path.starts_with(ancestor) && path.as_bytes()[ancestor.len()] == b'/'
}

/// The set of path subtrees permitted for one filesystem verb.
///
/// Membership is *prefix-closed*: an entry permits itself and everything
/// beneath it. The set is a [`BTreeSet`] so it is de-duplicated and
/// order-stable, which keeps the lowering deterministic.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PathScope {
    /// The permitted path prefixes, normalized and absolute.
    pub allow: BTreeSet<String>,
}

impl PathScope {
    /// Build a scope from raw path strings, validating and normalizing each.
    ///
    /// Redundant entries are pruned: if both `/workspace` and `/workspace/src`
    /// are given, only `/workspace` is kept, because the narrower one adds
    /// nothing to a prefix-closed set. Pruning is what makes
    /// [`intersect`](Self::intersect) produce one canonical answer rather than
    /// one of several equivalent ones.
    ///
    /// # Errors
    ///
    /// The first [`PathScopeError`] encountered, so a malformed prefix is a
    /// load failure rather than a silently dropped restriction.
    pub fn from_paths<I, S>(paths: I) -> Result<Self, PathScopeError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut allow = BTreeSet::new();
        for path in paths {
            allow.insert(normalize(path.as_ref())?);
        }
        Ok(Self {
            allow: prune_redundant(allow),
        })
    }

    /// Whether this scope permits `path`.
    ///
    /// A non-absolute or malformed `path` is **not** permitted: the query
    /// cannot be normalized, and answering "permitted" for input this function
    /// could not interpret is the fail-open answer.
    pub fn permits(&self, path: &str) -> bool {
        let Ok(candidate) = normalize(path) else {
            return false;
        };
        self.allow.iter().any(|a| contains(a.as_str(), &candidate))
    }

    /// Whether a restriction is in force that permits nothing at all.
    ///
    /// `true` is deny-all, **never** "no restriction" — see the module docs.
    pub fn permits_nothing(&self) -> bool {
        self.allow.is_empty()
    }

    /// The permitted prefixes, ordered.
    pub fn iter(&self) -> impl Iterator<Item = &str> + '_ {
        self.allow.iter().map(String::as_str)
    }

    /// The most-restrictive-wins merge of two scopes: their set intersection.
    ///
    /// Computed over subtrees rather than over strings. Two tiers that name
    /// `/workspace` and `/workspace/src` intersect to `/workspace/src` — the
    /// narrower tier shrinks the broader one — whereas plain string
    /// intersection would yield the empty set and a plain union would yield
    /// `/workspace`, widening the narrower tier into permitting everything the
    /// broader one did.
    ///
    /// A **disjoint** pair intersects to empty, which is
    /// [`permits_nothing`](Self::permits_nothing) — deny-all. That is the
    /// fail-closed collapse, and it is the reason presence of the node rather
    /// than non-emptiness of the set is what means "a restriction is in force".
    pub fn intersect(&self, other: &Self) -> Self {
        let mut allow: BTreeSet<String> = BTreeSet::new();
        for entry in &self.allow {
            if other.allow.iter().any(|a| contains(a.as_str(), entry.as_str())) {
                allow.insert(entry.clone());
            }
        }
        for entry in &other.allow {
            if self.allow.iter().any(|a| contains(a.as_str(), entry.as_str())) {
                allow.insert(entry.clone());
            }
        }
        Self {
            allow: prune_redundant(allow),
        }
    }
}

/// Drop every entry that another, strictly broader entry already contains.
fn prune_redundant(allow: BTreeSet<String>) -> BTreeSet<String> {
    allow
        .iter()
        .filter(|entry| {
            !allow
                .iter()
                .any(|other| other.as_str() != entry.as_str() && contains(other.as_str(), entry.as_str()))
        })
        .cloned()
        .collect()
}

/// The filesystem path-scope node of the canonical policy AST.
///
/// Read and write are separate verbs because an agent that may read a source
/// tree it may not modify is the ordinary case, and a single combined scope
/// could not express it.
///
/// `write` covers create, rename, write and delete together: those collapse
/// onto one `FilesystemWrite` domain at the execution boundary, and the policy
/// vocabulary does not separate them either. That residual gap is reported by
/// the `aa-isolation` lowering rather than papered over here.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FilesystemPolicy {
    /// Paths the agent may read. `None` means the operator stated nothing —
    /// **not** that reads are unrestricted.
    pub read: Option<PathScope>,
    /// Paths the agent may write, create, rename or delete. `None` means the
    /// operator stated nothing — **not** that writes are unrestricted.
    pub write: Option<PathScope>,
}

impl FilesystemPolicy {
    /// Whether either verb carries a scope.
    ///
    /// `false` is indistinguishable from an absent `filesystem:` section and is
    /// treated as one everywhere: an authored `filesystem: {}` states nothing.
    pub fn is_stated(&self) -> bool {
        self.read.is_some() || self.write.is_some()
    }

    /// The most-restrictive-wins merge of two nodes, verb by verb.
    ///
    /// A verb one side left unstated cannot widen the other side's scope — the
    /// stated one stands, exactly as `aa_core::merge_capabilities` keeps a
    /// non-empty `allow` when the other tier declares none. Silence is never
    /// permission, so it is never a reason to drop a restriction either.
    pub fn intersect(&self, other: &Self) -> Self {
        Self {
            read: intersect_verb(self.read.as_ref(), other.read.as_ref()),
            write: intersect_verb(self.write.as_ref(), other.write.as_ref()),
        }
    }
}

fn intersect_verb(a: Option<&PathScope>, b: Option<&PathScope>) -> Option<PathScope> {
    match (a, b) {
        (None, None) => None,
        (Some(scope), None) | (None, Some(scope)) => Some(scope.clone()),
        (Some(x), Some(y)) => Some(x.intersect(y)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(paths: &[&str]) -> PathScope {
        PathScope::from_paths(paths).expect("fixture paths are valid")
    }

    // ── Authoring-time validation ───────────────────────────────────────────

    /// Each rejection has a reading under which the prefix permits more than it
    /// looks like it permits, so each is a load failure. The control is the
    /// last line: a well-formed absolute path is accepted, so the function is
    /// not simply rejecting everything.
    #[test]
    fn malformed_prefixes_are_rejected_and_a_well_formed_one_is_not() {
        assert_eq!(PathScope::from_paths([""]), Err(PathScopeError::Empty));
        assert_eq!(PathScope::from_paths(["   "]), Err(PathScopeError::Empty));
        assert_eq!(
            PathScope::from_paths(["workspace"]),
            Err(PathScopeError::NotAbsolute("workspace".to_string()))
        );
        assert_eq!(
            PathScope::from_paths(["/workspace/../etc"]),
            Err(PathScopeError::ParentTraversal("/workspace/../etc".to_string()))
        );
        assert_eq!(
            PathScope::from_paths(["/work\0space"]),
            Err(PathScopeError::InteriorNul("/work\0space".to_string()))
        );
        assert!(PathScope::from_paths(["/workspace"]).is_ok());
    }

    /// `/workspace/../etc` denotes `/etc`. Rejecting rather than resolving is
    /// the decision; this pins that a traversing entry never becomes a live
    /// permission for the directory it actually denotes.
    #[test]
    fn a_traversing_prefix_never_becomes_a_permission() {
        assert!(PathScope::from_paths(["/workspace/../etc"]).is_err());
        // The control: the path it would have resolved to IS admissible when
        // an operator writes it out, so the rejection is about the notation
        // and not about `/etc`.
        assert!(scope(&["/etc"]).permits("/etc/passwd"));
    }

    #[test]
    fn notation_is_normalized_so_equal_paths_compare_equal() {
        assert_eq!(scope(&["/workspace//src/"]), scope(&["/workspace/src"]));
        assert_eq!(scope(&["/workspace/./src"]), scope(&["/workspace/src"]));
        assert_eq!(scope(&["///"]).allow, BTreeSet::from(["/".to_string()]));
    }

    // ── Matching ────────────────────────────────────────────────────────────

    /// The prefix-widening bug a path allow-list exists to prevent: a byte
    /// prefix test makes `/workspace` permit `/workspace-evil`. Both directions
    /// are asserted so this cannot pass against a matcher that permits or
    /// refuses everything.
    #[test]
    fn matching_is_component_aware_not_a_byte_prefix() {
        let s = scope(&["/workspace"]);
        assert!(s.permits("/workspace"));
        assert!(s.permits("/workspace/src/main.rs"));
        assert!(!s.permits("/workspace-evil/secrets"));
        assert!(!s.permits("/workspacex"));
        assert!(!s.permits("/etc/passwd"));
    }

    #[test]
    fn root_permits_every_absolute_path() {
        let s = scope(&["/"]);
        assert!(s.permits("/etc/passwd"));
        assert!(s.permits("/"));
    }

    /// A query this function cannot interpret must not be answered
    /// "permitted" — that is the fail-open answer.
    #[test]
    fn an_uninterpretable_query_is_not_permitted() {
        let s = scope(&["/"]);
        assert!(!s.permits("relative/path"));
        assert!(!s.permits(""));
        assert!(!s.permits("/a/../b"));
    }

    /// An empty scope is a restriction that permits nothing, never the absence
    /// of one. The control is the non-empty scope beside it: `permits_nothing`
    /// separates the two.
    #[test]
    fn an_empty_scope_permits_nothing_rather_than_everything() {
        let empty = scope(&[]);
        assert!(empty.permits_nothing());
        assert!(!empty.permits("/workspace"));
        assert!(!empty.permits("/"));

        let stated = scope(&["/workspace"]);
        assert!(!stated.permits_nothing());
        assert!(stated.permits("/workspace"));
    }

    // ── Pruning ─────────────────────────────────────────────────────────────

    #[test]
    fn a_redundant_narrower_entry_is_pruned() {
        let s = scope(&["/workspace", "/workspace/src", "/tmp"]);
        assert_eq!(s.allow, BTreeSet::from(["/tmp".to_string(), "/workspace".to_string()]));
        // Pruning must not change what the scope permits.
        assert!(s.permits("/workspace/src/main.rs"));
    }

    // ── Most-restrictive-wins ───────────────────────────────────────────────

    /// The fixture is chosen so the three candidate merges disagree: over
    /// `{/workspace}` and `{/workspace/src, /tmp}` a union yields `/workspace`
    /// (widening the narrow tier), a string intersection yields the empty set
    /// (deny-all, stricter than either tier wrote), and the subtree
    /// intersection this asserts yields `/workspace/src`. Only the last is
    /// most-restrictive-wins.
    #[test]
    fn intersect_narrows_to_the_stricter_subtree() {
        let merged = scope(&["/workspace"]).intersect(&scope(&["/workspace/src", "/tmp"]));
        assert_eq!(merged.allow, BTreeSet::from(["/workspace/src".to_string()]));

        assert!(merged.permits("/workspace/src/main.rs"));
        // Permitted by the broad tier alone, and by neither once merged.
        assert!(!merged.permits("/workspace/docs/readme.md"));
        // Permitted by the narrow tier alone; the broad tier never allowed it.
        assert!(!merged.permits("/tmp/scratch"));
    }

    #[test]
    fn intersect_is_order_independent() {
        let a = scope(&["/workspace", "/var/log"]);
        let b = scope(&["/workspace/src", "/tmp"]);
        assert_eq!(a.intersect(&b), b.intersect(&a));
    }

    /// Two tiers that share nothing collapse to deny-all rather than to "no
    /// restriction" — the disjoint-cascade case AAASM-4154 had to close for
    /// capabilities.
    #[test]
    fn disjoint_tiers_collapse_to_deny_all() {
        let merged = scope(&["/workspace"]).intersect(&scope(&["/opt"]));
        assert!(merged.permits_nothing());
        assert!(!merged.permits("/workspace"));
        assert!(!merged.permits("/opt"));

        // The control: overlapping tiers do not collapse, so the collapse is
        // attributable to disjointness and not to `intersect` emptying always.
        assert!(!scope(&["/workspace"])
            .intersect(&scope(&["/workspace"]))
            .permits_nothing());
    }

    /// An in-force empty scope on either side wins: it permits nothing, so the
    /// intersection permits nothing.
    #[test]
    fn an_empty_scope_dominates_the_intersection() {
        assert!(scope(&["/workspace"]).intersect(&scope(&[])).permits_nothing());
        assert!(scope(&[]).intersect(&scope(&["/workspace"])).permits_nothing());
    }

    // ── FilesystemPolicy verb handling ──────────────────────────────────────

    #[test]
    fn a_verb_only_one_side_states_survives_the_merge() {
        let stated = FilesystemPolicy {
            read: Some(scope(&["/workspace"])),
            write: None,
        };
        let silent = FilesystemPolicy::default();
        let merged = stated.intersect(&silent);
        assert_eq!(merged.read, Some(scope(&["/workspace"])));
        assert_eq!(merged.write, None);
        // Symmetric: silence never drops a restriction from either side.
        assert_eq!(silent.intersect(&stated), merged);
    }

    #[test]
    fn verbs_merge_independently() {
        let a = FilesystemPolicy {
            read: Some(scope(&["/workspace"])),
            write: Some(scope(&["/workspace"])),
        };
        let b = FilesystemPolicy {
            read: Some(scope(&["/workspace/src"])),
            write: Some(scope(&["/opt"])),
        };
        let merged = a.intersect(&b);
        assert_eq!(merged.read, Some(scope(&["/workspace/src"])));
        assert!(merged.write.as_ref().unwrap().permits_nothing());
    }

    #[test]
    fn an_all_none_node_states_nothing() {
        assert!(!FilesystemPolicy::default().is_stated());
        assert!(FilesystemPolicy {
            read: Some(scope(&[])),
            write: None,
        }
        .is_stated());
    }
}
