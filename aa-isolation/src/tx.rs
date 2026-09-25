//! Backend-neutral contract for a staged, drift-checked workspace transaction
//! (AAASM-6162).
//!
//! Every type here is pure data: no filesystem access, no hashing, no process
//! spawning. `aa-workspace-tx` (a separate, unpublished mechanism crate) is
//! the only thing that measures a real directory tree or writes to disk; this
//! module only names the shapes that measurement and that commit decision are
//! allowed to produce, so that `CapabilityDomain::WorkspaceTransaction`
//! reports and any future second backend answer in the same vocabulary.
//!
//! # Why a transaction, not a per-write mediation
//!
//! `CapabilityDomain::FilesystemWrite` answers "may this write happen". This
//! module answers a different, later question: given a working directory
//! that a confined process already wrote to (staged, never the real base),
//! may the resulting change set be folded back onto the base tree at all,
//! atomically, once? A backend can implement one axis without the other.

use std::fmt;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Opaque identifier for one workspace transaction.
///
/// Carries no structure a caller should parse: it is a stable handle for
/// `aasm workspace tx show/discard/gc`, not a timestamp or a path fragment,
/// even though a real mechanism will likely derive it from both.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TransactionId(String);

impl TransactionId {
    /// Wrap an already-generated identifier.
    ///
    /// Does not validate shape: generation (uniqueness, collision avoidance)
    /// is a mechanism concern, not a contract concern.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The identifier's string form.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for TransactionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A content digest of a workspace tree or of one entry within it.
///
/// Opaque here on purpose: this crate does not name a hash algorithm (that is
/// `aa-workspace-tx`'s decision, currently SHA-256 hex). A digest is only ever
/// compared for equality by this contract, never recomputed from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct WorkspaceDigest(String);

impl WorkspaceDigest {
    /// Wrap an already-computed digest string.
    pub fn new(digest: impl Into<String>) -> Self {
        Self(digest.into())
    }

    /// The digest's string form (mechanism-defined encoding, e.g. hex).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for WorkspaceDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// What kind of filesystem entry a manifest or change-set entry describes.
///
/// Kept distinct from a change verb (`ChangeEntry`): a kind is a fact about
/// one snapshot, a change is a fact about the difference between two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link. Its target is carried verbatim wherever this kind
    /// appears: this contract never resolves a symlink target, only records
    /// it, per the applier-side boundary in the ticket's design notes.
    Symlink,
}

/// One measured entry of a `BaseManifest` or a materialized workspace.
///
/// Path is relative to the declared surface's root; this contract never
/// carries an absolute path so that a manifest cannot be replayed against the
/// wrong root by mistake.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ManifestEntry {
    path: String,
    kind: EntryKind,
    digest: Option<WorkspaceDigest>,
    symlink_target: Option<String>,
}

impl ManifestEntry {
    /// A measured regular file.
    pub fn file(path: impl Into<String>, digest: WorkspaceDigest) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::File,
            digest: Some(digest),
            symlink_target: None,
        }
    }

    /// A measured directory. Directories carry no content digest.
    pub fn directory(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::Directory,
            digest: None,
            symlink_target: None,
        }
    }

    /// A measured symlink. `target` is the link's literal target string,
    /// never a resolved path.
    pub fn symlink(path: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            kind: EntryKind::Symlink,
            digest: None,
            symlink_target: Some(target.into()),
        }
    }

    /// The entry's path, relative to the surface root.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// What kind of entry this is.
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// The entry's content digest, if it has one (files only).
    pub fn digest(&self) -> Option<&WorkspaceDigest> {
        self.digest.as_ref()
    }

    /// The entry's literal symlink target, if it is a symlink.
    pub fn symlink_target(&self) -> Option<&str> {
        self.symlink_target.as_deref()
    }
}

/// A measurement of the base tree over a declared surface, taken before a
/// transaction opens (and re-taken, over the same surface, immediately before
/// commit to detect drift).
///
/// Deliberately not a full-tree copy or a full-tree hash: the surface is
/// declared (included roots plus exclusions), matching the ticket's "declared
/// surface, not a full-tree copy" decision. Two manifests are comparable only
/// if they were taken over the same surface root and exclusions; this type
/// does not check that itself, the caller (`aa-workspace-tx`) is responsible
/// for measuring both sides identically.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BaseManifest {
    surface_root: String,
    exclusions: Vec<String>,
    entries: Vec<ManifestEntry>,
}

impl BaseManifest {
    /// Build a manifest from its measured entries.
    ///
    /// `exclusions` are the selectors (glob-like strings, opaque to this
    /// contract) that were excluded from measurement, recorded so a later
    /// drift check can tell "excluded, so not compared" apart from "included
    /// and unchanged".
    pub fn new(surface_root: impl Into<String>, exclusions: Vec<String>, entries: Vec<ManifestEntry>) -> Self {
        Self {
            surface_root: surface_root.into(),
            exclusions,
            entries,
        }
    }

    /// The root of the declared surface this manifest was measured over.
    pub fn surface_root(&self) -> &str {
        &self.surface_root
    }

    /// Selectors excluded from measurement.
    pub fn exclusions(&self) -> &[String] {
        &self.exclusions
    }

    /// Every measured entry, in no particular guaranteed order.
    pub fn entries(&self) -> &[ManifestEntry] {
        &self.entries
    }

    /// The entry at `path`, if the manifest has one.
    pub fn entry(&self, path: &str) -> Option<&ManifestEntry> {
        self.entries.iter().find(|e| e.path == path)
    }
}

/// One path's change between a `BaseManifest` and a materialized workspace.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "verb", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ChangeEntry {
    /// A path present in the workspace and absent from the base.
    Added {
        /// Path relative to the surface root.
        path: String,
    },
    /// A path present in both, with different content.
    Modified {
        /// Path relative to the surface root.
        path: String,
    },
    /// A path present in the base and absent from the workspace.
    Deleted {
        /// Path relative to the surface root.
        path: String,
    },
}

impl ChangeEntry {
    /// The path this entry concerns, regardless of verb.
    pub fn path(&self) -> &str {
        match self {
            Self::Added { path } | Self::Modified { path } | Self::Deleted { path } => path,
        }
    }
}

/// The full set of changes between a `BaseManifest` and a materialized
/// workspace, as measured by `aa-workspace-tx`'s diff step.
///
/// A plain `Vec` wrapper rather than a `HashMap` keyed by path: entries are
/// produced once, by one diff pass, and every consumer (protected-path
/// intersection, apply ordering, evidence rendering) wants them in the stable
/// order the diff found them, not a hash order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ChangeSet {
    entries: Vec<ChangeEntry>,
}

impl ChangeSet {
    /// An empty change set: the workspace matches its base exactly.
    pub fn empty() -> Self {
        Self { entries: Vec::new() }
    }

    /// Build a change set from its entries.
    pub fn new(entries: Vec<ChangeEntry>) -> Self {
        Self { entries }
    }

    /// Every changed path, in diff order.
    pub fn entries(&self) -> &[ChangeEntry] {
        &self.entries
    }

    /// Whether any path changed at all.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every changed path as a set of strings, for intersection against
    /// protected-path selectors or against a re-measured drift set.
    pub fn paths(&self) -> std::collections::BTreeSet<&str> {
        self.entries.iter().map(ChangeEntry::path).collect()
    }
}

/// Where a transaction is in its lifecycle.
///
/// The crash-safety invariant this contract exists to state:
/// **`Committed` is the only status an apply may ever produce, and it is
/// reached only by `aa-workspace-tx`'s own two-phase apply completing.** No
/// status here is reachable by a later run "noticing" an open or closed
/// transaction and applying it automatically: that behavior is out of scope
/// for every status below, not merely unimplemented.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TransactionStatus {
    /// The confined process may still be writing to the staged workspace.
    Open,
    /// The confined process has exited; the staged workspace is stable and
    /// eligible for a commit or discard decision, but neither has run yet.
    Closed,
    /// The two-phase apply finished: every entry in the change set was
    /// applied to the base, the journal was fsync'd complete, and the
    /// transaction's own state was marked done. Terminal.
    Committed,
    /// The transaction was explicitly discarded: the staged workspace is
    /// removed (or scheduled for removal) and the base was never touched.
    /// Terminal.
    Discarded,
    /// Commit was refused before any base path was touched. Terminal for the
    /// transaction as attempted; a caller may open a new transaction to retry.
    ConflictRefused {
        /// Why the commit was refused.
        refusal: CommitRefusal,
    },
    /// The apply journal was found partially applied when a run examined the
    /// transaction, e.g. the process died mid-apply. Never produced by a
    /// clean run; only ever discovered. Requires explicit operator action
    /// (`aasm workspace tx show/discard`), never auto-resolved.
    InterruptedApply,
}

impl TransactionStatus {
    /// Whether this status is terminal: no further state transition is
    /// valid for the transaction.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Committed | Self::Discarded | Self::ConflictRefused { .. })
    }
}

/// Why a commit was refused, in full detail.
///
/// Every variant here corresponds to a fail-closed decision: none of them are
/// recoverable by retrying the same commit unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "reason", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum CommitRefusal {
    /// Re-measuring the base immediately before commit found a path inside
    /// the change set that differs from the `BaseManifest` recorded when the
    /// transaction opened: someone else wrote to the base concurrently.
    BaseDrift {
        /// The drifted paths, intersected with the change set.
        paths: Vec<String>,
    },
    /// The change set touches at least one protected-path selector and no
    /// approval token authorizing that touch was presented.
    ProtectedPathNotApproved {
        /// The protected selectors the change set intersects.
        selectors: Vec<String>,
    },
    /// A staged entry's path failed the applier-side boundary check: absolute,
    /// contains a parent-directory component, or is otherwise not a normal
    /// relative path.
    BoundaryEscape {
        /// The offending path, as staged.
        path: String,
    },
    /// A staged entry shares an inode with a base entry: the copy-never-
    /// hardlink invariant was violated somewhere upstream of commit.
    HardlinkToBase {
        /// The offending path.
        path: String,
    },
    /// The transaction is not `TransactionStatus::Closed` (e.g. still `Open`,
    /// or already terminal): a commit was attempted at the wrong lifecycle
    /// point.
    NotClosed {
        /// The status actually observed.
        observed: Box<TransactionStatus>,
    },
    /// The transaction's exclusive lock could not be acquired, or its state
    /// directory's ownership/mode could not be verified as the original
    /// owner's private state: ambiguity here is refused rather than assumed
    /// safe.
    LockUnavailable {
        /// Why the lock or ownership check failed, in words.
        detail: String,
    },
}

/// What a successful commit produced.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CommitOutcome {
    transaction: TransactionId,
    base_digest: WorkspaceDigest,
    result_digest: WorkspaceDigest,
    applied: ChangeSet,
}

impl CommitOutcome {
    /// Record a successful commit.
    pub fn new(
        transaction: TransactionId,
        base_digest: WorkspaceDigest,
        result_digest: WorkspaceDigest,
        applied: ChangeSet,
    ) -> Self {
        Self {
            transaction,
            base_digest,
            result_digest,
            applied,
        }
    }

    /// The transaction that was committed.
    pub fn transaction(&self) -> &TransactionId {
        &self.transaction
    }

    /// The base tree's digest immediately before this commit applied.
    pub fn base_digest(&self) -> &WorkspaceDigest {
        &self.base_digest
    }

    /// The base tree's digest immediately after this commit applied.
    pub fn result_digest(&self) -> &WorkspaceDigest {
        &self.result_digest
    }

    /// The exact change set that was applied.
    pub fn applied(&self) -> &ChangeSet {
        &self.applied
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_set_paths_deduplicates_and_reflects_every_verb() {
        let set = ChangeSet::new(vec![
            ChangeEntry::Added { path: "a".into() },
            ChangeEntry::Modified { path: "b".into() },
            ChangeEntry::Deleted { path: "c".into() },
        ]);
        let paths = set.paths();
        assert_eq!(paths.len(), 3);
        assert!(paths.contains("a"));
        assert!(paths.contains("b"));
        assert!(paths.contains("c"));
    }

    #[test]
    fn empty_change_set_is_empty() {
        assert!(ChangeSet::empty().is_empty());
        assert!(!ChangeSet::new(vec![ChangeEntry::Added { path: "x".into() }]).is_empty());
    }

    #[test]
    fn terminal_statuses_are_exactly_committed_discarded_and_conflict_refused() {
        assert!(TransactionStatus::Committed.is_terminal());
        assert!(TransactionStatus::Discarded.is_terminal());
        assert!(TransactionStatus::ConflictRefused {
            refusal: CommitRefusal::NotClosed {
                observed: Box::new(TransactionStatus::Open)
            }
        }
        .is_terminal());
        assert!(!TransactionStatus::Open.is_terminal());
        assert!(!TransactionStatus::Closed.is_terminal());
        assert!(!TransactionStatus::InterruptedApply.is_terminal());
    }

    #[test]
    fn base_manifest_entry_lookup_by_path() {
        let manifest = BaseManifest::new(
            "/base",
            vec![],
            vec![
                ManifestEntry::file("a.txt", WorkspaceDigest::new("deadbeef")),
                ManifestEntry::directory("sub"),
                ManifestEntry::symlink("link", "a.txt"),
            ],
        );
        assert_eq!(manifest.entry("a.txt").unwrap().kind(), EntryKind::File);
        assert_eq!(manifest.entry("sub").unwrap().kind(), EntryKind::Directory);
        assert_eq!(manifest.entry("link").unwrap().symlink_target(), Some("a.txt"));
        assert!(manifest.entry("missing").is_none());
    }
}
