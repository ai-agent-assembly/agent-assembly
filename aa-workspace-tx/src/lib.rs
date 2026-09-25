//! Materialized workspace transactions: the mechanism behind
//! `aa-isolation`'s `CapabilityDomain::WorkspaceTransaction` (AAASM-6162).
//!
//! # What this crate is
//!
//! A portable, dependency-light implementation of "stage a working
//! directory's changes against a copy, then fold them back onto the base
//! tree atomically, once, with drift and protected-path checks" — over a
//! *declared surface* (an explicit root plus exclusions), never a full-tree
//! copy. This repository's own build directories have reached hundreds of
//! gigabytes across worktrees; copying "everything under the working
//! directory" by default would repeat that mistake for every launch.
//!
//! `git worktree` and overlayfs were both considered and rejected — see the
//! ticket's design notes: a fresh git worktree has no untracked/ignored build
//! state (fails real dogfood workflows) and overlayfs is Linux-only and
//! unfalsifiable on this development host.
//!
//! # What this crate is not
//!
//! It does not mediate individual syscalls. `aa-isolation-native` /
//! `aa-isolation-sandlock` answer "may this write happen, right now"; this
//! crate answers "may this already-written, staged change set be folded back
//! onto the base tree" — a single decision made once, offline, after the
//! confined process has already exited. See
//! `aa_isolation::CapabilityDomain::WorkspaceTransaction`'s own doc comment.
//!
//! # The one invariant every module here exists to hold
//!
//! **A base path is never written to before `commit` decides to apply it,
//! and `commit` never partially applies.** Concretely:
//!
//! - [`materialize`] copies content, never hard-links it — a hardlink shares
//!   an inode with the base, so a write through the staged path would mutate
//!   the base before any commit decision. [`commit::apply`] additionally
//!   refuses any staged entry whose inode matches a base entry's, as a second
//!   line of defense against a materialization bug.
//! - [`commit::commit`] re-measures the base immediately before touching
//!   anything and refuses the whole commit — nothing applied — if a change-set
//!   path drifted since the transaction opened ([`CommitRefusal::BaseDrift`]).
//! - [`commit::commit`] refuses the whole commit if the change set touches a
//!   protected selector without an approval token
//!   ([`CommitRefusal::ProtectedPathNotApproved`]).
//! - Apply is two-phase: a journal describing every planned operation is
//!   written and `fsync`'d *before* any base path is touched, so a crash
//!   mid-apply is discoverable (`TransactionStatus::InterruptedApply`) rather
//!   than silently half-done. Nothing in this crate ever auto-applies a
//!   journal on a later run — that is a deliberate scope boundary, not a gap.

pub mod commit;
pub mod manifest;
pub mod materialize;
pub mod state;

pub use aa_isolation::{
    BaseManifest, ChangeEntry, ChangeSet, CommitOutcome, CommitRefusal, EntryKind, ManifestEntry, TransactionId,
    TransactionStatus, WorkspaceDigest,
};

use std::io;
use std::path::{Path, PathBuf};

use crate::state::{StateDir, StateError};

/// A single open-or-closed workspace transaction: a base directory, a
/// declared surface over it, and a staged copy a confined process may write
/// to.
pub struct WorkspaceTransaction {
    id: TransactionId,
    state: StateDir,
    base_root: PathBuf,
    exclusions: Vec<String>,
    base_manifest: BaseManifest,
    status: TransactionStatus,
}

/// Everything that can go wrong opening, closing or discarding a
/// transaction. Kept separate from [`CommitRefusal`]: these are setup/
/// teardown failures, not a fail-closed commit decision.
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    /// The private per-transaction state directory could not be created or
    /// verified as this user's own private state.
    #[error("transaction state error: {0}")]
    State(#[from] StateError),
    /// Copying the base surface into the staged workspace failed.
    #[error("materialization failed: {0}")]
    Materialize(#[source] io::Error),
    /// Measuring a manifest over the declared surface failed.
    #[error("manifest measurement failed: {0}")]
    Manifest(#[source] io::Error),
}

impl WorkspaceTransaction {
    /// Open a new transaction: measure the base surface, materialize a
    /// staged copy of it under a freshly-created, owner-verified state
    /// directory, and record the base manifest for later drift/diff checks.
    ///
    /// `state_root` is the directory under which per-transaction state
    /// directories are created — callers pick this explicitly (never
    /// `std::env::temp_dir()`; see [`state`] module docs) so tests can point
    /// it at an isolated fixture without touching a real user's `~/.aasm`.
    pub fn open(
        id: TransactionId,
        state_root: &Path,
        base_root: &Path,
        exclusions: Vec<String>,
    ) -> Result<Self, TransactionError> {
        let state = StateDir::create(state_root, &id)?;
        let base_manifest = manifest::measure(base_root, &exclusions).map_err(TransactionError::Manifest)?;
        materialize::copy_surface(base_root, state.staged_dir(), &base_manifest)
            .map_err(TransactionError::Materialize)?;
        Ok(Self {
            id,
            state,
            base_root: base_root.to_path_buf(),
            exclusions,
            base_manifest,
            status: TransactionStatus::Open,
        })
    }

    /// The transaction's identifier.
    pub fn id(&self) -> &TransactionId {
        &self.id
    }

    /// The staged workspace a confined process should be given as its
    /// working directory instead of the real base.
    pub fn staged_dir(&self) -> &Path {
        self.state.staged_dir()
    }

    /// Current lifecycle status.
    pub fn status(&self) -> &TransactionStatus {
        &self.status
    }

    /// The manifest recorded when the transaction opened.
    pub fn base_manifest(&self) -> &BaseManifest {
        &self.base_manifest
    }

    /// Mark the transaction closed: the confined process has exited and the
    /// staged workspace is stable. Required before [`Self::commit`] —
    /// enforced as [`CommitRefusal::NotClosed`], not a panic, because the
    /// caller is a CLI command reading real process state and can get this
    /// wrong.
    pub fn close(&mut self) {
        if matches!(self.status, TransactionStatus::Open) {
            self.status = TransactionStatus::Closed;
        }
    }

    /// Discard the transaction: remove the staged workspace, touch nothing
    /// under the base root, mark the transaction terminally
    /// [`TransactionStatus::Discarded`].
    pub fn discard(mut self) -> Result<(), TransactionError> {
        self.state.remove_staged().map_err(TransactionError::Materialize)?;
        self.status = TransactionStatus::Discarded;
        Ok(())
    }

    /// Attempt to commit the transaction. See [`commit::commit`] for the
    /// full fail-closed decision sequence; this is a thin `self`-consuming
    /// wrapper that updates `self.status` to match the outcome.
    pub fn commit(mut self, protected: &[String], approved: bool) -> Result<CommitOutcome, CommitRefusal> {
        if !matches!(self.status, TransactionStatus::Closed) {
            let refusal = CommitRefusal::NotClosed {
                observed: Box::new(self.status.clone()),
            };
            self.status = TransactionStatus::ConflictRefused {
                refusal: refusal.clone(),
            };
            return Err(refusal);
        }
        match commit::commit(
            &self.id,
            &self.state,
            &self.base_root,
            &self.exclusions,
            &self.base_manifest,
            protected,
            approved,
        ) {
            Ok(outcome) => {
                self.status = TransactionStatus::Committed;
                Ok(outcome)
            }
            Err(refusal) => {
                self.status = TransactionStatus::ConflictRefused {
                    refusal: refusal.clone(),
                };
                Err(refusal)
            }
        }
    }
}
