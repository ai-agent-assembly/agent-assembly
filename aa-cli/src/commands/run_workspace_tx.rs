//! `aasm run --workspace-tx`: bind a launch's working directory to a
//! materialized [`aa_workspace_tx::WorkspaceTransaction`] instead of the real
//! base directory (AAASM-6162).
//!
//! # What this module owns
//!
//! Everything `run.rs` needs to know about a transactional launch and
//! nothing more: resolving the flags into a [`WorkspaceTxPlan`], the three
//! fail-closed preconditions checked before anything is registered or
//! copied, a [`WorkspaceTxGuard`] whose `Drop` discards an unsettled
//! transaction, the commit-or-discard decision in [`settle`], and the
//! `workspace_tx.*` stderr block both the confined and unconfined launch
//! paths print via [`machine_block`].
//!
//! `run.rs` still owns the two things only it can: calling
//! `ResolvedRunPlan::set_workspace_staged_dir` before `bind` (so the staged
//! directory reaches the child's cwd the same way `NetworkPlan::set_endpoint`
//! reaches the child's proxy variables), and deriving this launch's
//! [`aa_isolation::TransactionId`] from `RegistrationHandle::session_id` —
//! this module never invents an id of its own.
use std::path::{Path, PathBuf};

use aa_isolation::{CommitOutcome, TransactionId};
use aa_workspace_tx::WorkspaceTransaction;

use super::execution_receipt::schema::NOT_TRANSACTIONAL;
use super::execution_receipt::store::state_base;
use super::run::RunArgs;

/// One launch's resolved `--workspace-tx` configuration, or nothing when the
/// flag was not passed.
pub(crate) struct WorkspaceTxPlan {
    pub(crate) base_root: PathBuf,
    pub(crate) exclusions: Vec<String>,
    pub(crate) protected: Vec<String>,
    pub(crate) approved: bool,
}

/// `$AASM_STATE_DIR/workspace-tx`, or `~/.aasm/workspace-tx` — a sibling of
/// the execution-receipt store's own state root (see [`state_base`]), never
/// nested under it and never sharing a file with it.
pub(crate) fn state_root() -> anyhow::Result<PathBuf> {
    Ok(state_base()
        .map_err(|e| anyhow::anyhow!("could not resolve the workspace-transaction state root: {e}"))?
        .join("workspace-tx"))
}

/// Resolve `args` into a [`WorkspaceTxPlan`], or `None` when `--workspace-tx`
/// was not passed.
///
/// Every precondition below fails closed with a message naming the
/// offending path, and every one of them runs before anything is
/// registered, materialized or copied — matching the ordering
/// `RunPlanner::resolve` already holds its own stage 0 (`--workdir`) to.
pub(crate) fn resolve(args: &RunArgs) -> Option<Result<WorkspaceTxPlan, String>> {
    if !args.workspace_tx {
        return None;
    }

    let base_root = match &args.workdir {
        Some(dir) => dir.clone(),
        None => match std::env::current_dir() {
            Ok(dir) => dir,
            Err(e) => {
                return Some(Err(format!(
                    "--workspace-tx could not resolve the current directory: {e}"
                )))
            }
        },
    };

    if !base_root.is_dir() {
        return Some(Err(format!(
            "--workspace-tx's base directory {} is not a directory on this host",
            base_root.display()
        )));
    }

    let state_root = match state_root() {
        Ok(root) => root,
        Err(e) => return Some(Err(e.to_string())),
    };

    if let Some(reason) = nesting_refusal(&state_root, &base_root) {
        return Some(Err(reason));
    }

    if let Some(reason) = exact_root_or_home_refusal(&base_root) {
        return Some(Err(reason));
    }

    let exclusions = args
        .workspace_tx_exclude
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();

    Some(Ok(WorkspaceTxPlan {
        base_root,
        exclusions,
        protected: args.workspace_tx_protect.clone(),
        approved: args.workspace_tx_approve,
    }))
}

/// Refuse when the transaction state root and the base directory nest
/// inside one another — the staged copy must never land inside the surface
/// it is staging, and the surface must never land inside the state root
/// either.
fn nesting_refusal(state_root: &Path, base_root: &Path) -> Option<String> {
    let canon_state = state_root.canonicalize().unwrap_or_else(|_| state_root.to_path_buf());
    let canon_base = base_root.canonicalize().unwrap_or_else(|_| base_root.to_path_buf());
    if canon_base.starts_with(&canon_state) || canon_state.starts_with(&canon_base) {
        return Some(format!(
            "--workspace-tx refuses: the transaction state root {} and the base directory {} nest inside one \
             another. A staged copy inside its own surface (or the surface inside the state root) would put \
             transaction bookkeeping inside the tree being staged, or vice versa.",
            state_root.display(),
            base_root.display()
        ));
    }
    None
}

/// Refuse when the base directory is exactly the filesystem root or exactly
/// the operator's home directory — a narrow, exact-path check (never an
/// ancestor walk), matching a launch under any *other* directory,
/// deliberately.
fn exact_root_or_home_refusal(base_root: &Path) -> Option<String> {
    let canon_base = base_root.canonicalize().unwrap_or_else(|_| base_root.to_path_buf());
    if canon_base == Path::new("/") {
        return Some("--workspace-tx refuses to materialize a transaction over the filesystem root `/`".to_string());
    }
    if let Some(home) = dirs::home_dir() {
        let canon_home = home.canonicalize().unwrap_or(home);
        if canon_base == canon_home {
            return Some(format!(
                "--workspace-tx refuses to materialize a transaction over the home directory {}",
                canon_base.display()
            ));
        }
    }
    None
}

/// An open `aa_workspace_tx::WorkspaceTransaction`, discarded on `Drop`
/// unless [`settle`] has already taken it.
///
/// Every refusal path between opening the transaction and reaching
/// [`settle`] — a boundary refusal, an adapter error, a registration
/// failure — drops this guard instead, which is exactly the fail-closed
/// behaviour AC 4 requires: no staged tree and no base modification survive
/// a launch that never got as far as running.
pub(crate) struct WorkspaceTxGuard(Option<WorkspaceTransaction>);

impl WorkspaceTxGuard {
    /// Open a transaction over `plan`'s declared surface, named `id`.
    pub(crate) fn open(id: TransactionId, plan: &WorkspaceTxPlan) -> anyhow::Result<Self> {
        let root = state_root()?;
        let tx = WorkspaceTransaction::open(id, &root, &plan.base_root, plan.exclusions.clone())
            .map_err(|e| anyhow::anyhow!("--workspace-tx could not open a transaction: {e}"))?;
        Ok(Self(Some(tx)))
    }

    /// The staged workspace a confined process should be given as its
    /// working directory — `None` only if [`settle`] already consumed this
    /// guard, which never happens before `bind`.
    pub(crate) fn staged_dir(&self) -> Option<&Path> {
        self.0.as_ref().map(WorkspaceTransaction::staged_dir)
    }
}

impl Drop for WorkspaceTxGuard {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.discard();
        }
    }
}

/// Everything the receipt binding and the stderr block both read about one
/// settled transaction.
///
/// `pub`, not `pub(crate)`: [`execution_receipt::ReceiptContext`] — which
/// crosses the crate boundary into this crate's own `tests/` integration
/// suite — carries an `Option<&WorkspaceOutcome>` field, so the type must be
/// nameable from outside this crate even though every constructor here
/// stays `pub(crate)`.
pub struct WorkspaceOutcome {
    pub(crate) id: String,
    pub(crate) base_digest_hex: String,
    pub(crate) result_digest_hex: Option<String>,
    pub(crate) added: usize,
    pub(crate) modified: usize,
    pub(crate) deleted: usize,
    /// `(verb, path)` for every entry actually applied, sorted — the exact
    /// set a receipt's `diff_digest` is taken over (AAASM-6162). Empty
    /// unless the commit succeeded: a discarded or refused transaction's
    /// change set never reaches a receipt as anything but counts.
    pub(crate) sorted_changes: Vec<(&'static str, String)>,
    pub(crate) committed: bool,
    pub(crate) refusal_kind: Option<&'static str>,
    pub(crate) surface_entry_count: usize,
    pub(crate) surface_excluded_count: usize,
    pub(crate) protected_selector_count: usize,
    pub(crate) approval_presented: bool,
}

/// Decide and execute a transaction's fate: `close()` it, then commit when
/// the child exited `0` and discard otherwise. Removes the transaction's
/// private state directory on `Committed` or `Discarded`; keeps it on a
/// refusal so the refused change set stays inspectable.
///
/// The exit-code rule is the entire disposition contract: there is no
/// separate `--workspace-tx-commit` mode to get out of sync with it.
pub(crate) fn settle(guard: &mut WorkspaceTxGuard, exit_code: Option<i32>, plan: &WorkspaceTxPlan) -> WorkspaceOutcome {
    let surface_excluded_count = plan.exclusions.len();
    let protected_selector_count = plan.protected.len();
    let approval_presented = plan.approved;

    let Some(mut tx) = guard.0.take() else {
        return WorkspaceOutcome {
            id: String::new(),
            base_digest_hex: String::new(),
            result_digest_hex: None,
            added: 0,
            modified: 0,
            deleted: 0,
            sorted_changes: Vec::new(),
            committed: false,
            refusal_kind: None,
            surface_entry_count: 0,
            surface_excluded_count,
            protected_selector_count,
            approval_presented,
        };
    };

    tx.close();
    let id = tx.id().as_str().to_string();
    let surface_entry_count = tx.base_manifest().entries().len();
    let state_dir_root = state_root().ok().map(|root| root.join(&id));

    if exit_code == Some(0) {
        match tx.commit(&plan.protected, plan.approved) {
            Ok(outcome) => {
                if let Some(root) = &state_dir_root {
                    let _ = std::fs::remove_dir_all(root);
                }
                from_commit_outcome(
                    id,
                    &outcome,
                    surface_entry_count,
                    surface_excluded_count,
                    protected_selector_count,
                    approval_presented,
                )
            }
            Err(refusal) => WorkspaceOutcome {
                id,
                base_digest_hex: String::new(),
                result_digest_hex: None,
                added: 0,
                modified: 0,
                deleted: 0,
                sorted_changes: Vec::new(),
                committed: false,
                refusal_kind: Some(refusal.kind_str()),
                surface_entry_count,
                surface_excluded_count,
                protected_selector_count,
                approval_presented,
            },
        }
    } else {
        let _ = tx.discard();
        if let Some(root) = &state_dir_root {
            let _ = std::fs::remove_dir_all(root);
        }
        WorkspaceOutcome {
            id,
            base_digest_hex: String::new(),
            result_digest_hex: None,
            added: 0,
            modified: 0,
            deleted: 0,
            sorted_changes: Vec::new(),
            committed: false,
            refusal_kind: None,
            surface_entry_count,
            surface_excluded_count,
            protected_selector_count,
            approval_presented,
        }
    }
}

fn from_commit_outcome(
    id: String,
    outcome: &CommitOutcome,
    surface_entry_count: usize,
    surface_excluded_count: usize,
    protected_selector_count: usize,
    approval_presented: bool,
) -> WorkspaceOutcome {
    let mut added = 0usize;
    let mut modified = 0usize;
    let mut deleted = 0usize;
    let mut sorted_changes: Vec<(&'static str, String)> = Vec::new();
    for entry in outcome.applied().entries() {
        match entry {
            aa_isolation::ChangeEntry::Added { path } => {
                added += 1;
                sorted_changes.push(("added", path.clone()));
            }
            aa_isolation::ChangeEntry::Modified { path } => {
                modified += 1;
                sorted_changes.push(("modified", path.clone()));
            }
            aa_isolation::ChangeEntry::Deleted { path } => {
                deleted += 1;
                sorted_changes.push(("deleted", path.clone()));
            }
            _ => {}
        }
    }
    sorted_changes.sort();
    WorkspaceOutcome {
        id,
        base_digest_hex: outcome.base_digest().as_str().to_string(),
        result_digest_hex: Some(outcome.result_digest().as_str().to_string()),
        added,
        modified,
        deleted,
        sorted_changes,
        committed: true,
        refusal_kind: None,
        surface_entry_count,
        surface_excluded_count,
        protected_selector_count,
        approval_presented,
    }
}

/// The `workspace_tx.*` stderr block — the only surface a `--workspace-tx`
/// run's truth appears on when no execution boundary ran (the unconfined
/// `--isolation none` path writes no receipt at all). Mirrors
/// `run::isolation_machine_block`'s `key=value` style.
pub(crate) fn machine_block(outcome: &WorkspaceOutcome) -> String {
    let mut out = String::new();
    out.push_str(&format!("workspace_tx.id={}\n", outcome.id));
    out.push_str(&format!("workspace_tx.committed={}\n", outcome.committed));
    out.push_str(&format!("workspace_tx.base_digest={}\n", outcome.base_digest_hex));
    out.push_str(&format!(
        "workspace_tx.result_digest={}\n",
        outcome.result_digest_hex.as_deref().unwrap_or("none")
    ));
    if let Some(kind) = outcome.refusal_kind {
        out.push_str(&format!("workspace_tx.refusal={kind}\n"));
    }
    out.push_str(&format!("workspace_tx.added={}\n", outcome.added));
    out.push_str(&format!("workspace_tx.modified={}\n", outcome.modified));
    out.push_str(&format!("workspace_tx.deleted={}\n", outcome.deleted));
    out.push_str(&format!(
        "workspace_tx.surface_entries={}\n",
        outcome.surface_entry_count
    ));
    out.push_str(&format!(
        "workspace_tx.surface_excluded={}\n",
        outcome.surface_excluded_count
    ));
    out.push_str(&format!(
        "workspace_tx.protected_selectors={}\n",
        outcome.protected_selector_count
    ));
    out.push_str(&format!(
        "workspace_tx.approval_presented={}\n",
        outcome.approval_presented
    ));
    out.push_str(&format!(
        "workspace_tx.not_transactional={}\n",
        NOT_TRANSACTIONAL.join(",")
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        run: RunArgs,
    }

    fn parse(argv: &[&str]) -> RunArgs {
        let mut full = vec!["aasm"];
        full.extend_from_slice(argv);
        TestCli::try_parse_from(full).expect("parse").run
    }

    #[test]
    fn absent_flag_resolves_to_none() {
        let args = parse(&["claude"]);
        assert!(resolve(&args).is_none());
    }

    #[test]
    fn a_base_root_nested_inside_the_state_root_refuses() {
        let state = tempfile::tempdir().unwrap();
        let nested = state.path().join("project");
        std::fs::create_dir(&nested).unwrap();
        let reason = nesting_refusal(state.path(), &nested);
        assert!(reason.is_some(), "a base root inside the state root must refuse");
    }

    #[test]
    fn the_exact_filesystem_root_refuses() {
        assert!(exact_root_or_home_refusal(Path::new("/")).is_some());
    }

    #[test]
    fn the_exact_home_directory_refuses() {
        if let Some(home) = dirs::home_dir() {
            assert!(exact_root_or_home_refusal(&home).is_some());
        }
    }

    #[test]
    fn an_ordinary_project_directory_does_not_refuse() {
        let dir = tempfile::tempdir().unwrap();
        assert!(exact_root_or_home_refusal(dir.path()).is_none());
    }

    #[test]
    fn settle_on_an_already_taken_guard_returns_an_empty_outcome() {
        let mut guard = WorkspaceTxGuard(None);
        let plan = WorkspaceTxPlan {
            base_root: PathBuf::from("/tmp"),
            exclusions: vec![],
            protected: vec![],
            approved: false,
        };
        let outcome = settle(&mut guard, Some(0), &plan);
        assert!(!outcome.committed);
        assert!(outcome.refusal_kind.is_none());
    }

    #[test]
    fn machine_block_names_every_not_transactional_token() {
        let outcome = WorkspaceOutcome {
            id: "tx-1".to_string(),
            base_digest_hex: "deadbeef".to_string(),
            result_digest_hex: Some("beefdead".to_string()),
            added: 1,
            modified: 2,
            deleted: 3,
            sorted_changes: Vec::new(),
            committed: true,
            refusal_kind: None,
            surface_entry_count: 10,
            surface_excluded_count: 1,
            protected_selector_count: 0,
            approval_presented: false,
        };
        let block = machine_block(&outcome);
        for token in NOT_TRANSACTIONAL {
            assert!(
                block.contains(token),
                "machine_block is missing the non-transactional token `{token}`: {block}"
            );
        }
        assert!(block.contains("workspace_tx.committed=true"));
    }

    #[test]
    fn a_full_open_close_commit_cycle_reports_the_real_change_set() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("keep.txt"), b"original").unwrap();
        let state = tempfile::tempdir().unwrap();

        let plan = WorkspaceTxPlan {
            base_root: base.path().to_path_buf(),
            exclusions: vec![],
            protected: vec![],
            approved: false,
        };
        let tx = WorkspaceTransaction::open(TransactionId::new("tx-cycle"), state.path(), &plan.base_root, vec![])
            .expect("open");
        let mut guard = WorkspaceTxGuard(Some(tx));

        std::fs::write(guard.staged_dir().unwrap().join("new.txt"), b"added").unwrap();
        std::fs::remove_file(guard.staged_dir().unwrap().join("keep.txt")).unwrap();

        let outcome = settle(&mut guard, Some(0), &plan);
        assert!(outcome.committed);
        assert_eq!(outcome.added, 1);
        assert_eq!(outcome.deleted, 1);
        assert!(base.path().join("new.txt").exists());
        assert!(!base.path().join("keep.txt").exists());
    }

    #[test]
    fn a_nonzero_exit_discards_and_leaves_the_base_untouched() {
        let base = tempfile::tempdir().unwrap();
        std::fs::write(base.path().join("keep.txt"), b"original").unwrap();
        let state = tempfile::tempdir().unwrap();

        let plan = WorkspaceTxPlan {
            base_root: base.path().to_path_buf(),
            exclusions: vec![],
            protected: vec![],
            approved: false,
        };
        let tx = WorkspaceTransaction::open(TransactionId::new("tx-discard"), state.path(), &plan.base_root, vec![])
            .expect("open");
        let mut guard = WorkspaceTxGuard(Some(tx));
        std::fs::write(guard.staged_dir().unwrap().join("new.txt"), b"added").unwrap();

        let outcome = settle(&mut guard, Some(1), &plan);
        assert!(!outcome.committed);
        assert!(!base.path().join("new.txt").exists());
        assert_eq!(std::fs::read(base.path().join("keep.txt")).unwrap(), b"original");
    }
}
