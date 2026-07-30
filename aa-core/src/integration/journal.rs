//! The write-ahead record that makes an interrupted apply or remove a *state*
//! rather than an accident.
//!
//! # A partially-applied plan is normal
//!
//! Applying an integration writes several files. A laptop lid closes, a process
//! is killed, a disk fills. The lifecycle already has a resting state for it —
//! [`PartiallyIntegrated`](super::ProtectionLevel::PartiallyIntegrated) — but a
//! resting state is only recoverable if something recorded *which* steps got as
//! far as running. That record is this journal, and it is written **before** the
//! first mutation, not after.
//!
//! # The ordering that makes recovery decidable
//!
//! Apply runs: write journal → mutate, marking each step as it completes → write
//! receipt → delete journal.
//! Remove runs: write journal → reverse each step, marking as it completes →
//! delete receipt → delete journal.
//!
//! Two facts — is there a journal, is there a receipt — therefore determine the
//! recovery action uniquely, with no guessing and no timestamps:
//!
//! | Journal | Receipt | What happened | [`RecoveryAction`] |
//! | --- | --- | --- | --- |
//! | none | any | nothing was in flight | [`Nothing`](RecoveryAction::Nothing) |
//! | `Apply` | absent | crashed mid-apply | [`RollBackInterruptedApply`](RecoveryAction::RollBackInterruptedApply) |
//! | `Apply` | present | crashed after the receipt was written | [`ClearStaleJournal`](RecoveryAction::ClearStaleJournal) |
//! | `Remove` | present | crashed mid-remove | [`ResumeInterruptedRemove`](RecoveryAction::ResumeInterruptedRemove) |
//! | `Remove` | absent | crashed after the receipt was deleted | [`ClearStaleJournal`](RecoveryAction::ClearStaleJournal) |
//!
//! # Why apply rolls back and remove resumes
//!
//! They are not symmetric, and the asymmetry is deliberate. An interrupted apply
//! produced no receipt, so nothing can claim protection from it and the
//! half-written state is *pure liability*: rolling it back returns the developer
//! to exactly where they started, and re-running apply is a plan-time decision
//! they can review again. An interrupted **remove**, by contrast, has already
//! begun taking AASM's changes out; stopping half-way would leave AASM-owned
//! artifacts on a host whose owner asked for them to be gone. Finishing is the
//! only direction that honours the request, and it is safe to repeat because
//! every reversal is idempotent — deleting an already-deleted artifact and
//! restoring an already-restored key are both no-ops.

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::step::SettingsScope;
use super::version::LIFECYCLE_SCHEMA_VERSION;
use crate::dev_tool::DevToolKind;

/// Which direction the interrupted operation was going.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum JournalOperation {
    /// Steps were being applied.
    Apply,
    /// Steps were being reversed.
    Remove,
}

/// How far one step got.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum StepProgress {
    /// Not started, or started and not recorded — indistinguishable on purpose,
    /// which is why every reversal must be idempotent.
    Pending,
    /// The mutation completed.
    Applied,
    /// The mutation was attempted and failed.
    Failed {
        /// Why, for the user and for the audit trail.
        reason: String,
    },
    /// The mutation was undone.
    Reversed,
}

/// One step's line in the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct JournalEntry {
    /// The [`IntegrationStep::id`](super::IntegrationStep::id) this line is
    /// about.
    pub step_id: String,
    /// How far it got.
    pub progress: StepProgress,
}

/// The write-ahead record of an operation in flight.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OperationJournal {
    /// The [`LIFECYCLE_SCHEMA_VERSION`] the writing core used.
    pub schema_version: u32,
    /// Which direction the operation was going.
    pub operation: JournalOperation,
    /// The plan or receipt the operation is executing.
    pub plan_id: String,
    /// The tool being operated on.
    pub tool: DevToolKind,
    /// Which configuration surface the operation targets. Recorded so recovery
    /// resumes against the file the operation actually chose, not the one the
    /// recovering process's working directory would suggest.
    pub settings_scope: SettingsScope,
    /// When the operation started, as seconds since the Unix epoch.
    pub started_at_unix_secs: u64,
    /// One line per step, in execution order.
    pub entries: Vec<JournalEntry>,
}

impl OperationJournal {
    /// Open a journal for `step_ids`, all [`Pending`](StepProgress::Pending).
    pub fn starting(
        operation: JournalOperation,
        plan_id: impl Into<String>,
        tool: DevToolKind,
        settings_scope: SettingsScope,
        started_at_unix_secs: u64,
        step_ids: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            operation,
            plan_id: plan_id.into(),
            tool,
            settings_scope,
            started_at_unix_secs,
            entries: step_ids
                .into_iter()
                .map(|step_id| JournalEntry {
                    step_id,
                    progress: StepProgress::Pending,
                })
                .collect(),
        }
    }

    /// Record how far `step_id` got. Unknown ids are appended rather than
    /// dropped — a step the journal did not anticipate still happened.
    pub fn mark(&mut self, step_id: &str, progress: StepProgress) {
        match self.entries.iter_mut().find(|e| e.step_id == step_id) {
            Some(entry) => entry.progress = progress,
            None => self.entries.push(JournalEntry {
                step_id: step_id.to_string(),
                progress,
            }),
        }
    }

    /// Steps whose mutation completed, in execution order.
    pub fn applied_step_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.progress == StepProgress::Applied)
            .map(|e| e.step_id.clone())
            .collect()
    }

    /// Steps a removal has not yet recorded as reversed, in execution order.
    ///
    /// Includes [`Pending`](StepProgress::Pending) and
    /// [`Failed`](StepProgress::Failed) lines: a reversal that failed once is
    /// retried, because leaving an AASM artifact behind after the user asked for
    /// removal is the worse outcome.
    pub fn unreversed_step_ids(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter(|e| e.progress != StepProgress::Reversed)
            .map(|e| e.step_id.clone())
            .collect()
    }

    /// Whether any step is recorded as having failed.
    pub fn has_failures(&self) -> bool {
        self.entries
            .iter()
            .any(|e| matches!(e.progress, StepProgress::Failed { .. }))
    }

    /// Whether this journal was written by a core newer than the one reading it.
    ///
    /// Recovery refuses to act on one: replaying steps whose semantics this
    /// build may not share is exactly the guess the lifecycle model forbids.
    pub fn is_schema_newer_than_running_core(&self) -> bool {
        self.schema_version > LIFECYCLE_SCHEMA_VERSION
    }
}

/// What a recovering process must do, decided from the journal and the presence
/// of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[non_exhaustive]
pub enum RecoveryAction {
    /// Nothing was in flight.
    Nothing,
    /// An apply was interrupted before its receipt was written. Reverse these
    /// step ids in reverse execution order, then delete the journal.
    RollBackInterruptedApply {
        /// The steps the journal recorded as applied.
        step_ids: Vec<String>,
    },
    /// A remove was interrupted. Reverse these step ids, then delete the receipt
    /// and the journal.
    ResumeInterruptedRemove {
        /// The steps not yet recorded as reversed.
        step_ids: Vec<String>,
    },
    /// The operation completed; only the journal outlived it. Delete it.
    ClearStaleJournal,
    /// The journal cannot be acted on and needs a human.
    ///
    /// Recovery is the one place where doing *something* is more dangerous than
    /// doing nothing, so an unreadable journal stops here instead of guessing.
    Escalate {
        /// What is wrong, in words a user can act on.
        reason: String,
    },
}

/// Decide the recovery action from the two facts that determine it.
///
/// See the module docs for the table this implements and why apply and remove
/// recover in opposite directions.
pub fn recovery_action(journal: Option<&OperationJournal>, receipt_present: bool) -> RecoveryAction {
    let Some(journal) = journal else {
        return RecoveryAction::Nothing;
    };

    if journal.is_schema_newer_than_running_core() {
        return RecoveryAction::Escalate {
            reason: "an interrupted operation was recorded by a newer Agent Assembly release than the one \
                     running; upgrade Agent Assembly and retry"
                .to_string(),
        };
    }

    match (journal.operation, receipt_present) {
        (JournalOperation::Apply, false) => {
            let step_ids = journal.applied_step_ids();
            if step_ids.is_empty() {
                // Nothing got as far as mutating anything.
                RecoveryAction::ClearStaleJournal
            } else {
                RecoveryAction::RollBackInterruptedApply { step_ids }
            }
        }
        (JournalOperation::Apply, true) => RecoveryAction::ClearStaleJournal,
        (JournalOperation::Remove, true) => {
            let step_ids = journal.unreversed_step_ids();
            if step_ids.is_empty() {
                RecoveryAction::ClearStaleJournal
            } else {
                RecoveryAction::ResumeInterruptedRemove { step_ids }
            }
        }
        (JournalOperation::Remove, false) => RecoveryAction::ClearStaleJournal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn journal(operation: JournalOperation) -> OperationJournal {
        OperationJournal::starting(
            operation,
            "p1",
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000_000,
            ["settings".to_string(), "ca".to_string(), "env".to_string()],
        )
    }

    #[test]
    fn no_journal_means_nothing_to_recover() {
        assert_eq!(recovery_action(None, true), RecoveryAction::Nothing);
        assert_eq!(recovery_action(None, false), RecoveryAction::Nothing);
    }

    #[test]
    fn an_interrupted_apply_rolls_back_exactly_what_it_applied() {
        let mut j = journal(JournalOperation::Apply);
        j.mark("settings", StepProgress::Applied);
        j.mark("ca", StepProgress::Applied);
        // `env` never ran.

        assert_eq!(
            recovery_action(Some(&j), false),
            RecoveryAction::RollBackInterruptedApply {
                step_ids: vec!["settings".to_string(), "ca".to_string()],
            },
            "a step that never ran must not be reversed"
        );
    }

    #[test]
    fn an_apply_that_wrote_its_receipt_completed() {
        let mut j = journal(JournalOperation::Apply);
        j.mark("settings", StepProgress::Applied);
        assert_eq!(recovery_action(Some(&j), true), RecoveryAction::ClearStaleJournal);
    }

    #[test]
    fn an_apply_that_mutated_nothing_needs_no_rollback() {
        let j = journal(JournalOperation::Apply);
        assert_eq!(recovery_action(Some(&j), false), RecoveryAction::ClearStaleJournal);
    }

    #[test]
    fn an_interrupted_remove_finishes_rather_than_reverting() {
        let mut j = journal(JournalOperation::Remove);
        j.mark("env", StepProgress::Reversed);
        j.mark(
            "ca",
            StepProgress::Failed {
                reason: "the file was locked".to_string(),
            },
        );

        assert_eq!(
            recovery_action(Some(&j), true),
            RecoveryAction::ResumeInterruptedRemove {
                step_ids: vec!["settings".to_string(), "ca".to_string()],
            },
            "a failed reversal is retried; leaving an AASM artifact behind is the worse outcome"
        );
        assert!(j.has_failures());
    }

    #[test]
    fn a_remove_that_deleted_its_receipt_completed() {
        let mut j = journal(JournalOperation::Remove);
        j.mark("settings", StepProgress::Reversed);
        assert_eq!(recovery_action(Some(&j), false), RecoveryAction::ClearStaleJournal);
    }

    #[test]
    fn recovery_is_idempotent_across_repeated_runs() {
        // Running recovery twice must ask for the same thing, because the second
        // run cannot know the first one finished.
        let mut j = journal(JournalOperation::Apply);
        j.mark("settings", StepProgress::Applied);
        let first = recovery_action(Some(&j), false);
        let second = recovery_action(Some(&j), false);
        assert_eq!(first, second);
    }

    #[test]
    fn a_journal_from_a_newer_core_escalates_instead_of_replaying() {
        let mut j = journal(JournalOperation::Apply);
        j.schema_version = LIFECYCLE_SCHEMA_VERSION + 1;
        j.mark("settings", StepProgress::Applied);
        assert!(matches!(
            recovery_action(Some(&j), false),
            RecoveryAction::Escalate { .. }
        ));
    }

    #[test]
    fn marking_an_unanticipated_step_records_it_rather_than_dropping_it() {
        let mut j = journal(JournalOperation::Apply);
        j.mark("surprise", StepProgress::Applied);
        assert_eq!(j.applied_step_ids(), vec!["surprise".to_string()]);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn journals_round_trip_through_json() {
        let mut j = journal(JournalOperation::Apply);
        j.mark("settings", StepProgress::Applied);
        let json = serde_json::to_string(&j).unwrap();
        assert_eq!(serde_json::from_str::<OperationJournal>(&json).unwrap(), j);
    }
}
