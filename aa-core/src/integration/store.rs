//! Where receipts and journals live on disk, and the permissions they are held
//! to.
//!
//! # Why not inside the tool's own configuration tree
//!
//! The AAASM-5276 spike scaffolding deliberately did not store receipts under
//! the tool's config directory, and this module keeps that decision for three
//! reasons that are each sufficient on their own:
//!
//! 1. **The receipt is evidence about the tool, not configuration of it.** A
//!    file inside `~/.claude/` is something the tool may read, rewrite,
//!    reformat, or sync to a vendor's cloud. A record whose whole job is to say
//!    what the tool's directory *should* contain cannot itself be one of the
//!    things being described.
//! 2. **Removal has to be able to empty the tool's directory.** If the receipt
//!    lived there, removing an integration would have to either delete its own
//!    evidence mid-operation or leave an AASM file behind in a directory it just
//!    promised to clean.
//! 3. **One tool per directory, many tools per developer.** Status across every
//!    integrated tool is a single directory read here, rather than a walk of
//!    every tool's private layout.
//!
//! Receipts therefore live under `${AASM_STATE_DIR:-~/.aasm}/integrations/`,
//! the state directory the installer, the PID file and the uninstaller already
//! use (`scripts/install-cli.sh`, `aa-cli/src/commands/pidfile.rs`).
//!
//! # Permissions, asserted on load and not only at creation
//!
//! A receipt names every file AASM governs on this host, which mechanism it
//! relies on, and where the trust material sits — a useful map for anyone
//! planning to defeat the integration. The directory is `0700` and each file is
//! `0600`, matching `aa-runtime/src/ipc/server.rs:83` and
//! `aa-proxy/src/tls/ca.rs:108-123`. As in the CA loader, the mode is
//! **re-asserted on every load**: a file created by an older build, restored
//! from a backup, or copied in with loose permissions must not stay
//! group-readable across a restart, and creation-time enforcement alone cannot
//! prevent that.
//!
//! # Integrity is corruption detection, not tamper prevention
//!
//! The envelope carries a hash over the canonical receipt. It catches truncated
//! writes, partial syncs and hand-edits, and it makes a corrupt receipt
//! *reportable* as [`DriftKind::ReceiptCorrupt`](super::DriftKind::ReceiptCorrupt)
//! rather than silently misread. It is **not** a MAC and does not pretend to be:
//! an attacker with the developer's UID can recompute it, and host-level tamper
//! prevention is an explicit non-goal (ADR 0030 accepted risks). What it does
//! guarantee is that a receipt that does not verify is never acted on.

use std::path::{Path, PathBuf};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use super::fingerprint::fingerprint_raw;
use super::journal::OperationJournal;
use super::receipt::IntegrationReceipt;
use super::state::ProtectionLevel;
use super::step::SettingsScope;
use crate::dev_tool::DevToolKind;

/// Schema version of the on-disk envelope, which advances independently of
/// [`LIFECYCLE_SCHEMA_VERSION`](super::LIFECYCLE_SCHEMA_VERSION): the way a
/// receipt is *stored* can change
/// without the receipt's own shape changing, and conflating the two would force
/// a lifecycle bump for a storage-layout fix.
pub const RECEIPT_ENVELOPE_VERSION: u32 = 1;

/// How many superseded receipts an envelope keeps.
///
/// Bounded because the upgrade history is for explaining *this* integration's
/// provenance, not for being an audit log — that is `aa-core::audit`'s job, and
/// an unbounded list would grow a file that must stay readable at every start.
pub const MAX_SUPERSEDED_RECEIPTS: usize = 8;

/// Why a receipt or journal could not be read or written.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The filesystem refused.
    #[error("integration state at {path} could not be accessed: {source}")]
    Io {
        /// What was being accessed.
        path: PathBuf,
        /// The underlying error.
        #[source]
        source: std::io::Error,
    },
    /// The file is not the JSON this store writes.
    #[error("the stored integration state at {path} is unreadable: {detail}")]
    Corrupt {
        /// What was being read.
        path: PathBuf,
        /// Why it could not be read, without echoing the file's contents.
        detail: String,
    },
    /// The envelope's hash does not cover what the file now contains.
    #[error("the receipt at {path} failed its integrity check and will not be used")]
    IntegrityMismatch {
        /// What was being read.
        path: PathBuf,
    },
    /// The envelope was written by a newer core.
    #[error("the receipt at {path} was written by a newer Agent Assembly release (envelope v{found}, this build reads v{readable})")]
    EnvelopeTooNew {
        /// What was being read.
        path: PathBuf,
        /// The version found in the file.
        found: u32,
        /// The newest version this build understands.
        readable: u32,
    },
    /// No state directory could be resolved.
    #[error("no Agent Assembly state directory could be resolved; set AASM_STATE_DIR")]
    NoStateDirectory,
}

impl StoreError {
    /// The user-facing reason a drift check should report, or `None` when the
    /// condition is not about the receipt's trustworthiness.
    ///
    /// Feeds [`DriftInputs::receipt_unreadable`](super::DriftInputs::receipt_unreadable),
    /// which is what turns an unreadable receipt into an observable, fail-closed
    /// state instead of an error the caller might treat as "no receipt".
    pub fn as_untrustworthy_receipt_reason(&self) -> Option<String> {
        match self {
            Self::Corrupt { detail, .. } => Some(detail.clone()),
            Self::IntegrityMismatch { .. } => Some("its integrity hash does not match its contents".to_string()),
            Self::EnvelopeTooNew { found, readable, .. } => Some(format!(
                "it uses storage envelope v{found} and this build reads v{readable}"
            )),
            Self::Io { .. } | Self::NoStateDirectory => None,
        }
    }
}

/// The minimum a superseded receipt is remembered by after an upgrade.
///
/// Deliberately not the whole prior receipt: the useful question later is "what
/// was here before, when, and how protected was it", and keeping the full prior
/// step list would retain prior-state snapshots — including displaced settings
/// values — long after anything can restore them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SupersededReceipt {
    /// The receipt that was replaced.
    pub receipt_id: String,
    /// The plan it recorded.
    pub plan_id: String,
    /// When it was applied.
    pub applied_at_unix_secs: u64,
    /// The level it reached.
    pub achieved_level: ProtectionLevel,
    /// The core version that wrote it, so an upgrade path is legible.
    pub core_version: String,
    /// The adapter version that authored its plan.
    pub adapter_version: String,
}

impl SupersededReceipt {
    /// Summarise `receipt` for the upgrade history.
    pub fn of(receipt: &IntegrationReceipt) -> Self {
        Self {
            receipt_id: receipt.receipt_id.clone(),
            plan_id: receipt.plan_id.clone(),
            applied_at_unix_secs: receipt.applied_at_unix_secs,
            achieved_level: receipt.achieved_level,
            core_version: receipt.versions.core.to_string(),
            adapter_version: receipt.versions.adapter.to_string(),
        }
    }
}

/// What one receipt file holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ReceiptEnvelope {
    /// [`RECEIPT_ENVELOPE_VERSION`] the writing core used.
    pub envelope_version: u32,
    /// Hash over the canonical JSON of [`receipt`](Self::receipt).
    pub integrity: String,
    /// The receipt itself.
    pub receipt: IntegrationReceipt,
    /// Receipts this one replaced, newest first, bounded by
    /// [`MAX_SUPERSEDED_RECEIPTS`].
    pub superseded: Vec<SupersededReceipt>,
}

impl ReceiptEnvelope {
    /// Seal `receipt` with its integrity hash and an upgrade history.
    pub fn seal(receipt: IntegrationReceipt, superseded: Vec<SupersededReceipt>) -> Result<Self, StoreError> {
        let integrity = integrity_of(&receipt)?;
        Ok(Self {
            envelope_version: RECEIPT_ENVELOPE_VERSION,
            integrity,
            receipt,
            superseded,
        })
    }

    /// Whether the hash still covers the receipt.
    pub fn integrity_holds(&self) -> bool {
        integrity_of(&self.receipt).is_ok_and(|computed| computed == self.integrity)
    }
}

fn integrity_of(receipt: &IntegrationReceipt) -> Result<String, StoreError> {
    // The receipt derives `Serialize` into `serde_json`'s BTreeMap-backed
    // objects, so this rendering is already key-ordered and stable across runs.
    let canonical = serde_json::to_string(receipt).map_err(|e| StoreError::Corrupt {
        path: PathBuf::new(),
        detail: e.to_string(),
    })?;
    Ok(fingerprint_raw(&canonical))
}

/// A stable, filesystem-safe slug for a tool.
///
/// `Custom` names come from adapters, so every character outside
/// `[a-z0-9._-]` is folded to `_`: a tool name is not allowed to choose which
/// directory its receipt lands in.
fn tool_slug(tool: &DevToolKind) -> String {
    let raw = match tool {
        DevToolKind::ClaudeCode => "claude-code",
        DevToolKind::Codex => "codex",
        DevToolKind::GitHubCopilot => "github-copilot",
        DevToolKind::WindsurfCascade => "windsurf-cascade",
        DevToolKind::Custom(name) => name.as_str(),
    };
    raw.chars()
        .map(|c| {
            let c = c.to_ascii_lowercase();
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Receipts and journals on the local filesystem.
///
/// One store per state directory; one receipt per (tool, settings scope) pair,
/// because the same tool integrated at user scope and at project scope are two
/// integrations with two sets of artifacts.
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    root: PathBuf,
}

impl ReceiptStore {
    /// A store rooted at `root`, which is created on first write.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The default store: `${AASM_STATE_DIR:-~/.aasm}/integrations`.
    pub fn default_location() -> Result<Self, StoreError> {
        let base = match std::env::var_os("AASM_STATE_DIR") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => dirs::home_dir().ok_or(StoreError::NoStateDirectory)?.join(".aasm"),
        };
        Ok(Self::at(base.join("integrations")))
    }

    /// The directory receipts and journals are written to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where this tool's receipt at this scope lives.
    pub fn receipt_path(&self, tool: &DevToolKind, scope: SettingsScope) -> PathBuf {
        self.root.join(format!("{}--{scope}.receipt.json", tool_slug(tool)))
    }

    /// Where this tool's in-flight journal at this scope lives.
    pub fn journal_path(&self, tool: &DevToolKind, scope: SettingsScope) -> PathBuf {
        self.root.join(format!("{}--{scope}.journal.json", tool_slug(tool)))
    }

    /// Whether a receipt exists, without reading or trusting it.
    ///
    /// Recovery needs this rather than a successful load: "a receipt is there"
    /// is what the journal's ordering rule turns on, and a receipt that is
    /// present but corrupt still means the apply reached the point of writing
    /// one.
    pub fn receipt_exists(&self, tool: &DevToolKind, scope: SettingsScope) -> bool {
        self.receipt_path(tool, scope).exists()
    }

    /// Read the stored envelope, verifying its version and integrity.
    ///
    /// `Ok(None)` means no receipt has been written. Every other failure is an
    /// error the caller must fail closed on — a receipt that cannot be trusted
    /// is never reported as an absent one.
    pub fn load_envelope(
        &self,
        tool: &DevToolKind,
        scope: SettingsScope,
    ) -> Result<Option<ReceiptEnvelope>, StoreError> {
        let path = self.receipt_path(tool, scope);
        let Some(raw) = read_secure(&path)? else {
            return Ok(None);
        };

        let envelope: ReceiptEnvelope = serde_json::from_str(&raw).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            detail: e.to_string(),
        })?;

        if envelope.envelope_version > RECEIPT_ENVELOPE_VERSION {
            return Err(StoreError::EnvelopeTooNew {
                path,
                found: envelope.envelope_version,
                readable: RECEIPT_ENVELOPE_VERSION,
            });
        }
        if !envelope.integrity_holds() {
            return Err(StoreError::IntegrityMismatch { path });
        }
        Ok(Some(envelope))
    }

    /// The stored receipt, or `None` when none has been written.
    pub fn load_receipt(
        &self,
        tool: &DevToolKind,
        scope: SettingsScope,
    ) -> Result<Option<IntegrationReceipt>, StoreError> {
        Ok(self.load_envelope(tool, scope)?.map(|e| e.receipt))
    }

    /// Write `receipt`, folding whatever it replaced into the upgrade history.
    ///
    /// A previous receipt that cannot be read is *not* an error here: the new
    /// receipt describes what is on the host now, and refusing to record it
    /// would leave the host mutated with nothing to reverse it. The unreadable
    /// predecessor is dropped from the history rather than guessed at.
    pub fn save_receipt(&self, receipt: &IntegrationReceipt) -> Result<(), StoreError> {
        let scope = receipt.settings_scope;
        let mut superseded = Vec::new();
        if let Ok(Some(existing)) = self.load_envelope(&receipt.tool, scope) {
            if existing.receipt.receipt_id != receipt.receipt_id {
                superseded.push(SupersededReceipt::of(&existing.receipt));
            }
            superseded.extend(existing.superseded);
            superseded.truncate(MAX_SUPERSEDED_RECEIPTS);
        }

        let envelope = ReceiptEnvelope::seal(receipt.clone(), superseded)?;
        let path = self.receipt_path(&receipt.tool, scope);
        let body = serde_json::to_string_pretty(&envelope).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            detail: e.to_string(),
        })?;
        self.write_secure(&path, &body)
    }

    /// Delete the receipt. Deleting one that is not there is a success — remove
    /// has to be safe to run twice.
    pub fn delete_receipt(&self, tool: &DevToolKind, scope: SettingsScope) -> Result<(), StoreError> {
        remove_if_present(&self.receipt_path(tool, scope))
    }

    /// Read the in-flight journal, if there is one.
    pub fn load_journal(
        &self,
        tool: &DevToolKind,
        scope: SettingsScope,
    ) -> Result<Option<OperationJournal>, StoreError> {
        let path = self.journal_path(tool, scope);
        let Some(raw) = read_secure(&path)? else {
            return Ok(None);
        };
        serde_json::from_str(&raw).map(Some).map_err(|e| StoreError::Corrupt {
            path,
            detail: e.to_string(),
        })
    }

    /// Write the journal. Called before the first mutation and after each step.
    pub fn save_journal(&self, journal: &OperationJournal) -> Result<(), StoreError> {
        let path = self.journal_path(&journal.tool, journal.settings_scope);
        let body = serde_json::to_string_pretty(journal).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            detail: e.to_string(),
        })?;
        self.write_secure(&path, &body)
    }

    /// Delete the journal, marking the operation complete.
    pub fn delete_journal(&self, tool: &DevToolKind, scope: SettingsScope) -> Result<(), StoreError> {
        remove_if_present(&self.journal_path(tool, scope))
    }

    /// Write `body` to `path` atomically, owner-only.
    ///
    /// Content goes to a sibling temporary file and is renamed into place, so a
    /// crash mid-write leaves either the old file or the new one — never a
    /// truncated receipt that would then fail its own integrity check and lock
    /// the user out of their own integration.
    fn write_secure(&self, path: &Path, body: &str) -> Result<(), StoreError> {
        std::fs::create_dir_all(&self.root).map_err(|source| StoreError::Io {
            path: self.root.clone(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
                StoreError::Io {
                    path: self.root.clone(),
                    source,
                }
            })?;
        }

        let tmp = path.with_extension("tmp");
        write_owner_only(&tmp, body)?;
        std::fs::rename(&tmp, path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

#[cfg(unix)]
fn write_owner_only(path: &Path, body: &str) -> Result<(), StoreError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

    // `create(true).truncate(true)` rather than `create_new`, because a previous
    // crash may have left the temporary file behind and refusing to overwrite it
    // would wedge every subsequent write.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    file.write_all(body.as_bytes()).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    // An existing file keeps its old mode through `OpenOptions::mode`, which
    // only applies at creation — re-assert it so a loosened temporary file
    // cannot launder permissions into the renamed destination.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, body: &str) -> Result<(), StoreError> {
    // Windows ACL equivalence is a stated reconsideration trigger in ADR 0030
    // and is not assumed here; the file is written without a mode claim rather
    // than with one this platform cannot keep.
    std::fs::write(path, body).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Read `path`, re-asserting owner-only permissions first.
///
/// Returns `Ok(None)` when the file does not exist. The permission re-assertion
/// happens *before* the read for the same reason `aa-proxy`'s CA loader does it:
/// creation-time enforcement says nothing about a file restored from a backup or
/// copied in by hand, and a receipt left group-readable is a map of everything
/// AASM governs on this host.
fn read_secure(path: &Path) -> Result<Option<String>, StoreError> {
    if !path.exists() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|source| StoreError::Io {
                path: path.to_path_buf(),
                source,
            })?
            .permissions()
            .mode()
            & 0o777;
        if mode & 0o077 != 0 {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
                StoreError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
        }
    }
    std::fs::read_to_string(path)
        .map(Some)
        .map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            source,
        })
}

fn remove_if_present(path: &Path) -> Result<(), StoreError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integration::journal::{JournalOperation, StepProgress};
    use crate::integration::plan::ProtectionProfile;
    use crate::integration::receipt::StepReceipt;
    use crate::integration::step::{IntegrationStep, SettingsMerge, StepAction};
    use crate::integration::version::{core_version, ComponentVersions, ToolVersion, LIFECYCLE_SCHEMA_VERSION};
    use std::path::PathBuf;

    fn step() -> IntegrationStep {
        IntegrationStep::new(
            "settings",
            StepAction::WriteManagedSettings {
                scope: SettingsScope::User,
                path: PathBuf::from("/home/dev/.claude/settings.json"),
                managed_keys: vec!["permissions".to_string()],
                content_sha256: "abc".to_string(),
                merge: SettingsMerge::MergeManagedKeys,
                format: crate::integration::step::DocumentFormat::Json,
            },
            "write the managed settings block",
        )
    }

    fn receipt(id: &str) -> IntegrationReceipt {
        IntegrationReceipt {
            schema_version: LIFECYCLE_SCHEMA_VERSION,
            receipt_id: id.to_string(),
            plan_id: format!("plan-{id}"),
            tool: DevToolKind::ClaudeCode,
            profile: ProtectionProfile::Recommended,
            settings_scope: SettingsScope::User,
            applied_at_unix_secs: 1_000_000,
            versions: ComponentVersions {
                core: core_version(),
                adapter: ToolVersion::new(0, 1, 0),
                lifecycle_schema: LIFECYCLE_SCHEMA_VERSION,
            },
            tool_version: Some(ToolVersion::new(2, 1, 220)),
            steps: vec![StepReceipt::applied(&step(), Some("sha256:managed".to_string()))],
            planned_level: ProtectionLevel::Integrated,
            achieved_level: ProtectionLevel::Integrated,
            achieved_evidence: vec![],
            verified_at_unix_secs: Some(1_000_000),
        }
    }

    fn store() -> (tempfile::TempDir, ReceiptStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::at(dir.path().join("integrations"));
        (dir, store)
    }

    #[test]
    fn a_receipt_round_trips_through_the_store() {
        let (_dir, store) = store();
        assert_eq!(
            store
                .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap(),
            None
        );

        let r = receipt("r1");
        store.save_receipt(&r).unwrap();
        assert_eq!(
            store
                .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap(),
            Some(r)
        );
    }

    #[test]
    fn user_and_project_scope_are_separate_integrations() {
        let (_dir, store) = store();
        let user = receipt("r-user");
        let mut project = receipt("r-project");
        project.settings_scope = SettingsScope::Project;

        store.save_receipt(&user).unwrap();
        store.save_receipt(&project).unwrap();

        assert_eq!(
            store
                .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap()
                .unwrap()
                .receipt_id,
            "r-user"
        );
        assert_eq!(
            store
                .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::Project)
                .unwrap()
                .unwrap()
                .receipt_id,
            "r-project"
        );
    }

    #[test]
    fn a_tampered_receipt_fails_closed_rather_than_being_read() {
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();

        let path = store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);
        let raw = std::fs::read_to_string(&path).unwrap();
        // Change the receipt without recomputing the envelope's hash — exactly
        // what a hand-edit or a partial sync produces.
        let tampered = raw.replace(
            "\"achieved_level\": \"Integrated\"",
            "\"achieved_level\": \"HostEnforced\"",
        );
        assert_ne!(tampered, raw, "the fixture must actually have been modified");
        std::fs::write(&path, tampered).unwrap();

        let err = store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .expect_err("a receipt whose hash does not match must not load");
        assert!(matches!(err, StoreError::IntegrityMismatch { .. }), "{err:?}");
        assert!(err.as_untrustworthy_receipt_reason().is_some());
    }

    #[test]
    fn a_truncated_receipt_is_corrupt_not_absent() {
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();
        let path = store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);
        std::fs::write(&path, "{\"envelope_version\": 1, \"integ").unwrap();

        let err = store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .expect_err("a truncated receipt must not read as no receipt");
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err:?}");
        assert!(
            store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User),
            "recovery still needs to know the apply got as far as writing one"
        );
    }

    #[test]
    fn an_envelope_from_a_newer_build_is_refused() {
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();
        let path = store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);
        let raw = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            raw.replace(
                &format!("\"envelope_version\": {RECEIPT_ENVELOPE_VERSION}"),
                &format!("\"envelope_version\": {}", RECEIPT_ENVELOPE_VERSION + 1),
            ),
        )
        .unwrap();

        assert!(matches!(
            store.load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User),
            Err(StoreError::EnvelopeTooNew { .. })
        ));
    }

    #[test]
    fn reinstalling_records_the_receipt_it_replaced() {
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();
        store.save_receipt(&receipt("r2")).unwrap();

        let envelope = store
            .load_envelope(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(envelope.receipt.receipt_id, "r2");
        assert_eq!(envelope.superseded.len(), 1);
        assert_eq!(envelope.superseded[0].receipt_id, "r1");

        // Saving the same receipt again is not an upgrade and must not grow the
        // history — reapply is idempotent all the way down to the store.
        store.save_receipt(&receipt("r2")).unwrap();
        let envelope = store
            .load_envelope(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(envelope.superseded.len(), 1);
    }

    #[test]
    fn the_upgrade_history_is_bounded() {
        let (_dir, store) = store();
        for i in 0..(MAX_SUPERSEDED_RECEIPTS + 5) {
            store.save_receipt(&receipt(&format!("r{i}"))).unwrap();
        }
        let envelope = store
            .load_envelope(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(envelope.superseded.len(), MAX_SUPERSEDED_RECEIPTS);
    }

    #[test]
    fn deleting_a_receipt_twice_succeeds() {
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();
        store
            .delete_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap();
        store
            .delete_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap();
        assert!(!store.receipt_exists(&DevToolKind::ClaudeCode, SettingsScope::User));
    }

    #[test]
    fn journals_round_trip_and_delete() {
        let (_dir, store) = store();
        let mut journal = OperationJournal::starting(
            JournalOperation::Apply,
            "p1",
            DevToolKind::ClaudeCode,
            SettingsScope::User,
            1_000_000,
            ["settings".to_string()],
        );
        journal.mark("settings", StepProgress::Applied);
        store.save_journal(&journal).unwrap();
        assert_eq!(
            store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap(),
            Some(journal)
        );

        store
            .delete_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap();
        assert_eq!(
            store
                .load_journal(&DevToolKind::ClaudeCode, SettingsScope::User)
                .unwrap(),
            None
        );
    }

    #[cfg(unix)]
    #[test]
    fn receipts_are_owner_only_at_rest() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();

        let path = store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "a receipt names every file AASM governs on this host"
        );
        assert_eq!(
            std::fs::metadata(store.root()).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_re_asserted_on_load_not_only_at_creation() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, store) = store();
        store.save_receipt(&receipt("r1")).unwrap();
        let path = store.receipt_path(&DevToolKind::ClaudeCode, SettingsScope::User);

        // Simulate a receipt restored from a backup or copied in by hand.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        store
            .load_receipt(&DevToolKind::ClaudeCode, SettingsScope::User)
            .unwrap()
            .unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600,
            "creation-time enforcement alone cannot keep a restored file owner-only"
        );
    }

    #[test]
    fn a_custom_tool_name_cannot_choose_its_own_path() {
        let (_dir, store) = store();
        let path = store.receipt_path(
            &DevToolKind::Custom("../../etc/Evil Tool".to_string()),
            SettingsScope::User,
        );
        assert_eq!(path.parent(), Some(store.root()));
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            ".._.._etc_evil_tool--user.receipt.json"
        );
    }
}
