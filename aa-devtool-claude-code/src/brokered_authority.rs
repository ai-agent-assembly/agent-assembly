//! The terminal-first privileged-file authority — AAASM-6491.
//!
//! [`MacOsAdminAuthority`](crate::managed_settings::MacOsAdminAuthority) raises a
//! GUI dialog from whichever process owns the installer. Here the installer runs
//! in the detached runtime, which has no terminal, so a password can only be
//! asked for by the *client* that owns one. [`BrokeredAuthority`] therefore does
//! no elevation itself: it hands one [`ElevatedOperation`] — paths and a digest,
//! never content or a command — to an [`ElevationBroker`] and maps the answer.
//!
//! Everything the installer does around the placement (backup, staging,
//! read-back of hash, owner and mode, install record, rollback) is unchanged and
//! stays unprivileged; only *how the one placement is authorized* differs.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_devtool_contract::{
    sha256_hex, ElevatedKind, ElevatedOperation, ElevationBroker, ElevationOutcome, ElevationPurpose,
};

use crate::managed_settings::{Authorization, ManagedSettingsError, PrivilegedFileAuthority};

/// What the disclosure says about how authorization is obtained, verbatim.
pub const TERMINAL_MECHANISM: &str =
    "sudo in the terminal that ran this command: a fixed set of root commands (install -d, tee, install, rm -f, rmdir) on one managed-settings file and its directory only; aasm and the runtime are not elevated";

/// Where an operation goes.
#[derive(Clone)]
enum Channel {
    /// A live path to the operator's terminal.
    Broker(Arc<dyn ElevationBroker>),
    /// Planning: nothing will be elevated, only described.
    DisclosureOnly,
    /// An apply arrived on a connection with no way to reach a terminal.
    Unreachable,
    /// Refused before anything is asked, with the reason shown to the operator.
    Refused(String),
}

/// Elevates through the operator's own terminal, via the client.
#[derive(Clone)]
pub struct BrokeredAuthority {
    channel: Channel,
    /// The one path this authority will ever name: the installer's own target.
    expected_target: PathBuf,
}

impl std::fmt::Debug for BrokeredAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokeredAuthority")
            .field("expected_target", &self.expected_target)
            .finish_non_exhaustive()
    }
}

impl BrokeredAuthority {
    /// An authority that performs operations through `broker`.
    pub fn new(broker: Arc<dyn ElevationBroker>, expected_target: impl Into<PathBuf>) -> Self {
        Self {
            channel: Channel::Broker(broker),
            expected_target: expected_target.into(),
        }
    }

    /// An authority used only to describe the mechanism while planning.
    pub fn disclosure_only(expected_target: impl Into<PathBuf>) -> Self {
        Self {
            channel: Channel::DisclosureOnly,
            expected_target: expected_target.into(),
        }
    }

    /// An authority for a request that asked for terminal authorization on a
    /// connection that cannot carry it. Refuses as non-interactive.
    pub fn without_channel(expected_target: impl Into<PathBuf>) -> Self {
        Self {
            channel: Channel::Unreachable,
            expected_target: expected_target.into(),
        }
    }

    /// An authority that refuses every operation, saying `reason`.
    pub fn refusing(expected_target: impl Into<PathBuf>, reason: impl Into<String>) -> Self {
        Self {
            channel: Channel::Refused(reason.into()),
            expected_target: expected_target.into(),
        }
    }

    fn guard(&self, target: &Path) -> Result<(), ManagedSettingsError> {
        if target != self.expected_target {
            return Err(ManagedSettingsError::AuthorizationUnavailable {
                detail: format!(
                    "this authority elevates only for {}; {} is not that path",
                    self.expected_target.display(),
                    target.display()
                ),
            });
        }
        self.availability().require(target)
    }

    fn perform(&self, target: &Path, operation: ElevatedOperation) -> Result<(), ManagedSettingsError> {
        let Channel::Broker(broker) = &self.channel else {
            // `guard` already refused every non-broker channel through
            // `availability`; reaching here would be a logic error, and the safe
            // reading of one is a refusal.
            return Err(ManagedSettingsError::NonInteractive {
                detail: "no terminal channel to the client is available".to_string(),
            });
        };
        let path = target.display().to_string();
        match broker.perform(&operation) {
            ElevationOutcome::Completed => Ok(()),
            ElevationOutcome::Denied(detail) | ElevationOutcome::Cancelled(detail) => {
                Err(ManagedSettingsError::PermissionRequired { path, detail })
            }
            ElevationOutcome::Unavailable(detail) => Err(ManagedSettingsError::AuthorizationUnavailable { detail }),
            ElevationOutcome::NonInteractive(detail) => Err(ManagedSettingsError::NonInteractive { detail }),
        }
    }
}

impl PrivilegedFileAuthority for BrokeredAuthority {
    fn mechanism(&self) -> &str {
        TERMINAL_MECHANISM
    }

    fn availability(&self) -> Authorization {
        match &self.channel {
            Channel::Broker(_) => Authorization::Available,
            Channel::DisclosureOnly => {
                if cfg!(target_os = "macos") {
                    Authorization::Available
                } else {
                    Authorization::Unavailable {
                        detail: "endpoint-managed settings are a macOS mechanism".to_string(),
                    }
                }
            }
            Channel::Unreachable => Authorization::NonInteractive {
                detail: "terminal authorization needs the client that ran this command to keep its terminal \
                         attached, and this connection has no such channel; upgrade the runtime, or pass \
                         --admin-auth gui"
                    .to_string(),
            },
            Channel::Refused(reason) => Authorization::Unavailable { detail: reason.clone() },
        }
    }

    fn install_file(&self, target: &Path, staged: &Path) -> Result<(), ManagedSettingsError> {
        self.install_file_for(target, staged, ElevationPurpose::PlaceReviewed)
    }

    fn install_file_for(
        &self,
        target: &Path,
        staged: &Path,
        purpose: ElevationPurpose,
    ) -> Result<(), ManagedSettingsError> {
        self.guard(target)?;
        let body = std::fs::read_to_string(staged).map_err(|e| ManagedSettingsError::Io {
            path: staged.display().to_string(),
            detail: e.to_string(),
        })?;
        self.perform(
            target,
            ElevatedOperation {
                kind: ElevatedKind::InstallFile,
                purpose,
                target: target.to_path_buf(),
                staged: Some(staged.to_path_buf()),
                staged_sha256: Some(sha256_hex(&body)),
            },
        )
    }

    fn delete_file(&self, target: &Path) -> Result<(), ManagedSettingsError> {
        self.guard(target)?;
        self.perform(
            target,
            ElevatedOperation {
                kind: ElevatedKind::DeleteFile,
                purpose: ElevationPurpose::Remove,
                target: target.to_path_buf(),
                staged: None,
                staged_sha256: None,
            },
        )
    }
}

/// A broker double, shipped (like the authority doubles) so the runtime's and
/// the CLI's tests can exercise the terminal path without a terminal.
#[doc(hidden)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    /// Answers every operation with a scripted outcome, and records them.
    #[derive(Debug)]
    pub struct FakeBroker {
        outcome: ElevationOutcome,
        perform_copy: bool,
        operations: Mutex<Vec<ElevatedOperation>>,
    }

    impl FakeBroker {
        /// Completes every operation, performing the placement as an
        /// unprivileged copy so read-back has something to verify.
        pub fn completing() -> Arc<Self> {
            Arc::new(Self {
                outcome: ElevationOutcome::Completed,
                perform_copy: true,
                operations: Mutex::new(Vec::new()),
            })
        }

        /// Answers every operation with `outcome`, touching nothing.
        pub fn answering(outcome: ElevationOutcome) -> Arc<Self> {
            Arc::new(Self {
                outcome,
                perform_copy: false,
                operations: Mutex::new(Vec::new()),
            })
        }

        /// Every operation this broker was handed.
        pub fn operations(&self) -> Vec<ElevatedOperation> {
            self.operations.lock().expect("broker log").clone()
        }
    }

    impl ElevationBroker for FakeBroker {
        fn perform(&self, operation: &ElevatedOperation) -> ElevationOutcome {
            self.operations.lock().expect("broker log").push(operation.clone());
            if self.perform_copy {
                let done = match (operation.kind, &operation.staged) {
                    (ElevatedKind::InstallFile, Some(staged)) => {
                        if let Some(parent) = operation.target.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        std::fs::copy(staged, &operation.target).is_ok()
                    }
                    (ElevatedKind::DeleteFile, _) => {
                        matches!(std::fs::remove_file(&operation.target), Ok(())) || !operation.target.exists()
                    }
                    _ => false,
                };
                if !done {
                    return ElevationOutcome::Unavailable("the test broker could not perform the operation".into());
                }
            }
            self.outcome.clone()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeBroker;
    use super::*;
    use crate::managed_settings::{managed_settings_document, ManagedSettingsInstaller};
    use aa_devtool_contract::ProtectionProfile;

    struct Host {
        _dir: tempfile::TempDir,
        target: PathBuf,
        work: PathBuf,
    }

    impl Host {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("ClaudeCode").join("managed-settings.json");
            let work = dir.path().join("state");
            Self {
                _dir: dir,
                target,
                work,
            }
        }

        fn installer(&self, authority: BrokeredAuthority) -> ManagedSettingsInstaller {
            use std::os::unix::fs::MetadataExt;
            std::fs::create_dir_all(&self.work).expect("work");
            let uid = std::fs::metadata(&self.work).expect("meta").uid();
            ManagedSettingsInstaller::new(&self.target, &self.work, Arc::new(authority)).expecting_owner_uid(uid)
        }
    }

    fn document() -> String {
        managed_settings_document(ProtectionProfile::Recommended).expect("document")
    }

    #[test]
    fn a_brokered_install_hands_one_placement_to_the_broker_and_reads_it_back() {
        let host = Host::new();
        let broker = FakeBroker::completing();
        let installer = host.installer(BrokeredAuthority::new(broker.clone(), &host.target));
        let disclosure = installer.disclose(&document()).expect("disclosure");
        let outcome = installer.install(&disclosure).expect("install");
        assert!(outcome.mutated);
        let ops = broker.operations();
        assert_eq!(ops.len(), 1, "{ops:?}");
        assert_eq!(ops[0].kind, ElevatedKind::InstallFile);
        assert_eq!(ops[0].purpose, ElevationPurpose::PlaceReviewed);
        assert_eq!(
            ops[0].staged_sha256.as_deref(),
            Some(disclosure.proposed_sha256.as_str())
        );
    }

    #[test]
    fn denied_and_cancelled_map_to_permission_required_and_leave_no_remnants() {
        for outcome in [
            ElevationOutcome::Denied("sudo: 3 incorrect password attempts".into()),
            ElevationOutcome::Cancelled("cancelled".into()),
        ] {
            let host = Host::new();
            let broker = FakeBroker::answering(outcome);
            let installer = host.installer(BrokeredAuthority::new(broker, &host.target));
            let disclosure = installer.disclose(&document()).expect("disclosure");
            let err = installer.install(&disclosure).expect_err("refused");
            assert!(matches!(err, ManagedSettingsError::PermissionRequired { .. }), "{err}");
            assert!(!host.target.exists());
            let left: Vec<_> = std::fs::read_dir(&host.work).expect("work").collect();
            assert!(left.is_empty(), "{left:?}");
        }
    }

    #[test]
    fn unavailable_and_non_interactive_map_to_their_own_refusals() {
        let host = Host::new();
        let broker = FakeBroker::answering(ElevationOutcome::Unavailable("no sudo".into()));
        let installer = host.installer(BrokeredAuthority::new(broker, &host.target));
        let disclosure = installer.disclose(&document()).expect("disclosure");
        let err = installer.install(&disclosure).expect_err("refused");
        assert!(
            matches!(err, ManagedSettingsError::AuthorizationUnavailable { .. }),
            "{err}"
        );

        let host = Host::new();
        let broker = FakeBroker::answering(ElevationOutcome::NonInteractive("no tty".into()));
        let installer = host.installer(BrokeredAuthority::new(broker, &host.target));
        let disclosure = installer.disclose(&document()).expect("disclosure");
        let err = installer.install(&disclosure).expect_err("refused");
        assert!(matches!(err, ManagedSettingsError::NonInteractive { .. }), "{err}");
    }

    #[test]
    fn terminal_without_a_channel_is_refused_before_anything_is_staged() {
        let host = Host::new();
        let installer = host.installer(BrokeredAuthority::without_channel(&host.target));
        let disclosure = installer.disclose(&document()).expect("disclosure");
        let err = installer.install(&disclosure).expect_err("refused");
        assert!(matches!(err, ManagedSettingsError::NonInteractive { .. }), "{err}");
        assert!(std::fs::read_dir(&host.work).expect("work").next().is_none());
    }

    #[test]
    fn a_target_other_than_the_installers_is_never_handed_to_the_broker() {
        let host = Host::new();
        let broker = FakeBroker::completing();
        let authority = BrokeredAuthority::new(broker.clone(), &host.target);
        let other = host.target.with_file_name("elsewhere.json");
        let err = authority.delete_file(&other).expect_err("refused");
        assert!(
            matches!(err, ManagedSettingsError::AuthorizationUnavailable { .. }),
            "{err}"
        );
        assert!(broker.operations().is_empty());
    }

    #[test]
    fn rollback_after_install_asks_the_broker_to_remove_when_there_was_no_prior_file() {
        let host = Host::new();
        let broker = FakeBroker::completing();
        let installer = host.installer(BrokeredAuthority::new(broker.clone(), &host.target));
        let disclosure = installer.disclose(&document()).expect("disclosure");
        installer.install(&disclosure).expect("install");
        installer.rollback().expect("rollback");
        assert!(!host.target.exists());
        let ops = broker.operations();
        assert_eq!(ops.len(), 2, "{ops:?}");
        assert_eq!(ops[1].kind, ElevatedKind::DeleteFile);
        assert_eq!(ops[1].purpose, ElevationPurpose::Remove);
    }

    #[test]
    fn the_terminal_mechanism_line_is_the_one_the_disclosure_promises() {
        let authority = BrokeredAuthority::disclosure_only("/x");
        assert_eq!(
            authority.mechanism(),
            "sudo in the terminal that ran this command: a fixed set of root commands (install -d, tee, install, rm -f, rmdir) on one managed-settings file and its directory only; aasm and the runtime are not elevated"
        );
    }
}
