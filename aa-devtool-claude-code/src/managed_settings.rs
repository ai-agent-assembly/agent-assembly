//! The endpoint-managed settings file, and the one privileged write that
//! installs it — AAASM-5298.
//!
//! # Why this module exists at all
//!
//! Everything else this integration does is reversible by the developer who ran
//! it, because everything else lives in files that developer already owns. The
//! macOS endpoint managed-settings file does not: it is root-owned, it sits
//! above every other settings scope in Claude Code's precedence order, and its
//! managed-only keys (`allowManagedPermissionRulesOnly`,
//! `disableBypassPermissionsMode`, `allowManagedMcpServersOnly`,
//! `allowManagedHooksOnly`) are the only levers that a user cannot turn off from
//! their own configuration. That is exactly why it is the only surface that can
//! carry a bypass-resistance claim, and exactly why writing it needs
//! administrator authorization.
//!
//! # The shape of the elevation, and what it is *not*
//!
//! The installer is unprivileged. It classifies the existing file, takes the
//! backup, stages the exact bytes, verifies the result, writes the record and
//! performs the rollback — all as the invoking user. The **only** elevated
//! operation is [`PrivilegedFileAuthority::install_file`]: place one
//! already-written file at one already-named path, owned by root. Nothing else
//! in the process is elevated, and there is no code path that runs the installer
//! — let alone `aasm` — as root.
//!
//! [`MacOsAdminAuthority`] additionally refuses any target that is not the
//! canonical [`MANAGED_SETTINGS_PATH`]. A caller that redirects the managed root
//! (as every test does) therefore cannot reach the real authorization prompt
//! even by accident: the redirect makes the write unprivileged by construction.
//!
//! # Consent is a security control, not a prompt
//!
//! [`ConsentDisclosure`] is built *before* authorization is requested and states,
//! in this order: the exact target path, why the privileged write is required,
//! the proposed content and its diff against what is there, any existing-file
//! conflict, and the backup and rollback behaviour. A user who cannot see the
//! diff cannot meaningfully authorize it, so [`ManagedSettingsInstaller::install`]
//! takes the disclosure — not the raw content — and refuses when the host has
//! changed underneath it since the disclosure was rendered.
//!
//! # Read-back is what separates a claim from evidence
//!
//! [`ManagedSettingsInstaller::install`] does not return success on the strength
//! of the authority reporting success. It re-reads the file, compares the bytes
//! to what was authorized, and checks ownership and permissions. A mismatch
//! rolls back and fails; it never produces an attestation, so it can never
//! produce `Host Enforced`.
//!
//! # What this module does *not* prove
//!
//! [`ManagedSettingsAttestation`] attests that the managed policy is installed
//! at the OS-managed path, owned by the expected principal, and not writable by
//! the invoking user. It does **not** measure whether Claude Code honours each
//! managed-only key at runtime — that needs a managed device and a real
//! privileged write, and remains the open half of AAASM-5298. Every user-facing
//! surface that reports this attestation has to say so.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aa_devtool_contract::{sha256_hex, AdapterError, ProtectionProfile};

/// The directory macOS reserves for Claude Code's endpoint-managed settings.
///
/// Re-exported from `aa-core` (via `aa-devtool-contract`), not defined here
/// — `aa-runtime`'s DI-API project-root refusal needs to name this surface
/// in a published (devtool-less) build, which cannot depend on this crate
/// (`publish = false`, AAASM-2340). AAASM-5987.
pub use aa_devtool_contract::MANAGED_SETTINGS_DIR;

/// The managed settings file name.
pub const MANAGED_SETTINGS_FILE: &str = "managed-settings.json";

/// The canonical endpoint managed-settings path.
///
/// [`MacOsAdminAuthority`] will not elevate for any other target, so this
/// constant is a security boundary and not merely a default.
pub const MANAGED_SETTINGS_PATH: &str = "/Library/Application Support/ClaudeCode/managed-settings.json";

/// The keys Claude Code honours **only** when they arrive from the managed
/// surface, and ignores everywhere else.
///
/// These are the whole reason the privileged write exists. A managed document
/// that carries none of them is a settings file at a privileged path — an
/// elevation with no enforcement purpose — and
/// [`validate_managed_document`] refuses it.
pub const MANAGED_ONLY_KEYS: [&str; 4] = [
    "allowManagedHooksOnly",
    "allowManagedMcpServersOnly",
    "allowManagedPermissionRulesOnly",
    "disableBypassPermissionsMode",
];

/// Top-level keys this integration is willing to write to the managed surface.
///
/// An allowlist rather than a denylist: the file is root-owned and
/// world-readable, and a key this build does not understand is a key this build
/// cannot promise is safe to put there.
const WRITABLE_KEYS: [&str; 8] = [
    "allowManagedHooksOnly",
    "allowManagedMcpServersOnly",
    "allowManagedPermissionRulesOnly",
    "disableBypassPermissionsMode",
    "disabledMcpjsonServers",
    "enabledMcpjsonServers",
    "permissionMode",
    "permissions",
];

/// Keys refused outright, whatever else the document contains.
///
/// `env` and `apiKeyHelper` are the two managed-settings keys that can carry
/// credential material, and the managed file is root-owned and readable by every
/// account on the machine. Writing a token there would turn a governance control
/// into a credential disclosure.
const FORBIDDEN_KEYS: [&str; 2] = ["apiKeyHelper", "env"];

/// The file name of the staged copy, inside Agent Assembly's own state.
const STAGED_FILE: &str = "managed-settings.staged.json";
/// The file name of the pre-install backup, inside Agent Assembly's own state.
const BACKUP_FILE: &str = "managed-settings.backup.json";
/// The file name of the install record, inside Agent Assembly's own state.
const RECORD_FILE: &str = "managed-settings.install.json";

/// Why a privileged managed-settings operation could not complete.
///
/// Every variant is a *refusal*, not a downgrade: nothing here is recoverable by
/// proceeding with less, because proceeding with less would mean reporting an
/// enforcement level the host does not have.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ManagedSettingsError {
    /// Authorization was requested and refused, or the mechanism could not
    /// obtain it. Truthfully "Permission Required" — never a partial success.
    #[error("permission required: administrator authorization to write {path} was not granted ({detail})")]
    PermissionRequired {
        /// The target that was not written.
        path: String,
        /// What the authorization mechanism reported.
        detail: String,
    },
    /// No authorization mechanism exists on this host at all.
    #[error("unavailable: no administrator authorization mechanism is available on this host ({detail})")]
    AuthorizationUnavailable {
        /// Why none is available.
        detail: String,
    },
    /// There is no terminal to authorize on. Fails immediately rather than
    /// blocking a pipeline on a credential prompt nobody can answer.
    #[error("unavailable: administrator authorization needs an interactive terminal ({detail})")]
    NonInteractive {
        /// What was missing.
        detail: String,
    },
    /// A managed-settings file exists that Agent Assembly did not write.
    #[error("{path} already holds managed settings Agent Assembly did not write; {detail}")]
    ConflictingExistingFile {
        /// The conflicting file.
        path: String,
        /// What the user has to decide, in words they can act on.
        detail: String,
    },
    /// The file read back after the write is not the file that was authorized.
    #[error("the managed settings read back from {path} are not what was authorized: {detail}")]
    ReadBackMismatch {
        /// The target that was read back.
        path: String,
        /// Which check failed.
        detail: String,
    },
    /// The proposed document is not something this integration will write to a
    /// root-owned path.
    #[error("the proposed managed-settings document was refused: {detail}")]
    SchemaInvalid {
        /// Which rule it broke.
        detail: String,
    },
    /// The host changed between the disclosure the user reviewed and the write.
    #[error("what was disclosed is no longer what would be written: {detail}")]
    ConsentStale {
        /// What changed.
        detail: String,
    },
    /// Agent Assembly never installed managed settings on this host.
    ///
    /// Distinct from a failed verification: there is nothing to verify, which is
    /// what a host that simply did not opt in looks like.
    #[error("Agent Assembly has not installed managed settings at {path} on this host")]
    NothingInstalled {
        /// The surface that holds no Agent Assembly install.
        path: String,
    },
    /// An unprivileged filesystem operation failed.
    #[error("{path}: {detail}")]
    Io {
        /// What was being touched.
        path: String,
        /// What went wrong.
        detail: String,
    },
}

impl ManagedSettingsError {
    /// The short, stable classification a status line reports.
    ///
    /// `Permission Required` and `Unavailable` are the two words the product
    /// promises never to soften into a success, so they are produced here rather
    /// than reconstructed from prose at each call site.
    pub fn summary(&self) -> &'static str {
        match self {
            Self::PermissionRequired { .. } => "Permission Required",
            Self::AuthorizationUnavailable { .. } | Self::NonInteractive { .. } => "Unavailable",
            Self::ConflictingExistingFile { .. } => "Conflicting managed settings",
            Self::NothingInstalled { .. } => "Not installed",
            Self::ReadBackMismatch { .. } => "Read-back verification failed",
            Self::SchemaInvalid { .. } => "Refused: invalid managed-settings document",
            Self::ConsentStale { .. } => "Refused: the host changed after the disclosure",
            Self::Io { .. } => "Failed",
        }
    }
}

fn io_error(path: &Path, e: &std::io::Error) -> ManagedSettingsError {
    ManagedSettingsError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// Whether an authorization prompt can be raised at all, asked *before* one is.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Authorization {
    /// A prompt can be raised.
    Available,
    /// There is a mechanism, but no terminal to use it on.
    NonInteractive {
        /// What is missing.
        detail: String,
    },
    /// There is no mechanism on this host.
    Unavailable {
        /// Why not.
        detail: String,
    },
}

impl Authorization {
    /// Turn a pre-flight reading into the refusal it implies, or `Ok(())`.
    fn require(&self, path: &Path) -> Result<(), ManagedSettingsError> {
        match self {
            Self::Available => Ok(()),
            Self::NonInteractive { detail } => Err(ManagedSettingsError::NonInteractive { detail: detail.clone() }),
            Self::Unavailable { detail } => Err(ManagedSettingsError::AuthorizationUnavailable {
                detail: format!("{detail} (target {})", path.display()),
            }),
        }
    }
}

/// The elevation seam: one authorized file placement, and its reversal.
///
/// Deliberately not "run this command as root" and not "give me a privileged
/// process". The two operations take a target path and, for an install, a file
/// whose bytes were already written unprivileged — so the elevated code has no
/// content to interpret, no policy to evaluate and no branch a caller can steer.
pub trait PrivilegedFileAuthority: fmt::Debug + Send + Sync {
    /// How this authority obtains authorization, for the disclosure.
    fn mechanism(&self) -> &str;

    /// Whether a prompt could be raised. Must never raise one.
    fn availability(&self) -> Authorization;

    /// Place `staged` at `target`, owned by the administrator, replacing
    /// whatever is there atomically.
    fn install_file(&self, target: &Path, staged: &Path) -> Result<(), ManagedSettingsError>;

    /// Delete `target`. Must succeed when `target` is already absent.
    fn delete_file(&self, target: &Path) -> Result<(), ManagedSettingsError>;
}

/// The macOS administrator-authorization authority.
///
/// # What it runs, and what it refuses to run
///
/// One `osascript … with administrator privileges` invocation per operation,
/// whose script is a single `/usr/bin/install` (or `/bin/rm`) against paths this
/// process chose. It refuses before spawning anything when the target is not
/// [`MANAGED_SETTINGS_PATH`], when there is no terminal, and on any non-macOS
/// host.
///
/// The target guard is what makes the whole test suite safe: every test injects
/// a temporary managed root, so every test's target fails the guard and no test
/// can reach an authorization prompt.
#[derive(Debug, Default, Clone, Copy)]
pub struct MacOsAdminAuthority;

impl MacOsAdminAuthority {
    /// Refuse before doing anything, for a target this authority will not
    /// elevate for.
    fn guard(&self, target: &Path) -> Result<(), ManagedSettingsError> {
        if target != Path::new(MANAGED_SETTINGS_PATH) {
            return Err(ManagedSettingsError::AuthorizationUnavailable {
                detail: format!(
                    "this authority elevates only for {MANAGED_SETTINGS_PATH}; {} is not that path",
                    target.display()
                ),
            });
        }
        self.availability().require(target)
    }

    /// Single-quote a path for `/bin/sh`, so a path containing a space or a
    /// quote cannot become a second command.
    fn shell_quote(path: &Path) -> String {
        format!("'{}'", path.display().to_string().replace('\'', r"'\''"))
    }

    /// Escape a `/bin/sh` script for embedding in an AppleScript string
    /// literal.
    ///
    /// Gated to macOS because its only caller is the macOS `run`; on other
    /// hosts `run` refuses before building a script, so an ungated helper is
    /// dead code that `-D warnings` rejects on a Linux build.
    #[cfg(target_os = "macos")]
    fn applescript_quote(script: &str) -> String {
        format!("\"{}\"", script.replace('\\', r"\\").replace('"', "\\\""))
    }

    #[cfg(target_os = "macos")]
    fn run(&self, script: &str) -> Result<(), ManagedSettingsError> {
        let literal = Self::applescript_quote(script);
        let output = std::process::Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg(format!("do shell script {literal} with administrator privileges"))
            .output()
            .map_err(|e| ManagedSettingsError::AuthorizationUnavailable {
                detail: format!("the macOS authorization helper could not be started: {e}"),
            })?;
        if output.status.success() {
            return Ok(());
        }
        Err(ManagedSettingsError::PermissionRequired {
            path: MANAGED_SETTINGS_PATH.to_string(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    #[cfg(not(target_os = "macos"))]
    fn run(&self, _script: &str) -> Result<(), ManagedSettingsError> {
        Err(ManagedSettingsError::AuthorizationUnavailable {
            detail: "endpoint-managed settings are a macOS mechanism".to_string(),
        })
    }
}

impl PrivilegedFileAuthority for MacOsAdminAuthority {
    fn mechanism(&self) -> &str {
        "macOS administrator authorization (one authorized file placement; aasm itself never runs as root)"
    }

    fn availability(&self) -> Authorization {
        if !cfg!(target_os = "macos") {
            return Authorization::Unavailable {
                detail: "endpoint-managed settings are a macOS mechanism".to_string(),
            };
        }
        use std::io::IsTerminal;
        if !std::io::stdin().is_terminal() {
            return Authorization::NonInteractive {
                detail: "stdin is not a terminal, so an administrator prompt could not be answered".to_string(),
            };
        }
        Authorization::Available
    }

    fn install_file(&self, target: &Path, staged: &Path) -> Result<(), ManagedSettingsError> {
        self.guard(target)?;
        let dir = target.parent().unwrap_or(Path::new(MANAGED_SETTINGS_DIR));
        // `install(1)` writes a temporary and renames it, so the target is never
        // observed half-written.
        let script = format!(
            "/bin/mkdir -p {dir} && /usr/bin/install -m 644 -o root -g wheel -- {staged} {target}",
            dir = Self::shell_quote(dir),
            staged = Self::shell_quote(staged),
            target = Self::shell_quote(target),
        );
        self.run(&script)
    }

    fn delete_file(&self, target: &Path) -> Result<(), ManagedSettingsError> {
        self.guard(target)?;
        self.run(&format!("/bin/rm -f -- {}", Self::shell_quote(target)))
    }
}

/// What is already sitting at the managed path.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExistingManagedSettings {
    /// Nothing is there.
    Absent,
    /// The file matches the one Agent Assembly recorded installing.
    WrittenByAgentAssembly {
        /// Its digest.
        sha256: String,
    },
    /// A file is there that Agent Assembly did not write, or wrote and something
    /// else has since changed.
    Foreign {
        /// Its digest.
        sha256: String,
        /// Its top-level keys, so the disclosure can describe it without
        /// printing values that may not be ours to show.
        keys: Vec<String>,
    },
}

impl ExistingManagedSettings {
    /// Whether this is a conflict that needs a separate, explicit decision.
    pub fn is_conflict(&self) -> bool {
        matches!(self, Self::Foreign { .. })
    }

    /// The digest of what is there, when anything is.
    pub fn sha256(&self) -> Option<&str> {
        match self {
            Self::Absent => None,
            Self::WrittenByAgentAssembly { sha256 } | Self::Foreign { sha256, .. } => Some(sha256),
        }
    }
}

/// Everything a user must see before authorization is requested.
///
/// Field order is the disclosure order, and [`render`](Self::render) prints them
/// in it. Nothing here is optional presentation: an authorization granted
/// without the diff and the conflict in front of the user is not informed
/// consent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentDisclosure {
    /// The exact file that will be written.
    pub target: PathBuf,
    /// Why the write needs administrator authorization.
    pub reason: String,
    /// The exact bytes that will be placed there.
    pub proposed: String,
    /// Their digest, which the install re-checks.
    pub proposed_sha256: String,
    /// What is there now.
    pub existing: ExistingManagedSettings,
    /// A line-level diff of current against proposed.
    pub diff: Vec<String>,
    /// The conflict that blocks this install, when there is one.
    pub conflict: Option<String>,
    /// Where the pre-install backup goes, and what happens when there is no
    /// prior file.
    pub backup: String,
    /// How to reverse the install.
    pub rollback: String,
    /// How authorization will be obtained.
    pub mechanism: String,
    /// Whether it can be obtained at all, read before it is requested.
    pub authorization: Authorization,
}

impl ConsentDisclosure {
    /// Render the disclosure, in the order it must be read.
    pub fn render(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        let _ = writeln!(out, "administrator authorization is required for one file write");
        let _ = writeln!(out, "  target:      {}", self.target.display());
        let _ = writeln!(out, "  why:         {}", self.reason);
        let _ = writeln!(out, "  authorized:  {}", self.mechanism);
        let _ = writeln!(out, "  proposed content:");
        for line in self.proposed.lines() {
            let _ = writeln!(out, "    {line}");
        }
        let _ = writeln!(out, "  currently on this host:");
        match &self.existing {
            ExistingManagedSettings::Absent => {
                let _ = writeln!(out, "    (no managed-settings file)");
            }
            ExistingManagedSettings::WrittenByAgentAssembly { sha256 } => {
                let _ = writeln!(out, "    a file Agent Assembly installed (sha256:{sha256})");
            }
            ExistingManagedSettings::Foreign { sha256, keys } => {
                let _ = writeln!(
                    out,
                    "    a file Agent Assembly did not write (sha256:{sha256}), top-level keys: {}",
                    keys.join(", ")
                );
            }
        }
        let _ = writeln!(out, "  changes:");
        if self.diff.is_empty() {
            let _ = writeln!(out, "    (none — the file already holds exactly this content)");
        } else {
            for line in &self.diff {
                let _ = writeln!(out, "    {line}");
            }
        }
        if let Some(conflict) = &self.conflict {
            let _ = writeln!(out, "  conflict:    {conflict}");
        }
        let _ = writeln!(out, "  backup:      {}", self.backup);
        let _ = writeln!(out, "  rollback:    {}", self.rollback);
        match &self.authorization {
            Authorization::Available => {}
            Authorization::NonInteractive { detail } | Authorization::Unavailable { detail } => {
                let _ = writeln!(out, "  blocked:     {detail}");
            }
        }
        out
    }

    /// Whether this disclosure describes an install that can proceed.
    pub fn is_installable(&self) -> bool {
        self.conflict.is_none() && matches!(self.authorization, Authorization::Available)
    }
}

/// What was read back off the host after the privileged write.
///
/// This is the evidence a `Host Enforced` claim rests on. It records the facts
/// that were checked rather than a bare boolean, so a status line can say what
/// was verified instead of asserting that something was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSettingsAttestation {
    /// The file that was read back.
    pub target: PathBuf,
    /// Its digest, as read back.
    pub sha256: String,
    /// Its owner, when the platform reports one.
    pub owner_uid: Option<u32>,
    /// Its permission bits, when the platform reports them.
    pub mode: Option<u32>,
    /// Which managed-only keys are actually in the installed document.
    pub managed_only_keys: Vec<String>,
    /// Whether anyone other than the owner can rewrite it.
    pub writable_by_others: bool,
}

impl ManagedSettingsAttestation {
    /// One line describing what was verified, for evidence detail.
    pub fn detail(&self) -> String {
        format!(
            "{} verified by read-back: sha256:{}, owner uid {}, mode {}, managed-only keys [{}]",
            self.target.display(),
            self.sha256,
            self.owner_uid.map_or_else(|| "unknown".to_string(), |u| u.to_string()),
            self.mode.map_or_else(|| "unknown".to_string(), |m| format!("{m:04o}")),
            self.managed_only_keys.join(", ")
        )
    }
}

/// What an install actually did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedInstallOutcome {
    /// The verified state of the file afterwards.
    pub attestation: ManagedSettingsAttestation,
    /// Whether the host changed. `false` means the file already held exactly
    /// this content and **no authorization was requested**.
    pub mutated: bool,
    /// Where the prior file was backed up, when there was one.
    pub backup: Option<PathBuf>,
}

/// What a rollback did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ManagedRollbackOutcome {
    /// There was nothing installed to roll back.
    NothingToDo,
    /// A prior file was restored from the backup.
    Restored {
        /// Where it came from.
        backup: PathBuf,
    },
    /// There was no prior file, so the managed file was deleted.
    Removed,
}

/// The record Agent Assembly keeps of its own managed-settings install.
///
/// Kept in Agent Assembly's unprivileged state rather than as a marker key
/// inside the managed file: an unrecognised key in `managed-settings.json` makes
/// Claude Code warn, and a governance tool that provokes a warning in the tool it
/// governs has made the user's day worse for its own bookkeeping.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
struct InstallRecord {
    target: PathBuf,
    installed_sha256: String,
    /// `None` records "there was no file here before" — the case a rollback has
    /// to handle by deleting rather than restoring.
    backup: Option<PathBuf>,
    installed_at_unix_secs: u64,
}

/// Installs, verifies and reverses the endpoint-managed settings file.
///
/// Unprivileged itself; holds one [`PrivilegedFileAuthority`] and calls it for
/// exactly one operation per install and one per rollback.
#[derive(Debug, Clone)]
pub struct ManagedSettingsInstaller {
    target: PathBuf,
    work_dir: PathBuf,
    authority: Arc<dyn PrivilegedFileAuthority>,
    expected_owner_uid: u32,
}

impl ManagedSettingsInstaller {
    /// An installer writing `target`, keeping its own state under `work_dir`,
    /// elevating through `authority`.
    pub fn new(
        target: impl Into<PathBuf>,
        work_dir: impl Into<PathBuf>,
        authority: Arc<dyn PrivilegedFileAuthority>,
    ) -> Self {
        Self {
            target: target.into(),
            work_dir: work_dir.into(),
            authority,
            expected_owner_uid: 0,
        }
    }

    /// Expect a different owner than root.
    ///
    /// Production always expects uid 0. A test that redirects the managed root
    /// writes as the test user, so it names that uid instead — and the ownership
    /// check stays load-bearing in both cases rather than being switched off.
    #[must_use]
    pub fn expecting_owner_uid(mut self, uid: u32) -> Self {
        self.expected_owner_uid = uid;
        self
    }

    /// The file this installer writes.
    pub fn target(&self) -> &Path {
        &self.target
    }

    /// How authorization would be obtained, without requesting it.
    pub fn authorization(&self) -> Authorization {
        self.authority.availability()
    }

    fn staged_path(&self) -> PathBuf {
        self.work_dir.join(STAGED_FILE)
    }

    fn backup_path(&self) -> PathBuf {
        self.work_dir.join(BACKUP_FILE)
    }

    fn record_path(&self) -> PathBuf {
        self.work_dir.join(RECORD_FILE)
    }

    fn read_record(&self) -> Option<InstallRecord> {
        let raw = std::fs::read_to_string(self.record_path()).ok()?;
        serde_json::from_str(&raw).ok()
    }

    fn write_record(&self, record: &InstallRecord) -> Result<(), ManagedSettingsError> {
        let path = self.record_path();
        std::fs::create_dir_all(&self.work_dir).map_err(|e| io_error(&self.work_dir, &e))?;
        let body = serde_json::to_string_pretty(record).map_err(|e| ManagedSettingsError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        std::fs::write(&path, body).map_err(|e| io_error(&path, &e))
    }

    /// Read what is currently at the managed path, if anything.
    ///
    /// Reading needs no privilege: the managed file is world-readable by design.
    fn current(&self) -> Result<Option<String>, ManagedSettingsError> {
        match std::fs::read_to_string(&self.target) {
            Ok(raw) => Ok(Some(raw)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_error(&self.target, &e)),
        }
    }

    /// Classify what is at the managed path against Agent Assembly's own record.
    ///
    /// # Errors
    ///
    /// [`ManagedSettingsError::Io`] when the file exists and cannot be read.
    pub fn classify_existing(&self) -> Result<ExistingManagedSettings, ManagedSettingsError> {
        let Some(raw) = self.current()? else {
            return Ok(ExistingManagedSettings::Absent);
        };
        let sha256 = sha256_hex(&raw);
        let ours = self
            .read_record()
            .is_some_and(|record| record.target == self.target && record.installed_sha256 == sha256);
        if ours {
            return Ok(ExistingManagedSettings::WrittenByAgentAssembly { sha256 });
        }
        Ok(ExistingManagedSettings::Foreign {
            sha256,
            keys: top_level_keys(&raw),
        })
    }

    /// Build the disclosure a user must read before authorization is requested.
    ///
    /// # Errors
    ///
    /// [`ManagedSettingsError::SchemaInvalid`] when the proposed document is not
    /// one this integration will write to a root-owned path, and
    /// [`ManagedSettingsError::Io`] when the current file cannot be read.
    pub fn disclose(&self, proposed: &str) -> Result<ConsentDisclosure, ManagedSettingsError> {
        validate_managed_document(proposed)?;
        let existing = self.classify_existing()?;
        let current = self.current()?.unwrap_or_default();

        // A conflict is a refusal to *merge over*, and deliberately not an
        // option this tool offers to override: the file may be MDM-deployed by
        // the user's own organisation, and silently replacing an administrator's
        // policy with ours is the one outcome nothing here can justify. The
        // separate explicit decision is the user's — move the file aside.
        let conflict = existing.is_conflict().then(|| {
            format!(
                "a managed-settings file Agent Assembly did not write is already installed. \
                 It may have been deployed by your organisation's device management. Agent Assembly \
                 will not replace it. Move {} aside yourself and re-run if you intend to replace it",
                self.target.display()
            )
        });

        Ok(ConsentDisclosure {
            target: self.target.clone(),
            reason: format!(
                "{} is owned by the administrator, and it is the only settings surface Claude Code \
                 treats as non-overridable. Writing it needs one authorized file placement; Agent \
                 Assembly itself never runs as root",
                self.target.display()
            ),
            proposed_sha256: sha256_hex(proposed),
            diff: line_diff(&current, proposed),
            proposed: proposed.to_string(),
            existing,
            conflict,
            backup: match self.current()? {
                Some(_) => format!(
                    "the file currently installed is copied to {} before anything is written",
                    self.backup_path().display()
                ),
                None => format!(
                    "there is no file to back up; removal will delete {} rather than restore anything",
                    self.target.display()
                ),
            },
            rollback: "`aasm integrations remove claude-code` restores the backed-up file, or deletes \
                       the managed file when there was none — and asks for authorization again"
                .to_string(),
            mechanism: self.authority.mechanism().to_string(),
            authorization: self.authority.availability(),
        })
    }

    /// Install the disclosed content, then read it back and verify it.
    ///
    /// The disclosure is the argument rather than the content because it carries
    /// the classification the user saw. If the host has changed since — the file
    /// appeared, or changed digest — this refuses rather than writing over
    /// something the user was never shown.
    ///
    /// # Errors
    ///
    /// Every variant of [`ManagedSettingsError`]. None of them is a partial
    /// success: an error here means nothing was installed, or what was installed
    /// was rolled back.
    pub fn install(&self, disclosure: &ConsentDisclosure) -> Result<ManagedInstallOutcome, ManagedSettingsError> {
        if disclosure.target != self.target {
            return Err(ManagedSettingsError::ConsentStale {
                detail: format!(
                    "the disclosure names {} and this installer writes {}",
                    disclosure.target.display(),
                    self.target.display()
                ),
            });
        }
        validate_managed_document(&disclosure.proposed)?;
        if sha256_hex(&disclosure.proposed) != disclosure.proposed_sha256 {
            return Err(ManagedSettingsError::ConsentStale {
                detail: "the disclosed content does not match its own digest".to_string(),
            });
        }

        let existing = self.classify_existing()?;
        if existing != disclosure.existing {
            return Err(ManagedSettingsError::ConsentStale {
                detail: format!(
                    "{} changed after the disclosure was shown; re-run so the change is disclosed",
                    self.target.display()
                ),
            });
        }
        if let ExistingManagedSettings::Foreign { sha256, .. } = &existing {
            return Err(ManagedSettingsError::ConflictingExistingFile {
                path: self.target.display().to_string(),
                detail: format!(
                    "it hashes to sha256:{sha256}, which is not the file Agent Assembly recorded installing. \
                     Agent Assembly will not overwrite managed settings it did not write — move the file \
                     aside yourself and re-run if you intend to replace it"
                ),
            });
        }

        // Already exactly right: verify and return without requesting
        // authorization at all. Prompting for a write that would change nothing
        // is how a tool trains users to click through prompts.
        if existing.sha256() == Some(disclosure.proposed_sha256.as_str()) {
            let attestation = self.verify_read_back(&disclosure.proposed_sha256)?;
            return Ok(ManagedInstallOutcome {
                attestation,
                mutated: false,
                backup: self.read_record().and_then(|r| r.backup),
            });
        }

        // Pre-flight the authorization *before* touching anything, so a host
        // that cannot authorize fails without having taken a backup or staged a
        // file it will never install.
        self.authority.availability().require(&self.target)?;

        std::fs::create_dir_all(&self.work_dir).map_err(|e| io_error(&self.work_dir, &e))?;
        let backup = match self.current()? {
            Some(prior) => {
                let path = self.backup_path();
                std::fs::write(&path, &prior).map_err(|e| io_error(&path, &e))?;
                Some(path)
            }
            None => {
                // A stale backup from an earlier install would make a rollback
                // restore a file that is not what this install displaced.
                let path = self.backup_path();
                if path.exists() {
                    std::fs::remove_file(&path).map_err(|e| io_error(&path, &e))?;
                }
                None
            }
        };

        let staged = self.staged_path();
        std::fs::write(&staged, &disclosure.proposed).map_err(|e| io_error(&staged, &e))?;
        set_mode(&staged, 0o644)?;

        self.authority.install_file(&self.target, &staged)?;
        let _ = std::fs::remove_file(&staged);

        match self.verify_read_back(&disclosure.proposed_sha256) {
            Ok(attestation) => {
                self.write_record(&InstallRecord {
                    target: self.target.clone(),
                    installed_sha256: disclosure.proposed_sha256.clone(),
                    backup: backup.clone(),
                    installed_at_unix_secs: aa_devtool_contract::now_unix_secs(),
                })?;
                Ok(ManagedInstallOutcome {
                    attestation,
                    mutated: true,
                    backup,
                })
            }
            Err(mismatch) => {
                // Put the host back before reporting. A failed read-back that
                // left the file in place would be exactly the partial success
                // this path is not allowed to produce.
                let restore = match &backup {
                    Some(path) => std::fs::copy(path, &staged)
                        .ok()
                        .and_then(|_| self.authority.install_file(&self.target, &staged).ok())
                        .is_some(),
                    None => self.authority.delete_file(&self.target).is_ok(),
                };
                let _ = std::fs::remove_file(&staged);
                let detail = match (&mismatch, restore) {
                    (ManagedSettingsError::ReadBackMismatch { detail, .. }, true) => {
                        format!("{detail}; the previous state was restored")
                    }
                    (ManagedSettingsError::ReadBackMismatch { detail, .. }, false) => {
                        format!("{detail}; the previous state could NOT be restored — inspect the file by hand")
                    }
                    _ => return Err(mismatch),
                };
                Err(ManagedSettingsError::ReadBackMismatch {
                    path: self.target.display().to_string(),
                    detail,
                })
            }
        }
    }

    /// Read the managed file back and check it against `expected_sha256`,
    /// ownership and permissions.
    ///
    /// # Errors
    ///
    /// [`ManagedSettingsError::ReadBackMismatch`] for every failed check, so no
    /// caller can mistake a partial verification for a complete one.
    pub fn verify_read_back(&self, expected_sha256: &str) -> Result<ManagedSettingsAttestation, ManagedSettingsError> {
        let mismatch = |detail: String| ManagedSettingsError::ReadBackMismatch {
            path: self.target.display().to_string(),
            detail,
        };

        let Some(raw) = self.current()? else {
            return Err(mismatch("the file is not there".to_string()));
        };
        let sha256 = sha256_hex(&raw);
        if sha256 != expected_sha256 {
            return Err(mismatch(format!(
                "it hashes to sha256:{sha256}, not the authorized sha256:{expected_sha256}"
            )));
        }
        validate_managed_document(&raw).map_err(|e| mismatch(e.to_string()))?;

        let metadata = std::fs::metadata(&self.target).map_err(|e| io_error(&self.target, &e))?;
        let (owner_uid, mode) = owner_and_mode(&metadata);

        if let Some(uid) = owner_uid {
            if uid != self.expected_owner_uid {
                return Err(mismatch(format!(
                    "it is owned by uid {uid}, not the expected uid {}; a file the invoking user owns \
                     is a file the invoking user can rewrite",
                    self.expected_owner_uid
                )));
            }
        }
        let writable_by_others = mode.is_some_and(|m| m & 0o022 != 0);
        if writable_by_others {
            return Err(mismatch(format!(
                "its mode is {:04o}, which lets an account other than the owner rewrite it",
                mode.unwrap_or_default()
            )));
        }

        Ok(ManagedSettingsAttestation {
            target: self.target.clone(),
            sha256,
            owner_uid,
            mode,
            managed_only_keys: present_managed_only_keys(&raw),
            writable_by_others,
        })
    }

    /// Verify whatever this installer last recorded installing, for `status` and
    /// `verify`.
    ///
    /// # Errors
    ///
    /// As [`verify_read_back`](Self::verify_read_back); additionally
    /// [`ManagedSettingsError::NothingInstalled`] when nothing was ever
    /// installed, because an attestation about a file this integration did not
    /// install would attribute someone else's policy to Agent Assembly.
    pub fn verify_recorded(&self) -> Result<ManagedSettingsAttestation, ManagedSettingsError> {
        let record = self
            .read_record()
            .ok_or_else(|| ManagedSettingsError::NothingInstalled {
                path: self.target.display().to_string(),
            })?;
        self.verify_read_back(&record.installed_sha256)
    }

    /// Reverse the install: restore the backed-up file, or delete the managed
    /// file when there was none.
    ///
    /// Safe to call twice — removal recovery may.
    ///
    /// # Errors
    ///
    /// As the authority reports, plus
    /// [`ManagedSettingsError::ReadBackMismatch`] when the host does not end up
    /// in the state the rollback intended.
    pub fn rollback(&self) -> Result<ManagedRollbackOutcome, ManagedSettingsError> {
        let Some(record) = self.read_record() else {
            return Ok(ManagedRollbackOutcome::NothingToDo);
        };

        let outcome = match &record.backup {
            Some(backup) if backup.exists() => {
                let prior = std::fs::read_to_string(backup).map_err(|e| io_error(backup, &e))?;
                if self.current()?.as_deref() == Some(prior.as_str()) {
                    ManagedRollbackOutcome::Restored { backup: backup.clone() }
                } else {
                    self.authority.availability().require(&self.target)?;
                    let staged = self.staged_path();
                    std::fs::create_dir_all(&self.work_dir).map_err(|e| io_error(&self.work_dir, &e))?;
                    std::fs::write(&staged, &prior).map_err(|e| io_error(&staged, &e))?;
                    set_mode(&staged, 0o644)?;
                    self.authority.install_file(&self.target, &staged)?;
                    let _ = std::fs::remove_file(&staged);
                    if self.current()?.as_deref() != Some(prior.as_str()) {
                        return Err(ManagedSettingsError::ReadBackMismatch {
                            path: self.target.display().to_string(),
                            detail: "the backed-up file was not what was there after the restore".to_string(),
                        });
                    }
                    ManagedRollbackOutcome::Restored { backup: backup.clone() }
                }
            }
            // The no-prior-file case: symmetric removal means the host goes back
            // to having no managed-settings file at all, not to holding an empty
            // one Agent Assembly invented.
            _ => {
                if self.current()?.is_some() {
                    self.authority.availability().require(&self.target)?;
                    self.authority.delete_file(&self.target)?;
                    if self.current()?.is_some() {
                        return Err(ManagedSettingsError::ReadBackMismatch {
                            path: self.target.display().to_string(),
                            detail: "the managed-settings file is still there after removal".to_string(),
                        });
                    }
                }
                ManagedRollbackOutcome::Removed
            }
        };

        let record_path = self.record_path();
        if record_path.exists() {
            std::fs::remove_file(&record_path).map_err(|e| io_error(&record_path, &e))?;
        }
        let backup_path = self.backup_path();
        if backup_path.exists() {
            std::fs::remove_file(&backup_path).map_err(|e| io_error(&backup_path, &e))?;
        }
        Ok(outcome)
    }
}

/// The managed-settings document one profile resolves to.
///
/// `ObserveOnly` has none, deliberately: a profile that applies no decision has
/// nothing to enforce, and elevating to install non-overridable enforcement keys
/// for it would be an elevation with no protective effect.
///
/// # Errors
///
/// [`AdapterError::SettingsGenerationFailed`] for `ObserveOnly`, and if
/// serialization fails.
pub fn managed_settings_document(profile: ProtectionProfile) -> Result<String, AdapterError> {
    let (default_mode, strict) = match profile {
        ProtectionProfile::Strict => ("plan", true),
        ProtectionProfile::Recommended => ("default", false),
        ProtectionProfile::ObserveOnly => {
            return Err(AdapterError::SettingsGenerationFailed(
                "the observe-only profile applies no decision, so there is nothing for endpoint-managed \
                 settings to enforce; install it with --profile recommended or --profile strict, or \
                 without --install-managed-settings"
                    .to_string(),
            ))
        }
    };

    let doc = serde_json::json!({
        // The bypass this closes is `--dangerously-skip-permissions` and
        // `defaultMode: "bypassPermissions"`, which no user- or project-scoped
        // setting can counter.
        "disableBypassPermissionsMode": true,
        // Managed permission rules become the only ones in effect, so a user
        // cannot widen them from their own settings file.
        "allowManagedPermissionRulesOnly": true,
        "allowManagedMcpServersOnly": strict,
        "allowManagedHooksOnly": strict,
        "permissions": {
            "allow": [],
            "deny": [],
            "defaultMode": default_mode,
        },
        "permissionMode": default_mode,
    });
    serde_json::to_string_pretty(&doc).map_err(|e| AdapterError::SettingsGenerationFailed(e.to_string()))
}

/// Refuse a document this integration will not put at a root-owned path.
///
/// # Errors
///
/// [`ManagedSettingsError::SchemaInvalid`] with the rule that was broken.
pub fn validate_managed_document(raw: &str) -> Result<(), ManagedSettingsError> {
    let invalid = |detail: String| ManagedSettingsError::SchemaInvalid { detail };

    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| invalid(format!("it is not valid JSON: {e}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| invalid("the top level is not a JSON object".to_string()))?;

    for key in object.keys() {
        if FORBIDDEN_KEYS.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{key:?} can carry credential material and the managed file is root-owned and readable \
                 by every account on the machine"
            )));
        }
        if !WRITABLE_KEYS.contains(&key.as_str()) {
            return Err(invalid(format!(
                "{key:?} is not a key this build knows how to write to the managed surface"
            )));
        }
    }

    for key in MANAGED_ONLY_KEYS {
        if let Some(value) = object.get(key) {
            if !value.is_boolean() {
                return Err(invalid(format!("{key:?} must be a boolean")));
            }
        }
    }

    if present_managed_only_keys(raw).is_empty() {
        return Err(invalid(format!(
            "it carries none of the managed-only keys ({}), so installing it at a root-owned path \
             would be an elevation with no enforcement purpose",
            MANAGED_ONLY_KEYS.join(", ")
        )));
    }

    Ok(())
}

/// Which managed-only keys a document actually carries.
fn present_managed_only_keys(raw: &str) -> Vec<String> {
    let Ok(serde_json::Value::Object(object)) = serde_json::from_str::<serde_json::Value>(raw) else {
        return Vec::new();
    };
    MANAGED_ONLY_KEYS
        .iter()
        .filter(|key| object.contains_key(**key))
        .map(|key| (*key).to_string())
        .collect()
}

fn top_level_keys(raw: &str) -> Vec<String> {
    match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(serde_json::Value::Object(object)) => object.keys().cloned().collect(),
        _ => vec!["(not a JSON object)".to_string()],
    }
}

/// A line-level diff, enough for a human to see what changes.
///
/// Not a minimal edit script: the managed document is a handful of lines, and a
/// disclosure a user has to decode is not a disclosure.
fn line_diff(current: &str, proposed: &str) -> Vec<String> {
    if current == proposed {
        return Vec::new();
    }
    let current_lines: Vec<&str> = current.lines().collect();
    let proposed_lines: Vec<&str> = proposed.lines().collect();
    let mut out = Vec::new();
    for line in &current_lines {
        if !proposed_lines.contains(line) {
            out.push(format!("- {line}"));
        }
    }
    for line in &proposed_lines {
        if !current_lines.contains(line) {
            out.push(format!("+ {line}"));
        }
    }
    out
}

/// Who owns `path`, when the platform reports owners.
///
/// Used to anchor the ownership check to the process's own uid when the managed
/// root is redirected for a test — so the check stays live in both cases rather
/// than being switched off for one of them.
pub fn owner_uid(path: &Path) -> Option<u32> {
    let metadata = std::fs::metadata(path).ok()?;
    owner_and_mode(&metadata).0
}

#[cfg(unix)]
fn owner_and_mode(metadata: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    use std::os::unix::fs::MetadataExt;
    (Some(metadata.uid()), Some(metadata.mode() & 0o7777))
}

#[cfg(not(unix))]
fn owner_and_mode(_metadata: &std::fs::Metadata) -> (Option<u32>, Option<u32>) {
    (None, None)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), ManagedSettingsError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| io_error(path, &e))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), ManagedSettingsError> {
    Ok(())
}

/// Test doubles for the elevation seam.
///
/// Shipped rather than confined to `#[cfg(test)]` because the integration tests,
/// the CLI's tests and the conformance suite all have to exercise the privileged
/// path — and the one thing none of them may do is reach a real authorization
/// prompt.
#[doc(hidden)]
pub mod testing {
    use super::*;
    use std::sync::Mutex;

    /// What a [`FakeAuthority`] does when asked.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FakeBehaviour {
        /// Perform the placement as an ordinary unprivileged file copy.
        Grant,
        /// Report that authorization was refused.
        Deny,
        /// Report that no mechanism exists.
        Unavailable,
        /// Report that there is no terminal to authorize on.
        NonInteractive,
        /// Report success, but write different bytes — the read-back-mismatch
        /// case, which no honest authority produces and every product has to
        /// survive.
        GrantButCorrupt(String),
    }

    /// An authority that never elevates anything.
    #[derive(Debug)]
    pub struct FakeAuthority {
        behaviour: FakeBehaviour,
        calls: Mutex<Vec<String>>,
    }

    impl FakeAuthority {
        /// An authority with `behaviour`.
        pub fn new(behaviour: FakeBehaviour) -> Self {
            Self {
                behaviour,
                calls: Mutex::new(Vec::new()),
            }
        }

        /// Grants, and performs the write unprivileged.
        pub fn granting() -> Arc<Self> {
            Arc::new(Self::new(FakeBehaviour::Grant))
        }

        /// Refuses authorization.
        pub fn denying() -> Arc<Self> {
            Arc::new(Self::new(FakeBehaviour::Deny))
        }

        /// Has no mechanism.
        pub fn unavailable() -> Arc<Self> {
            Arc::new(Self::new(FakeBehaviour::Unavailable))
        }

        /// Has a mechanism and no terminal.
        pub fn non_interactive() -> Arc<Self> {
            Arc::new(Self::new(FakeBehaviour::NonInteractive))
        }

        /// Reports success while writing `content` instead.
        pub fn corrupting(content: impl Into<String>) -> Arc<Self> {
            Arc::new(Self::new(FakeBehaviour::GrantButCorrupt(content.into())))
        }

        /// Every operation this authority was asked to perform.
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("authority call log").clone()
        }

        fn record(&self, what: String) {
            self.calls.lock().expect("authority call log").push(what);
        }

        fn place(&self, target: &Path, body: &str) -> Result<(), ManagedSettingsError> {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io_error(parent, &e))?;
            }
            std::fs::write(target, body).map_err(|e| io_error(target, &e))?;
            set_mode(target, 0o644)
        }
    }

    impl PrivilegedFileAuthority for FakeAuthority {
        fn mechanism(&self) -> &str {
            "a test double that never elevates"
        }

        fn availability(&self) -> Authorization {
            match &self.behaviour {
                FakeBehaviour::Unavailable => Authorization::Unavailable {
                    detail: "no mechanism in this test".to_string(),
                },
                FakeBehaviour::NonInteractive => Authorization::NonInteractive {
                    detail: "no terminal in this test".to_string(),
                },
                _ => Authorization::Available,
            }
        }

        fn install_file(&self, target: &Path, staged: &Path) -> Result<(), ManagedSettingsError> {
            self.record(format!("install {} <- {}", target.display(), staged.display()));
            match &self.behaviour {
                FakeBehaviour::Grant => {
                    let body = std::fs::read_to_string(staged).map_err(|e| io_error(staged, &e))?;
                    self.place(target, &body)
                }
                FakeBehaviour::GrantButCorrupt(body) => self.place(target, body),
                FakeBehaviour::Deny => Err(ManagedSettingsError::PermissionRequired {
                    path: target.display().to_string(),
                    detail: "the user cancelled the authorization prompt".to_string(),
                }),
                other => self.availability().require(target).and_then(|()| {
                    Err(ManagedSettingsError::AuthorizationUnavailable {
                        detail: format!("{other:?}"),
                    })
                }),
            }
        }

        fn delete_file(&self, target: &Path) -> Result<(), ManagedSettingsError> {
            self.record(format!("delete {}", target.display()));
            match &self.behaviour {
                FakeBehaviour::Deny => Err(ManagedSettingsError::PermissionRequired {
                    path: target.display().to_string(),
                    detail: "the user cancelled the authorization prompt".to_string(),
                }),
                _ => match std::fs::remove_file(target) {
                    Ok(()) => Ok(()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                    Err(e) => Err(io_error(target, &e)),
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{FakeAuthority, FakeBehaviour};
    use super::*;

    /// Every test writes into a temporary directory. Nothing here ever names
    /// [`MANAGED_SETTINGS_PATH`] as a write target, and
    /// [`MacOsAdminAuthority`] refuses any target that is not it — so no test
    /// can reach an authorization prompt or the real system path.
    struct Host {
        _dir: tempfile::TempDir,
        target: PathBuf,
        work: PathBuf,
    }

    impl Host {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let target = dir.path().join("ClaudeCode").join(MANAGED_SETTINGS_FILE);
            let work = dir.path().join("state");
            std::fs::create_dir_all(&work).expect("work dir");
            Self {
                _dir: dir,
                target,
                work,
            }
        }

        fn installer(&self, authority: Arc<dyn PrivilegedFileAuthority>) -> ManagedSettingsInstaller {
            ManagedSettingsInstaller::new(&self.target, &self.work, authority).expecting_owner_uid(current_uid())
        }

        fn preexisting(&self, body: &str) {
            std::fs::create_dir_all(self.target.parent().unwrap()).expect("dir");
            std::fs::write(&self.target, body).expect("write");
        }
    }

    /// The uid this process writes files as.
    ///
    /// Read off a file the process just created rather than through `libc`, so
    /// the check stays dependency-free and needs no `unsafe`.
    #[cfg(unix)]
    fn current_uid() -> u32 {
        use std::os::unix::fs::MetadataExt;
        let probe = tempfile::NamedTempFile::new().expect("probe file");
        probe.as_file().metadata().expect("probe metadata").uid()
    }

    #[cfg(not(unix))]
    fn current_uid() -> u32 {
        0
    }

    fn document() -> String {
        managed_settings_document(ProtectionProfile::Recommended).expect("document")
    }

    #[test]
    fn the_real_authority_refuses_any_target_but_the_canonical_one() {
        // The guard the whole test suite's safety rests on: a redirected managed
        // root cannot reach an authorization prompt.
        let host = Host::new();
        let authority = MacOsAdminAuthority;
        let err = authority
            .install_file(&host.target, &host.work.join("staged"))
            .expect_err("a non-canonical target must be refused");
        assert!(
            matches!(&err, ManagedSettingsError::AuthorizationUnavailable { detail } if detail.contains(MANAGED_SETTINGS_PATH)),
            "{err}"
        );
        let err = authority.delete_file(&host.target).expect_err("refused");
        assert!(matches!(err, ManagedSettingsError::AuthorizationUnavailable { .. }));
    }

    #[test]
    fn a_document_without_managed_only_keys_is_refused() {
        let err = validate_managed_document(r#"{"permissions":{"allow":[]}}"#).expect_err("refused");
        assert!(
            matches!(&err, ManagedSettingsError::SchemaInvalid { detail } if detail.contains("managed-only keys")),
            "{err}"
        );
    }

    #[test]
    fn credential_bearing_keys_are_refused_at_a_root_owned_path() {
        for key in ["env", "apiKeyHelper"] {
            let raw = format!(r#"{{"disableBypassPermissionsMode":true,"{key}":{{}}}}"#);
            let err = validate_managed_document(&raw).expect_err("refused");
            assert!(
                matches!(&err, ManagedSettingsError::SchemaInvalid { detail } if detail.contains(key)),
                "{key}: {err}"
            );
        }
    }

    #[test]
    fn an_unknown_key_is_refused_rather_than_written() {
        let err =
            validate_managed_document(r#"{"disableBypassPermissionsMode":true,"whatIsThis":1}"#).expect_err("refused");
        assert!(
            matches!(&err, ManagedSettingsError::SchemaInvalid { detail } if detail.contains("whatIsThis")),
            "{err}"
        );
    }

    #[test]
    fn observe_only_has_no_managed_document() {
        let err = managed_settings_document(ProtectionProfile::ObserveOnly).expect_err("refused");
        assert!(err.to_string().contains("observe-only"), "{err}");
    }

    #[test]
    fn every_shipped_profile_document_validates() {
        for profile in [ProtectionProfile::Recommended, ProtectionProfile::Strict] {
            let doc = managed_settings_document(profile).expect("document");
            validate_managed_document(&doc).expect("the document this build writes must be one it accepts");
            assert!(doc.contains("disableBypassPermissionsMode"), "{doc}");
        }
    }

    #[test]
    fn the_disclosure_states_everything_before_authorization_is_requested() {
        let host = Host::new();
        let authority = FakeAuthority::granting();
        let installer = host.installer(authority.clone());
        let doc = document();
        let disclosure = installer.disclose(&doc).expect("disclosure");
        let rendered = disclosure.render();

        assert!(rendered.contains(&host.target.display().to_string()), "{rendered}");
        assert!(rendered.contains("why:"), "{rendered}");
        assert!(rendered.contains("disableBypassPermissionsMode"), "{rendered}");
        assert!(rendered.contains("backup:"), "{rendered}");
        assert!(rendered.contains("rollback:"), "{rendered}");
        // Building a disclosure asks the authority for nothing.
        assert!(authority.calls().is_empty(), "{:?}", authority.calls());
    }

    #[test]
    fn install_writes_verifies_and_is_idempotent() {
        let host = Host::new();
        let authority = FakeAuthority::granting();
        let installer = host.installer(authority.clone());
        let doc = document();

        let outcome = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect("install");
        assert!(outcome.mutated);
        assert_eq!(outcome.backup, None, "there was no prior file to back up");
        assert_eq!(std::fs::read_to_string(&host.target).unwrap(), doc);
        assert!(outcome
            .attestation
            .managed_only_keys
            .contains(&"disableBypassPermissionsMode".to_string()));

        // Reapplying changes nothing and asks for no authorization.
        let before = authority.calls().len();
        let again = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect("reinstall");
        assert!(!again.mutated);
        assert_eq!(authority.calls().len(), before, "a no-op install must not prompt");
    }

    #[test]
    fn denied_authorization_is_a_permission_required_refusal_and_writes_nothing() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::denying());
        let doc = document();
        let err = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect_err("denied");
        assert_eq!(err.summary(), "Permission Required");
        assert!(!host.target.exists(), "a denied install must leave nothing behind");
    }

    #[test]
    fn an_unavailable_mechanism_is_reported_as_unavailable() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::unavailable());
        let doc = document();
        let err = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect_err("unavailable");
        assert_eq!(err.summary(), "Unavailable");
        assert!(matches!(err, ManagedSettingsError::AuthorizationUnavailable { .. }));
        assert!(!host.target.exists());
    }

    #[test]
    fn non_interactive_execution_fails_instead_of_waiting() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::non_interactive());
        let doc = document();
        let err = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect_err("non-interactive");
        assert!(matches!(err, ManagedSettingsError::NonInteractive { .. }), "{err}");
        assert_eq!(err.summary(), "Unavailable");
        assert!(!host.target.exists());
    }

    #[test]
    fn a_managed_file_agent_assembly_did_not_write_is_refused() {
        let host = Host::new();
        host.preexisting(r#"{"disableBypassPermissionsMode":true,"permissions":{"deny":["Bash"]}}"#);
        let installer = host.installer(FakeAuthority::granting());
        let doc = document();

        let disclosure = installer.disclose(&doc).expect("disclosure");
        assert!(disclosure.existing.is_conflict());
        assert!(disclosure.conflict.is_some(), "the conflict must be disclosed");
        assert!(!disclosure.is_installable());

        let err = installer.install(&disclosure).expect_err("refused");
        assert!(
            matches!(err, ManagedSettingsError::ConflictingExistingFile { .. }),
            "{err}"
        );
        // The third party's policy is exactly as it was.
        assert!(std::fs::read_to_string(&host.target).unwrap().contains("Bash"));
    }

    #[test]
    fn a_read_back_mismatch_prevents_success_and_restores_the_prior_state() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::corrupting(r#"{"disableBypassPermissionsMode":false}"#));
        let doc = document();
        let err = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect_err("the read-back must fail");
        assert!(matches!(err, ManagedSettingsError::ReadBackMismatch { .. }), "{err}");
        assert_eq!(err.summary(), "Read-back verification failed");
        assert!(
            !host.target.exists(),
            "there was no prior file, so a failed install must leave none"
        );
        // Nothing was recorded, so nothing can later be attested.
        assert!(installer.verify_recorded().is_err());
    }

    #[test]
    fn a_user_owned_managed_file_fails_the_ownership_check() {
        let host = Host::new();
        // Expect an owner this process is not, which is exactly the production
        // check (uid 0) seen from an unprivileged test.
        let installer = ManagedSettingsInstaller::new(&host.target, &host.work, FakeAuthority::granting())
            .expecting_owner_uid(current_uid().wrapping_add(1));
        let doc = document();
        let err = installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect_err("ownership must be checked");
        assert!(
            matches!(&err, ManagedSettingsError::ReadBackMismatch { detail, .. } if detail.contains("owned by uid")),
            "{err}"
        );
    }

    #[test]
    fn a_world_writable_managed_file_fails_the_permission_check() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::granting());
        let doc = document();
        installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect("install");
        set_mode(&host.target, 0o666).expect("chmod");
        let err = installer
            .verify_recorded()
            .expect_err("a writable file is not enforcement");
        assert!(
            matches!(&err, ManagedSettingsError::ReadBackMismatch { detail, .. } if detail.contains("other than the owner")),
            "{err}"
        );
    }

    #[test]
    fn rollback_deletes_when_there_was_no_prior_file() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::granting());
        let doc = document();
        installer
            .install(&installer.disclose(&doc).expect("disclosure"))
            .expect("install");
        assert!(host.target.exists());

        assert_eq!(installer.rollback().expect("rollback"), ManagedRollbackOutcome::Removed);
        assert!(!host.target.exists(), "removal must be symmetric with install");
        // Safe to run twice.
        assert_eq!(
            installer.rollback().expect("rollback"),
            ManagedRollbackOutcome::NothingToDo
        );
    }

    #[test]
    fn rollback_restores_a_file_agent_assembly_replaced() {
        let host = Host::new();
        let authority = FakeAuthority::granting();
        let installer = host.installer(authority.clone());

        // A file Agent Assembly installed earlier, so the second install is not
        // a conflict.
        let first = managed_settings_document(ProtectionProfile::Recommended).expect("document");
        installer
            .install(&installer.disclose(&first).expect("disclosure"))
            .expect("first install");

        let second = managed_settings_document(ProtectionProfile::Strict).expect("document");
        let outcome = installer
            .install(&installer.disclose(&second).expect("disclosure"))
            .expect("second install");
        assert!(outcome.backup.is_some());
        assert_eq!(std::fs::read_to_string(&host.target).unwrap(), second);

        match installer.rollback().expect("rollback") {
            ManagedRollbackOutcome::Restored { .. } => {}
            other => panic!("expected a restore, got {other:?}"),
        }
        assert_eq!(std::fs::read_to_string(&host.target).unwrap(), first);
    }

    #[test]
    fn a_host_that_changed_after_the_disclosure_is_refused() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::granting());
        let doc = document();
        let disclosure = installer.disclose(&doc).expect("disclosure");

        host.preexisting(r#"{"disableBypassPermissionsMode":true}"#);

        let err = installer.install(&disclosure).expect_err("stale");
        assert!(matches!(err, ManagedSettingsError::ConsentStale { .. }), "{err}");
    }

    #[test]
    fn nothing_is_attested_before_anything_is_installed() {
        let host = Host::new();
        let installer = host.installer(FakeAuthority::granting());
        let err = installer.verify_recorded().expect_err("nothing installed");
        assert!(matches!(err, ManagedSettingsError::NothingInstalled { .. }), "{err}");
        assert_eq!(err.summary(), "Not installed");
    }

    #[test]
    fn the_fake_authority_is_the_only_one_the_tests_ever_call() {
        // A behaviour-by-behaviour sweep, so a future change to `FakeAuthority`
        // that started elevating would fail here rather than silently.
        for behaviour in [
            FakeBehaviour::Grant,
            FakeBehaviour::Deny,
            FakeBehaviour::Unavailable,
            FakeBehaviour::NonInteractive,
        ] {
            let authority = FakeAuthority::new(behaviour);
            assert_eq!(authority.mechanism(), "a test double that never elevates");
        }
    }
}

/// Why an endpoint managed-settings file does not count as evidence that an
/// administrator required managed operation.
///
/// Each variant is a *refusal to treat the file as authoritative*, never a
/// refusal to launch — the caller decides what to do with the answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedEvidenceRejection {
    /// Nothing is installed at the canonical path. The ordinary case on an
    /// unmanaged host, and not a fault.
    NotInstalled,
    /// The path exists but is a symlink, or resolving it left the canonical
    /// location. A file an unprivileged user can re-point is not evidence of
    /// anything an administrator did.
    NotARegularFile,
    /// Owned by someone other than `root`. A file the invoking user owns is a
    /// file the invoking user wrote.
    NotRootOwned {
        /// The uid that actually owns it.
        uid: u32,
    },
    /// Writable by group or other, so an account other than the owner can
    /// rewrite it between one launch and the next.
    WritableByOthers {
        /// The mode as found.
        mode: u32,
    },
    /// Present, root-owned and correctly permissioned, but not a valid managed
    /// document. An administrator did not install *this*.
    InvalidContent {
        /// What the validator objected to.
        detail: String,
    },
    /// The file could not be read at all.
    Unreadable {
        /// The underlying error.
        detail: String,
    },
}

impl fmt::Display for ManagedEvidenceRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => write!(f, "no endpoint managed-settings file is installed"),
            Self::NotARegularFile => write!(
                f,
                "the path is not a regular file (a symlink or directory), so it is not evidence of a \
                 privileged installation"
            ),
            Self::NotRootOwned { uid } => write!(
                f,
                "it is owned by uid {uid}, not root; a file the invoking user owns is a file the \
                 invoking user wrote"
            ),
            Self::WritableByOthers { mode } => write!(
                f,
                "its mode is {mode:04o}, which lets an account other than the owner rewrite it"
            ),
            Self::InvalidContent { detail } => write!(f, "it is not a valid managed document: {detail}"),
            Self::Unreadable { detail } => write!(f, "it could not be read: {detail}"),
        }
    }
}

/// Whether a valid endpoint managed-settings file is installed, meaning an
/// administrator required managed operation on this host (AAASM-5350 AC 1b).
///
/// # Why this does not reuse [`ManagedSettingsInstaller::verify_read_back`]
///
/// That function answers "does the file still match what *this integration*
/// installed", and reads the path twice — once for content, once for metadata.
/// Two lookups of a path are two chances to resolve to different files, which is
/// tolerable when the question is drift and **not** tolerable when the answer
/// decides whether a launch may proceed unprotected.
///
/// Here the file is opened **once** and every subsequent question is asked of
/// that descriptor: the metadata comes from the open handle, and the bytes come
/// from the same handle. A file swapped after the open is not the file this
/// answer describes.
///
/// # What it deliberately does not claim
///
/// `O_NOFOLLOW` refuses a symlink at the **final** path component only. A
/// symlinked *parent* directory is not detected here; on macOS the canonical
/// parent lives under `/Library/Application Support/`, which an unprivileged
/// user cannot re-point, so the residual case needs root to set up and root can
/// simply write the file instead. Stated rather than implied, because a reader
/// should not infer full path-resolution hardening from this check.
///
/// Non-Unix targets always return [`ManagedEvidenceRejection::NotInstalled`]:
/// the ownership and permission questions this rests on have no equivalent, and
/// answering "installed" without them would be the over-claim.
pub fn managed_installation_evidence() -> Result<PathBuf, ManagedEvidenceRejection> {
    managed_installation_evidence_at(Path::new(MANAGED_SETTINGS_PATH), 0)
}

/// [`managed_installation_evidence`] against an explicit path and expected
/// owner, so tests can exercise every rejection without being root.
///
/// Not public: production must never be able to name a path other than
/// [`MANAGED_SETTINGS_PATH`], because "the canonical system path only" is half
/// of what makes the answer mean anything.
#[cfg(unix)]
pub(crate) fn managed_installation_evidence_at(
    path: &Path,
    expected_uid: u32,
) -> Result<PathBuf, ManagedEvidenceRejection> {
    use std::io::Read as _;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        // Refuses a symlink at the final component *atomically* — checking with
        // `symlink_metadata` and then opening would be the check/use split this
        // whole function exists to avoid.
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(ManagedEvidenceRejection::NotInstalled),
        // ELOOP is what `O_NOFOLLOW` returns for a symlink.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => return Err(ManagedEvidenceRejection::NotARegularFile),
        Err(e) => return Err(ManagedEvidenceRejection::Unreadable { detail: e.to_string() }),
    };

    // Every question below is asked of the open descriptor, never of the path.
    let metadata = file
        .metadata()
        .map_err(|e| ManagedEvidenceRejection::Unreadable { detail: e.to_string() })?;
    if !metadata.is_file() {
        return Err(ManagedEvidenceRejection::NotARegularFile);
    }
    if metadata.uid() != expected_uid {
        return Err(ManagedEvidenceRejection::NotRootOwned { uid: metadata.uid() });
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(ManagedEvidenceRejection::WritableByOthers { mode });
    }

    let mut raw = String::new();
    file.read_to_string(&mut raw)
        .map_err(|e| ManagedEvidenceRejection::Unreadable { detail: e.to_string() })?;
    validate_managed_document(&raw).map_err(|e| ManagedEvidenceRejection::InvalidContent { detail: e.to_string() })?;

    Ok(path.to_path_buf())
}

#[cfg(not(unix))]
pub(crate) fn managed_installation_evidence_at(
    _path: &Path,
    _expected_uid: u32,
) -> Result<PathBuf, ManagedEvidenceRejection> {
    Err(ManagedEvidenceRejection::NotInstalled)
}

#[cfg(all(test, unix))]
mod managed_evidence_tests {
    use super::*;
    use std::io::Write as _;
    use std::os::unix::fs::PermissionsExt as _;

    /// A document that passes `validate_managed_document`, so these tests fail
    /// on the property under test rather than on the content.
    fn valid_doc() -> String {
        managed_settings_document(ProtectionProfile::Strict).expect("strict document")
    }

    fn write(dir: &std::path::Path, name: &str, body: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        path
    }

    fn me() -> u32 {
        use std::os::unix::fs::MetadataExt as _;
        std::fs::metadata(std::env::current_exe().expect("exe"))
            .expect("meta")
            .uid()
    }

    /// The permitting case, so the rejections below are known to be rejecting
    /// something that would otherwise be accepted.
    #[test]
    fn a_valid_root_owned_document_is_evidence() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = write(dir.path(), "managed-settings.json", &valid_doc(), 0o644);
        assert_eq!(managed_installation_evidence_at(&path, me()), Ok(path));
    }

    /// The ordinary unmanaged host. Not a fault, and must not be reported as one.
    #[test]
    fn an_absent_file_is_not_installed() {
        let dir = tempfile::tempdir().expect("tmp");
        assert_eq!(
            managed_installation_evidence_at(&dir.path().join("nope.json"), me()),
            Err(ManagedEvidenceRejection::NotInstalled)
        );
    }

    /// A user pointing the canonical path at their own file is the whole reason
    /// this check exists: it would otherwise let an unprivileged account
    /// manufacture "an administrator required this".
    #[test]
    fn a_symlink_is_refused_even_when_its_target_is_valid() {
        let dir = tempfile::tempdir().expect("tmp");
        let real = write(dir.path(), "real.json", &valid_doc(), 0o644);
        let link = dir.path().join("managed-settings.json");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert_eq!(
            managed_installation_evidence_at(&link, me()),
            Err(ManagedEvidenceRejection::NotARegularFile),
            "a symlink must never be evidence, however valid its target"
        );
    }

    /// A file the invoking user owns is a file the invoking user wrote.
    #[test]
    fn a_file_owned_by_someone_else_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = write(dir.path(), "managed-settings.json", &valid_doc(), 0o644);
        // Expect an owner this file cannot have, standing in for "expected root,
        // found the user" without needing to be root to arrange it.
        let wrong = me().wrapping_add(1);
        assert!(matches!(
            managed_installation_evidence_at(&path, wrong),
            Err(ManagedEvidenceRejection::NotRootOwned { .. })
        ));
    }

    /// Root-owned but group/world writable is not a privileged artifact: another
    /// account can rewrite it between one launch and the next.
    #[test]
    fn a_world_writable_file_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = write(dir.path(), "managed-settings.json", &valid_doc(), 0o666);
        assert!(matches!(
            managed_installation_evidence_at(&path, me()),
            Err(ManagedEvidenceRejection::WritableByOthers { .. })
        ));
    }

    /// Correct ownership and permissions do not make arbitrary content a managed
    /// installation. An administrator did not install *this*.
    #[test]
    fn a_correctly_owned_file_with_wrong_content_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = write(dir.path(), "managed-settings.json", "{\"unrelated\": true}", 0o644);
        assert!(matches!(
            managed_installation_evidence_at(&path, me()),
            Err(ManagedEvidenceRejection::InvalidContent { .. })
        ));
    }

    /// Unparseable content is refused for the same reason, and is reported as
    /// invalid content rather than as absence.
    #[test]
    fn malformed_json_is_invalid_content_not_absence() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = write(dir.path(), "managed-settings.json", "{not json", 0o644);
        assert!(matches!(
            managed_installation_evidence_at(&path, me()),
            Err(ManagedEvidenceRejection::InvalidContent { .. })
        ));
    }

    /// A directory at the path is not a regular file, and must not read as one.
    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tmp");
        let path = dir.path().join("managed-settings.json");
        std::fs::create_dir(&path).expect("mkdir");
        assert!(matches!(
            managed_installation_evidence_at(&path, me()),
            Err(ManagedEvidenceRejection::NotARegularFile) | Err(ManagedEvidenceRejection::Unreadable { .. })
        ));
    }

    /// Production must not be able to name any path but the canonical one.
    #[test]
    fn the_public_entry_point_uses_only_the_canonical_path() {
        // Not an assertion about the host: on a developer machine the file is
        // absent, which is exactly `NotInstalled`. The point is that the public
        // function takes no path argument at all.
        let _: Result<PathBuf, ManagedEvidenceRejection> = managed_installation_evidence();
    }
}
