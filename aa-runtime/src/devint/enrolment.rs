//! The local enrolment file — how a first-party client on this host obtains a
//! capability token (ADR 0030 §5.3, AAASM-5280).
//!
//! # Why this exists at all
//!
//! [`super::token::TokenStore`] holds only hashes and hands the secret back
//! exactly once, to "the enrolment step". AAASM-5279 defined the store and left
//! the enrolment step to whoever built the first client. This is that step for
//! the client that ships in the same versioned unit as the runtime: `aasm`.
//!
//! It is deliberately the *narrow* case. A marketplace extension enrols
//! interactively and gets its own scoped token; this file covers only the CLI
//! that is distributed with the runtime, on the same machine, under the same
//! UID, and it is written into the `0700` run directory the socket already
//! lives in — so a reader of the token is already a process that could connect
//! to the socket and, being the same UID, could read the file the token would
//! have been typed into anyway. The token is not what keeps that attacker out;
//! the `0700` directory is (ADR 0030's accepted risk: "a capability token
//! stolen from the developer's own home directory is indistinguishable from the
//! legitimate client").
//!
//! # What the scope is, and why it is not narrower
//!
//! `aasm integrations <verb> <tool>` can name any tool the user asks for, so
//! the CLI's token is [`ToolScope::AllTools`] over the full lifecycle verb set.
//! Narrowing it per tool would mean re-enrolling on every `aasm integrations
//! install <new-tool>`, which buys nothing: the same UID that could use a
//! Codex-scoped token can read the file holding a Claude-Code-scoped one. The
//! per-tool scoping in §5.3 defends against a *third-party* client that was
//! enrolled for one tool, which is a different token and a different file.

use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::scope::{TokenScope, ToolScope};
use super::socket::{self, SocketError};
use super::token::{CapabilityToken, TokenRecord, TokenStore};

/// Filename of the local enrolment file inside the DI-API run directory.
const ENROLMENT_FILE: &str = "devint.token";

/// Environment override for the enrolment file path, so a test (or a second
/// runtime on the same machine) can point at its own.
const ENROLMENT_PATH_ENV: &str = "AA_DEVINT_TOKEN_FILE";

/// The mode both the writer and the reader require.
const REQUIRED_FILE_MODE: u32 = 0o600;

/// How long a locally enrolled CLI token lives before it must be re-issued.
///
/// Thirty days: long enough that a developer never meets it during normal work,
/// short enough that a token copied off a machine stops working within a
/// support window. The runtime re-enrols on every start, so the practical
/// lifetime is "until the runtime restarts", and this is the ceiling for a
/// runtime that never does.
pub const LOCAL_ENROLMENT_TTL_SECS: u64 = 30 * 24 * 60 * 60;

/// Why the enrolment file could not be written or read.
#[derive(Debug)]
pub enum EnrolmentError {
    /// The enrolment path could not be resolved.
    Path(SocketError),
    /// The file is not there. The caller has not been enrolled.
    NotEnrolled {
        /// Where the caller looked.
        path: PathBuf,
    },
    /// The file exists but is readable by more than its owner, so its contents
    /// must not be treated as a secret.
    Permissions {
        /// The offending file.
        path: PathBuf,
        /// What it actually is.
        actual: u32,
    },
    /// The file exists but holds nothing a token could be parsed from.
    Malformed {
        /// The offending file.
        path: PathBuf,
    },
    /// Reading or writing failed.
    Io(std::io::Error),
}

impl std::fmt::Display for EnrolmentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrolmentError::Path(e) => write!(f, "cannot resolve the enrolment file: {e}"),
            EnrolmentError::NotEnrolled { path } => write!(
                f,
                "this client is not enrolled with the runtime (no capability token at {}); \
                 restart the Agent Assembly runtime to enrol it",
                path.display()
            ),
            EnrolmentError::Permissions { path, actual } => write!(
                f,
                "the capability token at {} is mode {actual:o}, expected {REQUIRED_FILE_MODE:o}; \
                 it must not be treated as a secret — restart the runtime to re-enrol",
                path.display()
            ),
            EnrolmentError::Malformed { path } => write!(
                f,
                "the capability token at {} is empty or unreadable; restart the runtime to re-enrol",
                path.display()
            ),
            EnrolmentError::Io(e) => write!(f, "capability token I/O error: {e}"),
        }
    }
}

impl std::error::Error for EnrolmentError {}

impl From<std::io::Error> for EnrolmentError {
    fn from(e: std::io::Error) -> Self {
        EnrolmentError::Io(e)
    }
}

/// Resolve the enrolment file path: `$AA_DEVINT_TOKEN_FILE`, else the DI-API
/// socket's own `0700` directory.
///
/// Derived from the socket path rather than resolved independently so that a
/// test (or a second runtime) which redirects `AA_DEVINT_SOCKET` moves the
/// token with it — a token pointing at one runtime and a socket at another is a
/// confusing failure that this makes unrepresentable.
pub fn enrolment_path() -> Result<PathBuf, EnrolmentError> {
    if let Some(explicit) = std::env::var_os(ENROLMENT_PATH_ENV) {
        return Ok(PathBuf::from(explicit));
    }
    let socket = socket::devint_socket_path().map_err(EnrolmentError::Path)?;
    let dir = socket.parent().ok_or_else(|| {
        EnrolmentError::Path(SocketError::NoParent {
            path: socket.to_path_buf(),
        })
    })?;
    Ok(dir.join(ENROLMENT_FILE))
}

/// Issue a token for the first-party local client and write it `0600`.
///
/// Called by the runtime as it brings the DI-API up, so a `aasm integrations`
/// invocation against a freshly started runtime finds a live token rather than
/// an enrolment prompt it has no way to satisfy. Any previous file is replaced:
/// the old secret's record is gone with the old process's [`TokenStore`], so
/// leaving it in place would only offer a token that is guaranteed to be denied.
pub fn enrol_local_client(
    tokens: &TokenStore,
    client_name: &str,
    now_unix_secs: u64,
) -> Result<(PathBuf, TokenRecord), EnrolmentError> {
    let path = enrolment_path()?;
    // `prepare_socket_dir` operates on its argument's *parent*, so handing it
    // the token path reuses the socket's own `0700` construction verbatim — the
    // token never lands in a directory laxer than the socket beside it.
    socket::prepare_socket_dir(&path).map_err(EnrolmentError::Path)?;

    let (token, record) = tokens.issue(
        client_name,
        TokenScope::full_lifecycle(ToolScope::AllTools),
        now_unix_secs,
        LOCAL_ENROLMENT_TTL_SECS,
    );

    // Replace rather than truncate-in-place: an existing file may already be
    // open in a reader, and `.mode(0600)` only applies to a file this call
    // creates. Removing first makes the mode unconditional.
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(REQUIRED_FILE_MODE)
        .open(&path)?;
    file.write_all(token.expose().as_bytes())?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    drop(file);

    // Re-assert rather than assume, for the same reason the socket does: what
    // matters is what the kernel will enforce for the next reader.
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(REQUIRED_FILE_MODE))?;
    assert_owner_only(&path)?;

    Ok((path, record))
}

/// Read the enrolled capability token, refusing one that is not owner-only.
///
/// A token in a world-readable file is not a secret, and using it anyway would
/// turn a filesystem mistake into a silent authentication downgrade. Callers
/// get [`EnrolmentError::Permissions`] and a remediation instead.
pub fn read_local_token(path: &Path) -> Result<CapabilityToken, EnrolmentError> {
    if !path.exists() {
        return Err(EnrolmentError::NotEnrolled {
            path: path.to_path_buf(),
        });
    }
    assert_owner_only(path)?;
    let raw = std::fs::read_to_string(path)?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(EnrolmentError::Malformed {
            path: path.to_path_buf(),
        });
    }
    Ok(CapabilityToken::from_wire(trimmed))
}

fn assert_owner_only(path: &Path) -> Result<(), EnrolmentError> {
    let actual = std::fs::metadata(path)?.permissions().mode() & 0o777;
    if actual != REQUIRED_FILE_MODE {
        return Err(EnrolmentError::Permissions {
            path: path.to_path_buf(),
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devint::verb::DiVerb;

    /// Point the enrolment path at a temp file for the duration of a test.
    ///
    /// `AA_DEVINT_TOKEN_FILE` is process-global, so these tests are serialized
    /// by a mutex rather than by hope.
    fn with_path<T>(path: &Path, f: impl FnOnce() -> T) -> T {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        std::env::set_var(ENROLMENT_PATH_ENV, path);
        let out = f();
        std::env::remove_var(ENROLMENT_PATH_ENV);
        out
    }

    #[test]
    fn an_enrolled_token_round_trips_and_resolves_for_every_lifecycle_verb() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        let tokens = TokenStore::new();
        let (written, record) = with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("enrol"));
        assert_eq!(written, path);
        assert_eq!(record.client_name, "aasm");

        let token = read_local_token(&path).expect("read");
        for verb in DiVerb::ALL {
            assert!(
                tokens.resolve(Some(&token), verb, "claude-code", 1_001).is_ok(),
                "the local CLI token must cover {verb}"
            );
        }
    }

    #[test]
    fn the_enrolment_file_is_written_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        let tokens = TokenStore::new();
        with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("enrol"));
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, REQUIRED_FILE_MODE, "the token file must be 0600");
    }

    #[test]
    fn a_group_readable_token_is_refused_rather_than_used() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        let tokens = TokenStore::new();
        with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("enrol"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        match read_local_token(&path) {
            Err(EnrolmentError::Permissions { actual, .. }) => assert_eq!(actual, 0o644),
            other => panic!("a world-readable token must be refused, got {other:?}"),
        }
    }

    #[test]
    fn an_absent_file_reads_as_not_enrolled_rather_than_as_an_io_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        match read_local_token(&path) {
            Err(EnrolmentError::NotEnrolled { path: reported }) => assert_eq!(reported, path),
            other => panic!("expected NotEnrolled, got {other:?}"),
        }
    }

    #[test]
    fn re_enrolling_replaces_the_previous_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        let tokens = TokenStore::new();
        with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("first"));
        let first = std::fs::read_to_string(&path).expect("read");
        with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("second"));
        let second = std::fs::read_to_string(&path).expect("read");
        assert_ne!(first, second, "re-enrolment must not reuse the previous secret");
    }

    /// The error text is what a user sees when the runtime is running but has
    /// not enrolled them. It must never quote the token it was looking for.
    #[test]
    fn enrolment_errors_never_echo_a_secret() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("devint.token");
        let tokens = TokenStore::new();
        with_path(&path, || enrol_local_client(&tokens, "aasm", 1_000).expect("enrol"));
        let secret = std::fs::read_to_string(&path).expect("read").trim().to_string();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let rendered = read_local_token(&path).expect_err("must refuse").to_string();
        assert!(!rendered.contains(&secret), "an enrolment error leaked the token");
    }
}
