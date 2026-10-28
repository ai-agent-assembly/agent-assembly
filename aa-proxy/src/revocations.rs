//! Durable record of revoked broker credentials (AAASM-6262, J84 AC3).
//!
//! A revocation that lived only in memory would be undone by any proxy restart:
//! the next start re-reads `AA_PROXY_PROVIDER_KEYS` and injects the credential
//! again. This file is what makes a revocation survive that, so the proxy
//! re-applies it as a tombstone before it accepts a connection.
//!
//! The file holds **host names only**, one per line, lowercase. It never holds
//! or derives anything from a secret, so reading it, logging its path, or losing
//! it cannot expose a credential.
//!
//! Failure posture, stated because this is a security record: a file that
//! exists but cannot be read, is not owner-only, or contains an invalid line is
//! an error, and the proxy refuses to start on it, because "I cannot tell what
//! was revoked" must not be read as "nothing was revoked". A missing file is an
//! empty set.
//!
//! What this does not do: it does not authenticate who wrote the file. The
//! record only ever removes access, so tampering with it can deny service but
//! never grants it; a same-UID process that can delete a line can also restart
//! the proxy with its own environment, which this layer does not claim to stop.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Longest valid DNS name; anything longer is rejected rather than truncated.
const MAX_HOST_LEN: usize = 253;

/// Why the revocation record could not be loaded or written.
#[derive(Debug)]
pub enum RevocationFileError {
    /// The file could not be read or written.
    Io(std::io::Error),
    /// Line `line` (1-based) is not a valid host name.
    InvalidHost {
        /// The offending line number.
        line: usize,
    },
    /// The file is writable by group or others, so its content cannot be trusted
    /// to have come from the owner.
    Insecure {
        /// The file's permission bits.
        mode: u32,
    },
    /// The directory holding the file is writable by group or others, or belongs
    /// to another user, so whoever can write there can replace or remove the
    /// record, and an absent record would read as "nothing revoked".
    InsecureDir {
        /// The directory's permission bits.
        mode: u32,
        /// Whether the directory is owned by the proxy's own user.
        owned: bool,
    },
}

impl fmt::Display for RevocationFileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "revocation file I/O error: {e}"),
            Self::InvalidHost { line } => write!(f, "revocation file line {line} is not a valid host name"),
            Self::Insecure { mode } => write!(
                f,
                "revocation file mode {mode:o} lets group or others write it; refusing to trust it"
            ),
            Self::InsecureDir { mode, owned } => write!(
                f,
                "revocation file directory (mode {mode:o}, owned by this user: {owned}) is not private; refusing to trust it"
            ),
        }
    }
}

impl std::error::Error for RevocationFileError {}

impl From<std::io::Error> for RevocationFileError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Lowercase and validate a host name for the record.
///
/// Accepts ASCII letters, digits, `.` and `-` only: the store keys credentials
/// by bare host, so a port, a path or whitespace can never match one and is
/// refused rather than silently stored.
pub fn normalize_host(raw: &str) -> Option<String> {
    let host = raw.trim().to_ascii_lowercase();
    let valid = !host.is_empty()
        && host.len() <= MAX_HOST_LEN
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-');
    valid.then_some(host)
}

/// Refuse a record whose directory anyone but the proxy's own user can change.
///
/// The record's own mode is not enough: a directory another user can write lets
/// them delete the file, and a missing record reads as an empty set, which is
/// exactly "nothing was revoked". A directory that does not exist yet is not an
/// error here (there is nothing to trust, and nothing for anyone to have planted).
///
/// # Errors
///
/// [`RevocationFileError::InsecureDir`] when the directory is not owned by the
/// current user or is writable by group or others.
pub fn verify_private_parent(path: &Path) -> Result<(), RevocationFileError> {
    use std::os::unix::fs::MetadataExt;
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let metadata = match std::fs::metadata(parent) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    let mode = metadata.permissions().mode() & 0o777;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let owned = metadata.uid() == unsafe { libc::geteuid() };
    if !owned || mode & 0o022 != 0 {
        return Err(RevocationFileError::InsecureDir { mode, owned });
    }
    Ok(())
}

/// Read the revoked hosts from `path`.
///
/// A missing file is an empty set. Blank lines are ignored.
///
/// # Errors
///
/// [`RevocationFileError`] when the file exists but is unreadable, group/other
/// writable, or has an invalid line, or when its directory is not private
/// (see [`verify_private_parent`]).
pub fn load(path: &Path) -> Result<BTreeSet<String>, RevocationFileError> {
    verify_private_parent(path)?;
    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(e) => return Err(e.into()),
    };
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o022 != 0 {
        return Err(RevocationFileError::Insecure { mode });
    }
    let text = std::fs::read_to_string(path)?;
    let mut hosts = BTreeSet::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let host = normalize_host(line).ok_or(RevocationFileError::InvalidHost { line: index + 1 })?;
        hosts.insert(host);
    }
    Ok(hosts)
}

/// Add `host` to the record at `path`, durably.
///
/// Writes the whole set to a sibling temporary file created owner-only,
/// flushes it, and renames it over `path`, so a crash leaves either the old
/// record or the new one, never a torn file. Recording a host that is already
/// present is a no-op that still succeeds.
///
/// # Errors
///
/// [`RevocationFileError`] when the existing record cannot be trusted or the
/// write fails. The caller has already revoked in memory by then; it reports
/// the failure rather than undoing the revocation.
pub fn record(path: &Path, host: &str) -> Result<(), RevocationFileError> {
    let host = normalize_host(host).ok_or(RevocationFileError::InvalidHost { line: 0 })?;
    let mut hosts = load(path)?;
    if !hosts.insert(host) {
        return Ok(());
    }
    let tmp = temp_path_for(path);
    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        for h in &hosts {
            writeln!(file, "{h}")?;
        }
        file.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("revoked-credentials")
    }

    #[test]
    fn a_missing_file_is_an_empty_set() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&file_in(&dir)).unwrap().is_empty());
    }

    #[test]
    fn a_recorded_host_is_loaded_back_lowercased_and_deduplicated() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir);
        record(&path, "API.Anthropic.com").unwrap();
        record(&path, "api.anthropic.com").unwrap();
        record(&path, "api.openai.com").unwrap();
        let hosts: Vec<String> = load(&path).unwrap().into_iter().collect();
        assert_eq!(hosts, ["api.anthropic.com", "api.openai.com"]);
    }

    #[test]
    fn the_record_is_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir);
        record(&path, "api.anthropic.com").unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn a_group_or_world_writable_record_is_refused_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir);
        record(&path, "api.anthropic.com").unwrap();
        // Positive control: the same file loads while it is owner-only.
        assert_eq!(load(&path).unwrap().len(), 1);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(load(&path), Err(RevocationFileError::Insecure { .. })));
    }

    #[test]
    fn a_record_in_a_group_or_world_writable_directory_is_refused_even_when_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir);
        // Positive control: the same absent record in a private directory is an empty set.
        assert!(load(&path).unwrap().is_empty());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        // An absent record in a directory anyone can write would read as "nothing
        // revoked", which an attacker could arrange by deleting the file.
        assert!(matches!(
            load(&path),
            Err(RevocationFileError::InsecureDir { owned: true, .. })
        ));
        assert!(record(&path, "api.anthropic.com").is_err());
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn a_missing_directory_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("not-yet").join("revoked-credentials");
        assert!(load(&path).unwrap().is_empty());
    }

    #[test]
    fn an_invalid_line_fails_the_load_instead_of_being_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let path = file_in(&dir);
        std::fs::write(&path, "api.anthropic.com\nnot a host:443\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load(&path), Err(RevocationFileError::InvalidHost { line: 2 })));
    }

    #[test]
    fn host_names_with_ports_paths_or_whitespace_are_not_recorded() {
        assert_eq!(normalize_host(" API.Example.com "), Some("api.example.com".to_string()));
        for bad in ["", "host:443", "a/b", "a b", "ex ample.com", &"a".repeat(254)] {
            assert_eq!(normalize_host(bad), None, "{bad:?}");
        }
        let dir = tempfile::tempdir().unwrap();
        assert!(record(&file_in(&dir), "host:443").is_err());
        assert!(!file_in(&dir).exists(), "a refused host must not create the record");
    }

    #[test]
    fn recording_leaves_no_temporary_file_behind() {
        let dir = tempfile::tempdir().unwrap();
        record(&file_in(&dir), "api.anthropic.com").unwrap();
        let names: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["revoked-credentials"]);
    }
}
