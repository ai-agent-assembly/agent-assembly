//! A local, owner-only store for execution receipts (AAASM-6166).
//!
//! Mirrors `aa_core::integration::store::ReceiptStore`'s write/read discipline
//! (0700 directory, 0600 file, atomic rename, permissions re-asserted on
//! load) rather than widening that module's public API — `read_secure` there
//! is private, and this store's shape (one file per run, never overwritten)
//! differs enough from the one-receipt-per-(tool,scope) integration store
//! that sharing a type would be a worse fit than a ~20-line reimplementation
//! cited back to its source.
use super::schema::ReceiptEnvelope;

/// Subdirectory name under the state directory.
pub const RECEIPT_DIR: &str = "execution-receipts";

/// `aasm`'s state root: `$AASM_STATE_DIR`, or `~/.aasm` when unset.
///
/// Extracted out of [`ReceiptStore::default_location`] (AAASM-6162) so
/// `run_workspace_tx`'s own state root — a *sibling* subdirectory, never
/// nested under the receipt store's own `execution-receipts` — resolves
/// "where does aasm keep its state" exactly once, rather than re-deriving
/// the `$AASM_STATE_DIR`-or-`~/.aasm` fallback a second time and risking the
/// two answers drifting apart.
pub(crate) fn state_base() -> Result<std::path::PathBuf, StoreError> {
    match std::env::var_os("AASM_STATE_DIR") {
        Some(dir) if !dir.is_empty() => Ok(std::path::PathBuf::from(dir)),
        _ => Ok(dirs::home_dir().ok_or(StoreError::NoStateDirectory)?.join(".aasm")),
    }
}

/// Errors this store can produce.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No home directory could be resolved and `AASM_STATE_DIR` is unset.
    #[error("could not resolve a state directory: set AASM_STATE_DIR or ensure a home directory is discoverable")]
    NoStateDirectory,
    /// An I/O operation failed.
    #[error("I/O error at {path}: {source}")]
    Io {
        /// The path involved.
        path: std::path::PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The stored file could not be parsed as a receipt envelope.
    #[error("corrupt receipt at {path}: {detail}")]
    Corrupt {
        /// The path involved.
        path: std::path::PathBuf,
        /// What went wrong.
        detail: String,
    },
    /// The body could not be canonicalized to compute or check its seal.
    #[error("could not canonicalize the receipt body: {0}")]
    Canonical(#[from] super::canonical::CanonicalError),
}

/// A local store of execution receipts.
#[derive(Debug, Clone)]
pub struct ReceiptStore {
    root: std::path::PathBuf,
}

impl ReceiptStore {
    /// A store rooted at `root`, created on first write.
    pub fn at(root: impl Into<std::path::PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `${AASM_STATE_DIR:-~/.aasm}/execution-receipts` — a sibling
    /// subdirectory of `aa_core::integration::store::ReceiptStore`'s own
    /// default location, never sharing a file or name with an integration
    /// receipt.
    pub fn default_location() -> Result<Self, StoreError> {
        Ok(Self::at(state_base()?.join(RECEIPT_DIR)))
    }

    /// The directory receipts are written to.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }

    /// `<recorded_at_unix_secs>-<run_id>.execution-receipt.json`. One file per
    /// run; nothing is ever overwritten by [`write`](Self::write).
    pub fn path_for(&self, run_id: &str, recorded_at_unix_secs: u64) -> std::path::PathBuf {
        let safe_run_id: String = run_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        self.root
            .join(format!("{recorded_at_unix_secs}-{safe_run_id}.execution-receipt.json"))
    }

    /// Write `envelope`, 0700 directory / 0600 file, atomically.
    pub fn write(&self, envelope: &ReceiptEnvelope) -> Result<std::path::PathBuf, StoreError> {
        let path = self.path_for(&envelope.body.run_id, envelope.body.recorded_at_unix_secs);
        let body = serde_json::to_string_pretty(envelope).map_err(|e| StoreError::Corrupt {
            path: path.clone(),
            detail: e.to_string(),
        })?;

        std::fs::create_dir_all(&self.root).map_err(|source| StoreError::Io {
            path: self.root.clone(),
            source,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700)).map_err(|source| {
                StoreError::Io {
                    path: self.root.clone(),
                    source,
                }
            })?;
        }

        let tmp = path.with_extension("tmp");
        write_owner_only(&tmp, &body)?;
        std::fs::rename(&tmp, &path).map_err(|source| StoreError::Io {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    /// Load the envelope at `path`, re-asserting 0600 first.
    ///
    /// An unreadable or seal-mismatched file is an error the caller must fail
    /// closed on — never `Ok(None)`, never treated as "no receipt".
    pub fn load(path: &std::path::Path) -> Result<ReceiptEnvelope, StoreError> {
        let raw = read_secure(path)?;
        let envelope: ReceiptEnvelope = serde_json::from_str(&raw).map_err(|e| StoreError::Corrupt {
            path: path.to_path_buf(),
            detail: e.to_string(),
        })?;
        Ok(envelope)
    }
}

#[cfg(unix)]
fn write_owner_only(path: &std::path::Path, body: &str) -> Result<(), StoreError> {
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::fs::PermissionsExt as _;

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
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(())
}

#[cfg(not(unix))]
fn write_owner_only(path: &std::path::Path, body: &str) -> Result<(), StoreError> {
    std::fs::write(path, body).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Read `path`, re-asserting owner-only permissions first (cites
/// `aa-core/src/integration/store.rs`'s `read_secure` for the same pattern).
fn read_secure(path: &std::path::Path) -> Result<String, StoreError> {
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
    std::fs::read_to_string(path).map_err(|source| StoreError::Io {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::execution_receipt::schema::{
        AssertedIdentity, CredentialNames, ExecutionOutcome, PolicyBinding, ProducerIdentity, ReceiptBody, SpecBinding,
        TerminationRecord,
    };
    use crate::commands::execution_receipt::text::ReceiptText;

    fn sample_body() -> ReceiptBody {
        ReceiptBody {
            run_id: "run-1".to_string(),
            trace_id: "trace-1".to_string(),
            recorded_at_unix_secs: 1_700_000_000,
            asserted_identity: AssertedIdentity {
                agent_id: ReceiptText::screened("agent-1"),
                team_id: None,
                lineage: Vec::new(),
                depth: 0,
            },
            producer: ProducerIdentity::current(),
            policy: PolicyBinding {
                canonical_digest: None,
                source: None,
                resolution: ReceiptText::token("unconfigured"),
                unmapped: Vec::new(),
            },
            spec: SpecBinding {
                digest: super::super::canonical::Digest::of_canonical("{}"),
                program: ReceiptText::screened("true"),
                arg_count: 0,
                argv_digest: super::super::canonical::Digest::of_canonical("[]"),
                working_dir_digest: None,
                required_count: 0,
                optional_count: 0,
                degrade_if_unavailable_count: 0,
            },
            backend: None,
            host: Vec::new(),
            runtime_image: None,
            leases: Vec::new(),
            domains: Vec::new(),
            credentials: CredentialNames::default(),
            workspace: None,
            host_capability: None,
            execution: ExecutionOutcome {
                started_at_unix_secs: 1_700_000_000,
                ended_at_unix_secs: 1_700_000_001,
                exit_code: Some(0),
                no_code_detail: None,
                termination: TerminationRecord::SelfExited,
            },
            degraded: Vec::new(),
            withheld_fields: Vec::new(),
            evidence_refs: Vec::new(),
        }
    }

    #[test]
    fn a_written_receipt_is_owner_only_and_reloads_holding() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::at(dir.path());
        let envelope = ReceiptEnvelope::seal(sample_body()).unwrap();
        let path = store.write(&envelope).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600);
        }

        let loaded = ReceiptStore::load(&path).unwrap();
        assert_eq!(loaded, envelope);
        assert!(loaded.seal_holds().unwrap());
    }

    #[test]
    fn writing_twice_for_different_run_ids_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let store = ReceiptStore::at(dir.path());
        let mut body_a = sample_body();
        body_a.run_id = "run-a".to_string();
        let mut body_b = sample_body();
        body_b.run_id = "run-b".to_string();

        let path_a = store.write(&ReceiptEnvelope::seal(body_a).unwrap()).unwrap();
        let path_b = store.write(&ReceiptEnvelope::seal(body_b).unwrap()).unwrap();
        assert_ne!(path_a, path_b);
        assert!(path_a.exists());
        assert!(path_b.exists());
    }
}
