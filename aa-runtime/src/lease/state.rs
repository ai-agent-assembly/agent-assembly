//! The lease state record: what a governed run was granted and what has been
//! revoked since.
//!
//! # Why a record, and why a missing one is an error
//!
//! A governed run is bound to one policy digest and one issue time. The record
//! is the only place that binding and the revocation set survive a restart.
//! If a missing record were treated as "start a new run", deleting the file
//! would silently re-grant every revoked lease. So [`load`] reports
//! [`LeaseStateError::Missing`] as its own error and a new run is created only
//! by the explicit operator command, through [`init_run`].
//!
//! # Lease ids
//!
//! A lease id is `"{subject}:{digest12}:{run_id}:{issued_at}:{domain}"` (see
//! [`lease_id`]): the subject, the first 12 characters of the policy digest,
//! the run's random `run_id` (128 bits, lowercase hex), the run's `issued_at`
//! in unix seconds, and a domain word naming what the lease covers. The id is
//! derived, never stored, so the CLI that revokes it and the runtime that
//! checks it cannot disagree about its shape.
//!
//! * **Uniqueness per run** comes from `run_id`, drawn from the OS-seeded
//!   CSPRNG when a run is created. It does not depend on the clock, so a
//!   stepped-back clock, two inits in one second, or `init` over an unreadable
//!   or deleted record cannot recreate an id revoked in an earlier run.
//!   `issued_at` is informational.
//! * **Injective encoding.** Subjects are real agent ids and legitimately
//!   contain `:` (`did:key:...`), so the subject component is percent-encoded
//!   (`%` becomes `%25`, `:` becomes `%3A`). The domain word is restricted to
//!   `[a-z0-9_-]`, 1 to 64 characters. The remaining components contain no
//!   `:`, so distinct inputs cannot produce the same id.
//!
//! # Concurrency and crash safety
//!
//! Readers need no lock: `write_atomic` writes a temp file in the same
//! directory, fsyncs it, renames it over the record and fsyncs the directory,
//! so a reader sees the old record or the new one and never a partial one.
//! Writers that read-modify-write ([`revoke_ids`], [`init_run`]) serialise on
//! an exclusive `flock` of a sibling `<state>.lock` file.
//!
//! # What the record does and does not protect
//!
//! * Deleting the record and running `init` again starts a new run and drops
//!   every revocation, by design. That is why a runtime consuming this record
//!   must refuse to start when it is missing, never create one.
//! * A record is at most 1 MiB and at most [`MAX_REVOKED`] revoked ids. A
//!   revocation that would exceed either is refused before anything is
//!   written, so the stored record is always one `load` accepts.
//! * Rollback is not detected across loads: a restored older but valid record
//!   is accepted by [`load`], because [`check_monotonic`] only compares two
//!   in-memory records (AAASM-5533). Same-UID tampering is out of scope.
//! * Parent directories that are symlinks are refused, which includes paths
//!   under macOS `/tmp` (a symlink to `/private/tmp`) when the state file sits
//!   directly in a symlinked directory; use the resolved path.
//!
//! # Trust model
//!
//! The record and its directory are treated as operator-owned. The loader
//! refuses a symlinked record or parent directory, a record that is not a
//! regular file owned by the current user with mode `0600`-or-stricter, and a
//! parent directory that is group- or world-writable without the sticky bit.
//! Those checks are made on open file descriptors where possible, but a path
//! check followed by an open is not atomic: this does not defend against an
//! attacker who can already write inside the state directory as the same user.

use std::collections::BTreeSet;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

/// The only record version this build reads or writes.
pub const STATE_VERSION: u32 = 1;

/// Upper bound on a record read from disk, so a hostile file cannot make the
/// loader allocate without limit.
const MAX_RECORD_BYTES: u64 = 1024 * 1024;
const MAX_SUBJECT_LEN: usize = 512;
const MAX_ID_LEN: usize = 1024;
const DIGEST_MIN_LEN: usize = 12;
const DIGEST_MAX_LEN: usize = 128;
/// Number of leading digest characters embedded in a lease id.
const DIGEST_PREFIX_LEN: usize = 12;
/// Upper bound on the revocation set, so the record stays well inside
/// [`MAX_RECORD_BYTES`] and the runtime's reload stays cheap.
pub const MAX_REVOKED: usize = 10_000;
const RUN_ID_LEN: usize = 32;
const MAX_DOMAIN_LEN: usize = 64;

/// Why a record could not be loaded, written or accepted.
///
/// The variants are distinct on purpose: a caller deciding whether to refuse
/// to start must be able to tell "never initialised" from "tampered with".
#[derive(Debug)]
pub enum LeaseStateError {
    /// No record exists at the path. Never auto-created.
    Missing(PathBuf),
    /// A record exists but is not valid: not JSON, unknown field, malformed
    /// field, unsorted or duplicated revocations, oversized.
    Corrupt(String),
    /// A well-formed record of a `version` this build does not understand.
    VersionUnsupported(u64),
    /// An operating-system error other than the record being absent.
    Io(io::Error),
    /// Input to a constructor or mutator was rejected.
    Invalid(String),
    /// A record already exists and the caller did not ask to replace it.
    AlreadyExists(PathBuf),
    /// The path, its directory or its permissions are not acceptable (symlink,
    /// wrong owner, group/world access).
    InsecureTarget(String),
    /// A new record is not a legal successor of the one it would replace.
    NotMonotonic(String),
    /// The record is valid but belongs to a different subject or policy than
    /// the caller expected.
    Mismatch(String),
}

impl fmt::Display for LeaseStateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing(p) => write!(f, "lease state record not found at {}", p.display()),
            Self::Corrupt(why) => write!(f, "lease state record is corrupt: {why}"),
            Self::VersionUnsupported(v) => {
                write!(
                    f,
                    "lease state record version {v} is not supported (this build reads {STATE_VERSION})"
                )
            }
            Self::Io(e) => write!(f, "lease state I/O error: {e}"),
            Self::Invalid(why) => write!(f, "invalid lease state input: {why}"),
            Self::AlreadyExists(p) => write!(f, "a lease state record already exists at {}", p.display()),
            Self::InsecureTarget(why) => write!(f, "refusing insecure lease state location: {why}"),
            Self::NotMonotonic(why) => write!(f, "lease state change is not monotonic: {why}"),
            Self::Mismatch(why) => write!(f, "lease state record does not match this run: {why}"),
        }
    }
}

impl std::error::Error for LeaseStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for LeaseStateError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

/// The durable lease record.
///
/// Fields are private so every value in memory has passed `LeaseState::validate`;
/// construct with [`LeaseState::new_run`] or [`LeaseState::parse`].
///
/// Deserialization goes through a private raw struct and `LeaseState::validate`,
/// so a value obtained from serde is as trustworthy as one from [`LeaseState::parse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawLeaseState")]
pub struct LeaseState {
    version: u32,
    subject: String,
    policy_digest: String,
    run_id: String,
    issued_at: u64,
    generation: u64,
    revoked: Vec<String>,
}

/// Unvalidated wire form; never exposed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLeaseState {
    version: u32,
    subject: String,
    policy_digest: String,
    run_id: String,
    issued_at: u64,
    generation: u64,
    revoked: Vec<String>,
}

impl TryFrom<RawLeaseState> for LeaseState {
    type Error = String;
    fn try_from(r: RawLeaseState) -> Result<Self, String> {
        let s = Self {
            version: r.version,
            subject: r.subject,
            policy_digest: r.policy_digest,
            run_id: r.run_id,
            issued_at: r.issued_at,
            generation: r.generation,
            revoked: r.revoked,
        };
        s.validate()?;
        Ok(s)
    }
}

/// Reads only `version`, ignoring every other field, so an unsupported
/// version is reported as such rather than as an unknown-field error.
#[derive(Deserialize)]
struct VersionProbe {
    version: Option<serde_json::Value>,
}

fn check_text(what: &str, s: &str, max: usize) -> Result<(), String> {
    if s.trim().is_empty() {
        return Err(format!("{what} is empty"));
    }
    if s.len() > max {
        return Err(format!("{what} exceeds {max} bytes"));
    }
    if s.chars().any(char::is_control) {
        return Err(format!("{what} contains a control character"));
    }
    Ok(())
}

fn check_subject(s: &str) -> Result<(), String> {
    check_text("subject", s, MAX_SUBJECT_LEN)?;
    if s.chars().any(char::is_whitespace) {
        return Err("subject contains whitespace".to_string());
    }
    Ok(())
}

fn check_run_id(r: &str) -> Result<(), String> {
    if r.len() != RUN_ID_LEN || !r.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(format!("run_id must be {RUN_ID_LEN} lowercase hex characters"));
    }
    Ok(())
}

fn check_domain(d: &str) -> Result<(), String> {
    if d.is_empty()
        || d.len() > MAX_DOMAIN_LEN
        || !d
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(format!("domain must be 1..={MAX_DOMAIN_LEN} characters of [a-z0-9_-]"));
    }
    Ok(())
}

fn encode_subject(subject: &str) -> String {
    subject.replace('%', "%25").replace(':', "%3A")
}

fn check_digest(d: &str) -> Result<(), String> {
    if d.len() < DIGEST_MIN_LEN || d.len() > DIGEST_MAX_LEN {
        return Err(format!(
            "policy_digest must be {DIGEST_MIN_LEN}..={DIGEST_MAX_LEN} lowercase hex characters"
        ));
    }
    if !d.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("policy_digest must be lowercase hex".to_string());
    }
    Ok(())
}

impl LeaseState {
    /// A fresh run: generation 1, nothing revoked. `now` is unix seconds.
    ///
    /// Draws a fresh random `run_id`, which is what makes this run's lease ids
    /// distinct from every earlier run's regardless of the clock.
    pub fn new_run(subject: &str, policy_digest: &str, now: u64) -> Result<Self, LeaseStateError> {
        Self::new_run_with_id(subject, policy_digest, hex::encode(rand::random::<[u8; 16]>()), now)
    }

    fn new_run_with_id(subject: &str, policy_digest: &str, run_id: String, now: u64) -> Result<Self, LeaseStateError> {
        let s = Self {
            version: STATE_VERSION,
            subject: subject.to_string(),
            policy_digest: policy_digest.to_string(),
            run_id,
            issued_at: now,
            generation: 1,
            revoked: Vec::new(),
        };
        s.validate().map_err(LeaseStateError::Invalid)?;
        Ok(s)
    }

    /// Record version.
    pub fn version(&self) -> u32 {
        self.version
    }
    /// The server-side agent id this run's leases are issued to.
    pub fn subject(&self) -> &str {
        &self.subject
    }
    /// Digest of the policy this run is bound to.
    pub fn policy_digest(&self) -> &str {
        &self.policy_digest
    }
    /// Random per-run identifier (32 lowercase hex characters); part of every lease id.
    pub fn run_id(&self) -> &str {
        &self.run_id
    }
    /// Unix seconds at which the run was issued. Informational; uniqueness
    /// comes from [`run_id`](Self::run_id).
    pub fn issued_at(&self) -> u64 {
        self.issued_at
    }
    /// Monotonic revision counter, 1 for a fresh run.
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// Revoked lease ids, sorted and unique.
    pub fn revoked(&self) -> &[String] {
        &self.revoked
    }
    /// Whether `id` has been revoked.
    pub fn is_revoked(&self, id: &str) -> bool {
        self.revoked.binary_search_by(|r| r.as_str().cmp(id)).is_ok()
    }
    /// This run's id for `domain`; see [`lease_id`].
    pub fn lease_id(&self, domain: &str) -> Result<String, LeaseStateError> {
        lease_id(&self.subject, &self.policy_digest, &self.run_id, self.issued_at, domain)
    }
    /// Everything in this run's lease ids before the domain word, ending in `:`.
    pub fn lease_id_prefix(&self) -> String {
        let digest12: String = self.policy_digest.chars().take(DIGEST_PREFIX_LEN).collect();
        format!(
            "{}:{digest12}:{}:{}:",
            encode_subject(&self.subject),
            self.run_id,
            self.issued_at
        )
    }

    fn validate(&self) -> Result<(), String> {
        if self.version != STATE_VERSION {
            return Err(format!("version {} is not {STATE_VERSION}", self.version));
        }
        check_subject(&self.subject)?;
        check_digest(&self.policy_digest)?;
        check_run_id(&self.run_id)?;
        if self.issued_at == 0 {
            return Err("issued_at must be a positive unix time".to_string());
        }
        if self.generation == 0 {
            return Err("generation must be at least 1".to_string());
        }
        if self.revoked.len() > MAX_REVOKED {
            return Err(format!("revoked holds more than {MAX_REVOKED} ids"));
        }
        for id in &self.revoked {
            check_text("revoked id", id, MAX_ID_LEN)?;
        }
        if !self.revoked.windows(2).all(|w| w[0] < w[1]) {
            return Err("revoked must be sorted and free of duplicates".to_string());
        }
        Ok(())
    }

    /// Add `ids` to the revocation set. Returns whether the set changed.
    ///
    /// Idempotent: revoking only already-revoked ids changes nothing and does
    /// not advance the generation, since a reload would learn nothing new. Any
    /// real addition advances the generation by exactly one.
    pub fn revoke<I, S>(&mut self, ids: I) -> Result<bool, LeaseStateError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut set: BTreeSet<String> = self.revoked.iter().cloned().collect();
        let before = set.len();
        for id in ids {
            let id = id.as_ref();
            check_text("revoked id", id, MAX_ID_LEN).map_err(LeaseStateError::Invalid)?;
            set.insert(id.to_string());
        }
        if set.len() == before {
            return Ok(false);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| LeaseStateError::Invalid("generation overflow".to_string()))?;
        let mut candidate = self.clone();
        candidate.revoked = set.into_iter().collect();
        candidate.generation = generation;
        // Refuse here, before anything is written, any record `load` would
        // later reject for size, or the runtime could never start again.
        candidate.validate().map_err(LeaseStateError::Invalid)?;
        if candidate.to_bytes().len() as u64 > MAX_RECORD_BYTES {
            return Err(LeaseStateError::Invalid(format!(
                "revocation set would make the record larger than {MAX_RECORD_BYTES} bytes"
            )));
        }
        *self = candidate;
        Ok(true)
    }

    /// Canonical serialized form: pretty JSON, trailing newline.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = serde_json::to_vec_pretty(self).expect("LeaseState serialization is infallible");
        out.push(b'\n');
        out
    }

    /// Strictly parse a record. Rejects unknown or duplicated fields, trailing
    /// garbage, an unsupported version, and any value `LeaseState::validate`
    /// would refuse.
    pub fn parse(bytes: &[u8]) -> Result<Self, LeaseStateError> {
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(LeaseStateError::Corrupt(format!(
                "larger than {MAX_RECORD_BYTES} bytes"
            )));
        }
        let probe: VersionProbe = serde_json::from_slice(bytes).map_err(|e| LeaseStateError::Corrupt(e.to_string()))?;
        match probe.version {
            Some(serde_json::Value::Number(n)) => match n.as_u64() {
                Some(v) if v == u64::from(STATE_VERSION) => {}
                Some(v) => return Err(LeaseStateError::VersionUnsupported(v)),
                None => {
                    return Err(LeaseStateError::Corrupt(
                        "version is not an unsigned integer".to_string(),
                    ))
                }
            },
            Some(_) => return Err(LeaseStateError::Corrupt("version is not a number".to_string())),
            None => return Err(LeaseStateError::Corrupt("version is missing".to_string())),
        }
        // Validation runs inside deserialization (`try_from`).
        serde_json::from_slice(bytes).map_err(|e| LeaseStateError::Corrupt(e.to_string()))
    }
}

/// The deterministic lease id `"{subject}:{digest12}:{run_id}:{issued_at}:{domain}"`.
///
/// `digest12` is the first 12 characters of `policy_digest`; the subject has
/// `%` and `:` percent-encoded so the id is injective; `domain` must be 1-64
/// characters of `[a-z0-9_-]`. Invalid components are an error rather than an
/// id, so two different inputs can never share one. Pure, so the CLI and the
/// runtime derive identical ids from the same record.
pub fn lease_id(
    subject: &str,
    policy_digest: &str,
    run_id: &str,
    issued_at: u64,
    domain: &str,
) -> Result<String, LeaseStateError> {
    check_subject(subject).map_err(LeaseStateError::Invalid)?;
    check_digest(policy_digest).map_err(LeaseStateError::Invalid)?;
    check_run_id(run_id).map_err(LeaseStateError::Invalid)?;
    check_domain(domain).map_err(LeaseStateError::Invalid)?;
    let digest12: String = policy_digest.chars().take(DIGEST_PREFIX_LEN).collect();
    Ok(format!(
        "{}:{digest12}:{run_id}:{issued_at}:{domain}",
        encode_subject(subject)
    ))
}

/// Check that `new` may replace `old` on a reload.
///
/// The revocation set may only grow. The run's identity (subject, policy
/// digest, issue time, version) may not change at all: a different run is a
/// restart through `init`, never a reload. The generation may not go back, and
/// may not stay put while the set changes.
pub fn check_monotonic(old: &LeaseState, new: &LeaseState) -> Result<(), LeaseStateError> {
    let bad = |why: &str| Err(LeaseStateError::NotMonotonic(why.to_string()));
    if old.version != new.version {
        return bad("version changed");
    }
    if old.subject != new.subject {
        return bad("subject changed");
    }
    if old.policy_digest != new.policy_digest {
        return bad("policy digest changed");
    }
    if old.run_id != new.run_id {
        return bad("run_id changed");
    }
    if old.issued_at != new.issued_at {
        return bad("issued_at (run anchor) changed");
    }
    if new.generation < old.generation {
        return bad("generation went backwards");
    }
    let new_set: BTreeSet<&String> = new.revoked.iter().collect();
    if !old.revoked.iter().all(|id| new_set.contains(id)) {
        return bad("revocation set shrank");
    }
    if new.generation == old.generation && new.revoked != old.revoked {
        return bad("revocation set changed without a generation bump");
    }
    Ok(())
}

fn metadata_nofollow(path: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
}

/// Refuse a parent directory that is a symlink, not a directory, or writable
/// by group/other without the sticky bit.
fn check_parent(path: &Path) -> Result<(), LeaseStateError> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    let md = metadata_nofollow(parent)?;
    if md.file_type().is_symlink() {
        return Err(LeaseStateError::InsecureTarget(format!(
            "parent directory {} is a symlink",
            parent.display()
        )));
    }
    if !md.is_dir() {
        return Err(LeaseStateError::InsecureTarget(format!(
            "parent {} is not a directory",
            parent.display()
        )));
    }
    let mode = md.permissions().mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(LeaseStateError::InsecureTarget(format!(
            "parent directory {} is group/world-writable (mode {:o})",
            parent.display(),
            mode & 0o7777
        )));
    }
    Ok(())
}

/// Load and strictly validate the record at `path`.
///
/// Never creates anything. `Missing` is returned only when no entry exists.
pub fn load(path: &Path) -> Result<LeaseState, LeaseStateError> {
    match metadata_nofollow(path) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(LeaseStateError::InsecureTarget(format!(
                "{} is a symlink",
                path.display()
            )))
        }
        // A FIFO or device would block `open`; refuse before opening.
        Ok(md) if !md.is_file() => {
            return Err(LeaseStateError::InsecureTarget(format!(
                "{} is not a regular file",
                path.display()
            )))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(LeaseStateError::Missing(path.to_path_buf())),
        Err(e) => return Err(e.into()),
    }
    check_parent(path)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| match e.kind() {
            io::ErrorKind::NotFound => LeaseStateError::Missing(path.to_path_buf()),
            _ => LeaseStateError::Io(e),
        })?;
    let md = file.metadata()?;
    if !md.is_file() {
        return Err(LeaseStateError::InsecureTarget(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    if md.mode() & 0o077 != 0 {
        return Err(LeaseStateError::InsecureTarget(format!(
            "{} has mode {:o}; it must not be accessible to group or other",
            path.display(),
            md.mode() & 0o7777
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    if md.uid() != unsafe { libc::geteuid() } {
        return Err(LeaseStateError::InsecureTarget(format!(
            "{} is not owned by the current user",
            path.display()
        )));
    }
    let mut buf = Vec::new();
    file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut buf)?;
    LeaseState::parse(&buf)
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn fsync_dir(path: &Path) -> io::Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(parent)?.sync_all()
}

/// Atomically replace the record at `path` with `state`.
///
/// Temp file in the same directory (mode 0600, `O_EXCL`, no symlink follow),
/// fsync, rename, fsync of the directory. Refuses a symlinked target or parent.
/// A stale temp file left by a crash is never read by [`load`] and never blocks
/// a later write, which uses a fresh temp name.
///
/// Crate-private: callers outside this module go through [`init_run`] and
/// [`revoke_ids`], which hold the lock and enforce the monotonic rule.
pub(crate) fn write_atomic(path: &Path, state: &LeaseState) -> Result<(), LeaseStateError> {
    state.validate().map_err(LeaseStateError::Invalid)?;
    let bytes = state.to_bytes();
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(LeaseStateError::Invalid(format!(
            "record is larger than {MAX_RECORD_BYTES} bytes"
        )));
    }
    let name = path
        .file_name()
        .ok_or_else(|| LeaseStateError::Invalid("state path has no file name".to_string()))?
        .to_string_lossy()
        .into_owned();
    check_parent(path)?;
    match metadata_nofollow(path) {
        Ok(md) if md.file_type().is_symlink() => {
            return Err(LeaseStateError::InsecureTarget(format!(
                "{} is a symlink",
                path.display()
            )))
        }
        Ok(md) if !md.is_file() => {
            return Err(LeaseStateError::InsecureTarget(format!(
                "{} exists and is not a regular file",
                path.display()
            )))
        }
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }

    let tmp = path.with_file_name(format!(
        ".{name}.tmp.{}.{}",
        std::process::id(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> io::Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        fsync_dir(path)
    })();
    if let Err(e) = result {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    Ok(())
}

/// Exclusive advisory lock on `<state>.lock`, released on drop.
///
/// Serialises read-modify-write of one record across threads and processes.
/// `flock` locks are per open file description, so two `acquire` calls in one
/// process contend with each other as well.
pub struct StateLock {
    _file: File,
}

impl StateLock {
    /// Path of the lock file belonging to the record at `state_path`.
    pub fn lock_path(state_path: &Path) -> PathBuf {
        let mut name = state_path.file_name().map(|n| n.to_os_string()).unwrap_or_default();
        name.push(".lock");
        state_path.with_file_name(name)
    }

    /// Block until the exclusive lock is held. Creates the lock file (0600) if
    /// absent, so callers that must create nothing check for the record first.
    pub fn acquire(state_path: &Path) -> Result<Self, LeaseStateError> {
        check_parent(state_path)?;
        let lock = Self::lock_path(state_path);
        match metadata_nofollow(&lock) {
            Ok(md) if !md.is_file() => {
                return Err(LeaseStateError::InsecureTarget(format!(
                    "{} is not a regular file",
                    lock.display()
                )))
            }
            _ => {}
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&lock)?;
        let md = file.metadata()?;
        // SAFETY: geteuid has no preconditions and cannot fail.
        if !md.is_file() || md.mode() & 0o077 != 0 || md.uid() != unsafe { libc::geteuid() } {
            return Err(LeaseStateError::InsecureTarget(format!(
                "{} must be a regular file owned by the current user with mode 0600",
                lock.display()
            )));
        }
        use std::os::fd::AsRawFd;
        loop {
            // SAFETY: the fd is valid for the lifetime of `file`.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                break;
            }
            let err = io::Error::last_os_error();
            if err.kind() != io::ErrorKind::Interrupted {
                return Err(err.into());
            }
        }
        Ok(Self { _file: file })
    }
}

/// Create the record for a new run at `path`.
///
/// Refuses to touch an existing record unless `force`. With `force` the new
/// record is generation 1 with an empty revocation set and a fresh random
/// `run_id`, so none of its lease ids can equal an id revoked in the replaced
/// run, whether or not that record was readable and whatever the clock says.
pub fn init_run(
    path: &Path,
    subject: &str,
    policy_digest: &str,
    now: u64,
    force: bool,
) -> Result<LeaseState, LeaseStateError> {
    // Validate input before creating a lock file.
    let state = LeaseState::new_run(subject, policy_digest, now)?;
    let _lock = StateLock::acquire(path)?;
    match metadata_nofollow(path) {
        Ok(_) if !force => return Err(LeaseStateError::AlreadyExists(path.to_path_buf())),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    write_atomic(path, &state)?;
    Ok(state)
}

/// Load the record and require it to belong to `subject` and `policy_digest`.
///
/// This is the runtime's start-up check. Every error, `Mismatch` included,
/// means the runtime must refuse to start.
pub fn load_expected(path: &Path, subject: &str, policy_digest: &str) -> Result<LeaseState, LeaseStateError> {
    let state = load(path)?;
    if state.subject != subject {
        return Err(LeaseStateError::Mismatch("subject differs from the record".to_string()));
    }
    if state.policy_digest != policy_digest {
        return Err(LeaseStateError::Mismatch(
            "policy digest differs from the record".to_string(),
        ));
    }
    Ok(state)
}

/// Add `ids` to the record at `path` under the state lock.
///
/// Fails closed: a missing or corrupt record is an error and nothing is
/// created. Returns the record as it stands after the call.
pub fn revoke_ids<S: AsRef<str>>(path: &Path, ids: &[S]) -> Result<LeaseState, LeaseStateError> {
    for id in ids {
        check_text("revoked id", id.as_ref(), MAX_ID_LEN).map_err(LeaseStateError::Invalid)?;
    }
    // Existence is checked before the lock so a missing record leaves no lock file behind.
    match metadata_nofollow(path) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(LeaseStateError::Missing(path.to_path_buf())),
        Err(e) => return Err(e.into()),
    }
    let _lock = StateLock::acquire(path)?;
    let mut state = load(path)?;
    let old = state.clone();
    if state.revoke(ids)? {
        check_monotonic(&old, &state)?;
        write_atomic(path, &state)?;
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;

    const D: &str = "0123456789abcdef0123456789abcdef";
    const R: &str = "00112233445566778899aabbccddeeff";

    fn run(now: u64) -> LeaseState {
        LeaseState::new_run_with_id("agent-1", D, R.to_string(), now).unwrap()
    }

    fn tmp() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn round_trips_through_bytes() {
        let mut s = run(1_700_000_000);
        s.revoke(["b", "a"]).unwrap();
        assert_eq!(LeaseState::parse(&s.to_bytes()).unwrap(), s);
        assert_eq!(s.revoked(), ["a", "b"]);
        assert_eq!(s.generation(), 2);
    }

    #[test]
    fn json_shape_is_the_documented_record() {
        let v: serde_json::Value = serde_json::from_slice(&run(5).to_bytes()).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"version":1,"subject":"agent-1","policy_digest":D,"run_id":R,"issued_at":5,"generation":1,"revoked":[]})
        );
    }

    fn rec(extra: &str, version: &str, subject: &str, revoked: &str) -> String {
        format!(
            r#"{{"version":{version},"subject":"{subject}","policy_digest":"{D}","run_id":"{R}","issued_at":5,"generation":1,"revoked":{revoked}{extra}}}"#
        )
    }

    #[test]
    fn parse_accepts_the_baseline_fixture() {
        LeaseState::parse(rec("", "1", "s", "[]").as_bytes()).unwrap();
    }

    #[test]
    fn parse_rejects_unknown_field() {
        let e = LeaseState::parse(rec(r#","extra":1"#, "1", "s", "[]").as_bytes()).unwrap_err();
        assert!(matches!(e, LeaseStateError::Corrupt(_)), "{e}");
    }

    #[test]
    fn parse_rejects_wrong_version_distinctly() {
        let e = LeaseState::parse(rec("", "2", "s", "[]").as_bytes()).unwrap_err();
        assert!(matches!(e, LeaseStateError::VersionUnsupported(2)), "{e}");
        // A future version with fields this build has never heard of is still
        // "unsupported version", not "corrupt".
        let e = LeaseState::parse(rec(r#","new":1"#, "9", "s", "[]").as_bytes()).unwrap_err();
        assert!(matches!(e, LeaseStateError::VersionUnsupported(9)), "{e}");
        let e = LeaseState::parse(br#"{"subject":"s"}"#).unwrap_err();
        assert!(matches!(e, LeaseStateError::Corrupt(_)), "{e}");
    }

    #[test]
    fn parse_rejects_truncated_garbage_and_trailing_bytes() {
        let good = rec("", "1", "s", "[]");
        for bad in [
            &good.as_bytes()[..good.len() - 5],
            b"".as_slice(),
            b"not json".as_slice(),
            b"[]".as_slice(),
            b"null".as_slice(),
        ] {
            assert!(matches!(LeaseState::parse(bad), Err(LeaseStateError::Corrupt(_))));
        }
        let trailing = format!("{good} garbage");
        assert!(matches!(
            LeaseState::parse(trailing.as_bytes()),
            Err(LeaseStateError::Corrupt(_))
        ));
        let dup = good.replace(r#""generation":1"#, r#""generation":1,"generation":1"#);
        assert!(matches!(
            LeaseState::parse(dup.as_bytes()),
            Err(LeaseStateError::Corrupt(_))
        ));
    }

    #[test]
    fn parse_rejects_unsorted_duplicate_and_empty_values() {
        for revoked in [r#"["b","a"]"#, r#"["a","a"]"#, r#"[""]"#] {
            let e = LeaseState::parse(rec("", "1", "s", revoked).as_bytes()).unwrap_err();
            assert!(matches!(e, LeaseStateError::Corrupt(_)), "{revoked}: {e}");
        }
        for subject in ["", "  ", "a\\u0000b"] {
            let e = LeaseState::parse(rec("", "1", subject, "[]").as_bytes()).unwrap_err();
            assert!(matches!(e, LeaseStateError::Corrupt(_)), "{subject:?}: {e}");
        }
        for digest in ["", "abc", "ZZZZZZZZZZZZ", "0123456789AB"] {
            let json = rec("", "1", "s", "[]").replace(D, digest);
            assert!(matches!(
                LeaseState::parse(json.as_bytes()),
                Err(LeaseStateError::Corrupt(_))
            ));
        }
        let zero_gen = rec("", "1", "s", "[]").replace(r#""generation":1"#, r#""generation":0"#);
        assert!(matches!(
            LeaseState::parse(zero_gen.as_bytes()),
            Err(LeaseStateError::Corrupt(_))
        ));
    }

    #[test]
    fn new_run_rejects_bad_input() {
        assert!(matches!(
            LeaseState::new_run("", D, 5),
            Err(LeaseStateError::Invalid(_))
        ));
        assert!(matches!(
            LeaseState::new_run("s", "", 5),
            Err(LeaseStateError::Invalid(_))
        ));
        assert!(matches!(
            LeaseState::new_run("s", D, 0),
            Err(LeaseStateError::Invalid(_))
        ));
    }

    #[test]
    fn revoke_is_idempotent_and_bumps_generation_only_on_change() {
        let mut s = run(5);
        assert!(s.revoke(["x"]).unwrap());
        assert_eq!(s.generation(), 2);
        assert!(!s.revoke(["x"]).unwrap());
        assert_eq!(s.generation(), 2);
        assert!(s.revoke(["x", "y", "y"]).unwrap());
        assert_eq!(s.generation(), 3);
        assert!(s.is_revoked("y") && !s.is_revoked("z"));
        assert!(matches!(s.revoke([""]), Err(LeaseStateError::Invalid(_))));
        assert_eq!(s.generation(), 3);
    }

    #[test]
    fn lease_id_is_deterministic_and_has_the_documented_form() {
        let s = run(1234);
        let expect = format!("agent-1:0123456789ab:{R}:1234:net");
        assert_eq!(lease_id("agent-1", D, R, 1234, "net").unwrap(), expect);
        assert_eq!(s.lease_id("net").unwrap(), expect);
        assert_eq!(s.lease_id_prefix(), format!("agent-1:0123456789ab:{R}:1234:"));
        assert_ne!(s.lease_id("net").unwrap(), s.lease_id("fs").unwrap());
    }

    #[test]
    fn lease_id_is_injective_over_colon_bearing_inputs() {
        // The review's collision: with raw concatenation both inputs yield the
        // same string. Subjects may legitimately contain ':' (did:key).
        let a = lease_id("a:aaaaaaaaaaaa:5:b", "c".repeat(12).as_str(), R, 7, "dom").unwrap();
        // A domain containing ':' is not representable at all.
        assert!(matches!(
            lease_id("a", &"c".repeat(12), R, 7, "b:cccccccccccc:7:dom"),
            Err(LeaseStateError::Invalid(_))
        ));
        let b = lease_id("a", &"c".repeat(12), R, 7, "dom").unwrap();
        assert_ne!(a, b);
        // '%' and ':' in a subject encode distinctly.
        assert_ne!(
            lease_id("a%3Ab", D, R, 1, "d").unwrap(),
            lease_id("a:b", D, R, 1, "d").unwrap()
        );
        assert!(lease_id("did:key:z6Mk", D, R, 1, "d")
            .unwrap()
            .starts_with("did%3Akey%3Az6Mk:"));
        for bad in ["", "Net", "a b", "a/b", &"x".repeat(65)] {
            assert!(lease_id("a", D, R, 1, bad).is_err(), "{bad:?}");
        }
        assert!(lease_id("a b", D, R, 1, "d").is_err());
        assert!(lease_id("a", D, "short", 1, "d").is_err());
    }

    #[test]
    fn subject_with_colon_is_accepted_but_whitespace_is_not() {
        LeaseState::new_run("did:key:z6MkExample", D, 5).unwrap();
        for bad in ["a b", "a\tb", "a\nb"] {
            assert!(matches!(
                LeaseState::new_run(bad, D, 5),
                Err(LeaseStateError::Invalid(_))
            ));
        }
        let e = LeaseState::parse(rec("", "1", "a b", "[]").as_bytes()).unwrap_err();
        assert!(matches!(e, LeaseStateError::Corrupt(_)), "{e}");
    }

    #[test]
    fn serde_deserialize_cannot_bypass_validation() {
        // Unsorted revoked would make `is_revoked`'s binary search lie.
        let unsorted = rec("", "1", "s", r#"["b","a"]"#);
        assert!(serde_json::from_slice::<LeaseState>(unsorted.as_bytes()).is_err());
        let dup = rec("", "1", "s", r#"["a","a"]"#);
        assert!(serde_json::from_slice::<LeaseState>(dup.as_bytes()).is_err());
        let unknown = rec(r#","x":1"#, "1", "s", "[]");
        assert!(serde_json::from_slice::<LeaseState>(unknown.as_bytes()).is_err());
        let bad_run = rec("", "1", "s", "[]").replace(R, "ZZ");
        assert!(serde_json::from_slice::<LeaseState>(bad_run.as_bytes()).is_err());
        let ok: LeaseState = serde_json::from_slice(rec("", "1", "s", r#"["a","b"]"#).as_bytes()).unwrap();
        assert!(ok.is_revoked("b"));
    }

    #[test]
    fn run_id_is_random_per_run_and_well_formed() {
        let a = LeaseState::new_run("s", D, 100).unwrap();
        let b = LeaseState::new_run("s", D, 100).unwrap();
        assert_eq!(a.run_id().len(), 32);
        assert_ne!(a.run_id(), b.run_id());
        assert_ne!(a.lease_id("net").unwrap(), b.lease_id("net").unwrap());
    }

    #[test]
    fn revoke_refuses_oversize_record_before_writing() {
        let d = tmp();
        let p = d.path().join("lease.json");
        write_atomic(&p, &run(5)).unwrap();
        let big = |n: usize| format!("{n:04}{}", "x".repeat(1000));
        // Fill close to the cap in one in-memory step, then push past it
        // through the real revoke path one id at a time.
        let mut filled = load(&p).unwrap();
        filled.revoke((0..1020).map(big)).unwrap();
        write_atomic(&p, &filled).unwrap();
        let mut refused = false;
        for n in 1020..1100 {
            match revoke_ids(&p, &[big(n)]) {
                Ok(_) => {}
                Err(LeaseStateError::Invalid(_)) => {
                    refused = true;
                    break;
                }
                Err(e) => panic!("unexpected {e}"),
            }
        }
        assert!(refused, "size cap never tripped");
        let before = fs::read(&p).unwrap();
        assert!(before.len() as u64 <= MAX_RECORD_BYTES);
        assert!(matches!(revoke_ids(&p, &[big(9999)]), Err(LeaseStateError::Invalid(_))));
        assert_eq!(fs::read(&p).unwrap(), before, "record unchanged on refusal");
        load(&p).expect("stored record must stay loadable");
    }

    #[test]
    fn revoke_refuses_more_than_max_revoked_ids() {
        let mut s = run(5);
        let ids: Vec<String> = (0..MAX_REVOKED).map(|i| format!("i{i:05}")).collect();
        s.revoke(&ids).unwrap();
        let g = s.generation();
        assert!(matches!(s.revoke(["one-more"]), Err(LeaseStateError::Invalid(_))));
        assert_eq!(s.generation(), g);
        assert_eq!(s.revoked().len(), MAX_REVOKED);
    }

    #[test]
    fn load_expected_distinguishes_mismatch() {
        let d = tmp();
        let p = d.path().join("lease.json");
        assert!(matches!(
            load_expected(&p, "agent-1", D),
            Err(LeaseStateError::Missing(_))
        ));
        write_atomic(&p, &run(5)).unwrap();
        load_expected(&p, "agent-1", D).unwrap();
        assert!(matches!(
            load_expected(&p, "agent-2", D),
            Err(LeaseStateError::Mismatch(_))
        ));
        assert!(matches!(
            load_expected(&p, "agent-1", &"f".repeat(32)),
            Err(LeaseStateError::Mismatch(_))
        ));
    }

    #[test]
    fn fifo_record_and_fifo_lock_are_refused_without_blocking() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let c = std::ffi::CString::new(p.to_str().unwrap()).unwrap();
        // SAFETY: c is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(load(&p), Err(LeaseStateError::InsecureTarget(_))));
        let lock = StateLock::lock_path(&p);
        let c = std::ffi::CString::new(lock.to_str().unwrap()).unwrap();
        // SAFETY: as above.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(matches!(
            StateLock::acquire(&p),
            Err(LeaseStateError::InsecureTarget(_))
        ));
    }

    #[test]
    fn loose_lock_file_mode_is_refused() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let lock = StateLock::lock_path(&p);
        fs::write(&lock, b"").unwrap();
        fs::set_permissions(&lock, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            StateLock::acquire(&p),
            Err(LeaseStateError::InsecureTarget(_))
        ));
    }

    #[test]
    fn missing_and_corrupt_are_distinct() {
        let d = tmp();
        let p = d.path().join("lease.json");
        assert!(matches!(load(&p), Err(LeaseStateError::Missing(_))));
        write_atomic(&p, &run(5)).unwrap();
        fs::write(&p, b"{").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(load(&p), Err(LeaseStateError::Corrupt(_))));
        let missing_dir = d.path().join("nope").join("lease.json");
        assert!(matches!(load(&missing_dir), Err(LeaseStateError::Missing(_))));
    }

    #[test]
    fn write_then_load_round_trips_with_mode_0600() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let s = run(5);
        write_atomic(&p, &s).unwrap();
        assert_eq!(load(&p).unwrap(), s);
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn rewrite_tightens_a_loose_existing_mode() {
        let d = tmp();
        let p = d.path().join("lease.json");
        write_atomic(&p, &run(5)).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(load(&p), Err(LeaseStateError::InsecureTarget(_))));
        write_atomic(&p, &run(6)).unwrap();
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        load(&p).unwrap();
    }

    #[test]
    fn stale_partial_temp_neither_corrupts_nor_blocks() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let s = run(5);
        write_atomic(&p, &s).unwrap();
        // A crash mid-write leaves a truncated temp beside the record.
        let stale = d.path().join(".lease.json.tmp.1.0");
        fs::write(&stale, b"{\"version\":1,\"sub").unwrap();
        assert_eq!(load(&p).unwrap(), s);
        let mut s2 = s.clone();
        s2.revoke(["a"]).unwrap();
        write_atomic(&p, &s2).unwrap();
        assert_eq!(load(&p).unwrap(), s2);
        assert!(stale.exists(), "unrelated stale temp must be left alone");
    }

    #[test]
    fn failed_write_leaves_record_untouched_and_no_temp() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let s = run(5);
        write_atomic(&p, &s).unwrap();
        // Make the target a directory-shaped obstacle: rename onto it must fail.
        let q = d.path().join("dir");
        fs::create_dir(&q).unwrap();
        assert!(write_atomic(&q, &s).is_err());
        let leftovers: Vec<_> = fs::read_dir(d.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        assert_eq!(load(&p).unwrap(), s);
    }

    #[test]
    fn symlinked_target_is_refused_for_write_and_load() {
        let d = tmp();
        let real = d.path().join("real.json");
        write_atomic(&real, &run(5)).unwrap();
        let link = d.path().join("link.json");
        symlink(&real, &link).unwrap();
        assert!(matches!(load(&link), Err(LeaseStateError::InsecureTarget(_))));
        let before = fs::read(&real).unwrap();
        assert!(matches!(
            write_atomic(&link, &run(9)),
            Err(LeaseStateError::InsecureTarget(_))
        ));
        assert_eq!(fs::read(&real).unwrap(), before);
        // A dangling symlink must not be written through either.
        let dangling = d.path().join("dangling.json");
        symlink(d.path().join("nowhere.json"), &dangling).unwrap();
        assert!(matches!(
            write_atomic(&dangling, &run(9)),
            Err(LeaseStateError::InsecureTarget(_))
        ));
        assert!(!d.path().join("nowhere.json").exists());
    }

    #[test]
    fn symlinked_or_writable_parent_is_refused() {
        let d = tmp();
        let real = d.path().join("realdir");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let link = d.path().join("linkdir");
        symlink(&real, &link).unwrap();
        assert!(matches!(
            write_atomic(&link.join("lease.json"), &run(5)),
            Err(LeaseStateError::InsecureTarget(_))
        ));
        let open = d.path().join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(matches!(
            write_atomic(&open.join("lease.json"), &run(5)),
            Err(LeaseStateError::InsecureTarget(_))
        ));
    }

    #[test]
    fn monotonic_accepts_growth_and_identity_and_rejects_everything_else() {
        let old = {
            let mut s = run(5);
            s.revoke(["a", "b"]).unwrap();
            s
        };
        check_monotonic(&old, &old).unwrap();
        let mut grown = old.clone();
        grown.revoke(["c"]).unwrap();
        check_monotonic(&old, &grown).unwrap();

        let mut shrunk = old.clone();
        shrunk.revoked = vec!["a".into()];
        shrunk.generation += 1;
        let mut other_subject = old.clone();
        other_subject.subject = "agent-2".into();
        let mut other_digest = old.clone();
        other_digest.policy_digest = "f".repeat(32);
        let mut other_run = old.clone();
        other_run.run_id = "f".repeat(32);
        let mut other_anchor = old.clone();
        other_anchor.issued_at += 1;
        let mut backwards = grown.clone();
        backwards.generation = old.generation - 1;
        let mut same_gen_changed = grown.clone();
        same_gen_changed.generation = old.generation;
        for (name, bad) in [
            ("shrink", shrunk),
            ("subject", other_subject),
            ("digest", other_digest),
            ("anchor", other_anchor),
            ("run_id", other_run),
            ("backwards", backwards),
            ("same-gen change", same_gen_changed),
        ] {
            assert!(
                matches!(check_monotonic(&old, &bad), Err(LeaseStateError::NotMonotonic(_))),
                "{name} must be rejected"
            );
        }
    }

    #[test]
    fn init_refuses_existing_without_force() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let first = init_run(&p, "agent-1", D, 100, false).unwrap();
        assert_eq!(first.generation(), 1);
        let before = fs::read(&p).unwrap();
        assert!(matches!(
            init_run(&p, "agent-1", D, 200, false),
            Err(LeaseStateError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&p).unwrap(), before, "refusal must not modify the record");
    }

    #[test]
    fn force_init_never_reuses_a_revoked_id_even_over_corrupt_record_at_earlier_clock() {
        let d = tmp();
        let p = d.path().join("lease.json");
        let first = init_run(&p, "agent-1", D, 5_000, false).unwrap();
        let revoked_id = first.lease_id("net").unwrap();
        revoke_ids(&p, &[revoked_id.clone()]).unwrap();

        // Same second.
        let same = init_run(&p, "agent-1", D, 5_000, true).unwrap();
        assert_eq!(same.generation(), 1);
        assert!(same.revoked().is_empty());
        assert_ne!(same.lease_id("net").unwrap(), revoked_id);
        assert!(!same.is_revoked(&same.lease_id("net").unwrap()));

        // Unreadable old record and a clock stepped back.
        fs::write(&p, b"garbage").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let earlier = init_run(&p, "agent-1", D, 1_000, true).unwrap();
        assert!(earlier.issued_at() < first.issued_at());
        assert_ne!(earlier.lease_id("net").unwrap(), revoked_id);
        assert_ne!(earlier.lease_id("net").unwrap(), same.lease_id("net").unwrap());
    }

    #[test]
    fn two_inits_in_the_same_second_yield_different_ids() {
        let d = tmp();
        let a = init_run(&d.path().join("a.json"), "agent-1", D, 77, false).unwrap();
        let b = init_run(&d.path().join("b.json"), "agent-1", D, 77, false).unwrap();
        assert_eq!(a.issued_at(), b.issued_at());
        assert_ne!(a.lease_id("net").unwrap(), b.lease_id("net").unwrap());
    }

    #[test]
    fn revoke_on_missing_record_fails_and_creates_nothing() {
        let d = tmp();
        let p = d.path().join("lease.json");
        assert!(matches!(revoke_ids(&p, &["x"]), Err(LeaseStateError::Missing(_))));
        assert_eq!(fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[test]
    fn revoke_on_corrupt_record_fails_and_leaves_it_alone() {
        let d = tmp();
        let p = d.path().join("lease.json");
        write_atomic(&p, &run(5)).unwrap();
        fs::write(&p, b"garbage").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(matches!(revoke_ids(&p, &["x"]), Err(LeaseStateError::Corrupt(_))));
        assert_eq!(fs::read(&p).unwrap(), b"garbage");
    }

    #[test]
    fn concurrent_revokes_lose_no_id_and_generation_counts_each() {
        const THREADS: usize = 16;
        const PER: usize = 6;
        let d = tmp();
        let p = Arc::new(d.path().join("lease.json"));
        write_atomic(&p, &run(5)).unwrap();
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let p = Arc::clone(&p);
                std::thread::spawn(move || {
                    for i in 0..PER {
                        revoke_ids(&p, &[format!("lease-{t}-{i}")]).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let s = load(&p).unwrap();
        assert_eq!(s.revoked().len(), THREADS * PER, "an id was lost");
        assert_eq!(s.generation(), 1 + (THREADS * PER) as u64);
    }
}
