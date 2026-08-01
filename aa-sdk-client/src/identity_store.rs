//! Durable, owner-only storage for an agent's identity private key (AAASM-5332).
//!
//! # What this is for
//!
//! An agent's registration possession proof is the only control deciding who may
//! register as a given agent: `AgentLifecycleService.Register` is an
//! unauthenticated bootstrap endpoint by design (mounted behind
//! `enrich_interceptor`, which authenticates nothing and returns `Ok` for every
//! request). For that proof to mean anything, its private key has to be
//! something the caller *has* rather than something the caller can *compute*.
//!
//! Before AAASM-5332 it was computable: the signing key was seeded with
//! `SHA-256(agent_id)`, and the agent id is public — it shows up in audit
//! records, in topology views and on the dashboard. Anyone who could read an
//! agent id could rebuild that agent's private key and register as it.
//!
//! So the private key is now generated from the OS CSPRNG and kept here. That
//! trades "nothing to persist" for "a file that must be protected", and this
//! module's whole job is that protection.
//!
//! # The guarantees
//!
//! * **Random, never derived.** [`random_seed`] reads the kernel CSPRNG; no
//!   part of the private half is a function of the agent id, the DID, or any
//!   other public value.
//! * **One durable key per agent identity.** The key is written once and read
//!   back on every subsequent use, so the identity that registered, the identity
//!   a launch runs under, and the identity audit attributes actions to stay the
//!   same principal across restarts.
//! * **Owner-only, created atomically.** The file is created with `O_EXCL` and
//!   mode `0600` in a single `open(2)`, so it is never briefly world-readable
//!   and two racing enrolments cannot both win.
//! * **Never silently overwritten.** `O_EXCL` makes re-enrolment an error rather
//!   than a clobber; replacing a key is only ever [`IdentityStore::rotate`], and
//!   it retains the old key rather than destroying it.
//! * **Validated on read.** A key file that is a symlink, is not a regular file,
//!   is owned by another user, or is readable/writable by group or other is
//!   *refused*, not used. See [`verify_key_file`].
//!
//! # What is deliberately not here
//!
//! No key expiry and no automatic renewal (AAASM-5332 excludes them on purpose).
//! Renewal introduces a clock, a grace window and a set of failure modes that
//! belong in their own change, not in the repair of a key-generation defect.
//!
//! # Relationship to the proxy state file
//!
//! The read-side validation mirrors `aa-cli`'s
//! `commands::proxy::trust::verify_state_file`, deliberately: two files that a
//! governed launch trusts should be trusted for the same stated reasons. It is
//! stricter in one respect — the proxy record rejects group/other *write*
//! (`0o022`), this rejects group/other *access at all* (`0o077`) — because a
//! record another principal can only read is merely leaky, whereas a private key
//! another principal can read is that principal's key too.

use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::keypair::AgentKeypair;

/// First line of a key file, identifying format and version.
///
/// Present so a future format change is a refusal rather than a misparse: a file
/// whose first line is not this exact string is [`IdentityStoreError::Malformed`]
/// and the caller fails closed instead of guessing at the bytes.
const KEY_FILE_MAGIC: &str = "aa-identity-key/1";

/// Length of an Ed25519 secret seed, in bytes.
const SEED_LEN: usize = 32;

/// Permission bits any file holding a private key must have.
const KEY_FILE_MODE: u32 = 0o600;

/// Permission bits the directory holding key files must have.
const KEY_DIR_MODE: u32 = 0o700;

/// Access bits that disqualify a private key file: any group or other
/// permission at all, not merely write.
const FORBIDDEN_KEY_ACCESS_BITS: u32 = 0o077;

/// Why an identity key could not be resolved.
///
/// Every variant is a refusal. There is no variant meaning "carried on with a
/// weaker identity" — an agent whose durable key cannot be established has no
/// identity to register under, and inventing one is exactly the failure
/// AAASM-5332 removes.
#[derive(Debug)]
pub enum IdentityStoreError {
    /// Neither `AASM_STATE_DIR` nor a home directory could be resolved, so there
    /// is nowhere durable to keep a key.
    NoStateDirectory,
    /// The key file exists but this process must not act on it — wrong owner,
    /// too-permissive mode, a symlink, or not a regular file.
    Untrusted { path: PathBuf, reason: String },
    /// The key file exists and is trusted, but its contents are not a complete
    /// record. A half-written key supports no conclusion.
    Malformed { path: PathBuf, reason: String },
    /// The key file names a different agent than the one being loaded, which
    /// means two identities collided onto one path.
    IdentityMismatch { path: PathBuf },
    /// Enrolment was asked to create a key that already exists. Never resolved
    /// by overwriting: the existing key *is* the agent's identity.
    AlreadyEnrolled { path: PathBuf },
    /// An operation that needs an existing key found none.
    NotEnrolled { path: PathBuf },
    /// The key has been revoked and must not be used again.
    Revoked { path: PathBuf },
    /// The configured agent identifier is already a `did:key`. This crate holds
    /// no private key for a DID it did not generate, so it cannot prove
    /// possession of one — see [`crate::identity::agent_id_to_did_key`].
    ProvisionedDidUnsupported { did: String },
    /// The filesystem or the CSPRNG refused.
    Io { path: PathBuf, reason: String },
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoStateDirectory => write!(
                f,
                "no Agent Assembly state directory could be resolved, so this agent's identity key \
                 has nowhere to live; set AASM_STATE_DIR"
            ),
            Self::Untrusted { path, reason } => write!(
                f,
                "the agent identity key at {} cannot be trusted: {reason}. It is refused rather \
                 than used; move it aside and re-enrol if it is genuinely yours",
                path.display()
            ),
            Self::Malformed { path, reason } => write!(
                f,
                "the agent identity key at {} is not a complete record: {reason}",
                path.display()
            ),
            Self::IdentityMismatch { path } => write!(
                f,
                "the key file at {} belongs to a different agent identity",
                path.display()
            ),
            Self::AlreadyEnrolled { path } => write!(
                f,
                "this agent already has a durable identity key at {}; enrolling again would \
                 replace the identity it registers under. Use rotation if that is the intent",
                path.display()
            ),
            Self::NotEnrolled { path } => write!(f, "this agent has no durable identity key at {} yet", path.display()),
            Self::Revoked { path } => write!(
                f,
                "this agent's identity key has been revoked ({} exists) and must not be used \
                 again; enrol a new identity",
                path.display()
            ),
            Self::ProvisionedDidUnsupported { did } => write!(
                f,
                "the configured agent id is the DID `{did}`, but this agent holds no private key \
                 for it and so cannot prove possession of it at registration. Configure a plain \
                 agent identifier and let the durable identity key supply the DID"
            ),
            Self::Io { path, reason } => {
                write!(f, "the agent identity key at {} is unusable: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for IdentityStoreError {}

/// Read a fresh 32-byte secret seed from the operating system's CSPRNG.
///
/// Reads `/dev/urandom`, which is the same source `getrandom(2)` serves on the
/// Unix targets this crate's identity storage supports. It is read directly
/// rather than through the `rand`/`getrandom` crates because AAASM-5332 must not
/// alter the dependency graph: `rand` is currently a dev-dependency only, and
/// promoting it would rewrite `Cargo.lock` while three other lanes are in
/// flight. Adding the crate later is a mechanical swap — the seed's *source*
/// does not change, only which code reads it.
///
/// The bytes are collected from the reader rather than filled into a
/// zero-initialised array so that no constant ever appears in the seed's
/// data-flow, keeping the static analysers pointed at real hard-coded-key
/// findings instead of this one.
pub(crate) fn random_seed() -> io::Result<Zeroizing<[u8; SEED_LEN]>> {
    let file = fs::File::open("/dev/urandom")?;
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(SEED_LEN));
    file.take(SEED_LEN as u64).read_to_end(&mut bytes)?;

    // A short read means the CSPRNG did not supply a full seed. Failing here is
    // the only safe response: padding it would hand out a key with less entropy
    // than its length advertises.
    let seed: [u8; SEED_LEN] = bytes.as_slice().try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("the CSPRNG supplied {} bytes, not {SEED_LEN}", bytes.len()),
        )
    })?;
    Ok(Zeroizing::new(seed))
}

/// Constraint: the key file must be one only this user could have written or read.
///
/// A symlink is rejected rather than followed — the metadata that was vetted has
/// to be the metadata of the bytes that get read, and following a link opens a
/// window where the two differ. Group- and other-accessible modes are rejected
/// outright: a private key another principal can read is not private, and a
/// private key another principal can write lets them choose which key this agent
/// registers with, which is the whole attack this ticket closes.
///
/// `expected_uid` is a parameter rather than read inside so the rejection path
/// is reachable in a test — a check that can only ever be exercised with the
/// running user's own UID cannot be shown to fail. This mirrors
/// `aa-cli::commands::proxy::trust::verify_state_file` for the same reason.
pub fn verify_key_file(path: &Path, meta: &fs::Metadata, expected_uid: u32) -> Result<(), IdentityStoreError> {
    if meta.file_type().is_symlink() {
        return Err(IdentityStoreError::Untrusted {
            path: path.to_path_buf(),
            reason: "it is a symlink, so the bytes vetted need not be the bytes read".into(),
        });
    }
    if !meta.is_file() {
        return Err(IdentityStoreError::Untrusted {
            path: path.to_path_buf(),
            reason: "it is not a regular file".into(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;

        let owner = meta.uid();
        if owner != expected_uid {
            return Err(IdentityStoreError::Untrusted {
                path: path.to_path_buf(),
                reason: format!("it is owned by uid {owner}, not by this user (uid {expected_uid})"),
            });
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & FORBIDDEN_KEY_ACCESS_BITS != 0 {
            return Err(IdentityStoreError::Untrusted {
                path: path.to_path_buf(),
                reason: format!("its mode {mode:04o} grants access to group or other"),
            });
        }
    }
    Ok(())
}

/// The parsed contents of a key file.
struct KeyRecord {
    agent_id: String,
    seed: Zeroizing<[u8; SEED_LEN]>,
}

/// A completed key rotation.
pub struct Rotation {
    /// The `did:key` the agent registered under before rotating. It is no longer
    /// this agent's identity and should be deregistered at the gateway.
    pub previous_did: String,
    /// Where the superseded key was moved to. It is retained rather than
    /// deleted, so an operator can still prove what the old identity was.
    pub retired_path: PathBuf,
    /// The `did:key` the agent will register under from now on.
    pub current_did: String,
}

/// A completed revocation.
pub struct Revocation {
    /// The `did:key` that must no longer be accepted for this agent.
    pub revoked_did: String,
    /// The marker whose existence makes the key unloadable.
    pub marker_path: PathBuf,
}

/// A directory of durable agent identity keys.
pub struct IdentityStore {
    root: PathBuf,
}

impl IdentityStore {
    /// A store rooted at `root`, whose directory is created on first enrolment.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The default store: `${AASM_STATE_DIR:-$HOME/.aasm}/identity`.
    ///
    /// Same base directory as the integration receipt store in `aa-core`
    /// (`ReceiptStore::default_location`), so one environment variable relocates
    /// all of an installation's durable state — which is what the test harnesses
    /// already rely on to keep parallel runs off each other's files. `HOME` is
    /// read directly rather than through the `dirs` crate to keep this change
    /// out of `Cargo.lock`; on Unix `dirs::home_dir` consults `HOME` first
    /// anyway.
    pub fn default_location() -> Result<Self, IdentityStoreError> {
        let base = match std::env::var_os("AASM_STATE_DIR") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => match std::env::var_os("HOME") {
                Some(home) if !home.is_empty() => PathBuf::from(home).join(".aasm"),
                _ => return Err(IdentityStoreError::NoStateDirectory),
            },
        };
        Ok(Self::at(base.join("identity")))
    }

    /// The directory key files live in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Where `agent_id`'s key file lives.
    ///
    /// The filename is `SHA-256(agent_id)` hex rather than the agent id itself:
    /// an agent id is free-form text that may contain path separators, `..`, or
    /// characters the filesystem will not take, and none of that should be able
    /// to steer where a key is written. Hashing is used here purely to get a
    /// fixed-length, filesystem-safe name — it is *not* protecting anything, and
    /// the agent id is stored inside the file so a hash collision is caught on
    /// read rather than silently sharing one key between two identities.
    pub fn key_path(&self, agent_id: &str) -> PathBuf {
        self.root.join(format!("{}.key", slug(agent_id)))
    }

    /// Where `agent_id`'s revocation marker lives, if it has been revoked.
    pub fn revocation_path(&self, agent_id: &str) -> PathBuf {
        self.root.join(format!("{}.revoked", slug(agent_id)))
    }

    /// Load `agent_id`'s durable identity key, enrolling one on first use.
    ///
    /// This is the normal path. First use is enrolment: an agent that has never
    /// registered has no key, and generating one at that moment is what makes
    /// the identity durable from then on. Every later call reads the same key
    /// back, which is what keeps registration, launch and audit attribution
    /// pointing at one principal.
    ///
    /// A *revoked* identity is not silently re-enrolled — that would let the
    /// revocation be undone by simply running the agent again.
    pub fn load_or_enroll(&self, agent_id: &str) -> Result<AgentKeypair, IdentityStoreError> {
        match self.load(agent_id) {
            Err(IdentityStoreError::NotEnrolled { .. }) => self.enroll(agent_id),
            other => other,
        }
    }

    /// Load `agent_id`'s durable identity key, refusing to create one.
    ///
    /// Returns [`IdentityStoreError::NotEnrolled`] when no key exists, and
    /// refuses outright when one exists but cannot be trusted.
    pub fn load(&self, agent_id: &str) -> Result<AgentKeypair, IdentityStoreError> {
        let revocation = self.revocation_path(agent_id);
        if revocation.exists() {
            return Err(IdentityStoreError::Revoked { path: revocation });
        }

        // Establishes both that the identity directory is ours and which UID
        // "ours" is, so the file check below has something to compare against.
        let expected_uid = self.ensure_root()?;

        let path = self.key_path(agent_id);
        let meta = match fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(IdentityStoreError::NotEnrolled { path }),
            Err(e) => {
                return Err(IdentityStoreError::Untrusted {
                    path,
                    reason: format!("it could not be inspected ({e})"),
                })
            }
        };
        verify_key_file(&path, &meta, expected_uid)?;

        let contents = Zeroizing::new(fs::read_to_string(&path).map_err(|e| IdentityStoreError::Io {
            path: path.clone(),
            reason: e.to_string(),
        })?);
        let record = parse_key_record(&path, &contents)?;

        // The filename is a hash, so two agent ids could in principle land on
        // one path. Compare the authoritative copy inside the file rather than
        // trusting the name.
        if record.agent_id != agent_id {
            return Err(IdentityStoreError::IdentityMismatch { path });
        }

        Ok(AgentKeypair::from_seed(&record.seed))
    }

    /// Generate and persist a fresh durable identity key for `agent_id`.
    ///
    /// Fails with [`IdentityStoreError::AlreadyEnrolled`] if a key is already
    /// there. That refusal is the point: the key file *is* the agent's identity,
    /// so overwriting it would silently retire an identity the gateway has
    /// records for and start registering as a stranger. It is enforced by
    /// `O_EXCL` in the same `open(2)` that creates the file, so it also holds
    /// against a second process enrolling concurrently.
    pub fn enroll(&self, agent_id: &str) -> Result<AgentKeypair, IdentityStoreError> {
        let revocation = self.revocation_path(agent_id);
        if revocation.exists() {
            return Err(IdentityStoreError::Revoked { path: revocation });
        }

        let _ = self.ensure_root()?;
        let path = self.key_path(agent_id);

        let (keypair, seed) = AgentKeypair::generate().map_err(|e| IdentityStoreError::Io {
            path: path.clone(),
            reason: format!("the OS CSPRNG could not be read ({e})"),
        })?;

        write_key_file(&path, agent_id, &seed)?;
        Ok(keypair)
    }

    /// Retire `agent_id`'s current key and enrol a fresh one.
    ///
    /// The superseded key is renamed aside, not deleted — an operator
    /// reconstructing an incident needs to be able to say which key signed what,
    /// and this module deletes nothing. The rename happens before the new key is
    /// created so the `O_EXCL` guarantee in [`enroll`](Self::enroll) still holds.
    ///
    /// Rotation produces a **new `did:key`**, because the DID encodes the public
    /// key. The gateway therefore sees a new agent identity; the caller is
    /// responsible for deregistering [`Rotation::previous_did`]. See the crate
    /// docs on migration for why that is a deliberate consequence rather than a
    /// gap.
    pub fn rotate(&self, agent_id: &str) -> Result<Rotation, IdentityStoreError> {
        let previous = self.load(agent_id)?;
        let previous_did = previous.did_key();

        let path = self.key_path(agent_id);
        let retired_path = self.root.join(format!("{}.retired-{}.key", slug(agent_id), unix_now()));
        fs::rename(&path, &retired_path).map_err(|e| IdentityStoreError::Io {
            path: path.clone(),
            reason: format!("the superseded key could not be retired ({e})"),
        })?;

        let current = self.enroll(agent_id)?;
        Ok(Rotation {
            previous_did,
            retired_path,
            current_did: current.did_key(),
        })
    }

    /// Revoke `agent_id`'s identity so this store will never sign with it again.
    ///
    /// Writes a marker beside the key rather than editing or removing the key
    /// itself: the key bytes stay available for forensic comparison, and
    /// [`load`](Self::load) refuses as long as the marker exists. Local
    /// revocation is immediate and unconditional.
    ///
    /// **Propagation is the caller's job and is only partial.** Revoking here
    /// stops *this* installation from using the key; it does not tell the
    /// gateway to stop honouring the DID. The gateway's `AgentLifecycleService`
    /// exposes no revoke RPC (`proto/agent.proto` has `RequestChallenge`,
    /// `Register`, `Heartbeat`, `Deregister`, `ControlStream` and nothing else),
    /// so the strongest propagation available today is `Deregister` on the
    /// revoked DID. A real revocation list is deferred — see the report on this
    /// ticket.
    pub fn revoke(&self, agent_id: &str, reason: &str) -> Result<Revocation, IdentityStoreError> {
        let revoked_did = self.load(agent_id)?.did_key();
        let marker_path = self.revocation_path(agent_id);

        let record = format!(
            "revoked_at_unix={}\nrevoked_did={}\nreason={}\n",
            unix_now(),
            revoked_did,
            reason.replace('\n', " ")
        );
        create_exclusive(&marker_path, KEY_FILE_MODE, record.as_bytes())?;

        Ok(Revocation {
            revoked_did,
            marker_path,
        })
    }

    /// Create the key directory owner-only, and report the UID that owns it.
    ///
    /// The directory's mode matters as much as the files': a directory group or
    /// other can write to lets another principal unlink a key file and drop in
    /// their own, which [`verify_key_file`] cannot detect because the
    /// replacement would be a perfectly well-formed file owned by whoever
    /// created it.
    ///
    /// The returned UID is *how this module learns which principal it is*, and
    /// the reason is worth stating: `chmod(2)` succeeds only for the file's
    /// owner (or root), so a `set_permissions` that succeeds on this directory
    /// proves this process owns it, and the directory's owner UID is therefore
    /// this process's own. Learning it this way keeps the crate free of a `libc`
    /// dependency — `aa-sdk-client` is pinned by git SHA into three external SDK
    /// repos, so its dependency graph is deliberately minimal — and it fails
    /// closed in the case that actually matters: if the identity directory
    /// belongs to somebody else, the `chmod` returns `EPERM` and every load and
    /// enrolment refuses rather than trusting a stranger's directory.
    fn ensure_root(&self) -> Result<u32, IdentityStoreError> {
        fs::create_dir_all(&self.root).map_err(|e| IdentityStoreError::Io {
            path: self.root.clone(),
            reason: format!("the identity directory could not be created ({e})"),
        })?;
        restrict_dir(&self.root)?;
        owner_uid(&self.root)
    }
}

#[cfg(unix)]
fn owner_uid(path: &Path) -> Result<u32, IdentityStoreError> {
    use std::os::unix::fs::MetadataExt;
    fs::metadata(path)
        .map(|meta| meta.uid())
        .map_err(|e| IdentityStoreError::Io {
            path: path.to_path_buf(),
            reason: format!("the identity directory's owner could not be read ({e})"),
        })
}

#[cfg(not(unix))]
fn owner_uid(_path: &Path) -> Result<u32, IdentityStoreError> {
    Ok(0)
}

#[cfg(unix)]
fn restrict_dir(path: &Path) -> Result<(), IdentityStoreError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(KEY_DIR_MODE)).map_err(|e| IdentityStoreError::Io {
        path: path.to_path_buf(),
        reason: format!("the identity directory could not be restricted to this user ({e})"),
    })
}

#[cfg(not(unix))]
fn restrict_dir(_path: &Path) -> Result<(), IdentityStoreError> {
    Ok(())
}

/// Filesystem-safe, fixed-length name for an agent id. See
/// [`IdentityStore::key_path`] for why this is a hash and what it is not.
fn slug(agent_id: &str) -> String {
    hex::encode(Sha256::digest(agent_id.as_bytes()))
}

/// Seconds since the Unix epoch, or 0 if the clock is before it.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default()
}

/// Serialise and write a key file, refusing to replace an existing one.
fn write_key_file(path: &Path, agent_id: &str, seed: &Zeroizing<[u8; SEED_LEN]>) -> Result<(), IdentityStoreError> {
    let body = Zeroizing::new(format!(
        "{KEY_FILE_MAGIC}\nagent_id_hex={}\ncreated_at_unix={}\nsecret_seed_hex={}\n",
        hex::encode(agent_id.as_bytes()),
        unix_now(),
        hex::encode(seed.as_ref()),
    ));
    create_exclusive(path, KEY_FILE_MODE, body.as_bytes())
}

/// Create `path` with exactly `mode` and write `body`, failing if it exists.
///
/// `create_new` maps to `O_EXCL`, and `mode` is applied by the same `open(2)`
/// that creates the file. Both matter: the first makes "do not silently
/// overwrite" a kernel guarantee rather than a check with a race in it, and the
/// second means the file is never momentarily readable by anyone else, as it
/// would be if permissions were tightened after writing. The mode is reasserted
/// straight after creation so an unusually restrictive umask cannot leave the
/// owner unable to read back their own key.
fn create_exclusive(path: &Path, mode: u32, body: &[u8]) -> Result<(), IdentityStoreError> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }

    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            return Err(IdentityStoreError::AlreadyEnrolled {
                path: path.to_path_buf(),
            })
        }
        Err(e) => {
            return Err(IdentityStoreError::Io {
                path: path.to_path_buf(),
                reason: e.to_string(),
            })
        }
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|e| IdentityStoreError::Io {
            path: path.to_path_buf(),
            reason: format!("permissions could not be set ({e})"),
        })?;
    }

    file.write_all(body)
        .and_then(|()| file.sync_all())
        .map_err(|e| IdentityStoreError::Io {
            path: path.to_path_buf(),
            reason: e.to_string(),
        })
}

/// Parse a key file, rejecting anything that is not a complete record.
fn parse_key_record(path: &Path, contents: &str) -> Result<KeyRecord, IdentityStoreError> {
    let malformed = |reason: &str| IdentityStoreError::Malformed {
        path: path.to_path_buf(),
        reason: reason.to_string(),
    };

    let mut lines = contents.lines();
    if lines.next() != Some(KEY_FILE_MAGIC) {
        return Err(malformed("it does not start with a recognised key-file header"));
    }

    let mut agent_id_hex = None;
    let mut secret_seed_hex = None;
    for line in lines {
        match line.split_once('=') {
            Some(("agent_id_hex", value)) => agent_id_hex = Some(value),
            Some(("secret_seed_hex", value)) => secret_seed_hex = Some(value),
            _ => {}
        }
    }

    let agent_id_bytes = hex::decode(agent_id_hex.ok_or_else(|| malformed("it records no agent id"))?)
        .map_err(|_| malformed("its agent id is not valid hex"))?;
    let agent_id = String::from_utf8(agent_id_bytes).map_err(|_| malformed("its agent id is not valid UTF-8"))?;

    let seed_bytes = Zeroizing::new(
        hex::decode(secret_seed_hex.ok_or_else(|| malformed("it records no key material"))?)
            .map_err(|_| malformed("its key material is not valid hex"))?,
    );
    let seed: [u8; SEED_LEN] = seed_bytes
        .as_slice()
        .try_into()
        .map_err(|_| malformed("its key material is not a 32-byte Ed25519 seed"))?;

    Ok(KeyRecord {
        agent_id,
        seed: Zeroizing::new(seed),
    })
}
