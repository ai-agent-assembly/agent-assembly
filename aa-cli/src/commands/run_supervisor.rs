//! Cross-process parent-to-child authority handoff for `aasm run` (AAASM-6273,
//! ADR 0038 §27).
//!
//! # What this closes
//!
//! `aa_isolation::attenuation` makes a sub-agent's authority monotonic *inside
//! one process*: a [`ParentAuthority`] can only be built from a gated spec, and a
//! child is gated against it. A real sub-agent tree is several `aasm run`
//! processes, and a child process cannot be handed a [`ParentAuthority`]: ADR 0038
//! §27 forbids serializing one, passing one by file or flag, or re-deriving one
//! from a receipt, because anything a second process can construct is a way to
//! forge one.
//!
//! So the parent authority never leaves the process that holds it. The **tree-root**
//! `aasm run` (the one with no governed ancestor) keeps every hop's
//! [`ParentAuthority`] in memory and serves a Unix socket. A descendant `aasm run`
//! sends only a *request* — its own spec, leases it asks for — and receives the
//! narrowed leases the root derived for it. The decision is made in the root, by
//! the same `authority_gate` and [`DelegationLedger::derive_child`] the in-process
//! contract uses:
//!
//! * a lease wider than the parent's, a later expiry, a larger limit, a domain the
//!   parent does not hold, or a right to delegate the parent lacks is refused;
//! * a child can only retain or narrow; the next hop is gated against **this**
//!   hop's derived leases, so authority a hop dropped cannot be recovered by a
//!   later generation;
//! * the ledger records each edge once and revocation is transitive, so revoking
//!   the root's lease refuses every later admission below it.
//!
//! # How a descendant is placed in the tree
//!
//! By the kernel, not by anything the descendant says. The root records its own pid
//! (with a start-time marker so a reused pid is not mistaken for it) in a
//! per-user index directory, and every `aasm run` — with or without
//! `--root-agent`, and with any environment — walks its OS parent chain and looks
//! for an index entry. On the socket the root reads the peer's pid from the kernel
//! and walks the peer's parent chain to the nearest admitted hop. A peer that is
//! in no admitted hop's tree is refused, which is what keeps a sibling tree's
//! process from claiming this tree's authority. The lookup location depends only on
//! the effective uid: if it followed `$HOME` or `$AASM_STATE_DIR`, `HOME=/elsewhere
//! aasm run` would hide the root from its own descendant.
//!
//! # What this does NOT guarantee
//!
//! This is a guarantee about unmodified `aasm run` in an unreparented process
//! tree. It is **not** a containment boundary against an adversarial agent.
//!
//! * The walk follows parent pids. A same-uid descendant that double-forks is
//!   reparented to `init`/`launchd` and leaves the chain. Linux can set a
//!   subreaper; macOS has none.
//! * A patched `aasm` can skip the lookup, and a same-uid process can delete the
//!   index entry or the socket. Removing the *socket* with the entry in place
//!   refuses the launch; removing both is indistinguishable from "no governed
//!   ancestor".
//! * A pid-namespaced or VM-confined descendant sees a different pid space, so
//!   its walk does not reach the root. That combination is not exercised here.
//! * ADR 0038 §28 (registry write-protection under confinement) and the B3 kernel
//!   evidence gate are **not** implemented or satisfied by this module.
//! * Tree-roots are only the launches that carry at least one lease. A root with
//!   none stays on the rc.7 compatibility residual and hosts no supervisor.
//!
//! The wire protocol is one JSON request, half-close, one JSON response.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use aa_isolation::attenuation::{Ancestry, DelegationLedger, ParentAuthority};
use aa_isolation::authority::{authority_gate, AuthorityRefusal, AuthorityWitness};
use aa_isolation::lease::{ChildLeaseRequest, DelegationDenied, InheritanceMode, LeaseId};
use aa_isolation::spec::{ExecutionSpec, IdentityRef};
use aa_isolation::CapabilityLease;
use serde::{Deserialize, Serialize};

use crate::commands::proxy::ctl_path::verify_fallback_dir;
use crate::commands::proxy::revoke::peer_pid;

/// How many parent hops either walk follows before giving up.
const MAX_ANCESTRY_DEPTH: usize = 64;
/// Largest request or response accepted.
const MAX_MESSAGE_BYTES: u64 = 1 << 20;
/// Per-connection read and write timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(10);
/// Parent of the per-user registry directory. Short enough for a socket address on
/// every Unix host this ships on, and independent of the caller's environment.
const REGISTRY_BASE: &str = "/tmp";

// ---------------------------------------------------------------------------
// Kernel process facts
// ---------------------------------------------------------------------------

/// The two kernel facts both walks rely on, behind a trait so a test can supply a
/// synthetic process table and a real-process test uses the kernel's.
pub(crate) trait Procs: Send + Sync {
    /// The parent pid of `pid`, when the kernel reports one.
    fn parent_of(&self, pid: u32) -> Option<u32>;
    /// A value that changes when `pid` is reused by a different process (its start
    /// time, in microseconds).
    fn start_marker(&self, pid: u32) -> Option<u64>;
}

/// The host kernel.
pub(crate) struct Kernel;

impl Procs for Kernel {
    fn parent_of(&self, pid: u32) -> Option<u32> {
        kernel_proc(pid).map(|(ppid, _)| ppid)
    }

    fn start_marker(&self, pid: u32) -> Option<u64> {
        kernel_proc(pid).map(|(_, start)| start)
    }
}

/// `(parent pid, start time in microseconds)` for `pid`.
#[cfg(target_os = "macos")]
fn kernel_proc(pid: u32) -> Option<(u32, u64)> {
    // SAFETY: `info` is a plain-old-data struct the kernel fills; the size passed
    // is exactly its size and the call is checked against it.
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (written == size).then(|| (info.pbi_ppid, info.pbi_start_tvsec * 1_000_000 + info.pbi_start_tvusec))
}

/// `(parent pid, start time in clock ticks)` for `pid`, from `/proc/<pid>/stat`.
#[cfg(target_os = "linux")]
fn kernel_proc(pid: u32) -> Option<(u32, u64)> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `comm` may contain spaces and parentheses; the fields that matter follow the LAST `)`.
    let rest = stat.get(stat.rfind(')')? + 1..)?;
    let mut fields = rest.split_whitespace();
    let ppid: u32 = fields.nth(1)?.parse().ok()?;
    // After `)`: state(0) ppid(1) ... starttime is stat field 22, index 19 here.
    let start: u64 = fields.nth(17)?.parse().ok()?;
    Some((ppid, start))
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn kernel_proc(_pid: u32) -> Option<(u32, u64)> {
    None
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// Ask the tree root to admit the sender as a hop with these leases.
    Admit {
        spec: Box<ExecutionSpec>,
        /// What `--root-agent` named, if anything. A claim to check, never a source of lineage.
        declared_root_agent: Option<String>,
    },
    /// Revoke every lease the root issued. Safe direction only: it removes authority.
    Revoke { reason: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
enum Response {
    Admitted {
        leases: Vec<CapabilityLease>,
        lineage: Vec<String>,
    },
    Refused {
        kind: String,
        detail: String,
    },
    Revoked {
        leases: usize,
    },
}

/// What a descendant is given.
#[derive(Debug, Clone)]
pub struct Admission {
    /// The narrowed leases the root derived, in place of the ones asked for.
    pub leases: Vec<CapabilityLease>,
    /// The ancestors the root verified, outermost first.
    pub lineage: Vec<String>,
}

/// Why a descendant was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// A stable name for the refusal (`ChildExceedsParent`, `ParentRevoked`, ...).
    pub kind: String,
    /// Words an operator can act on.
    pub detail: String,
}

impl Refusal {
    fn new(kind: &str, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            detail: detail.into(),
        }
    }

    fn from_authority(refusal: &AuthorityRefusal) -> Self {
        let debug = format!("{refusal:?}");
        let kind = debug
            .split(|c: char| !c.is_alphanumeric())
            .next()
            .unwrap_or("AuthorityRefusal");
        Self::new(kind, refusal.to_string())
    }

    fn from_denied(denied: &DelegationDenied) -> Self {
        let kind = match denied {
            DelegationDenied::Wider | DelegationDenied::Incomparable => "ChildExceedsParent",
            DelegationDenied::NotDelegable => "ParentNotDelegable",
            DelegationDenied::DelegationRightsExceedParent => "DelegationRightsExceedParent",
            DelegationDenied::LimitsExceedParent { .. } => "ChildExceedsLimits",
            DelegationDenied::ParentRevoked => "ParentRevoked",
            DelegationDenied::AncestryUnverifiable => "LedgerUnverifiable",
            DelegationDenied::ContentMismatch => "LedgerContentMismatch",
            DelegationDenied::DuplicateLeaseId => "DuplicateLeaseId",
            DelegationDenied::UntrustedIssuer => "UntrustedIssuer",
            _ => "DelegationDenied",
        };
        Self::new(kind, format!("{denied:?}"))
    }
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.kind, self.detail)
    }
}

// ---------------------------------------------------------------------------
// Registry directory and index
// ---------------------------------------------------------------------------

fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// The per-user registry directory under `base`.
fn registry_dir_in(base: &Path) -> PathBuf {
    base.join(format!("aa-sup-{}", euid()))
}

fn default_registry_dir() -> PathBuf {
    registry_dir_in(Path::new(REGISTRY_BASE))
}

/// Create the registry directory (`0700`) if absent and require it to be a real
/// directory owned by this user with no group or other access.
fn ensure_registry_dir(dir: &Path) -> std::io::Result<()> {
    if let Err(e) = std::fs::DirBuilder::new().mode(0o700).create(dir) {
        if e.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(e);
        }
    }
    verify_fallback_dir(dir).map_err(|e| std::io::Error::other(e.to_string()))
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexEntry {
    supervisor_pid: u32,
    start_marker: u64,
    socket: PathBuf,
}

/// Where a governed ancestor's supervisor can be reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    /// The tree root's pid.
    pub supervisor_pid: u32,
    /// Its socket.
    pub socket: PathBuf,
}

/// Find the nearest governed ancestor of this process, if any.
///
/// `Ok(None)` is "this is a root launch". `Err` is "an ancestor IS governed and
/// that cannot be confirmed or reached", which the caller must turn into a refusal:
/// reading it as `None` would let a descendant shed the root's ceiling.
///
/// # Errors
///
/// A readable index entry for an ancestor that is corrupt or whose process start
/// time cannot be read, or whose socket does not answer.
pub fn locate_governed_ancestor() -> Result<Option<Endpoint>, String> {
    let found = locate_in(&default_registry_dir(), std::process::id(), &Kernel)?;
    if let Some(endpoint) = &found {
        probe(endpoint).map_err(|e| {
            format!(
                "an ancestor of this process (pid {}) is a governed `aasm run`, but its supervisor socket {} does not answer ({e})",
                endpoint.supervisor_pid,
                endpoint.socket.display()
            )
        })?;
    }
    Ok(found)
}

fn locate_in(dir: &Path, start_pid: u32, procs: &dyn Procs) -> Result<Option<Endpoint>, String> {
    match std::fs::symlink_metadata(dir) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot inspect the supervisor registry {}: {e}", dir.display())),
        Ok(_) => {}
    }
    // A directory this user does not exclusively control cannot have been written
    // by a legitimate supervisor (which creates it `0700`, owned), so nothing in it
    // is read.
    if verify_fallback_dir(dir).is_err() {
        return Ok(None);
    }
    let mut pid = start_pid;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let Some(parent) = procs.parent_of(pid) else {
            return Ok(None);
        };
        if parent <= 1 {
            return Ok(None);
        }
        if let Some(endpoint) = read_index(dir, parent, procs)? {
            return Ok(Some(endpoint));
        }
        pid = parent;
    }
    Ok(None)
}

fn read_index(dir: &Path, pid: u32, procs: &dyn Procs) -> Result<Option<Endpoint>, String> {
    let path = dir.join(format!("{pid}.idx"));
    let meta = match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot inspect supervisor index {}: {e}", path.display())),
        Ok(meta) => meta,
    };
    if !meta.file_type().is_file() || meta.uid() != euid() {
        return Err(format!(
            "supervisor index {} is not a regular file owned by this user",
            path.display()
        ));
    }
    let entry: IndexEntry = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(|| format!("supervisor index {} is unreadable or malformed", path.display()))?;
    if entry.supervisor_pid != pid {
        return Err(format!(
            "supervisor index {} names a different pid ({})",
            path.display(),
            entry.supervisor_pid
        ));
    }
    let current = procs.start_marker(pid).ok_or_else(|| {
        format!(
            "supervisor index {} exists but the start time of pid {pid} cannot be read",
            path.display()
        )
    })?;
    if current != entry.start_marker {
        // The recorded process is gone and its pid belongs to someone else now.
        return Ok(None);
    }
    Ok(Some(Endpoint {
        supervisor_pid: pid,
        socket: entry.socket,
    }))
}

fn connect(endpoint: &Endpoint) -> std::io::Result<UnixStream> {
    let stream = UnixStream::connect(&endpoint.socket)?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok(stream)
}

/// Whether the supervisor answers a connection.
///
/// # Errors
///
/// The connect error.
pub fn probe(endpoint: &Endpoint) -> std::io::Result<()> {
    connect(endpoint).map(drop)
}

fn exchange(endpoint: &Endpoint, request: &Request) -> Result<Response, String> {
    let mut stream = connect(endpoint).map_err(|e| format!("cannot reach the tree supervisor: {e}"))?;
    let body = serde_json::to_vec(request).map_err(|e| format!("cannot encode the request: {e}"))?;
    stream
        .write_all(&body)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write))
        .map_err(|e| format!("cannot send the request to the tree supervisor: {e}"))?;
    let mut reply = Vec::new();
    stream
        .take(MAX_MESSAGE_BYTES)
        .read_to_end(&mut reply)
        .map_err(|e| format!("cannot read the tree supervisor's reply: {e}"))?;
    serde_json::from_slice(&reply).map_err(|e| format!("the tree supervisor's reply is malformed: {e}"))
}

/// Ask the tree root to admit this process as a hop.
///
/// # Errors
///
/// [`Refusal`] when the root refuses, or when it cannot be reached or understood
/// (`SupervisorUnreachable`), so a failure to ask never reads as permission.
pub fn admit(
    endpoint: &Endpoint,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
) -> Result<Admission, Refusal> {
    let request = Request::Admit {
        spec: Box::new(spec.clone()),
        declared_root_agent: declared_root_agent.map(str::to_string),
    };
    match exchange(endpoint, &request).map_err(|e| Refusal::new("SupervisorUnreachable", e))? {
        Response::Admitted { leases, lineage } => Ok(Admission { leases, lineage }),
        Response::Refused { kind, detail } => Err(Refusal { kind, detail }),
        Response::Revoked { .. } => Err(Refusal::new(
            "SupervisorUnreachable",
            "the tree supervisor answered an admission with a revocation reply",
        )),
    }
}

/// Revoke every lease the tree root issued, so that no further admission below it
/// is accepted. Returns how many root leases were revoked.
///
/// Any process of this user that can reach the socket may send this. That only ever
/// removes authority, so it is a denial-of-service surface, not an escalation one.
/// It stops new admissions; it does not terminate a descendant already running.
///
/// # Errors
///
/// A description of why the supervisor could not be reached or refused.
pub fn revoke_tree(endpoint: &Endpoint, reason: &str) -> Result<usize, String> {
    match exchange(
        endpoint,
        &Request::Revoke {
            reason: reason.to_string(),
        },
    )? {
        Response::Revoked { leases } => Ok(leases),
        Response::Refused { kind, detail } => Err(format!("{kind}: {detail}")),
        Response::Admitted { .. } => Err("the tree supervisor answered a revocation with an admission".to_string()),
    }
}

// ---------------------------------------------------------------------------
// The tree root's state and the admission decision
// ---------------------------------------------------------------------------

/// What a tree-root `aasm run` hands its supervisor: its own gated authority and
/// the ledger its leases are tracked in.
pub struct TreeRoot {
    authority: ParentAuthority,
    ledger: Arc<DelegationLedger>,
    root_leases: Vec<LeaseId>,
    agent_id: String,
}

impl TreeRoot {
    /// Seed a supervisor from the root's own `spec`, which has already passed
    /// `authority_gate` (proven by `witness`).
    ///
    /// The ledger trusts `trusted_issuer` only. A root lease with another issuer is
    /// not tracked, so every descendant asking for that domain is refused
    /// (`LedgerUnverifiable`); the root itself is unaffected. Their ids are returned.
    pub fn seed(spec: &ExecutionSpec, witness: &AuthorityWitness, trusted_issuer: &str) -> (Self, Vec<LeaseId>) {
        let ledger = Arc::new(DelegationLedger::new().with_trusted_issuer(trusted_issuer));
        let mut root_leases = Vec::new();
        let mut untracked = Vec::new();
        for lease in spec.leases() {
            match ledger.register_parent(lease) {
                Ok(()) => root_leases.push(lease.id().clone()),
                Err(_) => untracked.push(lease.id().clone()),
            }
        }
        let authority = ParentAuthority::from_gated_spec(spec, witness, Arc::clone(&ledger));
        (
            Self {
                authority,
                ledger,
                root_leases,
                agent_id: spec.identity().agent_id.clone(),
            },
            untracked,
        )
    }
}

struct Hop {
    authority: ParentAuthority,
    agent_id: String,
    lineage: Vec<String>,
    /// `None` only if the kernel could not report it, which makes the hop unusable.
    start_marker: Option<u64>,
}

struct State {
    ledger: Arc<DelegationLedger>,
    root_leases: Vec<LeaseId>,
    hops: HashMap<u32, Hop>,
}

/// The nearest admitted hop above `peer` in the kernel's parent chain.
fn nearest_hop(peer: u32, hops: &HashMap<u32, Hop>, procs: &dyn Procs) -> Option<u32> {
    let mut pid = peer;
    for _ in 0..MAX_ANCESTRY_DEPTH {
        let parent = procs.parent_of(pid)?;
        if parent <= 1 {
            return None;
        }
        if let Some(hop) = hops.get(&parent) {
            // A recorded pid whose start time moved belongs to a different process now.
            if hop.start_marker.is_some() && hop.start_marker == procs.start_marker(parent) {
                return Some(parent);
            }
        }
        pid = parent;
    }
    None
}

fn admit_hop(
    state: &mut State,
    peer: u32,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    procs: &dyn Procs,
    now: SystemTime,
) -> Result<Admission, Refusal> {
    let Some(parent_pid) = nearest_hop(peer, &state.hops, procs) else {
        return Err(Refusal::new(
            "UnrecordedPeer",
            format!("pid {peer} is not a descendant of any process this supervisor admitted"),
        ));
    };
    if let Some(existing) = state.hops.get(&peer) {
        if existing.start_marker.is_some() && existing.start_marker == procs.start_marker(peer) {
            return Err(Refusal::new(
                "AlreadyAdmitted",
                format!("pid {peer} has already been admitted; a hop is admitted once"),
            ));
        }
    }
    let parent = &state.hops[&parent_pid];

    // Lineage is what the root verified, never what the launch asserted.
    let mut lineage = parent.lineage.clone();
    lineage.push(parent.agent_id.clone());
    if let Some(declared) = declared_root_agent {
        if !lineage.iter().any(|ancestor| ancestor == declared) {
            return Err(Refusal::new(
                "AncestryMismatch",
                format!(
                    "`--root-agent {declared}` names an agent that is not an ancestor of this launch in this tree (verified ancestors: {})",
                    lineage.join(", ")
                ),
            ));
        }
    }

    let child_id = spec.identity().agent_id.clone();
    let mut identity = IdentityRef::root(child_id.clone());
    identity.team_id = spec.identity().team_id.clone();
    identity.lineage = lineage.clone();

    let mut derived = Vec::with_capacity(spec.leases().len());
    for lease in spec.leases() {
        let domain = lease.domain();
        if lease.subject().agent_id != child_id {
            return Err(Refusal::new(
                "LeaseSubjectMismatch",
                format!(
                    "the `{domain}` lease was issued to `{}`, not to this launch (`{child_id}`)",
                    lease.subject().agent_id
                ),
            ));
        }
        let Some(parent_lease) = parent.authority.lease_for(domain) else {
            return Err(Refusal::new(
                "ChildExceedsParent",
                format!(
                    "this launch asks for a `{domain}` lease and its parent (`{}`) holds none",
                    parent.agent_id
                ),
            ));
        };
        let request = ChildLeaseRequest {
            // A fresh id per admission: a refused hop may already have derived some of its
            // leases, and a fixed `--agent-id` retried must not collide with that residue.
            child_id: LeaseId::new(format!("{child_id}-handoff-{domain}-{}", uuid::Uuid::new_v4().simple())),
            child_subject: identity.clone(),
            child_scope: lease.scope().clone(),
            child_expires_at: lease.expires_at(),
            // `Narrower`, not `Same`: `Same` would refuse a strictly narrower scope.
            mode: InheritanceMode::Narrower,
            child_delegation: lease.delegation(),
            child_limits: lease.limits().copied(),
        };
        match state.ledger.derive_child(parent_lease, request, now) {
            Ok(child) => derived.push(child),
            Err(denied) => return Err(Refusal::from_denied(&denied)),
        }
    }

    // The next hop is gated against what THIS hop was given, not what it asked for.
    let derived_spec = spec.clone().with_identity(identity).with_leases(derived.clone());
    let ancestry = Ancestry::Parent(Box::new(parent.authority.clone()));
    let witness = authority_gate(&derived_spec, &ancestry, now).map_err(|r| Refusal::from_authority(&r))?;
    let authority = ParentAuthority::from_gated_spec(&derived_spec, &witness, Arc::clone(&state.ledger));
    state.hops.insert(
        peer,
        Hop {
            authority,
            agent_id: child_id,
            lineage: lineage.clone(),
            start_marker: procs.start_marker(peer),
        },
    );
    Ok(Admission {
        leases: derived,
        lineage,
    })
}

fn revoke_all(state: &State, reason: &str) -> usize {
    for lease in &state.root_leases {
        state.ledger.revoke(lease, 1, reason);
    }
    state.root_leases.len()
}

fn handle(stream: &mut UnixStream, state: &Mutex<State>, procs: &dyn Procs) {
    let mut body = Vec::new();
    if (&*stream).take(MAX_MESSAGE_BYTES).read_to_end(&mut body).is_err() || body.is_empty() {
        // A bare connection is a liveness probe.
        return;
    }
    let response = match serde_json::from_slice::<Request>(&body) {
        Err(e) => Response::Refused {
            kind: "MalformedRequest".to_string(),
            detail: e.to_string(),
        },
        Ok(Request::Revoke { reason }) => {
            let state = state.lock().expect("supervisor state poisoned");
            Response::Revoked {
                leases: revoke_all(&state, &reason),
            }
        }
        Ok(Request::Admit {
            spec,
            declared_root_agent,
        }) => match peer_pid(stream) {
            None => Response::Refused {
                kind: "UnrecordedPeer".to_string(),
                detail: "the kernel did not report the peer's pid".to_string(),
            },
            Some(peer) => {
                let mut state = state.lock().expect("supervisor state poisoned");
                match admit_hop(
                    &mut state,
                    peer,
                    &spec,
                    declared_root_agent.as_deref(),
                    procs,
                    SystemTime::now(),
                ) {
                    Ok(admission) => Response::Admitted {
                        leases: admission.leases,
                        lineage: admission.lineage,
                    },
                    Err(refusal) => Response::Refused {
                        kind: refusal.kind,
                        detail: refusal.detail,
                    },
                }
            }
        },
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ = stream.write_all(&bytes);
    }
}

/// A running tree-root supervisor. Dropping it stops serving and removes its
/// socket and index entry.
pub struct TreeSupervisor {
    socket: PathBuf,
    index: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl TreeSupervisor {
    /// Start serving for the current process.
    ///
    /// # Errors
    ///
    /// When the registry directory cannot be made trustworthy or the socket cannot
    /// be bound. The caller must refuse the launch: a root that cannot serve would
    /// leave its descendants with no ceiling at all.
    pub fn start(root: TreeRoot) -> std::io::Result<Self> {
        Self::start_in(&default_registry_dir(), std::process::id(), root, Arc::new(Kernel))
    }

    pub(crate) fn start_in(dir: &Path, pid: u32, root: TreeRoot, procs: Arc<dyn Procs>) -> std::io::Result<Self> {
        ensure_registry_dir(dir)?;
        let socket = dir.join(format!("{pid}-{}.sock", uuid::Uuid::new_v4().simple()));
        let index = dir.join(format!("{pid}.idx"));
        let listener = UnixListener::bind(&socket)?;
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        listener.set_nonblocking(true)?;

        let start_marker = procs.start_marker(pid);
        let mut hops = HashMap::new();
        hops.insert(
            pid,
            Hop {
                authority: root.authority,
                agent_id: root.agent_id,
                lineage: Vec::new(),
                start_marker,
            },
        );
        let state = Arc::new(Mutex::new(State {
            ledger: root.ledger,
            root_leases: root.root_leases,
            hops,
        }));

        let Some(start_marker) = start_marker else {
            let _ = std::fs::remove_file(&socket);
            return Err(std::io::Error::other(format!(
                "the start time of this process (pid {pid}) cannot be read, so descendants could not tell it from a reused pid"
            )));
        };
        let entry = IndexEntry {
            supervisor_pid: pid,
            start_marker,
            socket: socket.clone(),
        };
        let encoded = serde_json::to_vec(&entry).map_err(std::io::Error::other)?;
        let staged = dir.join(format!("{pid}.idx.tmp"));
        std::fs::write(&staged, &encoded)?;
        std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
        std::fs::rename(&staged, &index)?;

        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                            let state = Arc::clone(&state);
                            let procs = Arc::clone(&procs);
                            std::thread::spawn(move || handle(&mut stream, &state, procs.as_ref()));
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => std::thread::sleep(Duration::from_millis(50)),
                    }
                }
            })
        };
        Ok(Self {
            socket,
            index,
            stop,
            thread: Some(thread),
        })
    }

    /// The socket this supervisor serves.
    pub fn socket(&self) -> &Path {
        &self.socket
    }
}

impl Drop for TreeSupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let _ = std::fs::remove_file(&self.index);
        let _ = std::fs::remove_file(&self.socket);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_isolation::capability::CapabilityDomain;
    use aa_isolation::lease::{DelegationRule, LeaseBasis};
    use aa_isolation::spec::RequirementScope;
    use std::collections::HashMap as Map;
    use std::time::Duration;

    const ISSUER: &str = "aasm-run:policy";

    /// A synthetic process table: `parents[pid] = ppid`, every pid has a stable start marker.
    struct Fake {
        parents: Map<u32, u32>,
        markers: Mutex<Map<u32, u64>>,
    }

    impl Fake {
        fn new(edges: &[(u32, u32)]) -> Self {
            let parents: Map<u32, u32> = edges.iter().copied().collect();
            let markers = parents
                .keys()
                .chain(parents.values())
                .map(|p| (*p, u64::from(*p) + 1))
                .collect();
            Self {
                parents,
                markers: Mutex::new(markers),
            }
        }
    }

    impl Procs for Fake {
        fn parent_of(&self, pid: u32) -> Option<u32> {
            self.parents.get(&pid).copied()
        }
        fn start_marker(&self, pid: u32) -> Option<u64> {
            self.markers.lock().unwrap().get(&pid).copied()
        }
    }

    fn now() -> SystemTime {
        SystemTime::now()
    }

    fn lease(
        subject: &str,
        domain: CapabilityDomain,
        scope: RequirementScope,
        ttl: u64,
        delegable: bool,
    ) -> CapabilityLease {
        let issued = now();
        CapabilityLease::new(
            LeaseId::new(format!("{subject}-{domain}")),
            IdentityRef::root(subject),
            domain,
            scope,
            issued,
            issued + Duration::from_secs(ttl),
            LeaseBasis::new(IdentityRef::root(ISSUER), "test"),
        )
        .with_delegation(if delegable {
            DelegationRule::DelegableWithNarrowerScope
        } else {
            DelegationRule::NotDelegable
        })
    }

    fn sel(items: &[&str]) -> RequirementScope {
        // Policy lowering emits `permit-only:`-prefixed selectors; the scope comparators
        // return `Incomparable` (a refusal) for anything else.
        RequirementScope::Selectors(items.iter().map(|s| aa_isolation::permit_only_selector(s)).collect())
    }

    fn spec_with(agent: &str, leases: Vec<CapabilityLease>) -> ExecutionSpec {
        let mut spec = ExecutionSpec::new("prog", IdentityRef::root(agent));
        for l in leases {
            spec = spec.with_lease(l);
        }
        spec
    }

    /// A tree root `root` (pid 100) holding `leases`, gated and seeded.
    fn root_state(leases: Vec<CapabilityLease>, procs: &dyn Procs) -> State {
        let spec = spec_with("root", leases);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).expect("root gates");
        let (root, untracked) = TreeRoot::seed(&spec, &witness, ISSUER);
        assert!(untracked.is_empty());
        let mut hops = HashMap::new();
        hops.insert(
            100,
            Hop {
                authority: root.authority,
                agent_id: root.agent_id,
                lineage: Vec::new(),
                start_marker: procs.start_marker(100),
            },
        );
        State {
            ledger: root.ledger,
            root_leases: root.root_leases,
            hops,
        }
    }

    fn fs_read(scope: RequirementScope, ttl: u64, delegable: bool, who: &str) -> CapabilityLease {
        lease(who, CapabilityDomain::FilesystemRead, scope, ttl, delegable)
    }

    // 100 (root) <- 110 (tool) <- 200 (gen2 aasm) <- 210 (tool) <- 300 (gen3 aasm)
    fn chain() -> Fake {
        Fake::new(&[(110, 100), (200, 110), (210, 200), (300, 210), (999, 1), (500, 999)])
    }

    #[test]
    fn three_generations_equal_or_narrower_are_admitted() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a", "/b"]), 3600, true, "root")], &procs);

        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a", "/b"]), 3600, true, "gen2")]);
        let a2 = admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect("equal admitted");
        assert_eq!(a2.lineage, vec!["root".to_string()]);

        let gen3 = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, false, "gen3")]);
        let a3 = admit_hop(&mut state, 300, &gen3, None, &procs, now()).expect("narrower admitted");
        assert_eq!(a3.lineage, vec!["root".to_string(), "gen2".to_string()]);
        assert_eq!(a3.leases[0].scope(), &sel(&["/a"]));
    }

    #[test]
    fn widening_at_generation_two_is_refused_and_the_same_shape_narrower_is_admitted() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);

        let broad = spec_with("gen2", vec![fs_read(sel(&["/a", "/etc"]), 3600, true, "gen2")]);
        let refused = admit_hop(&mut state, 200, &broad, None, &procs, now()).expect_err("broader refused");
        assert_eq!(refused.kind, "ChildExceedsParent", "{refused}");

        // Control: identical request shape, narrower.
        let narrow = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        admit_hop(&mut state, 200, &narrow, None, &procs, now()).expect("narrower admitted");
    }

    #[test]
    fn a_domain_generation_two_dropped_cannot_be_recovered_at_generation_three() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);

        // gen2 asks for no lease at all, so it holds none to pass on.
        let gen2 = spec_with("gen2", vec![]);
        admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect("gen2 admitted with nothing");

        let gen3 = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, true, "gen3")]);
        let refused = admit_hop(&mut state, 300, &gen3, None, &procs, now()).expect_err("recovery refused");
        assert_eq!(refused.kind, "ChildExceedsParent", "{refused}");
    }

    #[test]
    fn a_non_delegable_parent_lease_cannot_be_inherited() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, false, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        let refused = admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect_err("not delegable");
        assert_eq!(refused.kind, "ParentNotDelegable", "{refused}");
    }

    #[test]
    fn a_later_expiry_is_capped_to_the_parents_not_honoured() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 60, true, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 86_400, true, "gen2")]);
        let admission = admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect("admitted");
        let root_expiry = state.hops[&100]
            .authority
            .lease_for(CapabilityDomain::FilesystemRead)
            .unwrap()
            .expires_at();
        assert!(
            admission.leases[0].expires_at() <= root_expiry,
            "child outlived its parent"
        );
    }

    #[test]
    fn a_peer_in_no_admitted_tree_is_refused_and_a_tree_member_with_the_same_request_is_admitted() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        let request = spec_with("intruder", vec![fs_read(sel(&["/a"]), 3600, true, "intruder")]);

        // 500's chain is 500 -> 999 -> 1: it never meets the root's pid.
        let refused = admit_hop(&mut state, 500, &request, None, &procs, now()).expect_err("other tree");
        assert_eq!(refused.kind, "UnrecordedPeer", "{refused}");

        let member = spec_with("member", vec![fs_read(sel(&["/a"]), 3600, true, "member")]);
        admit_hop(&mut state, 200, &member, None, &procs, now()).expect("same shape from inside the tree");
    }

    #[test]
    fn a_declared_root_agent_must_be_a_verified_ancestor() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);

        let refused =
            admit_hop(&mut state, 200, &gen2, Some("someone-elses-agent"), &procs, now()).expect_err("foreign");
        assert_eq!(refused.kind, "AncestryMismatch", "{refused}");

        // Control: naming the true root is accepted, at gen2 and again at gen3.
        admit_hop(&mut state, 200, &gen2, Some("root"), &procs, now()).expect("true root");
        let gen3 = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, true, "gen3")]);
        admit_hop(&mut state, 300, &gen3, Some("root"), &procs, now()).expect("true root at gen3");
    }

    #[test]
    fn revoking_the_root_refuses_an_already_admitted_hops_descendant_and_without_it_they_run() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect("gen2 admitted");

        let gen3 = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, true, "gen3")]);

        // Control first, on a copy of the ledger's outcome: without revocation gen3 is admitted.
        let mut control = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        admit_hop(&mut control, 200, &gen2, None, &procs, now()).expect("control gen2");
        admit_hop(&mut control, 300, &gen3, None, &procs, now()).expect("no revocation: descendants run");

        assert_eq!(revoke_all(&state, "operator revoked"), 1);
        let refused = admit_hop(&mut state, 300, &gen3, None, &procs, now()).expect_err("revoked");
        assert!(
            refused.kind == "ParentRevoked" || refused.kind == "RevokedInLedger",
            "{refused}"
        );
    }

    #[test]
    fn a_lease_the_root_could_not_track_fails_closed_for_descendants_without_affecting_the_root() {
        let procs = chain();
        let foreign = {
            let issued = now();
            CapabilityLease::new(
                LeaseId::new("root-foreign"),
                IdentityRef::root("root"),
                CapabilityDomain::FilesystemRead,
                sel(&["/a"]),
                issued,
                issued + Duration::from_secs(3600),
                LeaseBasis::new(IdentityRef::root("some-other-issuer"), "authored issuer"),
            )
            .with_delegation(DelegationRule::DelegableWithNarrowerScope)
        };
        let spec = spec_with("root", vec![foreign]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).expect("the root itself still gates");
        let (root, untracked) = TreeRoot::seed(&spec, &witness, ISSUER);
        assert_eq!(untracked.len(), 1);
        let mut hops = HashMap::new();
        hops.insert(
            100,
            Hop {
                authority: root.authority,
                agent_id: root.agent_id,
                lineage: Vec::new(),
                start_marker: procs.start_marker(100),
            },
        );
        let mut state = State {
            ledger: root.ledger,
            root_leases: root.root_leases,
            hops,
        };
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        let refused = admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect_err("untracked parent lease");
        assert_eq!(refused.kind, "LedgerUnverifiable", "{refused}");
    }

    #[test]
    fn a_reused_pid_is_not_mistaken_for_an_admitted_hop() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        admit_hop(&mut state, 200, &gen2, None, &procs, now()).expect("gen2 admitted");

        // pid 200 now belongs to a different process: its start time moved.
        procs.markers.lock().unwrap().insert(200, 9_999_999);
        let request = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, true, "gen3")]);
        // 300's nearest *valid* hop is now the root (100), so the request is judged against the root's authority,
        // never against the stale hop it would have inherited from.
        let admission = admit_hop(&mut state, 300, &request, None, &procs, now()).expect("judged against the root");
        assert_eq!(admission.lineage, vec!["root".to_string()]);
    }

    // --- index / locate ---

    fn private_dir(tag: &str) -> PathBuf {
        let base = PathBuf::from("/tmp").join(format!("aa-sup-ut-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    #[test]
    fn locate_finds_the_nearest_governed_ancestor_and_ignores_a_stale_entry() {
        let base = private_dir("locate");
        let dir = registry_dir_in(&base);
        ensure_registry_dir(&dir).unwrap();
        let procs = chain();
        let write = |pid: u32, marker: u64| {
            let entry = IndexEntry {
                supervisor_pid: pid,
                start_marker: marker,
                socket: dir.join("x.sock"),
            };
            std::fs::write(dir.join(format!("{pid}.idx")), serde_json::to_vec(&entry).unwrap()).unwrap();
        };

        // Nothing recorded: a root launch.
        assert_eq!(locate_in(&dir, 300, &procs).unwrap(), None);

        write(100, procs.start_marker(100).unwrap());
        let found = locate_in(&dir, 300, &procs).unwrap().expect("governed ancestor");
        assert_eq!(found.supervisor_pid, 100);

        // The other tree (500 -> 999 -> 1) never reaches pid 100.
        assert_eq!(locate_in(&dir, 500, &procs).unwrap(), None);

        // A reused pid: same file, different process.
        write(100, 4_242);
        assert_eq!(locate_in(&dir, 300, &procs).unwrap(), None);

        // A malformed entry for a real ancestor fails closed.
        std::fs::write(dir.join("100.idx"), b"not json").unwrap();
        assert!(locate_in(&dir, 300, &procs).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn locate_ignores_a_registry_directory_other_users_can_write() {
        let base = private_dir("untrusted");
        let dir = registry_dir_in(&base);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        let procs = chain();
        let entry = IndexEntry {
            supervisor_pid: 100,
            start_marker: procs.start_marker(100).unwrap(),
            socket: dir.join("x.sock"),
        };
        std::fs::write(dir.join("100.idx"), serde_json::to_vec(&entry).unwrap()).unwrap();
        assert_eq!(locate_in(&dir, 300, &procs).unwrap(), None);
        let _ = std::fs::remove_dir_all(&base);
    }

    // --- real socket round trip, synthetic process table ---

    #[test]
    fn a_descendant_is_admitted_and_refused_over_the_real_socket_and_the_files_disappear_on_drop() {
        let base = private_dir("socket");
        let dir = registry_dir_in(&base);
        let me = std::process::id();
        // The peer is this very process; the synthetic table makes the supervisor's recorded pid its parent.
        let procs = Arc::new(Fake::new(&[(me, 100), (100, 1)]));
        procs.markers.lock().unwrap().insert(me, 7);

        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER);
        let supervisor = TreeSupervisor::start_in(&dir, 100, root, procs.clone()).expect("start");
        let socket = supervisor.socket().to_path_buf();
        let endpoint = locate_in(&dir, me, procs.as_ref()).unwrap().expect("index found");
        probe(&endpoint).expect("answers");

        let broad = spec_with("child", vec![fs_read(sel(&["/a", "/b"]), 3600, true, "child")]);
        let refused = admit(&endpoint, &broad, None).expect_err("broader refused over the socket");
        assert_eq!(refused.kind, "ChildExceedsParent", "{refused}");

        let ok = spec_with("child", vec![fs_read(sel(&["/a"]), 3600, true, "child")]);
        let admission = admit(&endpoint, &ok, None).expect("narrower admitted over the socket");
        assert_eq!(admission.leases[0].scope(), &sel(&["/a"]));
        assert!(
            admission.leases[0].provenance().is_some(),
            "re-issued through the ledger"
        );

        // A second admission of the same peer is refused: a hop is admitted once.
        let again = admit(&endpoint, &ok, None).expect_err("once");
        assert_eq!(again.kind, "AlreadyAdmitted", "{again}");

        assert_eq!(revoke_tree(&endpoint, "test").expect("revoked"), 1);

        drop(supervisor);
        assert!(!socket.exists(), "the socket must go with the supervisor");
        assert!(probe(&endpoint).is_err());
        assert_eq!(
            locate_in(&dir, me, procs.as_ref()).unwrap(),
            None,
            "the index must go too"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_deleted_socket_with_the_index_in_place_is_an_error_not_a_root_launch() {
        let base = private_dir("deleted");
        let dir = registry_dir_in(&base);
        let me = std::process::id();
        let procs = Arc::new(Fake::new(&[(me, 100), (100, 1)]));
        procs.markers.lock().unwrap().insert(me, 7);
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER);
        let supervisor = TreeSupervisor::start_in(&dir, 100, root, procs.clone()).expect("start");
        let endpoint = locate_in(&dir, me, procs.as_ref()).unwrap().expect("index found");
        probe(&endpoint).expect("answers while the socket exists");

        std::fs::remove_file(supervisor.socket()).unwrap();
        assert!(
            locate_in(&dir, me, procs.as_ref()).unwrap().is_some(),
            "the index still names a governed ancestor"
        );
        assert!(
            probe(&endpoint).is_err(),
            "and its socket is gone, which the launch must treat as a refusal"
        );
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn the_kernel_reports_this_processs_parent_and_a_stable_start_marker() {
        let kernel = Kernel;
        let me = std::process::id();
        let parent = kernel.parent_of(me).expect("a running process has a parent");
        assert_ne!(parent, me);
        let first = kernel.start_marker(me).expect("start marker");
        assert_eq!(kernel.start_marker(me), Some(first));
        assert_ne!(
            kernel.start_marker(parent),
            Some(first),
            "two processes must not share a start marker"
        );
    }
}
