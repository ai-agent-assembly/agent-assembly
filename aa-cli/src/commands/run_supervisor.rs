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
//! By what it **holds**, not by where it sits or by anything it says. Each admitted hop is
//! given a channel (one end of a datagram socketpair) that its `aasm run` passes to its tool on
//! a fixed descriptor ([`CHANNEL_FD`], close-on-exec cleared). Descendants inherit it through
//! `fork` and `exec`, so a descendant that double-forks, is reparented to `init`/`launchd`,
//! scrubs its environment (the environment is never consulted for placement) or outlives a deleted
//! socket path still holds it, for as long as it holds the descriptor. To ask anything, a descendant makes a stream pair and sends one end over
//! the channel (`SCM_RIGHTS`); the supervisor knows which hop the request speaks for from the
//! channel it arrived on. A process outside the tree has no way to obtain the descriptor.
//!
//! Alternatives weighed: process groups and sessions are changed freely by the process itself;
//! `kqueue`/`proc_info` child tracking (`NOTE_TRACK`) is absent on modern macOS and does not
//! follow a reparented process; a pidfd (Linux) identifies a process, it does not make it a
//! member of a tree.
//!
//! When no channel is inherited the placement falls back to the earlier mechanism: the root
//! records its own pid (with a start-time marker so a reused pid is not mistaken for it) in a
//! per-uid index directory, and an `aasm run` walks its OS parent chain looking for an entry. A
//! governed ancestor whose socket cannot be reached refuses the launch.
//!
//! # A descendant that lost the channel (AAASM-6273, M2)
//!
//! Node's `child_process` and Python's `subprocess` close descriptor 61 by default, and `nohup`, a
//! backgrounded job whose parent shell exited and a daemonizer reparent the process, so such a
//! descendant holds no channel and its parent chain no longer reaches the root. Every governed hop
//! therefore exports [`GOVERNED_HOP_ENV`] (`v1:<pid>:<start marker>` of its own `aasm run`) to its
//! tool, overwriting its parent's value. The marker is never admission evidence: it places nothing
//! and widens nothing, and can only cause a refusal.
//!
//! * No channel, a marker present (malformed counts) and no governed ancestor reachable by any exit
//!   of the walk: refused. The tree the process was born in is gone or unreachable; running it as a
//!   fresh root would put it above its parent's ceiling.
//! * On the path route the marker is sent as `expected_parent`; the supervisor refuses
//!   (`ParentHopMismatch`) unless the parent-pid walk lands on exactly that hop.
//! * A process that holds the channel is governed by it and its marker is ignored.
//!
//! `PR_SET_CHILD_SUBREAPER` is deliberately not used: it would keep a reparented descendant's parent
//! chain looking intact, which is the evidence this design must not rely on.
//!
//! # What this does NOT guarantee
//!
//! This is a guarantee about unmodified `aasm run`. It is **not** a containment boundary against an
//! adversarial agent.
//!
//! * A deliberate `env -u AA_GOVERNED_HOP` / `env -i` combined with a closed channel and a reparent
//!   leaves every mechanism: the process holds nothing, names nothing and has no parent chain. It is
//!   then an ungoverned root. Passing the descriptor to a non-descendant (`SCM_RIGHTS`,
//!   `pidfd_getfd`, `/proc/<pid>/fd` as the same uid) hands that process the descendant's identity.
//! * A process started outside the tree (`launchctl`, `systemd-run`, `cron`, `ssh`, a daemon the tool
//!   asks to start) never inherited anything, and one running as a different uid cannot be seen.
//! * On Linux, a third-party subreaper together with a scrubbed marker hides the reparenting.
//! * A patched `aasm` can skip the lookup and the admission.
//! * A confined backend controls the child's descriptors; the channel is wired only for the
//!   unconfined launch. A pid-namespaced or VM-confined descendant is not exercised.
//! * The supervisor trusts the same-uid kernel facts it reads (peer pid, start time). A same-uid
//!   process can `ptrace` the supervisor; ADR 0038 §28 (registry write-protection) and the B3 kernel
//!   evidence gate are **not** implemented or satisfied by this module.
//! * Tree-roots are only the launches that carry at least one lease. A root with none stays on the
//!   rc.7 compatibility residual and hosts no supervisor.
//!
//! The wire protocol is one JSON request, half-close, one JSON response (with the descendant's own
//! channel attached to an admission).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
/// The descriptor number every governed descendant inherits its authority channel on.
///
/// A path-based lookup cannot be the trust anchor: a same-uid process can delete the path, and
/// a parent-pid walk is lost when a descendant double-forks. A descriptor is neither: it is held
/// by the process, it survives `fork`/`exec` and reparenting, and a process outside the tree has
/// no way to obtain one. The number is a convention, not a secret: nothing is learned from
/// knowing it, and a process that fabricates its own fd 61 only talks to its own fake server.
/// The environment is deliberately NOT consulted to place a process that holds it, so `env -i` cannot
/// hide it ([`GOVERNED_HOP_ENV`] only ever adds a refusal for one that does not).
pub const CHANNEL_FD: RawFd = 61;

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

/// Names the environment variable a governed `aasm run` sets for its tool (AAASM-6273, M2).
///
/// Its value is `v1:<pid>:<start marker>` of the `aasm run` that governs the tool. It is never
/// admission evidence: it cannot place a process in a tree or widen anything. It can only make a
/// launch that lost both its channel and its parent chain refuse instead of running as a fresh root
/// above its parent's ceiling, and make a path admission refuse when the parent chain does not land on
/// the hop it names. The name avoids `KEY`/`TOKEN`/`SECRET` so no credential scrubber strips it.
pub const GOVERNED_HOP_ENV: &str = "AA_GOVERNED_HOP";

/// A hop as named by [`GOVERNED_HOP_ENV`]: the `aasm run` pid and its start marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HopKey {
    /// The governing `aasm run` process.
    pub pid: u32,
    /// Its start marker, so a reused pid is not mistaken for it.
    pub start: u64,
}

/// What this process's environment says about the hop that governs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopMarker {
    /// No marker: this process was not born under a governed `aasm run` (or scrubbed it).
    Absent,
    /// A well-formed marker.
    Present(HopKey),
    /// Set but unparseable. Counts as present: a broken marker is evidence of a governed ancestry.
    Malformed,
}

impl HopMarker {
    fn is_present(self) -> bool {
        !matches!(self, Self::Absent)
    }

    fn parse(raw: Option<&std::ffi::OsStr>) -> Self {
        let Some(raw) = raw else { return Self::Absent };
        let parsed = raw.to_str().and_then(|text| {
            let mut parts = text.split(':');
            (parts.next()? == "v1").then_some(())?;
            let key = HopKey {
                pid: parts.next()?.parse().ok()?,
                start: parts.next()?.parse().ok()?,
            };
            parts.next().is_none().then_some(key)
        });
        parsed.map_or(Self::Malformed, Self::Present)
    }
}

/// The marker in this process's environment.
pub fn hop_marker_from_env() -> HopMarker {
    HopMarker::parse(std::env::var_os(GOVERNED_HOP_ENV).as_deref())
}

/// The value this process sets for its tool as [`GOVERNED_HOP_ENV`], or `None` when the kernel
/// cannot report this process's start marker (the variable is then left unset).
pub fn governed_hop_value() -> Option<String> {
    let pid = std::process::id();
    Kernel.start_marker(pid).map(|start| format!("v1:{pid}:{start}"))
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    /// Ask the tree root to admit the sender as a hop with these leases.
    Admit {
        spec: Box<ExecutionSpec>,
        /// What `--root-agent` named, if anything. A claim to check, never a source of lineage.
        declared_root_agent: Option<String>,
        /// The sender's gateway registration DID. The gateway resolves a declared parent by DID, so
        /// a `--root-agent` is matched against an ancestor's agent id OR its DID.
        registration_did: String,
        /// The hop the sender's environment says it was born under (`AA_GOVERNED_HOP`), sent only on
        /// the path route. A claim that can only cause refusal: the supervisor refuses when the
        /// parent-pid walk does not land on exactly this hop.
        #[serde(default)]
        expected_parent: Option<HopKey>,
    },
    /// Revoke every lease the root issued. Safe direction only: it removes authority.
    Revoke { reason: String },
    /// Liveness: a supervisor that is gone must read as gone, not as "nothing to say".
    Ping,
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
    Pong,
}

/// What a descendant is given.
#[derive(Debug)]
pub struct Admission {
    /// The narrowed leases the root derived, in place of the ones asked for.
    pub leases: Vec<CapabilityLease>,
    /// The ancestors the root verified, outermost first.
    pub lineage: Vec<String>,
    /// The channel this hop's own descendants must inherit on [`CHANNEL_FD`].
    pub channel: Option<OwnedFd>,
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

// ---------------------------------------------------------------------------
// Inherited authority channel (SCM_RIGHTS rendezvous)
// ---------------------------------------------------------------------------

/// How a descendant reaches its governing supervisor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Governor {
    /// The channel inherited on [`CHANNEL_FD`]: identity is *holding* it, independent of the parent-pid
    /// chain and of any path.
    Inherited(RawFd),
    /// The path-based index found by walking the parent-pid chain. Only used when no channel was
    /// inherited; it keeps the parent-pid walk's limits.
    Path(Endpoint),
}

fn set_cloexec(fd: RawFd, on: bool) {
    // SAFETY: fcntl on a descriptor this module owns; failure only leaves the flag unchanged.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags >= 0 {
            let new = if on {
                flags | libc::FD_CLOEXEC
            } else {
                flags & !libc::FD_CLOEXEC
            };
            libc::fcntl(fd, libc::F_SETFD, new);
        }
    }
}

/// Send `data` on `sock`, attaching `fd` when given. The first write carries the descriptor.
fn sendmsg_fd(sock: RawFd, data: &[u8], fd: Option<RawFd>) -> std::io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let mut control = [0u64; 8];
    // SAFETY: `msg`, `iov` and `control` outlive the call; the control buffer is large and
    // aligned enough for one SCM_RIGHTS header carrying one descriptor.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        if let Some(fd) = fd {
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
            std::ptr::copy_nonoverlapping(
                (&fd as *const RawFd).cast::<u8>(),
                libc::CMSG_DATA(header),
                std::mem::size_of::<RawFd>(),
            );
        }
        // macOS answers a momentary mbuf shortage on a unix socket with ENOBUFS, and a signal
        // with EINTR; neither means the peer is gone, and dropping the reply there would make a
        // healthy supervisor look unreachable.
        let mut attempts = 0;
        loop {
            let sent = libc::sendmsg(sock, &msg, 0);
            if sent >= 0 {
                return Ok(sent as usize);
            }
            let err = std::io::Error::last_os_error();
            let transient = err.kind() == std::io::ErrorKind::Interrupted
                || matches!(err.raw_os_error(), Some(libc::ENOBUFS | libc::EAGAIN));
            attempts += 1;
            if !transient || attempts > 400 {
                return Err(err);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}

/// Receive into `buf`, returning the byte count and a descriptor if one was attached. The received
/// descriptor is marked close-on-exec: it is only given to a child deliberately.
fn recvmsg_fd(sock: RawFd, buf: &mut [u8]) -> std::io::Result<(usize, Option<OwnedFd>)> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr().cast(),
        iov_len: buf.len(),
    };
    let mut control = [0u64; 8];
    // SAFETY: as in `sendmsg_fd`; the received descriptor is wrapped in an `OwnedFd` immediately.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        // `MSG_CMSG_CLOEXEC` makes the kernel set close-on-exec as it installs each descriptor,
        // so none is inheritable even for an instant. macOS has no such flag; `set_cloexec` below
        // covers it there.
        #[cfg(target_os = "linux")]
        let flags = libc::MSG_CMSG_CLOEXEC;
        #[cfg(not(target_os = "linux"))]
        let flags = 0;
        let received = loop {
            let n = libc::recvmsg(sock, &mut msg, flags);
            if n >= 0 {
                break n;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() != std::io::ErrorKind::Interrupted {
                return Err(err);
            }
        };
        // Every descriptor in every control message is owned here, so any one this function does
        // not hand back is closed on return rather than left in the supervisor's table.
        let mut owned: Vec<OwnedFd> = Vec::new();
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let payload = ((*header).cmsg_len as usize).saturating_sub(libc::CMSG_LEN(0) as usize);
                let count = payload / std::mem::size_of::<RawFd>();
                for i in 0..count {
                    let mut raw: RawFd = -1;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(header).add(i * std::mem::size_of::<RawFd>()),
                        (&mut raw as *mut RawFd).cast::<u8>(),
                        std::mem::size_of::<RawFd>(),
                    );
                    if raw >= 0 {
                        set_cloexec(raw, true);
                        owned.push(OwnedFd::from_raw_fd(raw));
                    }
                }
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
        // Exactly one descriptor, untruncated, is a well-formed request; anything else is dropped
        // (and so closed) and reads as a datagram that carried no descriptor.
        let fd = if owned.len() == 1 && (msg.msg_flags & libc::MSG_CTRUNC) == 0 {
            owned.pop()
        } else {
            None
        };
        Ok((received as usize, fd))
    }
}

/// A connected datagram pair: `(supervisor end, descendant end)`. Both close-on-exec until the
/// descendant end is deliberately given to a child.
fn channel_pair() -> std::io::Result<(UnixDatagram, OwnedFd)> {
    let (server, client) = UnixDatagram::pair()?;
    set_cloexec(client.as_raw_fd(), true);
    server.set_read_timeout(Some(Duration::from_millis(200)))?;
    Ok((server, OwnedFd::from(client)))
}

/// Confirm the inherited channel is served, then keep it from this process's own children.
///
/// One step so that sealing cannot be skipped on the way to being governed by the channel.
fn adopt_inherited_channel(channel: RawFd) -> Result<Governor, String> {
    let governor = Governor::Inherited(channel);
    match exchange(&governor, &Request::Ping) {
        Ok((Response::Pong, _)) => {
            seal_inherited_channel(channel);
            Ok(governor)
        }
        Ok(_) | Err(_) => Err(
            "this process inherited a governed `aasm run` authority channel but its supervisor does not answer"
                .to_string(),
        ),
    }
}

/// Stop this process's own children inheriting the channel it was handed.
///
/// The descriptor is this hop's parent's channel: it carries the parent's authority, which is
/// wider than this hop's. A confined launch does not wire a channel of its own, and nothing
/// else this process spawns (the proxy, the confinement launcher) should hold it either, so a
/// nested `aasm run` below would otherwise be admitted as a sibling of this hop. The unconfined
/// launch re-clears the flag on the descriptor it gives its child, which is this hop's own
/// channel by then (`dup2` in the child's `pre_exec`), not this one.
fn seal_inherited_channel(fd: RawFd) {
    set_cloexec(fd, true);
}

/// The inherited channel on [`CHANNEL_FD`], when this process holds a datagram socket there.
fn inherited_channel() -> Option<RawFd> {
    // SAFETY: read-only queries on a descriptor number; nothing is closed or modified.
    unsafe {
        if libc::fcntl(CHANNEL_FD, libc::F_GETFD) < 0 {
            return None;
        }
        let mut kind: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = libc::getsockopt(
            CHANNEL_FD,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut len,
        );
        (rc == 0 && kind == libc::SOCK_DGRAM).then_some(CHANNEL_FD)
    }
}

/// Open a request stream to the supervisor over the inherited channel: make a stream pair and
/// send the supervisor's end across the channel. A supervisor that is gone makes the send fail.
///
/// Returns our end and the supervisor's end. The caller keeps the supervisor's end open until the
/// supervisor has answered: closing it straight after the send leaves it referenced only by the
/// in-flight message, and on macOS the request already queued on it can then be discarded, so the
/// supervisor reads end-of-file with no request (measured: 9 of 80 runs of the supervisor tests).
fn rendezvous(channel: RawFd) -> std::io::Result<(UnixStream, UnixStream)> {
    let (mine, theirs) = UnixStream::pair()?;
    sendmsg_fd(channel, &[0u8], Some(theirs.as_raw_fd()))?;
    mine.set_read_timeout(Some(IO_TIMEOUT))?;
    mine.set_write_timeout(Some(IO_TIMEOUT))?;
    Ok((mine, theirs))
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
pub fn locate_governed_ancestor() -> Result<Option<Governor>, String> {
    locate_governed_ancestor_via(inherited_channel(), hop_marker_from_env())
}

/// [`locate_governed_ancestor`] with the channel this process holds on [`CHANNEL_FD`] passed in, so
/// a test can drive the real adoption route without owning the process-global descriptor 61.
///
/// `marker` is consulted only when no channel is held: a process that holds the channel is governed by
/// it, whatever its environment says.
fn locate_governed_ancestor_via(inherited: Option<RawFd>, marker: HopMarker) -> Result<Option<Governor>, String> {
    // An inherited channel is the identity. It wins over the path: the path can be deleted and the
    // parent-pid chain can be lost, neither of which changes what this process holds.
    if let Some(channel) = inherited {
        return adopt_inherited_channel(channel).map(Some);
    }
    let found = locate_marked(&default_registry_dir(), std::process::id(), &Kernel, marker)?;
    if let Some(endpoint) = &found {
        probe(endpoint).map_err(|e| {
            format!(
                "an ancestor of this process (pid {}) is a governed `aasm run`, but its supervisor socket {} does not answer ({e})",
                endpoint.supervisor_pid,
                endpoint.socket.display()
            )
        })?;
    }
    Ok(found.map(Governor::Path))
}

/// [`locate_in`] with the reparenting tripwire: a process that carries [`GOVERNED_HOP_ENV`] was born
/// under a governed `aasm run`, so a walk that ends without finding the tree (for any of the ways it
/// can end) means that tree is gone or unreachable, which is a refusal and never a fresh root.
fn locate_marked(dir: &Path, start_pid: u32, procs: &dyn Procs, marker: HopMarker) -> Result<Option<Endpoint>, String> {
    let found = locate_in(dir, start_pid, procs)?;
    if found.is_none() && marker.is_present() {
        return Err(format!(
            "{GOVERNED_HOP_ENV} is set, so this process was started inside a governed `aasm run` tree, but that tree is gone or unreachable (the process lost its authority channel and no governed ancestor is reachable through its parent chain); it will not run as a fresh root above its parent's ceiling"
        ));
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

fn exchange(governor: &Governor, request: &Request) -> Result<(Response, Option<OwnedFd>), String> {
    let (stream, mut supervisor_end) = match governor {
        Governor::Path(endpoint) => connect(endpoint)
            .map(|s| (s, None))
            .map_err(|e| format!("cannot reach the tree supervisor: {e}")),
        Governor::Inherited(channel) => rendezvous(*channel)
            .map(|(mine, theirs)| (mine, Some(theirs)))
            .map_err(|e| format!("cannot reach the tree supervisor over the inherited channel: {e}")),
    }?;
    let body = serde_json::to_vec(request).map_err(|e| format!("cannot encode the request: {e}"))?;
    let sent = (&stream)
        .write_all(&body)
        .and_then(|()| stream.shutdown(std::net::Shutdown::Write));
    match sent {
        Ok(()) => {}
        // A supervisor that refused before our bytes landed has already queued its answer and
        // closed; the peer-gone write error must not hide that answer. When nothing was queued the
        // read below fails or returns an empty reply, and that error names the real problem.
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) => {}
        Err(e) => return Err(format!("cannot send the request to the tree supervisor: {e}")),
    }
    let mut reply = Vec::new();
    let mut channel = None;
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        let (n, fd) = recvmsg_fd(stream.as_raw_fd(), &mut chunk)
            .map_err(|e| format!("cannot read the tree supervisor's reply: {e}"))?;
        if channel.is_none() {
            channel = fd;
        }
        // The first reply byte proves the supervisor holds the request stream; only now may our copy
        // of its end go, so that its closing it ends our read.
        if n > 0 {
            drop(supervisor_end.take());
        }
        if n == 0 {
            break;
        }
        reply.extend_from_slice(&chunk[..n]);
        if reply.len() as u64 > MAX_MESSAGE_BYTES {
            return Err("the tree supervisor's reply is too large".to_string());
        }
    }
    let response = serde_json::from_slice(&reply)
        .map_err(|e| format!("the tree supervisor's reply is malformed or empty: {e}"))?;
    Ok((response, channel))
}

/// Ask the tree root to admit this process as a hop, over whichever way it reaches the root.
///
/// # Errors
///
/// [`Refusal`] when the root refuses, or when it cannot be reached or understood
/// (`SupervisorUnreachable`), so a failure to ask never reads as permission.
pub fn admit_via(
    governor: &Governor,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    registration_did: &str,
) -> Result<Admission, Refusal> {
    admit_expecting(
        governor,
        spec,
        declared_root_agent,
        registration_did,
        hop_marker_from_env(),
    )
}

/// [`admit_via`] with the environment marker passed in. On the path route the marker is sent so the
/// supervisor can check the parent-pid walk landed on the hop the process was born under; over a
/// channel the channel is the identity and the marker is not sent.
///
/// # Errors
///
/// As [`admit_via`]; a malformed marker on the path route is refused as `ParentHopMismatch`.
pub fn admit_expecting(
    governor: &Governor,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    registration_did: &str,
    marker: HopMarker,
) -> Result<Admission, Refusal> {
    if matches!((governor, marker), (Governor::Path(_), HopMarker::Malformed)) {
        return Err(Refusal::new(
            "ParentHopMismatch",
            format!(
                "{GOVERNED_HOP_ENV} is set but malformed, so the hop this process was born under cannot be established"
            ),
        ));
    }
    let expected_parent = match (governor, marker) {
        (Governor::Path(_), HopMarker::Present(key)) => Some(key),
        _ => None,
    };
    let request = Request::Admit {
        spec: Box::new(spec.clone()),
        declared_root_agent: declared_root_agent.map(str::to_string),
        registration_did: registration_did.to_string(),
        expected_parent,
    };
    match exchange(governor, &request).map_err(|e| Refusal::new("SupervisorUnreachable", e))? {
        // An admission with no channel would leave the parent's own channel on fd 61 in the
        // tool, still speaking at the parent's wider authority.
        (Response::Admitted { .. }, None) => Err(Refusal::new(
            "SupervisorUnreachable",
            "the tree supervisor admitted this launch without a channel for its descendants",
        )),
        (Response::Admitted { leases, lineage }, channel) => Ok(Admission {
            leases,
            lineage,
            channel,
        }),
        (Response::Refused { kind, detail }, _) => Err(Refusal { kind, detail }),
        (_, _) => Err(Refusal::new(
            "SupervisorUnreachable",
            "the tree supervisor answered an admission with an unrelated reply",
        )),
    }
}

/// [`admit_via`] over the path-based index.
///
/// # Errors
///
/// As [`admit_via`].
pub fn admit(
    endpoint: &Endpoint,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    registration_did: &str,
) -> Result<Admission, Refusal> {
    admit_via(
        &Governor::Path(endpoint.clone()),
        spec,
        declared_root_agent,
        registration_did,
    )
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
        &Governor::Path(endpoint.clone()),
        &Request::Revoke {
            reason: reason.to_string(),
        },
    )?
    .0
    {
        Response::Revoked { leases } => Ok(leases),
        Response::Refused { kind, detail } => Err(format!("{kind}: {detail}")),
        _ => Err("the tree supervisor answered a revocation with an unrelated reply".to_string()),
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
    aliases: Vec<String>,
}

impl TreeRoot {
    /// Seed a supervisor from the root's own `spec`, which has already passed
    /// `authority_gate` (proven by `witness`).
    ///
    /// The ledger trusts `trusted_issuer` only. A root lease with another issuer is
    /// not tracked, so every descendant asking for that domain is refused
    /// (`LedgerUnverifiable`); the root itself is unaffected. Their ids are returned.
    pub fn seed(
        spec: &ExecutionSpec,
        witness: &AuthorityWitness,
        trusted_issuer: &str,
        registration_did: &str,
    ) -> (Self, Vec<LeaseId>) {
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
                aliases: vec![spec.identity().agent_id.clone(), registration_did.to_string()],
            },
            untracked,
        )
    }
}

struct Hop {
    authority: ParentAuthority,
    agent_id: String,
    /// Every name this hop and its ancestors are known by (agent id and registration DID).
    aliases: Vec<String>,
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

#[cfg(test)]
fn admit_hop(
    state: &mut State,
    peer: u32,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    procs: &dyn Procs,
    now: SystemTime,
) -> Result<Admission, Refusal> {
    admit_hop_as(state, peer, spec, declared_root_agent, "", None, procs, now)
}

#[allow(clippy::too_many_arguments)]
fn admit_hop_as(
    state: &mut State,
    peer: u32,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    registration_did: &str,
    expected_parent: Option<HopKey>,
    procs: &dyn Procs,
    now: SystemTime,
) -> Result<Admission, Refusal> {
    let Some(parent_pid) = nearest_hop(peer, &state.hops, procs) else {
        return Err(Refusal::new(
            "UnrecordedPeer",
            format!("pid {peer} is not a descendant of any process this supervisor admitted"),
        ));
    };
    // The process was born under the hop its environment names; a parent chain that lands on a
    // different hop (or on none of that name) is a process that was moved above its parent.
    if let Some(key) = expected_parent {
        let bound = parent_pid == key.pid
            && state
                .hops
                .get(&key.pid)
                .is_some_and(|h| h.start_marker == Some(key.start));
        if !bound {
            return Err(Refusal::new(
                "ParentHopMismatch",
                format!(
                    "pid {peer} was born under governed hop pid {} but its parent chain reaches hop pid {parent_pid}",
                    key.pid
                ),
            ));
        }
    }
    admit_under(
        state,
        parent_pid,
        peer,
        spec,
        declared_root_agent,
        registration_did,
        procs,
        now,
    )
}

/// Admit `peer` as a child of the hop recorded under `parent_pid`.
///
/// `parent_pid` comes from the caller's identity evidence: the parent-pid walk for a path
/// connection, or the channel the request arrived on for an inherited one. Everything below is the
/// same for both, so the two cannot disagree about what a hop is allowed.
#[allow(clippy::too_many_arguments)]
fn admit_under(
    state: &mut State,
    parent_pid: u32,
    peer: u32,
    spec: &ExecutionSpec,
    declared_root_agent: Option<&str>,
    registration_did: &str,
    procs: &dyn Procs,
    now: SystemTime,
) -> Result<Admission, Refusal> {
    if !state.hops.contains_key(&parent_pid) {
        return Err(Refusal::new(
            "UnrecordedPeer",
            "the channel this request arrived on belongs to a hop that is no longer recorded",
        ));
    }
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
        if !parent.aliases.iter().any(|ancestor| ancestor == declared) {
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
    let mut aliases = parent.aliases.clone();
    aliases.push(child_id.clone());
    if !registration_did.is_empty() {
        aliases.push(registration_did.to_string());
    }
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
            aliases,
            lineage: lineage.clone(),
            start_marker: procs.start_marker(peer),
        },
    );
    Ok(Admission {
        leases: derived,
        lineage,
        channel: None,
    })
}

fn revoke_all(state: &State, reason: &str) -> usize {
    for lease in &state.root_leases {
        state.ledger.revoke(lease, 1, reason);
    }
    state.root_leases.len()
}

/// Everything the supervisor's threads share.
struct Shared {
    state: Mutex<State>,
    procs: Arc<dyn Procs>,
    stop: AtomicBool,
}

/// The most requests one channel serves at once. Admissions are short and rare, so this is generous.
/// The budget is per channel, so a hostile descendant can only use up the slots of the channel it
/// holds (its own hop's), never those another hop's descendants need.
const MAX_CONCURRENT_HANDLERS: usize = 8;

/// A claim on one of the [`MAX_CONCURRENT_HANDLERS`] slots, released on drop.
struct HandlerSlot(Arc<AtomicUsize>);

impl HandlerSlot {
    fn take(counter: &Arc<AtomicUsize>) -> Option<Self> {
        if counter.fetch_add(1, Ordering::SeqCst) >= MAX_CONCURRENT_HANDLERS {
            counter.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Self(Arc::clone(counter)))
    }
}

impl Drop for HandlerSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Tell a requester the channel's handler budget is full, instead of letting it wait out its read
/// timeout with no answer. One non-blocking write: the refusal is a few dozen bytes, so it fits the
/// socket buffer, and a peer that is not reading must not hold the channel loop (a blocking write
/// here would let a hostile descendant stall every other request on its hop's channel).
fn refuse_busy(stream_fd: OwnedFd) {
    let mut stream = UnixStream::from(stream_fd);
    if stream.set_nonblocking(true).is_err() {
        return;
    }
    let busy = Response::Refused {
        kind: "SupervisorBusy".to_string(),
        detail: format!("this hop's channel is already serving {MAX_CONCURRENT_HANDLERS} requests; retry shortly"),
    };
    if let Ok(bytes) = serde_json::to_vec(&busy) {
        let _ = stream.write(&bytes);
    }
    // Closing a socket that still holds unread request bytes makes Linux reset the connection and
    // discard the reply just written, so the requester would see ECONNRESET instead of the refusal.
    // Half-close, then drain what has already arrived, without blocking.
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut sink = [0u8; 4096];
    let mut drained = 0u64;
    while drained < MAX_MESSAGE_BYTES {
        match stream.read(&mut sink) {
            Ok(0) => break,
            Ok(n) => drained += n as u64,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

/// Whether the kernel reports `fd`'s peers all gone.
fn hung_up(fd: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid `pollfd` and a zero timeout; nothing is read or modified.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    rc > 0 && (poll.revents & libc::POLLHUP) != 0
}

/// Whether `fd` is a `SOCK_STREAM` socket.
fn is_stream_socket(fd: RawFd) -> bool {
    let mut kind: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: a read-only query into a local `c_int` of the size passed.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut kind as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    rc == 0 && kind == libc::SOCK_STREAM
}

/// How a connection proved which hop it speaks for.
#[derive(Clone, Copy)]
enum Via {
    /// Connected to the path socket: identity is the peer's place in the parent-pid chain.
    Path,
    /// Arrived over the channel handed to the hop recorded under this pid, whose process had this
    /// start marker when the channel was opened: identity is the channel. The marker keeps a channel
    /// from speaking for a different process that later reused the pid.
    Channel(u32, Option<u64>),
}

/// Read a request to end-of-stream, at most [`MAX_MESSAGE_BYTES`], within [`IO_TIMEOUT`] in total.
/// The per-read socket timeout alone would let a sender that trickles a byte at a time hold the
/// handler for as long as it likes.
fn read_request(stream: &mut UnixStream, body: &mut Vec<u8>) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    let mut chunk = [0u8; 4096];
    loop {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        let n = match stream.read(&mut chunk) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Ok(());
        }
        body.extend_from_slice(&chunk[..n]);
        if body.len() as u64 >= MAX_MESSAGE_BYTES {
            body.truncate(MAX_MESSAGE_BYTES as usize);
            return Ok(());
        }
    }
}

/// Write `bytes` within [`IO_TIMEOUT`] in total. The per-write socket timeout alone resets on every
/// partial write, so a peer that drains a byte at a time would hold the handler and its slot.
fn write_all_within_deadline(stream: &mut UnixStream, mut bytes: &[u8]) -> std::io::Result<()> {
    let deadline = std::time::Instant::now() + IO_TIMEOUT;
    while !bytes.is_empty() {
        if std::time::Instant::now() >= deadline {
            return Err(std::io::ErrorKind::TimedOut.into());
        }
        match stream.write(bytes) {
            Ok(0) => return Err(std::io::ErrorKind::WriteZero.into()),
            Ok(n) => bytes = &bytes[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

fn handle(stream: &mut UnixStream, shared: &Arc<Shared>, via: Via) {
    let mut body = Vec::new();
    let read = read_request(stream, &mut body);
    if read.is_err() || body.is_empty() {
        // A bare connection is a liveness probe.
        #[cfg(test)]
        eprintln!(
            "supervisor: request body empty or unreadable: read={read:?} len={}",
            body.len()
        );
        return;
    }
    let mut reply_fd: Option<OwnedFd> = None;
    let response = match serde_json::from_slice::<Request>(&body) {
        Err(e) => Response::Refused {
            kind: "MalformedRequest".to_string(),
            detail: e.to_string(),
        },
        Ok(Request::Ping) => Response::Pong,
        Ok(Request::Revoke { reason }) => {
            let state = shared.state.lock().expect("supervisor state poisoned");
            Response::Revoked {
                leases: revoke_all(&state, &reason),
            }
        }
        Ok(Request::Admit {
            spec,
            declared_root_agent,
            registration_did,
            expected_parent,
        }) => match peer_pid(stream) {
            None => Response::Refused {
                kind: "UnrecordedPeer".to_string(),
                detail: "the kernel did not report the peer's pid".to_string(),
            },
            Some(peer) => {
                let mut state = shared.state.lock().expect("supervisor state poisoned");
                let now = SystemTime::now();
                let procs = shared.procs.as_ref();
                let outcome = match via {
                    Via::Path => admit_hop_as(
                        &mut state,
                        peer,
                        &spec,
                        declared_root_agent.as_deref(),
                        &registration_did,
                        expected_parent,
                        procs,
                        now,
                    ),
                    Via::Channel(parent, marker) => {
                        if !channel_speaks_for(&state, parent, marker) {
                            Err(Refusal::new(
                                "UnrecordedPeer",
                                "the channel this request arrived on belongs to a hop that has been replaced by another process under the same pid",
                            ))
                        } else {
                            admit_under(
                                &mut state,
                                parent,
                                peer,
                                &spec,
                                declared_root_agent.as_deref(),
                                &registration_did,
                                procs,
                                now,
                            )
                        }
                    }
                };
                match outcome {
                    Ok(admission) => {
                        match open_channel(shared, peer, state.hops.get(&peer).and_then(|h| h.start_marker)) {
                            Ok(channel) => {
                                reply_fd = Some(channel);
                                Response::Admitted {
                                    leases: admission.leases,
                                    lineage: admission.lineage,
                                }
                            }
                            Err(e) => {
                                // A hop that cannot be given a channel has no way to govern ITS
                                // descendants; it must not run as a governed hop that does not exist.
                                state.hops.remove(&peer);
                                Response::Refused {
                                    kind: "ChannelUnavailable".to_string(),
                                    detail: format!("cannot open the descendant channel for this hop: {e}"),
                                }
                            }
                        }
                    }
                    Err(refusal) => Response::Refused {
                        kind: refusal.kind,
                        detail: refusal.detail,
                    },
                }
            }
        },
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        // The descriptor rides on the first write; the rest of a large reply follows plainly.
        let fd = reply_fd.as_ref().map(AsRawFd::as_raw_fd);
        match sendmsg_fd(stream.as_raw_fd(), &bytes, fd) {
            Ok(sent) => {
                let _ = write_all_within_deadline(stream, &bytes[sent.min(bytes.len())..]);
            }
            Err(e) => {
                #[cfg(test)]
                eprintln!("supervisor: reply not sent: {e}");
                #[cfg(not(test))]
                let _ = e;
            }
        }
    }
}

/// Whether a channel opened for the process `parent` had at `marker` still speaks for the hop
/// recorded under that pid. A recorded hop that a different process replaced (pid reuse) is not it.
fn channel_speaks_for(state: &State, parent: u32, marker: Option<u64>) -> bool {
    marker.is_some() && state.hops.get(&parent).map(|hop| hop.start_marker) == Some(marker)
}

/// Make the channel the hop recorded under `hop` hands to its descendants, and start serving it.
/// Returns the descendant end.
fn open_channel(shared: &Arc<Shared>, hop: u32, marker: Option<u64>) -> std::io::Result<OwnedFd> {
    let (server, client) = channel_pair()?;
    let shared = Arc::clone(shared);
    let handlers = Arc::new(AtomicUsize::new(0));
    // A fallible spawn: `open_channel` runs with the supervisor state locked, and a panic there
    // would poison the lock and take down every later admission in the tree.
    std::thread::Builder::new()
        .name("aasm-supervisor-channel".into())
        .spawn(move || {
            let mut byte = [0u8; 8];
            while !shared.stop.load(Ordering::SeqCst) {
                match recvmsg_fd(server.as_raw_fd(), &mut byte) {
                    Ok((_, Some(stream_fd))) => {
                        // A stopped supervisor answers nothing, even a request already in flight.
                        if shared.stop.load(Ordering::SeqCst) {
                            break;
                        }
                        // A descriptor from a descendant is untrusted: a pipe or file would ignore the
                        // read timeout and hold a handler for good.
                        if !is_stream_socket(stream_fd.as_raw_fd()) {
                            continue;
                        }
                        let Some(slot) = HandlerSlot::take(&handlers) else {
                            refuse_busy(stream_fd);
                            continue;
                        };
                        let mut stream = UnixStream::from(stream_fd);
                        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                        let shared = Arc::clone(&shared);
                        let _ = std::thread::Builder::new()
                            .name("aasm-supervisor-handler".into())
                            .spawn(move || {
                                let _slot = slot;
                                handle(&mut stream, &shared, Via::Channel(hop, marker));
                            });
                    }
                    // A datagram socket has no end-of-file, so an empty datagram is not a close: any
                    // holder of the channel can send one, and treating it as one would let it silence
                    // the hop's channel for every sibling and descendant. Only a kernel hang-up (every
                    // descendant end closed) ends the loop early; otherwise it ends on `stop`. No sleep
                    // here: the 200 ms receive timeout already bounds an idle loop, and a pause per
                    // datagram would let a flood of empty ones delay the real requests behind them.
                    Ok((0, None)) => {
                        if hung_up(server.as_raw_fd()) {
                            break;
                        }
                    }
                    Ok(_) => {}
                    // Also checked here: where a closed peer reads as a timeout rather than an empty
                    // datagram, this is the only place the loop could notice every end is gone.
                    Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {
                        if hung_up(server.as_raw_fd()) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        })?;
    Ok(client)
}

/// A running tree-root supervisor. Dropping it stops serving and removes its
/// socket and index entry.
pub struct TreeSupervisor {
    socket: PathBuf,
    index: PathBuf,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
    root_channel: Option<OwnedFd>,
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
                aliases: root.aliases,
                lineage: Vec::new(),
                start_marker,
            },
        );
        let shared = Arc::new(Shared {
            state: Mutex::new(State {
                ledger: root.ledger,
                root_leases: root.root_leases,
                hops,
            }),
            procs,
            stop: AtomicBool::new(false),
        });

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

        let root_channel = open_channel(&shared, pid, Some(start_marker))?;

        let thread = {
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                while !shared.stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
                            let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
                            let shared = Arc::clone(&shared);
                            std::thread::spawn(move || handle(&mut stream, &shared, Via::Path));
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
            shared,
            thread: Some(thread),
            root_channel: Some(root_channel),
        })
    }

    /// The socket this supervisor serves.
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The channel the root's own descendants must inherit on [`CHANNEL_FD`]. Handed out once.
    pub fn take_root_channel(&mut self) -> Option<OwnedFd> {
        self.root_channel.take()
    }
}

impl Drop for TreeSupervisor {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
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
        let (root, untracked) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        assert!(untracked.is_empty());
        let mut hops = HashMap::new();
        hops.insert(
            100,
            Hop {
                authority: root.authority,
                agent_id: root.agent_id,
                aliases: root.aliases,
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
    fn a_declared_root_agent_may_be_named_by_its_registration_did() {
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        let gen2 = spec_with("gen2", vec![fs_read(sel(&["/a"]), 3600, true, "gen2")]);
        // The gateway resolves a declared parent by DID, so a real `--root-agent` is a DID.
        let by_did = admit_hop_as(
            &mut state,
            200,
            &gen2,
            Some("did:key:root"),
            "did:key:gen2",
            None,
            &procs,
            now(),
        );
        assert!(by_did.is_ok(), "{by_did:?}");
        // Control: the gen2 DID is now an alias of an ancestor of gen3, a name nobody holds is not.
        let gen3 = spec_with("gen3", vec![fs_read(sel(&["/a"]), 3600, true, "gen3")]);
        let refused = admit_hop_as(
            &mut state,
            300,
            &gen3,
            Some("did:key:nobody"),
            "did:key:gen3",
            None,
            &procs,
            now(),
        )
        .expect_err("unknown DID");
        assert_eq!(refused.kind, "AncestryMismatch", "{refused}");
        admit_hop_as(
            &mut state,
            300,
            &gen3,
            Some("did:key:gen2"),
            "did:key:gen3",
            None,
            &procs,
            now(),
        )
        .expect("ancestor DID");
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
        let (root, untracked) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        assert_eq!(untracked.len(), 1);
        let mut hops = HashMap::new();
        hops.insert(
            100,
            Hop {
                authority: root.authority,
                agent_id: root.agent_id,
                aliases: root.aliases,
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
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let supervisor = TreeSupervisor::start_in(&dir, 100, root, procs.clone()).expect("start");
        let socket = supervisor.socket().to_path_buf();
        let endpoint = locate_in(&dir, me, procs.as_ref()).unwrap().expect("index found");
        probe(&endpoint).expect("answers");

        let broad = spec_with("child", vec![fs_read(sel(&["/a", "/b"]), 3600, true, "child")]);
        let refused = admit(&endpoint, &broad, None, "did:key:child").expect_err("broader refused over the socket");
        assert_eq!(refused.kind, "ChildExceedsParent", "{refused}");

        let ok = spec_with("child", vec![fs_read(sel(&["/a"]), 3600, true, "child")]);
        let admission = admit(&endpoint, &ok, None, "did:key:child").expect("narrower admitted over the socket");
        assert_eq!(admission.leases[0].scope(), &sel(&["/a"]));
        assert!(
            admission.leases[0].provenance().is_some(),
            "re-issued through the ledger"
        );

        // A second admission of the same peer is refused: a hop is admitted once.
        let again = admit(&endpoint, &ok, None, "did:key:child").expect_err("once");
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
    fn a_channel_does_not_speak_for_a_different_process_that_reused_its_pid() {
        struct Marker(u64);
        impl Procs for Marker {
            fn parent_of(&self, _: u32) -> Option<u32> {
                None
            }
            fn start_marker(&self, _: u32) -> Option<u64> {
                Some(self.0)
            }
        }
        let state = root_state(Vec::new(), &Marker(7));
        assert!(
            channel_speaks_for(&state, 100, Some(7)),
            "control: the hop's own channel"
        );
        assert!(
            !channel_speaks_for(&state, 100, Some(8)),
            "a channel opened for an earlier process under this pid"
        );
        assert!(!channel_speaks_for(&state, 100, None), "no marker, no identity");
        assert!(!channel_speaks_for(&state, 999, Some(7)), "an unrecorded hop");
    }

    #[test]
    fn a_hop_is_identified_by_the_channel_it_arrived_on_not_by_its_parent_pid_chain() {
        let base = private_dir("channel");
        let dir = registry_dir_in(&base);
        let me = std::process::id();
        // The synthetic table puts this process in NO tree: its parent chain ends at pid 1.
        let procs = Arc::new(Fake::new(&[(me, 1), (100, 1)]));
        procs.markers.lock().unwrap().insert(me, 7);

        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs.clone()).expect("start");
        let root_channel = supervisor.take_root_channel().expect("root channel");
        let socket = supervisor.socket().to_path_buf();
        let endpoint = Endpoint {
            supervisor_pid: 100,
            socket,
        };

        let ok = spec_with("child", vec![fs_read(sel(&["/a"]), 3600, true, "child")]);
        // Control: over the PATH this process is refused, because its parent chain reaches no hop.
        let by_path = admit(&endpoint, &ok, None, "did:key:child").expect_err("path peers need a pid chain");
        assert_eq!(by_path.kind, "UnrecordedPeer", "{by_path}");

        // Over the inherited channel the same request is admitted: holding the channel is the identity.
        let governor = Governor::Inherited(root_channel.as_raw_fd());
        let admission = admit_via(&governor, &ok, None, "did:key:child").expect("admitted by channel");
        assert_eq!(admission.lineage, vec!["root".to_string()]);
        let child_channel = admission
            .channel
            .expect("the admitted hop gets a channel for its own descendants");

        // A grandchild, over the CHILD's channel, is judged against the child, and can only narrow it.
        // The test process stands in for every hop, so give it a new start marker: the supervisor then
        // reads the recorded pid as a reused one rather than as the same hop admitted twice.
        procs.markers.lock().unwrap().insert(me, 8);
        let grandchild_governor = Governor::Inherited(child_channel.as_raw_fd());
        let broad = spec_with("grand", vec![fs_read(sel(&["/a", "/b"]), 3600, true, "grand")]);
        let refused = admit_via(&grandchild_governor, &broad, None, "did:key:grand").expect_err("wider than the child");
        assert_eq!(refused.kind, "ChildExceedsParent", "{refused}");

        drop(supervisor);
        assert!(
            admit_via(&governor, &ok, None, "did:key:child").is_err(),
            "a stopped supervisor must not answer an inherited channel"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn many_rendezvous_over_one_inherited_channel_are_all_answered() {
        // The request stream's far end travels as an in-flight descriptor; if the sender lets go of
        // it too early the supervisor can read end-of-file with no request (seen on macOS).
        let base = private_dir("rendezvous-burst");
        let dir = registry_dir_in(&base);
        let procs = Arc::new(Fake::new(&[(std::process::id(), 1), (100, 1)]));
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs).expect("start");
        let channel = supervisor.take_root_channel().expect("root channel");
        for i in 0..2000 {
            let answered = exchange(&Governor::Inherited(channel.as_raw_fd()), &Request::Ping);
            assert!(
                matches!(answered, Ok((Response::Pong, _))),
                "rendezvous {i}: {answered:?}"
            );
        }
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_hostile_datagram_on_the_channel_does_not_silence_it_or_leak_descriptors() {
        let base = private_dir("hostile-datagram");
        let dir = registry_dir_in(&base);
        let procs = Arc::new(Fake::new(&[(std::process::id(), 1), (100, 1)]));
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs).expect("start");
        let channel = supervisor.take_root_channel().expect("root channel");
        let governor = Governor::Inherited(channel.as_raw_fd());

        // Empty datagram: not an end-of-file, so the channel keeps answering afterwards.
        sendmsg_fd(channel.as_raw_fd(), &[], None).expect("empty datagram");
        // Descriptor that is not a stream socket (a pipe): ignored, not held by a handler forever.
        let (pipe_read, _pipe_write) = std::io::pipe().expect("pipe");
        sendmsg_fd(channel.as_raw_fd(), &[0u8], Some(pipe_read.as_raw_fd())).expect("pipe datagram");
        // A datagram socket where a stream is expected: also refused.
        let (dgram, _peer) = UnixDatagram::pair().expect("dgram pair");
        sendmsg_fd(channel.as_raw_fd(), &[0u8], Some(dgram.as_raw_fd())).expect("dgram datagram");

        for i in 0..20 {
            let answered = exchange(&governor, &Request::Ping);
            assert!(
                matches!(answered, Ok((Response::Pong, _))),
                "channel must still answer after hostile datagrams ({i}): {answered:?}"
            );
        }
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Adopting a served channel is what seals it: removing the seal from the adoption path
    /// must fail here, not only the helper's own test.
    #[test]
    fn adopting_a_served_inherited_channel_seals_it_against_spawned_children() {
        use std::os::fd::AsRawFd;
        let base = private_dir("adopt-seals");
        let dir = registry_dir_in(&base);
        let procs = Arc::new(Fake::new(&[(std::process::id(), 1), (100, 1)]));
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs).expect("start");
        let channel = supervisor.take_root_channel().expect("root channel");
        let fd = channel.as_raw_fd();
        let inherits = || {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("[ -e /dev/fd/{fd} ]"))
                .status()
                .expect("spawn sh")
                .success()
        };
        set_cloexec(fd, false);
        assert!(inherits(), "control: before adoption the child sees the descriptor");
        adopt_inherited_channel(fd).expect("a served channel is adopted");
        assert!(!inherits(), "adoption must keep the channel from spawned children");
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// H1 (review): a confined descendant must not hand the parent hop's wider channel to
    /// anything it spawns. Measured with a real exec: the child asks the OS whether the
    /// descriptor exists in its own table, first without the seal (control: it is inherited, so
    /// the probe can see an inherited descriptor at all), then with it.
    /// The route a launch actually takes is `locate_governed_ancestor`: if it ever stopped going
    /// through the adoption step, the parent hop's wider channel would reach every child again.
    #[test]
    fn locating_through_an_inherited_channel_seals_it_against_spawned_children() {
        use std::os::fd::AsRawFd;
        let base = private_dir("locate-seals");
        let dir = registry_dir_in(&base);
        let procs = Arc::new(Fake::new(&[(std::process::id(), 1), (100, 1)]));
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs).expect("start");
        let channel = supervisor.take_root_channel().expect("root channel");
        let fd = channel.as_raw_fd();
        let inherits = || {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("[ -e /dev/fd/{fd} ]"))
                .status()
                .expect("spawn sh")
                .success()
        };
        set_cloexec(fd, false);
        assert!(inherits(), "control: before locating, the child sees the descriptor");
        let located = locate_governed_ancestor_via(Some(fd), HopMarker::Absent).expect("a served channel is located");
        assert!(located.is_some(), "an inherited channel is the governor");
        assert!(
            !inherits(),
            "locating the governor must keep the channel from spawned children"
        );
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn a_sealed_inherited_channel_is_not_passed_to_spawned_children() {
        use std::os::fd::AsRawFd;
        let (held, _peer) = std::os::unix::net::UnixDatagram::pair().expect("socketpair");
        let fd = held.as_raw_fd();
        let inherits = |fd: RawFd| {
            std::process::Command::new("sh")
                .arg("-c")
                .arg(format!("[ -e /dev/fd/{fd} ]"))
                .status()
                .expect("spawn sh")
                .success()
        };
        set_cloexec(fd, false);
        assert!(inherits(fd), "control: an unsealed descriptor is visible to the child");
        seal_inherited_channel(fd);
        assert!(!inherits(fd), "a sealed channel must not reach a spawned child");
    }

    #[test]
    fn a_full_handler_budget_answers_busy_instead_of_dropping_the_request() {
        let base = private_dir("busy-budget");
        let dir = registry_dir_in(&base);
        let procs = Arc::new(Fake::new(&[(std::process::id(), 1), (100, 1)]));
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs).expect("start");
        let channel = supervisor.take_root_channel().expect("root channel");

        // Requests that connect and then say nothing hold a handler until the read times out.
        let mut silent = Vec::new();
        for _ in 0..MAX_CONCURRENT_HANDLERS {
            let (mine, theirs) = UnixStream::pair().expect("pair");
            sendmsg_fd(channel.as_raw_fd(), &[0u8], Some(theirs.as_raw_fd())).expect("send");
            silent.push(mine);
        }
        let started = std::time::Instant::now();
        let answered = exchange(&Governor::Inherited(channel.as_raw_fd()), &Request::Ping);
        match answered {
            Ok((Response::Refused { kind, .. }, _)) => assert_eq!(kind, "SupervisorBusy"),
            other => panic!("a full budget must refuse explicitly, got {other:?}"),
        }
        assert!(
            started.elapsed() < IO_TIMEOUT,
            "the refusal must not wait out the read timeout"
        );

        // Once the silent requests are gone the channel serves again.
        drop(silent);
        let mut served = false;
        for _ in 0..200 {
            if matches!(
                exchange(&Governor::Inherited(channel.as_raw_fd()), &Request::Ping),
                Ok((Response::Pong, _))
            ) {
                served = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert!(served, "slots must be released when the held requests end");
        drop(supervisor);
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
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
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

    // --- AAASM-6273 M2: the reparenting tripwire and hop binding ---

    fn present() -> HopMarker {
        HopMarker::Present(HopKey { pid: 100, start: 101 })
    }

    /// One walk per way `locate_in` can end in `Ok(None)`: `(label, registry dir, start pid)`.
    fn lost_tree_exits(base: &Path) -> Vec<(&'static str, PathBuf, u32)> {
        let usable = registry_dir_in(base);
        ensure_registry_dir(&usable).unwrap();
        let shared = base.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o777)).unwrap();
        vec![
            ("registry dir missing", base.join("absent"), 300),
            ("dir not exclusively owned", shared, 300),
            ("parent_of is None", usable.clone(), 777),
            ("parent is init", usable.clone(), 500),
            ("depth exhausted", usable, 2000),
        ]
    }

    fn lost_tree_table() -> Fake {
        let mut edges = vec![(110, 100), (200, 110), (210, 200), (300, 210), (999, 1), (500, 999)];
        // A chain longer than MAX_ANCESTRY_DEPTH that never meets an index or init.
        edges.extend((2000..2100).map(|p| (p, p + 1)));
        Fake::new(&edges)
    }

    #[test]
    fn a_marker_turns_every_lost_tree_exit_into_a_refusal_and_without_it_the_walk_reports_a_root() {
        let base = private_dir("tripwire");
        let procs = lost_tree_table();
        for (label, dir, start) in lost_tree_exits(&base) {
            // Control: with no marker the very same walk is a root launch.
            assert_eq!(
                locate_marked(&dir, start, &procs, HopMarker::Absent).unwrap(),
                None,
                "{label}: control"
            );
            for marker in [present(), HopMarker::Malformed] {
                let err = locate_marked(&dir, start, &procs, marker).expect_err(label);
                assert!(
                    err.contains(GOVERNED_HOP_ENV) && err.contains("gone or unreachable"),
                    "{label}: {err}"
                );
            }
        }

        // The marker never replaces a found tree: with an index for pid 100 the walk finds it.
        let dir = registry_dir_in(&base);
        let entry = IndexEntry {
            supervisor_pid: 100,
            start_marker: procs.start_marker(100).unwrap(),
            socket: dir.join("x.sock"),
        };
        std::fs::write(dir.join("100.idx"), serde_json::to_vec(&entry).unwrap()).unwrap();
        let found = locate_marked(&dir, 300, &procs, present()).unwrap();
        assert_eq!(found.map(|e| e.supervisor_pid), Some(100));
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn only_a_well_formed_v1_value_is_a_marker_and_any_other_value_counts_as_present() {
        use std::ffi::OsStr;
        let key = HopKey { pid: 12, start: 34 };
        assert_eq!(HopMarker::parse(Some(OsStr::new("v1:12:34"))), HopMarker::Present(key));
        assert_eq!(HopMarker::parse(None), HopMarker::Absent);
        for bad in [
            "",
            "v1",
            "v1:12",
            "v2:12:34",
            "v1:x:34",
            "v1:12:y",
            "v1:12:34:5",
            "12:34",
        ] {
            assert_eq!(HopMarker::parse(Some(OsStr::new(bad))), HopMarker::Malformed, "{bad:?}");
        }
        assert!(governed_hop_value().is_some_and(|v| v.starts_with(&format!("v1:{}:", std::process::id()))));
    }

    /// `100 (root) <- 110 <- 200 (hop H, admitted) <- 210 <- 300 (R)`, and a second table in which
    /// 300 hangs directly below the root although H (200) is recorded.
    fn hop_key(procs: &Fake, pid: u32) -> HopKey {
        HopKey {
            pid,
            start: procs.start_marker(pid).unwrap(),
        }
    }

    #[test]
    fn a_path_admission_bound_to_the_hop_its_marker_names_is_admitted_and_a_different_hop_is_refused() {
        let leases = |who: &str| vec![fs_read(sel(&["/a"]), 3600, true, who)];
        let admit_r = |state: &mut State, procs: &Fake, expected: Option<HopKey>| {
            let r = spec_with("r", leases("r"));
            admit_hop_as(state, 300, &r, None, "", expected, procs, now())
        };

        // P -> H -> R: the walk lands on H and the marker names H.
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        admit_hop(&mut state, 200, &spec_with("h", leases("h")), None, &procs, now()).expect("H admitted");
        let under_h = admit_r(&mut state, &procs, Some(hop_key(&procs, 200))).expect("R admitted under H");
        assert_eq!(under_h.lineage, vec!["root".to_string(), "h".to_string()]);

        // P -> R with H recorded: the marker names H but R's chain reaches only the root.
        let procs = Fake::new(&[(110, 100), (200, 110), (300, 110)]);
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        admit_hop(&mut state, 200, &spec_with("h", leases("h")), None, &procs, now()).expect("H admitted");
        let refused = admit_r(&mut state, &procs, Some(hop_key(&procs, 200))).expect_err("wrong hop");
        assert_eq!(refused.kind, "ParentHopMismatch", "{refused}");
        // Controls: the marker naming the hop the walk does land on, and no marker at all
        // (characterization: an unmarked process is placed by its walk and admitted under the root).
        let ok = admit_r(&mut state, &procs, Some(hop_key(&procs, 100))).expect("marker names the root");
        assert_eq!(ok.lineage, vec!["root".to_string()]);
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        admit_hop(&mut state, 200, &spec_with("h", leases("h")), None, &procs, now()).expect("H admitted");
        let unmarked = admit_r(&mut state, &procs, None).expect("no marker is the old behaviour");
        assert_eq!(unmarked.lineage, vec!["root".to_string()]);

        // An unknown hop, a wrong start marker and a reused pid are all refused.
        let procs = chain();
        let mut state = root_state(vec![fs_read(sel(&["/a"]), 3600, true, "root")], &procs);
        admit_hop(&mut state, 200, &spec_with("h", leases("h")), None, &procs, now()).expect("H admitted");
        for (label, key) in [
            ("unknown hop", HopKey { pid: 4321, start: 4322 }),
            ("wrong start marker", HopKey { pid: 200, start: 5 }),
        ] {
            let refused = admit_r(&mut state, &procs, Some(key)).expect_err(label);
            assert_eq!(refused.kind, "ParentHopMismatch", "{label}: {refused}");
        }
        let named = hop_key(&procs, 200);
        procs.markers.lock().unwrap().insert(200, 9_999_999);
        let refused = admit_r(&mut state, &procs, Some(named)).expect_err("reused pid");
        assert_eq!(refused.kind, "ParentHopMismatch", "{refused}");
    }

    #[test]
    fn the_marker_is_sent_over_the_path_and_checked_by_the_supervisor_and_ignored_over_a_channel() {
        let base = private_dir("marker-wire");
        let dir = registry_dir_in(&base);
        let me = std::process::id();
        let procs = Arc::new(Fake::new(&[(me, 100), (100, 1)]));
        procs.markers.lock().unwrap().insert(me, 7);
        let spec = spec_with("root", vec![fs_read(sel(&["/a"]), 3600, true, "root")]);
        let witness = authority_gate(&spec, &Ancestry::Root, now()).unwrap();
        let (root, _) = TreeRoot::seed(&spec, &witness, ISSUER, "did:key:root");
        let mut supervisor = TreeSupervisor::start_in(&dir, 100, root, procs.clone()).expect("start");
        let root_channel = supervisor.take_root_channel().expect("root channel");
        let endpoint = Endpoint {
            supervisor_pid: 100,
            socket: supervisor.socket().to_path_buf(),
        };
        let ask = spec_with("child", vec![fs_read(sel(&["/a"]), 3600, true, "child")]);
        let path = Governor::Path(endpoint);
        let wrong = HopMarker::Present(HopKey { pid: 4242, start: 1 });

        let refused = admit_expecting(&path, &ask, None, "did:key:c", wrong).expect_err("wrong hop");
        assert_eq!(refused.kind, "ParentHopMismatch", "{refused}");
        let malformed = admit_expecting(&path, &ask, None, "did:key:c", HopMarker::Malformed).expect_err("malformed");
        assert_eq!(malformed.kind, "ParentHopMismatch", "{malformed}");

        // Controls: the marker that names the walk's hop, and then a channel, which ignores a marker
        // that would have been refused on the path.
        let right = HopMarker::Present(hop_key(&procs, 100));
        admit_expecting(&path, &ask, None, "did:key:c", right).expect("the right hop is admitted");
        procs.markers.lock().unwrap().insert(me, 8);
        let channel = Governor::Inherited(root_channel.as_raw_fd());
        admit_expecting(&channel, &ask, None, "did:key:c", wrong).expect("a channel ignores the marker");
        drop(supervisor);
        let _ = std::fs::remove_dir_all(&base);
    }
}
