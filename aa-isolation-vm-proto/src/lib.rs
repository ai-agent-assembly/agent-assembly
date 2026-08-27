//! Wire contract for the `aa-isolation-macos-vm` host↔guest launch protocol
//! (AAASM-5837).
//!
//! # Why this is its own crate rather than living in either endpoint
//!
//! The host side (`aa-isolation-macos-vm`, a normal Rust binary/library) and
//! the guest side (`guest-init`, cross-compiled `aarch64`/`x86_64`-musl,
//! `panic = "abort"`, PID 1 in a VM with no way to attach a debugger) are two
//! different processes built by two different toolchains. Nothing but shared
//! code can hold a wire contract between them together — a comment saying
//! "these must match" is not a contract, it is a hope. [`Message`], the
//! [`read_frame`]/[`write_frame`] pair, and [`to_launcher_argv`] are that
//! shared code: change a field here and both sides fail to compile, rather
//! than one of them silently misinterpreting the other's bytes.
//!
//! # Framing: why the version lives in a header, not the JSON body
//!
//! A version field inside the JSON body can only be read *after* the body
//! parses — so a peer whose body shape changed would be misparsed before the
//! version check ever ran. [`read_frame`] reads `magic` and `version` before
//! the body, so a version mismatch is refused before a single byte of
//! (possibly incompatible) JSON is touched.
//!
//! # This crate never invents a claim
//!
//! ADR 0035 fixes the `IsolationReport`/`CapabilityReport`/`ClaimTerm`
//! vocabulary; this crate's [`Message::LaunchOutcome::implicit_grants`] is
//! *evidence input* for that vocabulary, not a new claim of its own — the
//! caller (`aa-isolation-macos-vm`) is the one that owns
//! `aa_isolation::EnforcementEvidence` and must record it under an existing
//! `ClaimTerm`, never a new one.

use std::io::{self, Read, Write};

use serde::{Deserialize, Serialize};

/// The four bytes every frame starts with. Chosen so a peer speaking an
/// unrelated protocol on the same vsock port (or a stale build sending the
/// old fixed `hello-from-guest-vsock` greeting) produces a named "wrong
/// magic" refusal instead of a JSON parse error whose cause is a mystery.
pub const MAGIC: [u8; 4] = *b"AASM";

/// The wire protocol's own version, independent of crate/workspace versions.
/// Bumped only when [`Message`]'s shape changes in a way an old peer could
/// misinterpret. A mismatch is refused by [`read_frame`] before the body is
/// parsed — see the crate documentation.
pub const PROTOCOL_VERSION: u16 = 1;

/// The largest body a frame may carry.
///
/// Stated as robustness against a garbled or version-mismatched peer, not as
/// an adversarial control: both ends of this channel are AASM's own
/// processes. 1 MiB comfortably covers a launch request's args/env and a
/// captured stdout/stderr pair; anything past it is refused rather than
/// silently truncated at the frame layer — see [`Message::LaunchOutcome`] for
/// where truncation *is* an explicit, named choice.
pub const MAX_BODY_BYTES: u32 = 1024 * 1024;

/// A framing-layer failure — the header or the body could not be trusted
/// enough to hand to [`serde_json`], or the transport itself failed.
///
/// Distinct from [`Message::ProtocolError`], which is a *message* one peer
/// sends the other after successfully framing it. A [`FrameError`] means
/// framing itself did not succeed, so there is nothing to send — the caller's
/// only remaining move is to report locally and tear down the connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum FrameError {
    /// The transport itself failed (read/write/EOF).
    Io(io::Error),
    /// The first four bytes were not [`MAGIC`].
    WrongMagic {
        /// The bytes actually read.
        found: [u8; 4],
    },
    /// The header named a protocol version this build does not speak.
    UnsupportedVersion {
        /// The version the peer sent.
        found: u16,
        /// The version this build speaks.
        expected: u16,
    },
    /// The header's length field exceeded [`MAX_BODY_BYTES`].
    BodyTooLarge {
        /// The length the header named.
        found: u32,
    },
    /// The body's bytes did not parse as a [`Message`].
    Malformed(serde_json::Error),
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "transport failed: {err}"),
            Self::WrongMagic { found } => write!(f, "wrong frame magic: found {found:02x?}, expected {MAGIC:02x?}"),
            Self::UnsupportedVersion { found, expected } => {
                write!(f, "unsupported protocol version {found}, this build speaks {expected}")
            }
            Self::BodyTooLarge { found } => {
                write!(f, "frame body of {found} bytes exceeds the {MAX_BODY_BYTES}-byte bound")
            }
            Self::Malformed(err) => write!(f, "frame body did not parse: {err}"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<io::Error> for FrameError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Read one framed [`Message`] from `reader`.
///
/// Validates magic and version *before* reading the body — see the crate
/// documentation for why that ordering is load-bearing, not stylistic — and
/// the length against [`MAX_BODY_BYTES`] before allocating a buffer for it,
/// so a peer that lies about a huge length cannot force an allocation before
/// this function has any reason to trust it.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Message, FrameError> {
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if magic != MAGIC {
        return Err(FrameError::WrongMagic { found: magic });
    }

    let mut version_bytes = [0u8; 2];
    reader.read_exact(&mut version_bytes)?;
    let version = u16::from_be_bytes(version_bytes);
    if version != PROTOCOL_VERSION {
        return Err(FrameError::UnsupportedVersion {
            found: version,
            expected: PROTOCOL_VERSION,
        });
    }

    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes)?;
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_BODY_BYTES {
        return Err(FrameError::BodyTooLarge { found: len });
    }

    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body)?;
    serde_json::from_slice(&body).map_err(FrameError::Malformed)
}

/// Write one framed [`Message`] to `writer`.
///
/// # Errors
///
/// [`FrameError::Io`] if the transport fails. Serialization of a well-formed
/// [`Message`] cannot itself fail (every field is a plain owned type), so
/// there is no `Malformed` case on the write side.
pub fn write_frame<W: Write>(writer: &mut W, message: &Message) -> Result<(), FrameError> {
    let body = serde_json::to_vec(message).expect("Message serializes: every field is a plain owned type");
    let len = u32::try_from(body.len()).expect("a well-formed Message never approaches u32::MAX bytes");
    writer.write_all(&MAGIC)?;
    writer.write_all(&PROTOCOL_VERSION.to_be_bytes())?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// How a launched execution ended, as the guest observed it.
///
/// Mirrors `aa_isolation::ExitDisposition` deliberately (`Exited`/`NoCode`
/// rather than `Code`/`NoCode`, to avoid colliding with the trait crate's own
/// name in a `use` block at the call site) — this crate does not depend on
/// `aa-isolation` (see the crate-level "never invents a claim" note), so it
/// restates the same two-state shape rather than importing it, and
/// `aa-isolation-macos-vm` maps one onto the other at the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Disposition {
    /// The launcher's own process exited and reported this code. Note that
    /// this is the **launcher's** exit code, not the confined program's —
    /// [`Message::LaunchOutcome::launcher_refused`] is what distinguishes "the
    /// launcher ran the program and it exited N" from "the launcher itself
    /// refused and exited 121", both of which arrive here as `Exited`.
    Exited {
        /// The exit code.
        code: i32,
    },
    /// The launcher ended without an observable exit code (signal-killed, or
    /// the guest could not reap it before tearing down).
    NoCode {
        /// What the guest could say about the ending, verbatim.
        detail: String,
    },
}

/// One message in the host↔guest launch protocol.
///
/// `#[serde(tag = "type")]` rather than an untagged enum: an untagged enum
/// matches structurally, so a `LaunchRefused` and a `TerminateAck` that
/// happened to share a field shape could be silently confused. A tagged enum
/// makes "which message is this" a fact read once, explicitly, not inferred
/// from which fields happen to be present.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Guest → host, sent once, immediately after the vsock connection opens
    /// and before anything else. The connection accepting is the "a guest
    /// process exists" signal; this message is the "and it can speak the
    /// protocol" signal — the two are different facts and this pass keeps
    /// them different messages rather than folding readiness into the
    /// connection event.
    GuestReady {
        /// This guest build's protocol version. Carried in the body too
        /// (redundantly with the frame header) so a version mismatch is
        /// nameable in the *reply* path as well — [`read_frame`] catches it
        /// on receipt, but a peer that logs `GuestReady.protocol_version`
        /// before attempting to read anything else gets the same fact
        /// without needing a successful frame read first.
        protocol_version: u16,
        /// Free-text diagnostics about this boot (kernel release, whether
        /// Landlock is present) — never parsed by the host, only logged.
        guest_notes: Vec<String>,
    },
    /// Host → guest: launch this program.
    LaunchRequest {
        /// Correlates this request with its eventual
        /// [`Message::LaunchAccepted`]/[`Message::LaunchRefused`]/[`Message::LaunchOutcome`].
        /// Opaque; the guest never inspects it beyond echoing it back.
        request_id: String,
        /// The program to execute, as a guest-absolute path. Never resolved
        /// against `PATH` by either side — see [`to_launcher_argv`].
        program: String,
        /// The program's arguments, excluding the program name.
        args: Vec<String>,
        /// The exact environment the program is to receive. A `BTreeMap`
        /// rather than inheriting anything: the guest process (PID 1) has an
        /// environment of its own that must never leak into a confined
        /// program by default, mirroring every other backend in this
        /// workspace.
        env: std::collections::BTreeMap<String, String>,
        /// The working directory to execute in, guest-absolute. `None` means
        /// the launcher's own default (its own current directory).
        working_dir: Option<String>,
        /// Guest-absolute paths the program may read (and, per
        /// `aa_isolation_native::rules`, execute within).
        fs_read: Vec<String>,
        /// Guest-absolute paths the program may write.
        fs_write: Vec<String>,
        /// Syscall names to allow, in `aa_security::policy::syscall::Syscall`'s
        /// vocabulary. `None` means no syscall requirement was named for this
        /// launch — the launcher installs no seccomp filter at all, matching
        /// `aa_isolation_native::launch::SyscallFilter::NotRequested`.
        syscall_filter: Option<Vec<String>>,
    },
    /// Guest → host: a child process now exists for this request.
    ///
    /// Sent **after `fork()` succeeded**, before waiting on it — this is what
    /// makes `IsolationBackend::spawn`'s contract truthful: without a
    /// distinct "something now exists" signal, `spawn` would return not
    /// knowing whether it did. This message means "a process exists in the
    /// guest", not "the confinement boundary installed successfully" — a
    /// launcher that installs the boundary and then refuses to exec is a
    /// legitimate, already-accepted run, reported later via
    /// [`Message::LaunchOutcome::launcher_refused`].
    LaunchAccepted {
        /// The request this accepts.
        request_id: String,
    },
    /// Guest → host: this request was refused before anything was forked.
    ///
    /// Distinct from a launcher-side refusal (which forks, execs the
    /// launcher, and the launcher itself declines — that is
    /// [`Message::LaunchOutcome::launcher_refused`], not this). This variant
    /// means the guest's own request validation failed: a relative program
    /// path, a request the guest could not even attempt.
    LaunchRefused {
        /// The request this refuses.
        request_id: String,
        /// Why, in words an operator can act on.
        reason: String,
    },
    /// Guest → host: the accepted launch ended.
    LaunchOutcome {
        /// The request this reports on.
        request_id: String,
        /// How the launcher process ended.
        disposition: Disposition,
        /// Whether the launcher itself refused rather than executing the
        /// program — the launcher's own `FAILURE_MARKER`/exit-121 convention,
        /// carried here as a typed fact rather than left for the host to
        /// infer by string-matching `launcher_stderr`.
        launcher_refused: bool,
        /// The launcher's own stderr, verbatim, truncated per
        /// `output_truncated` below.
        launcher_stderr: String,
        /// The confined program's captured stdout.
        stdout: Vec<u8>,
        /// The confined program's captured stderr.
        stderr: Vec<u8>,
        /// Whether `stdout`/`stderr` were cut short by [`MAX_BODY_BYTES`].
        /// Explicit rather than left for the caller to infer from a length —
        /// silent truncation is exactly the failure this field exists to
        /// name.
        output_truncated: bool,
        /// Grants this launch received beyond what the request named —
        /// currently always exactly the implicit program-path grant
        /// [`to_launcher_argv`] adds. Reported so evidence never claims a
        /// narrower boundary than the one actually installed. See the crate
        /// documentation's note on never inventing a claim: this is *evidence
        /// input*, and the caller must record it under an existing
        /// `ClaimTerm`, not a new one.
        implicit_grants: Vec<String>,
    },
    /// Host → guest: stop the process behind `request_id`.
    TerminateRequest {
        /// The request naming the process to stop.
        request_id: String,
        /// Whether to give the process a chance to decline.
        mode: TerminationMode,
    },
    /// Guest → host: a termination request was acted on.
    ///
    /// `Ok`/`delivered: true` means the request reached the process, never
    /// that it stopped — matching
    /// `aa_isolation::IsolationBackend::terminate`'s own contract, which this
    /// message exists to carry across the vsock boundary without weakening
    /// it.
    TerminateAck {
        /// The request this acknowledges.
        request_id: String,
        /// Whether the termination signal was delivered.
        delivered: bool,
        /// What happened, verbatim.
        detail: String,
    },
    /// Either direction: something about the protocol itself failed —
    /// distinct from any `*Refused`/`*_refused` field above, which describe a
    /// *launch* failing correctly. This means the exchange itself could not
    /// continue. Sent best-effort; the connection is expected to close
    /// immediately after.
    ProtocolError {
        /// What went wrong, verbatim.
        reason: String,
    },
}

/// Hand-written because [`Message::LaunchRequest::env`] holds credential
/// values by design — mirroring every other backend in this workspace, the
/// confined program's environment is built explicitly rather than inherited,
/// so it is exactly where a governance identity, a proxy address or a
/// delegated secret lives on the wire. A derived `Debug` would print every
/// `NAME=VALUE` pair, and this type is printed: `protocol-harness`, this
/// crate's real-hardware verification binary, logs every [`Message`] it
/// sends and receives (AAASM-5942). Every other field here is already public
/// on the wire (via `Serialize`) or free of credential material, so only
/// `LaunchRequest::env` is redacted to a count.
impl core::fmt::Debug for Message {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::GuestReady {
                protocol_version,
                guest_notes,
            } => f
                .debug_struct("GuestReady")
                .field("protocol_version", protocol_version)
                .field("guest_notes", guest_notes)
                .finish(),
            Self::LaunchRequest {
                request_id,
                program,
                args,
                env,
                working_dir,
                fs_read,
                fs_write,
                syscall_filter,
            } => f
                .debug_struct("LaunchRequest")
                .field("request_id", request_id)
                .field("program", program)
                .field("args", args)
                .field("env", &format!("<{} var(s)>", env.len()))
                .field("working_dir", working_dir)
                .field("fs_read", fs_read)
                .field("fs_write", fs_write)
                .field("syscall_filter", syscall_filter)
                .finish(),
            Self::LaunchAccepted { request_id } => f
                .debug_struct("LaunchAccepted")
                .field("request_id", request_id)
                .finish(),
            Self::LaunchRefused { request_id, reason } => f
                .debug_struct("LaunchRefused")
                .field("request_id", request_id)
                .field("reason", reason)
                .finish(),
            Self::LaunchOutcome {
                request_id,
                disposition,
                launcher_refused,
                launcher_stderr,
                stdout,
                stderr,
                output_truncated,
                implicit_grants,
            } => f
                .debug_struct("LaunchOutcome")
                .field("request_id", request_id)
                .field("disposition", disposition)
                .field("launcher_refused", launcher_refused)
                .field("launcher_stderr", launcher_stderr)
                .field("stdout", stdout)
                .field("stderr", stderr)
                .field("output_truncated", output_truncated)
                .field("implicit_grants", implicit_grants)
                .finish(),
            Self::TerminateRequest { request_id, mode } => f
                .debug_struct("TerminateRequest")
                .field("request_id", request_id)
                .field("mode", mode)
                .finish(),
            Self::TerminateAck {
                request_id,
                delivered,
                detail,
            } => f
                .debug_struct("TerminateAck")
                .field("request_id", request_id)
                .field("delivered", delivered)
                .field("detail", detail)
                .finish(),
            Self::ProtocolError { reason } => f.debug_struct("ProtocolError").field("reason", reason).finish(),
        }
    }
}

/// Whether a termination request gives the process a chance to decline.
///
/// Mirrors `aa_isolation::TerminationRequest` for the same reason
/// [`Disposition`] mirrors `ExitDisposition` — see that type's documentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationMode {
    /// Let the process run whatever it does on the way out.
    Graceful,
    /// Stop it without giving it the opportunity to decline.
    Immediate,
}

/// Build the launcher's argument vector for a [`Message::LaunchRequest`],
/// including the implicit grant on the program's own path.
///
/// # Why an implicit grant is added here at all
///
/// `landlock`'s `AccessFs::from_read` (the access set a `--fs-read` grant
/// installs) bundles `Execute` together with `ReadFile`/`ReadDir` — so a
/// program can only be exec'd from a path the boundary also grants read
/// access to. A request naming only the paths *policy* asked to be readable
/// would refuse to exec the very program policy asked to run, unless the
/// program happens to already live under one of those paths. Every backend
/// in this workspace that reaches this problem solves it the same way: grant
/// the program's own path, automatically, so a launch never fails to exec
/// its own target for a reason no policy author could see coming.
///
/// # Why the file, not its directory
///
/// A grant is built with [`aa_isolation_native::launch::build`], the same
/// function that builds every other grant this launcher understands — this
/// function does not re-derive the launcher's argv grammar (flag names,
/// separator, ordering) a second time. `aa_isolation_native::rules::file_safe`
/// (see that crate) already narrows a *file*-targeted grant to exactly
/// `Execute | ReadFile` — no directory-listing right leaks in — so granting
/// the file is strictly narrower than granting its containing directory, and
/// this function grants exactly `program`, never `program`'s parent.
///
/// # What this function does not validate
///
/// Nothing. It mirrors `aa_isolation_native::launch::build`'s own infallible
/// signature. If `program` is not absolute, the emitted grant is not
/// absolute either, and `aa_isolation_native::launch::parse` — running inside
/// the launcher process, after fork+exec, on the guest — refuses it as
/// `ArgvError::RelativeGrant`, which surfaces as a legitimate
/// `launcher_refused` outcome. A caller that wants to refuse a relative
/// `program` *before* forking (to avoid spending a fork on a request that
/// cannot succeed) checks that itself — this crate does not decide when a
/// caller forks.
pub fn to_launcher_argv(request: &Message) -> Vec<String> {
    let Message::LaunchRequest {
        program,
        args,
        fs_read,
        fs_write,
        syscall_filter,
        ..
    } = request
    else {
        panic!("to_launcher_argv called with a non-LaunchRequest message");
    };

    let mut grants = aa_isolation_native::launch::Grants::default();
    grants.read.extend(fs_read.iter().cloned());
    // The implicit grant: exactly the program's own path, so exec never fails
    // for a reason policy could not have named. See this function's own docs.
    grants.read.insert(program.clone());
    grants.write.extend(fs_write.iter().cloned());

    let syscalls = match syscall_filter {
        None => aa_isolation_native::launch::SyscallFilter::NotRequested,
        Some(names) => {
            let allowed = names
                .iter()
                .filter_map(|name| name.parse().ok())
                .collect::<std::collections::BTreeSet<_>>();
            aa_isolation_native::launch::SyscallFilter::Allow(allowed)
        }
    };

    aa_isolation_native::launch::build(&grants, &syscalls, program, args)
}

/// The implicit grant [`to_launcher_argv`] adds, for a caller that needs to
/// report it as evidence without re-deriving it from the request.
pub fn implicit_grant(request: &Message) -> Option<String> {
    match request {
        Message::LaunchRequest { program, .. } => Some(program.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_request() -> Message {
        Message::LaunchRequest {
            request_id: "r1".to_string(),
            program: "/usr/local/bin/busybox".to_string(),
            args: vec!["cat".to_string(), "/etc/testfile".to_string()],
            env: std::collections::BTreeMap::new(),
            working_dir: None,
            fs_read: vec!["/etc".to_string()],
            fs_write: vec!["/tmp".to_string()],
            syscall_filter: None,
        }
    }

    /// **AAASM-5942, falsifiability-critical.** `{:?}` on a `LaunchRequest`
    /// carrying a resolved `env` must not recover the sentinel value —
    /// absence, not a mask token, per this ticket's own warning that a test
    /// grepping for a mask string "passes against the vulnerable code and
    /// proves nothing".
    ///
    /// The negative control is documented rather than left committed: with
    /// `#[derive(Debug)]` restored on `Message` in place of its hand-written
    /// impl, this exact assertion reddened with the sentinel visible in the
    /// formatted output, confirming the test can fail. See this ticket's
    /// implementation report for the before/after transcript.
    #[test]
    fn debug_formatting_of_a_launch_request_env_never_recovers_its_value() {
        const SENTINEL: &str = "aaasm-5942-sentinel-not-a-real-secret-9f3c9e2b";
        let request = Message::LaunchRequest {
            request_id: "r1".to_string(),
            program: "/usr/local/bin/busybox".to_string(),
            args: Vec::new(),
            env: std::collections::BTreeMap::from([("AASM_TEST_CREDENTIAL".to_string(), SENTINEL.to_string())]),
            working_dir: None,
            fs_read: Vec::new(),
            fs_write: Vec::new(),
            syscall_filter: None,
        };
        let rendered = format!("{request:?}");
        assert!(
            !rendered.contains(SENTINEL),
            "Debug output recovered the sentinel value: {rendered}"
        );
    }

    #[test]
    fn frame_round_trips_through_a_byte_buffer() {
        let message = Message::GuestReady {
            protocol_version: PROTOCOL_VERSION,
            guest_notes: vec!["kernel 6.6.71-linuxkit".to_string()],
        };
        let mut buffer = Vec::new();
        write_frame(&mut buffer, &message).expect("write succeeds");
        let mut cursor = std::io::Cursor::new(buffer);
        let read_back = read_frame(&mut cursor).expect("read succeeds");
        assert_eq!(read_back, message);
    }

    #[test]
    fn wrong_magic_is_refused_by_name() {
        let mut buffer = b"XXXX".to_vec();
        buffer.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        buffer.extend_from_slice(&0u32.to_be_bytes());
        let mut cursor = std::io::Cursor::new(buffer);
        let error = read_frame(&mut cursor).expect_err("wrong magic must refuse");
        assert!(matches!(error, FrameError::WrongMagic { found } if found == *b"XXXX"));
    }

    #[test]
    fn version_mismatch_is_refused_by_name() {
        let mut buffer = MAGIC.to_vec();
        buffer.extend_from_slice(&99u16.to_be_bytes());
        buffer.extend_from_slice(&0u32.to_be_bytes());
        let mut cursor = std::io::Cursor::new(buffer);
        let error = read_frame(&mut cursor).expect_err("version mismatch must refuse");
        assert!(matches!(
            error,
            FrameError::UnsupportedVersion { found: 99, expected } if expected == PROTOCOL_VERSION
        ));
    }

    #[test]
    fn oversized_length_is_refused_before_reading_the_body() {
        let mut buffer = MAGIC.to_vec();
        buffer.extend_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        buffer.extend_from_slice(&(MAX_BODY_BYTES + 1).to_be_bytes());
        // Deliberately no body bytes follow — if this function tried to read
        // the body before checking the length, it would block/fail on EOF
        // instead of returning `BodyTooLarge`, which is the bug this test
        // pins.
        let mut cursor = std::io::Cursor::new(buffer);
        let error = read_frame(&mut cursor).expect_err("oversized length must refuse");
        assert!(matches!(error, FrameError::BodyTooLarge { found } if found == MAX_BODY_BYTES + 1));
    }

    /// The two-process contract test: what [`to_launcher_argv`] builds must
    /// parse back, via `aa_isolation_native::launch::parse` (the launcher's
    /// own parser), into the grants the request asked for plus the implicit
    /// program grant — and the program/args must round-trip unchanged. This
    /// is the only thing that can hold the host-side builder and the
    /// guest-side launcher's parser together, since they run in different
    /// processes built by different toolchains.
    #[test]
    fn built_argv_parses_back_with_the_implicit_program_grant() {
        let request = sample_request();
        let argv = to_launcher_argv(&request);
        let parsed = aa_isolation_native::launch::parse(argv).expect("built argv must parse");

        assert_eq!(parsed.program, "/usr/local/bin/busybox");
        assert_eq!(parsed.args, vec!["cat".to_string(), "/etc/testfile".to_string()]);
        assert!(
            parsed.grants.read.contains("/usr/local/bin/busybox"),
            "the implicit program grant is missing: {:?}",
            parsed.grants.read
        );
        assert!(
            parsed.grants.read.contains("/etc"),
            "the request's own fs_read grant is missing"
        );
        assert!(
            parsed.grants.write.contains("/tmp"),
            "the request's own fs_write grant is missing"
        );
    }

    #[test]
    fn implicit_grant_names_exactly_the_program_path() {
        let request = sample_request();
        assert_eq!(implicit_grant(&request), Some("/usr/local/bin/busybox".to_string()));
    }
}
