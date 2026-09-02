//! Asking a resolved `aa-proxy` binary what build it is (AAASM-5984).
//!
//! `resolve_binary()` (`start.rs`) picks *which* `aa-proxy` a launch spawns;
//! this module answers a different question — *what build is the binary it
//! picked*, so a governed run's evidence can attribute a redaction claim to a
//! named commit rather than to whatever happened to be at that path.
//!
//! # Why a probe, and not the child's own startup log
//!
//! `aa-proxy`'s startup line (AAASM-5984 AC1) states its identity, but
//! `ProxyGuard::spawn`'s command wires the child's stdout/stderr to
//! `Stdio::null()` (`guard.rs::build_command`) — piping them to capture the
//! startup line would create a pipe nobody drains, and when its buffer fills
//! the proxy blocks on write, stalling interception. That is a direct AC7
//! violation, so this asks the binary directly instead, via a separate,
//! bounded `--version` invocation before the long-running spawn.
//!
//! # Why the probe never refuses a launch
//!
//! [`probe`] is infallible by contract: any failure — spawn error, non-zero
//! exit, unparseable output, timeout — yields the [`UNKNOWN_SHA`]/`Absent`
//! sentinel, never an error the caller must propagate. A probe that could
//! refuse an otherwise-successful launch would be new refusal surface AC7
//! does not authorise; "we could not ask" must read as unidentifiable
//! evidence, not as a reason to fail closed.
//!
//! # The TOCTOU this does not close
//!
//! The probe names the file at the resolved path, not the live image of the
//! process [`super::guard::ProxyGuard::spawn_with_binary`] goes on to spawn a
//! moment later. Closing that gap would require the running process to
//! report its own identity over some channel `aasm` reads back — a new IPC or
//! protocol surface, which AAASM-5984's own non-goals exclude. This is
//! self-reported build identity at the same trust level AAASM-5628
//! established for `aa-runtime`, not a supply-chain attestation.
//!
//! [`UNKNOWN_SHA`]: aa_runtime::build_identity::UNKNOWN_SHA

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use aa_runtime::build_identity::{parse_version_banner, BuildIdentity};

/// Bounded wait for the probed binary's `--version` to answer. A governed
/// launch must never hang indefinitely on a foreign binary at the resolved
/// path — the falsification fixture for this mechanism is, by definition,
/// exactly such a binary.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What the `aa-proxy` a launch resolved to says it is.
#[derive(Debug, Clone)]
pub struct ProxyBuildEvidence {
    /// The canonical path `resolve_binary()`/`canonical_binary()` selected.
    pub executable: PathBuf,
    /// The identity that binary's `--version` output claims. `Absent`/
    /// [`UNKNOWN_SHA`] when the probe could not establish one — see the
    /// module doc for why that is never a launch failure.
    ///
    /// [`UNKNOWN_SHA`]: aa_runtime::build_identity::UNKNOWN_SHA
    pub identity: BuildIdentity,
}

/// Ask the binary at `path` what build it is.
///
/// Spawns `<path> --version` with stdin/stderr discarded and stdout piped,
/// polls for exit up to [`PROBE_TIMEOUT`], killing and reporting unknown on
/// timeout. Never panics and never returns `Err` — see the module doc.
pub fn probe(path: &Path) -> ProxyBuildEvidence {
    let unknown = || ProxyBuildEvidence {
        executable: path.to_path_buf(),
        identity: parse_version_banner(""),
    };

    let mut child = match Command::new(path)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return unknown(),
    };

    let deadline = Instant::now() + PROBE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return unknown();
                }
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return unknown();
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return unknown(),
        }
    }

    let Some(mut stdout) = child.stdout.take() else {
        return unknown();
    };
    let mut output = String::new();
    if std::io::Read::read_to_string(&mut stdout, &mut output).is_err() {
        return unknown();
    }

    ProxyBuildEvidence {
        executable: path.to_path_buf(),
        identity: parse_version_banner(&output),
    }
}
