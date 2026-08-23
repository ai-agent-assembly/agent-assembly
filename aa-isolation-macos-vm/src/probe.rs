//! One measured pair, run inside one short-lived guest, deciding whether this
//! backend can honestly claim to prevent anything.
//!
//! # Why this exists at all
//!
//! Everything else this crate could say about the guest's boundary is
//! second-hand: an artifact exists on disk, a helper is codesigned, a wire
//! message calls itself `GuestReady`. None of those is a statement that an
//! action was stopped. AAASM-5813's own AC3 requires the same measured-probe
//! discipline `aa_isolation_native::capability::discover` holds itself to —
//! see [`aa_isolation_native::probe`]'s module documentation, which this
//! module mirrors closely enough to reuse its [`Observation`] type rather
//! than fork the vocabulary.
//!
//! So this backend measures, once, at construction, before it will report
//! any domain as capable of prevention — via [`measure`], called from
//! [`crate::MacosVmBackend::discover`].
//!
//! # What is different from the native probe
//!
//! * **One guest, not one process per attempt.** A confined attempt here is
//!   a `LaunchRequest` round trip through an already-booted guest, not a
//!   fresh subprocess — so [`measure`] boots exactly one [`vmm::VmSession`]
//!   and reuses it for every launch, tearing it down when the last one
//!   returns. Measured cost: ~0.3s for boot + 4 launches + teardown on real
//!   hardware (AAASM-5837's `tests/real_hardware.rs` measured the same
//!   order of magnitude for boot + 1 launch), which is what makes probing
//!   inside `discover()` affordable rather than a guess.
//! * **The grant under test is the virtiofs share**, not a scratch directory
//!   under the host's own filesystem, because [`crate::paths::to_guest_path`]
//!   only ever maps a real launch's grants onto that share — measuring
//!   anything else would claim coverage no real launch can obtain.
//! * **No loader/shell baseline grant is needed.** `busybox` in this guest
//!   image is a static, self-contained binary providing every applet this
//!   probe uses (`sh`, `cat`, `printf`) with no dynamic loader and no
//!   separate `/bin`/`/lib` dependency — confirmed empirically (AAASM-5813
//!   Task 0 gate). So unlike the native probe's `system_grants`, the
//!   baseline grant set here is empty: the *only* difference between a
//!   control run and a test run is the one path under test.
//! * **No syscall pair.** The guest kernel is aarch64 and this backend's
//!   `spawn` always sends `syscall_filter: None` (`aa_isolation_native`'s
//!   filter is built for x86_64 syscall numbers only) — there is nothing to
//!   measure, so [`crate::capability`] reports that domain unsupported
//!   without a probe attempt, the same way the native backend's own syscall
//!   domain is reported unsupported on a host whose kernel cannot support
//!   the filter at all.
//!
//! # Why every attempt is nested
//!
//! Mirrors `aa_isolation_native::probe`'s own rationale: an agent that
//! escapes confinement by spawning a child has no boundary at all if only
//! the directly-launched process is covered. Every attempt here runs as
//! `busybox sh -c 'busybox sh -c "…"; exit 0'; exit 0` — the command that
//! actually performs the read or write is a grandchild of the process the
//! guest's launcher `execve`d, the same two-fork/exec depth the native
//! probe requires before it will report [`aa_isolation::DescendantCoverage::ProcessTree`].

use std::io::Write as _;
use std::path::Path;
use std::time::Duration;

pub use aa_isolation_native::Observation;

use aa_isolation_vm_proto::Message;

use crate::vmm::{self, VmConfig, VmSession};

/// The one program this probe ever launches: present in every guest image
/// ([`crate::paths::GUEST_RESIDENT_PROGRAMS`]) and self-contained (see the
/// module docs on why no baseline grant is needed).
const PROBE_PROGRAM: &str = "/usr/local/bin/busybox";

/// The content the read probe looks for. Distinctive so it cannot be
/// produced by a diagnostic that happens to mention the path.
const PROBE_SECRET: &str = "aa-macos-vm-probe-secret-9f2e";

/// How long [`measure`] waits for any single `recv` before giving up on the
/// whole probe. A wedged guest must not be able to hang
/// [`crate::MacosVmBackend::discover`] forever — a caller (including the CLI's
/// own `--dry-run` preview) has no way to know whether anything is running
/// while it waits.
const PROBE_RECV_TIMEOUT: Duration = Duration::from_secs(15);

/// What this backend measured about the guest it booted to check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestProbe {
    /// Whether a grandchild was denied a read the launch did not grant.
    pub filesystem_read: Observation,
    /// Whether a grandchild was denied a write the launch did not grant.
    pub filesystem_write: Observation,
}

impl GuestProbe {
    /// A probe that measured nothing, for hosts where this backend cannot be
    /// used at all.
    pub fn unmeasured(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let observation = Observation::Inconclusive { detail: detail.clone() };
        Self {
            filesystem_read: observation.clone(),
            filesystem_write: observation,
        }
    }

    /// Whether every filesystem measurement observed a denial to a
    /// *grandchild* — the basis for reporting
    /// [`aa_isolation::DescendantCoverage::ProcessTree`] on the filesystem
    /// domains.
    pub fn covers_descendants(&self) -> bool {
        self.filesystem_read.is_denied() && self.filesystem_write.is_denied()
    }
}

/// Run every measurement described in the module documentation.
///
/// Boots one guest, runs four launches through it, tears it down. Never
/// panics, never fails outright: every failure this function can reach
/// becomes [`Observation::Inconclusive`] on the affected domain (or both, for
/// a failure — like a boot failure — that precedes any measurement at all).
pub fn measure(config: &VmConfig) -> GuestProbe {
    let Ok(scratch) = TempDir::new("aa-isolation-macos-vm-probe") else {
        return GuestProbe::unmeasured("no scratch directory could be created for the probe");
    };
    let target = scratch.path().join("target");
    if std::fs::create_dir(&target).is_err() {
        return GuestProbe::unmeasured("the probe's target directory could not be created");
    }
    let secret = target.join("secret");
    let wrote_secret = std::fs::File::create(&secret).and_then(|mut f| f.write_all(PROBE_SECRET.as_bytes()));
    if wrote_secret.is_err() {
        return GuestProbe::unmeasured("the probe's secret file could not be written");
    }

    let mut session = match vmm::boot(config, Some(scratch.path())) {
        Ok(session) => session,
        Err(err) => return GuestProbe::unmeasured(format!("the probe's guest failed to boot: {err}")),
    };
    if let Err(err) = session.set_read_timeout(Some(PROBE_RECV_TIMEOUT)) {
        return GuestProbe::unmeasured(format!("could not bound the probe's connection: {err}"));
    }

    GuestProbe {
        filesystem_read: measure_read(&mut session),
        filesystem_write: measure_write(&mut session),
    }
}

/// Read: the control run grants read of the share's target directory, the
/// test run grants nothing.
fn measure_read(session: &mut VmSession) -> Observation {
    let script = nested(&format!("{PROBE_PROGRAM} cat /mnt/share/target/secret"));
    let control = run_confined(session, "probe-read-control", &["/mnt/share/target"], &script);
    let test = run_confined(session, "probe-read-test", &[], &script);
    compare(
        "filesystem read",
        control.map(|o| (o.stdout.contains(PROBE_SECRET), o.diagnostic)),
        test.map(|o| (o.stdout.contains(PROBE_SECRET), o.diagnostic)),
    )
}

/// Write: the control run grants read+write of the share's target directory,
/// the test run grants read only — so a write failure cannot be misread as
/// "the shell could not even open the target directory".
///
/// The observable is an **in-guest read-back**, not a host-side existence
/// check and not the launch's exit code: `nested`'s own `; exit 0` means a
/// script's exit status is deliberately not meaningful (see its docs), so
/// `printf … > file && cat file` is the only way a failed write is
/// distinguishable from a successful one — the `&&` short-circuits the
/// read-back when the write itself failed, and every command in the chain
/// must carry its own `PROBE_PROGRAM` prefix (there is no `cat`/`printf` on
/// this guest's `PATH` outside the busybox binary itself).
fn measure_write(session: &mut VmSession) -> Observation {
    const CONTROL_MARKER: &str = "aa-macos-vm-probe-write-control-3d17";
    const TEST_MARKER: &str = "aa-macos-vm-probe-write-test-3d17";
    let control_script = nested(&format!(
        "{PROBE_PROGRAM} printf {CONTROL_MARKER} > /mnt/share/target/control-write && \
         {PROBE_PROGRAM} cat /mnt/share/target/control-write"
    ));
    let test_script = nested(&format!(
        "{PROBE_PROGRAM} printf {TEST_MARKER} > /mnt/share/target/test-write && \
         {PROBE_PROGRAM} cat /mnt/share/target/test-write"
    ));
    let control = run_confined_rw(session, "probe-write-control", &control_script);
    let test = run_confined_ro(session, "probe-write-test", &test_script);
    compare(
        "filesystem write",
        control.map(|o| (o.stdout.contains(CONTROL_MARKER), o.diagnostic)),
        test.map(|o| (o.stdout.contains(TEST_MARKER), o.diagnostic)),
    )
}

/// Turn a control/test pair into an [`Observation`].
///
/// The asymmetry is the point, mirroring
/// `aa_isolation_native::probe::compare`: a control that did not produce the
/// effect makes the pair inconclusive whatever the test run did, so no
/// measurement can be read as a denial on the strength of two failures.
fn compare(what: &str, control: Result<(bool, String), String>, test: Result<(bool, String), String>) -> Observation {
    match control {
        Ok((true, _)) => {}
        Ok((false, diagnostic)) => {
            return Observation::Inconclusive {
                detail: format!(
                    "the {what} control run did not produce its effect even though the launch permitted it, \
                     so the test run's failure is not attributable to the guest's boundary ({diagnostic})"
                ),
            }
        }
        Err(detail) => {
            return Observation::Inconclusive {
                detail: format!("the {what} control run could not be executed: {detail}"),
            }
        }
    }
    match test {
        Ok((true, _)) => Observation::Permitted,
        Ok((false, _)) => Observation::Denied,
        Err(detail) => Observation::Inconclusive {
            detail: format!("the {what} test run could not be executed: {detail}"),
        },
    }
}

/// What one confined launch produced.
struct RunOutput {
    /// Every measurement's observable — read content directly, or a
    /// write's read-back — lives in stdout, never in the exit code: see
    /// `nested`'s own docs on why a script's status is not meaningful here.
    stdout: String,
    /// Everything needed to say *why* a run did not produce its effect, in
    /// one line — present on success too, and only ever rendered into an
    /// [`Observation::Inconclusive`] detail.
    diagnostic: String,
}

/// Run `script` through the guest's launcher with `fs_read` granted and
/// nothing else.
fn run_confined(
    session: &mut VmSession,
    request_id: &str,
    fs_read: &[&str],
    script: &str,
) -> Result<RunOutput, String> {
    run_confined_inner(session, request_id, fs_read, &[], script)
}

/// Run `script` with read+write granted on the share's target directory.
fn run_confined_rw(session: &mut VmSession, request_id: &str, script: &str) -> Result<RunOutput, String> {
    run_confined_inner(
        session,
        request_id,
        &["/mnt/share/target"],
        &["/mnt/share/target"],
        script,
    )
}

/// Run `script` with read only granted on the share's target directory.
fn run_confined_ro(session: &mut VmSession, request_id: &str, script: &str) -> Result<RunOutput, String> {
    run_confined_inner(session, request_id, &["/mnt/share/target"], &[], script)
}

fn run_confined_inner(
    session: &mut VmSession,
    request_id: &str,
    fs_read: &[&str],
    fs_write: &[&str],
    script: &str,
) -> Result<RunOutput, String> {
    session
        .send(&Message::LaunchRequest {
            request_id: request_id.to_string(),
            program: PROBE_PROGRAM.to_string(),
            args: vec!["sh".to_string(), "-c".to_string(), script.to_string()],
            env: Default::default(),
            working_dir: Some(crate::paths::GUEST_SHARE_MOUNTPOINT.to_string()),
            fs_read: fs_read.iter().map(|s| s.to_string()).collect(),
            fs_write: fs_write.iter().map(|s| s.to_string()).collect(),
            syscall_filter: None,
        })
        .map_err(|err| format!("could not send the probe's LaunchRequest: {err}"))?;
    match session
        .recv()
        .map_err(|err| format!("could not read the guest's reply: {err}"))?
    {
        Message::LaunchAccepted { .. } => {}
        Message::LaunchRefused { reason, .. } => return Err(format!("the guest refused the probe launch: {reason}")),
        other => return Err(format!("expected LaunchAccepted, got {other:?}")),
    }
    match session
        .recv()
        .map_err(|err| format!("could not read the guest's LaunchOutcome: {err}"))?
    {
        Message::LaunchOutcome {
            disposition,
            launcher_refused,
            launcher_stderr,
            stdout,
            stderr,
            ..
        } => Ok(RunOutput {
            stdout: String::from_utf8_lossy(&stdout).into_owned(),
            diagnostic: format!(
                "{disposition:?}, launcher refused: {launcher_refused}, stderr: {}",
                if stderr.is_empty() {
                    if launcher_stderr.is_empty() {
                        "<empty>".to_string()
                    } else {
                        launcher_stderr
                    }
                } else {
                    String::from_utf8_lossy(&stderr).into_owned()
                }
            ),
        }),
        other => Err(format!("expected LaunchOutcome, got {other:?}")),
    }
}

/// Wrap a command so it runs in a *grandchild* of the process the guest's
/// launcher `execve`d — see the module docs on why every attempt is nested.
///
/// `exit 0` on both levels keeps the script's own status out of every
/// measurement: the observable under test is the effect (stdout content, a
/// file's presence read back by a later command), never an exit code, which
/// a shell can produce without the action having been attempted.
///
/// `inner` must already carry a [`PROBE_PROGRAM`] prefix on **every**
/// command it names (`{PROBE_PROGRAM} cat …`, or `{PROBE_PROGRAM} printf … &&
/// {PROBE_PROGRAM} cat …`) — this guest's `PATH` has no bare `cat`/`printf`/
/// `sh` outside the busybox binary itself, and `nested` does not add the
/// prefix for you: a chained command silently missing it is exactly the
/// "not found" failure [`tests::every_attempt_runs_in_a_grandchild`] and
/// AAASM-5813's own Task 0 gate both hit once, the trap this doc comment
/// exists to name.
fn nested(inner: &str) -> String {
    // No `2>/dev/null`: redirecting to the null device opens it *for
    // writing*, and a default-deny write policy denies that — the shell
    // would never reach the command, and every measurement would read as
    // inconclusive for a reason unrelated to what is under test (the same
    // trap `aa_isolation_native::probe::nested` documents).
    format!(
        "{PROBE_PROGRAM} sh -c {}; exit 0",
        shell_word(&format!("{inner}; exit 0"))
    )
}

/// Single-quote a value for the one place this crate builds a shell script.
///
/// Only ever used for the probe's own fixed command strings — no
/// caller-supplied value reaches it.
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// A directory that removes itself. Rolled by hand, matching
/// `aa_isolation_native::probe::TempDir` — a probe scratch directory is not a
/// reason to widen this crate's dependency list.
struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> std::io::Result<Self> {
        let unique = format!(
            "{prefix}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or(Duration::ZERO)
                .as_nanos()
        );
        let path = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&path)?;
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The asymmetry that keeps a broken probe from reading as a denial.
    #[test]
    fn a_control_that_did_not_fire_makes_the_pair_inconclusive() {
        let outcome = compare(
            "filesystem write",
            Ok((false, "Exited { code: 121 }, launcher refused: true".to_string())),
            Ok((false, String::new())),
        );
        assert!(matches!(outcome, Observation::Inconclusive { .. }), "{outcome:?}");
    }

    #[test]
    fn a_denial_requires_the_control_to_have_succeeded() {
        let effect = || (true, String::new());
        let none = || (false, String::new());
        assert_eq!(compare("x", Ok(effect()), Ok(none())), Observation::Denied);
        assert_eq!(compare("x", Ok(effect()), Ok(effect())), Observation::Permitted);
        assert!(matches!(
            compare("x", Err("boom".into()), Ok(none())),
            Observation::Inconclusive { .. }
        ));
    }

    /// Every attempt must be nested, or descendant coverage is not what is
    /// being measured.
    #[test]
    fn every_attempt_runs_in_a_grandchild() {
        let script = nested("cat /mnt/share/target/secret");
        assert!(script.starts_with(PROBE_PROGRAM), "{script}");
        assert!(script.contains("cat /mnt/share/target/secret"), "{script}");
        assert!(!script.contains("/dev/null"), "{script}");
        // `run_confined_inner` wraps this string as `args = ["sh", "-c",
        // script]` on top of `program = PROBE_PROGRAM` — one nesting level
        // (the launched process itself). This string must contain exactly
        // one MORE `sh -c` re-invocation, so the command that actually runs
        // `inner` is a grandchild of the launched process, not a child.
        assert_eq!(script.matches("sh -c").count(), 1, "{script}");
    }

    #[test]
    fn an_unmeasured_probe_denies_nothing_and_covers_nothing() {
        let probe = GuestProbe::unmeasured("host is not configured");
        assert!(!probe.filesystem_read.is_denied());
        assert!(!probe.filesystem_write.is_denied());
        assert!(!probe.covers_descendants());
    }

    /// A path with a quote in it must not be able to end the quoting and
    /// start a new command — asserted by running a real shell if one exists
    /// on this (host, not guest) machine, matching
    /// `aa_isolation_native::probe`'s own discipline.
    #[test]
    fn shell_quoting_survives_an_embedded_quote() {
        if !Path::new("/bin/sh").exists() {
            return;
        }
        for hostile in ["a'b", "a'; id; 'b", "$(id)", "`id`", "a\"b", "; id"] {
            let output = std::process::Command::new("/bin/sh")
                .arg("-c")
                .arg(format!("printf %s {}", shell_word(hostile)))
                .output()
                .expect("the host has a shell");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                hostile,
                "`{hostile}` did not survive quoting"
            );
            assert!(
                !String::from_utf8_lossy(&output.stdout).contains("uid="),
                "`{hostile}` escaped its quoting and ran a command"
            );
        }
    }

    #[test]
    fn temp_dir_removes_itself() {
        let path = {
            let dir = TempDir::new("aa-isolation-macos-vm-probe-test").expect("temp dir");
            let path = dir.path().to_path_buf();
            assert!(path.exists());
            path
        };
        assert!(!path.exists(), "{} outlived its handle", path.display());
    }
}
