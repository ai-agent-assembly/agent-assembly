//! Live confinement measurements, each with its own control.
//!
//! # Why this exists at all
//!
//! Everything else this crate could say about the boundary is second-hand: a
//! launcher binary is on disk, a kernel answers a version query, a security
//! module is listed in `/sys`. None of those is a statement that an action was
//! stopped. ADR 0035's validation bar is that availability must never be promoted
//! into enforcement, and the only thing that clears it is watching a real attempt
//! fail.
//!
//! So the backend measures, once, at construction, before it will report any
//! domain as capable of prevention.
//!
//! # Every measurement is a controlled pair
//!
//! "The effect did not happen" is not evidence of denial on its own. It is
//! equally consistent with a command that never ran, a directory that was never
//! writable, or a probe that was silently wrong. So each measurement runs the
//! *same confined command twice*, and the two runs differ by exactly one grant:
//!
//! | Measurement | Control run | Test run |
//! |---|---|---|
//! | filesystem read | grant read of the scratch tree | no grant |
//! | filesystem write | grant write of the target directory | no grant |
//!
//! The **baseline** — read access to the system directories the dynamic loader
//! and the shell need — is present in the control run and the test run alike, so
//! it is never the difference between them. Withholding it from the test run
//! would deny the shell its own interpreter, and the absent effect would be
//! attributable to a program that could not start rather than to the grant under
//! test. That is the failure this table's second column exists to rule out, and
//! [`tests::the_only_difference_between_the_runs_is_the_grant_under_test`] pins
//! it.
//!
//! A measurement counts only when the control run produced the effect and the
//! test run did not. If the control run *also* fails, nothing has been measured —
//! the outcome is [`Observation::Inconclusive`], never a denial — because a probe
//! that cannot succeed cannot fail either. Because the control run is itself
//! confined, a boundary that failed to install makes the control fail, so "the
//! mechanism never engaged" can never be read as "the mechanism denied it".
//!
//! # What this probe deliberately does NOT measure
//!
//! It does not measure `truncate(2)`, and an earlier draft of it *appeared* to:
//! a pair built on the shell's `> file` redirection is `open(O_TRUNC)`, which the
//! write right already governs, so the denial it observed was the same denial the
//! write pair observes. It would have been a second measurement of the first
//! thing, presented as a measurement of the standalone truncate syscall — the
//! exact shape of over-claim ADR 0035's validation bar exists to refuse.
//!
//! The standalone syscall is genuinely a different question, and it is what the
//! backend's ABI floor turns on: `truncate(2)` takes a path and needs no writable
//! descriptor, so below [`crate::rules::REQUIRED_ABI_VERSION`] the kernel does not
//! handle it and a path-scoped write restriction does not stop it. Two things
//! answer it, and neither is here:
//!
//! * **By construction**, [`crate::rules::install`] asks for the whole
//!   [`REQUIRED_ABI`](crate::rules::REQUIRED_ABI) right set as a *hard*
//!   requirement, so a kernel that cannot handle the truncate right fails to
//!   install the boundary rather than installing one without it — and
//!   [`crate::host`] refuses earlier still.
//! * **By measurement**, `tests/adversarial_boundary_native_linux.rs` calls
//!   `truncate(2)` by path from inside the boundary, with a control that shrinks a
//!   file inside the grant. That needs an interpreter the host may not have, which
//!   is why it is a scenario that can decline rather than a capability gate that
//!   would make the write claim depend on `python3` being installed.
//!
//! # Why the attempt comes from a grandchild
//!
//! ADR 0035 §6 makes descendant coverage part of correctness: an agent that
//! escapes by spawning a child has no boundary at all. Every attempt here is made
//! by `sh -c '… sh -c "…"'`, so the process performing the action is two
//! `fork`/`exec` steps below the one the launcher `execve`d. A boundary covering
//! only the launched process would let these through, and the probe would see the
//! effect.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use aa_security::policy::syscall::Syscall;

use crate::host::HostFacts;
use crate::launch::{Grants, SyscallFilter, FAILURE_MARKER};

/// The shell every probe drives. The one executable a Linux host is entitled to
/// assume; its absence makes a probe inconclusive rather than negative.
const PROBE_SHELL: &str = "/bin/sh";

/// System directories the confined runs are granted read access to, so the
/// dynamic loader and the shell work and the *only* thing under test is the grant
/// that differs between the two runs. Filtered by existence before use.
const SYSTEM_READ_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"];

/// The content the read probe looks for. Distinctive so it cannot be produced by
/// a diagnostic that happens to mention the path.
const PROBE_SECRET: &str = "aa-native-probe-secret-71c4";

/// What one controlled pair established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The control run produced the effect and the test run did not. The boundary
    /// stopped it.
    Denied,
    /// Both runs produced the effect. The boundary demonstrably did not stop it.
    Permitted,
    /// The control run did not produce the effect, so the test run's silence means
    /// nothing. Unknown, not known-absent.
    Inconclusive {
        /// What went wrong, including the launcher's own diagnostics, so a CI log
        /// says which of the probe's assumptions failed.
        detail: String,
    },
}

impl Observation {
    /// Whether a denial was observed.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied)
    }

    /// A phrase for a prerequisite message or an evidence record.
    pub fn describe(&self) -> String {
        match self {
            Self::Denied => "observed: a grandchild of the confined process was denied, while the same \
                             command under a control policy that permitted it succeeded"
                .to_string(),
            Self::Permitted => {
                "observed: the action succeeded under confinement; this boundary does not stop it".to_string()
            }
            Self::Inconclusive { detail } => format!("not measured: {detail}"),
        }
    }
}

/// Everything the discovery probe established about this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfinementProbe {
    /// Whether a grandchild was denied a read the policy did not grant.
    pub filesystem_read: Observation,
    /// Whether a grandchild was denied a write the policy did not grant.
    pub filesystem_write: Observation,
    /// Whether a grandchild was denied a syscall the launch did not permit.
    pub syscall: Observation,
}

impl ConfinementProbe {
    /// A probe that measured nothing, for hosts where the backend is not usable
    /// at all.
    pub fn unmeasured(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let observation = Observation::Inconclusive { detail: detail.clone() };
        Self {
            filesystem_read: observation.clone(),
            filesystem_write: observation.clone(),
            syscall: observation,
        }
    }

    /// Whether every filesystem measurement observed a denial to a *grandchild*.
    ///
    /// The basis for reporting
    /// [`DescendantCoverage::ProcessTree`](aa_isolation::DescendantCoverage) on
    /// the filesystem domains, and the reason that value is reported only when it
    /// was seen rather than because inheritance is documented.
    pub fn covers_descendants(&self) -> bool {
        self.filesystem_read.is_denied() && self.filesystem_write.is_denied()
    }
}

/// Run every measurement described in the module documentation.
///
/// Costs five confined process launches, once per backend construction, never
/// per plan.
pub fn measure(facts: &HostFacts) -> ConfinementProbe {
    let Ok(scratch) = TempDir::new("aa-native-probe") else {
        return ConfinementProbe::unmeasured("no scratch directory could be created for the probe");
    };
    if !Path::new(PROBE_SHELL).exists() {
        return ConfinementProbe::unmeasured(format!("{PROBE_SHELL} is absent, so no attempt can be made"));
    }
    let target = scratch.path().join("target");
    if std::fs::create_dir(&target).is_err() {
        return ConfinementProbe::unmeasured("the probe's target directory could not be created");
    }
    let secret = target.join("secret");
    if std::fs::write(&secret, PROBE_SECRET).is_err() {
        return ConfinementProbe::unmeasured("the probe's secret file could not be written");
    }

    ConfinementProbe {
        filesystem_read: measure_read(facts, &secret),
        filesystem_write: measure_write(facts, &target),
        syscall: measure_syscall(facts, &target),
    }
}

/// Syscall: the control run's filter additionally permits `write`, the test
/// run's does not. Both permit the loader/shell baseline this file's own
/// [`system_grants`] and [`syscall_baseline`] describe, so the *only*
/// difference between the two allowlists is `write` — mirroring this module's
/// filesystem measurements, which hold the same property for their grant sets
/// ([`tests::the_only_difference_between_the_runs_is_the_grant_under_test`]).
///
/// Both runs also carry the same filesystem write grant on `dir`
/// ([`write_grant`]): the syscall allowlist is the variable under test here,
/// not the Landlock policy, so both runs need the Landlock permission that
/// lets `printf`'s `openat`+`write` land in `dir` at all — otherwise a bare
/// [`system_grants`] (no write grant anywhere) makes the control fail on a
/// Landlock `EACCES` before the syscall filter is ever exercised, and the
/// pair reads as inconclusive regardless of what the syscall filter did.
///
/// The observable is the target file's **content**, not its existence:
/// `openat(O_CREAT)` is permitted either way (`openat` is in the baseline, not
/// under test), so a mere existence check would compare two `true`s and prove
/// nothing about `write` in particular. What `write` decides is whether the
/// grandchild's `printf` can put bytes *into* the descriptor `openat` already
/// handed it — so the pair looks at what landed in the file, exactly the trap
/// this file's read/write measurements above are built to avoid.
fn measure_syscall(facts: &HostFacts, dir: &Path) -> Observation {
    let control_target = dir.join("syscall-control");
    let test_target = dir.join("syscall-test");
    let control = run_confined_with_syscalls(
        facts,
        write_grant(dir),
        syscall_baseline_with_write(),
        &nested(&format!("printf x > {}", shell_word(&control_target.to_string_lossy()))),
    );
    let test = run_confined_with_syscalls(
        facts,
        write_grant(dir),
        syscall_baseline(),
        &nested(&format!("printf x > {}", shell_word(&test_target.to_string_lossy()))),
    );
    compare(
        "syscall",
        control.map(|o| {
            (
                control_target.exists() && std::fs::read(&control_target).map(|b| !b.is_empty()).unwrap_or(false),
                o.diagnostic,
            )
        }),
        test.map(|o| {
            (
                test_target.exists() && std::fs::read(&test_target).map(|b| !b.is_empty()).unwrap_or(false),
                o.diagnostic,
            )
        }),
    )
}

/// Loader/shell-needed syscalls this probe's confined runs need to start at
/// all, deliberately **excluding** `write` — the syscall under test.
fn syscall_baseline() -> BTreeSet<Syscall> {
    [
        Syscall::Read,
        Syscall::Openat,
        Syscall::Close,
        Syscall::Fstat,
        Syscall::Lseek,
        Syscall::Mmap,
        Syscall::Munmap,
        Syscall::Brk,
        Syscall::Getrandom,
        Syscall::ExitGroup,
        Syscall::RtSigaction,
        Syscall::RtSigprocmask,
        Syscall::ClockGettime,
    ]
    .into_iter()
    .collect()
}

/// [`syscall_baseline`] plus `write` — the control allowlist.
fn syscall_baseline_with_write() -> BTreeSet<Syscall> {
    let mut allow = syscall_baseline();
    allow.insert(Syscall::Write);
    allow
}

/// Read: the control run grants read of the file's directory, the test run does
/// not.
fn measure_read(facts: &HostFacts, secret: &Path) -> Observation {
    let dir = secret.parent().unwrap_or(secret);
    let script = nested(&format!("cat {}", shell_word(&secret.to_string_lossy())));
    let control = run_confined(facts, read_grant(dir), &script);
    let test = run_confined(facts, system_grants(), &script);
    compare(
        "filesystem read",
        control.map(|o| (o.stdout.contains(PROBE_SECRET), o.diagnostic)),
        test.map(|o| (o.stdout.contains(PROBE_SECRET), o.diagnostic)),
    )
}

/// Write: the control run grants write of the directory, the test run does not.
fn measure_write(facts: &HostFacts, dir: &Path) -> Observation {
    let control_target = dir.join("control-write");
    let test_target = dir.join("test-write");
    let control = run_confined(
        facts,
        write_grant(dir),
        &nested(&format!("printf x > {}", shell_word(&control_target.to_string_lossy()))),
    );
    let test = run_confined(
        facts,
        system_grants(),
        &nested(&format!("printf x > {}", shell_word(&test_target.to_string_lossy()))),
    );
    compare(
        "filesystem write",
        control.map(|o| (control_target.exists(), o.diagnostic)),
        test.map(|o| (test_target.exists(), o.diagnostic)),
    )
}

/// The system read grants plus a read grant on `dir`.
fn read_grant(dir: &Path) -> Grants {
    let mut grants = system_grants();
    grants.read.insert(dir.to_string_lossy().into_owned());
    grants
}

/// The system read grants plus a write grant on `dir`.
fn write_grant(dir: &Path) -> Grants {
    let mut grants = system_grants();
    grants.write.insert(dir.to_string_lossy().into_owned());
    grants
}

/// The read grants every confined run needs so the loader and the shell work.
///
/// Present in the control run and the test run alike, so they are never the
/// difference between them.
fn system_grants() -> Grants {
    Grants {
        read: SYSTEM_READ_PATHS
            .iter()
            .filter(|p| Path::new(p).exists())
            .map(|p| (*p).to_string())
            .collect(),
        write: Default::default(),
    }
}

/// Turn a control/test pair into an [`Observation`].
///
/// The asymmetry is the point: a control that did not produce the effect makes
/// the pair inconclusive whatever the test run did, so no measurement can be read
/// as a denial on the strength of two failures.
fn compare(what: &str, control: Result<(bool, String), String>, test: Result<(bool, String), String>) -> Observation {
    match control {
        Ok((true, _)) => {}
        Ok((false, diagnostic)) => {
            return Observation::Inconclusive {
                detail: format!(
                    "the {what} control run did not produce its effect even though the policy permitted \
                     it, so the test run's failure is not attributable to the boundary ({diagnostic})"
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

/// What one confined run produced.
struct RunOutput {
    stdout: String,
    /// Everything needed to say *why* a run did not produce its effect, in one
    /// line. Present on success too, and only ever rendered into an
    /// [`Observation::Inconclusive`] detail — a probe whose failure message is
    /// "it did not work" costs a whole CI round-trip to diagnose.
    diagnostic: String,
}

/// Run `script` through the launcher with exactly `grants` installed and no
/// syscall filter.
fn run_confined(facts: &HostFacts, grants: Grants, script: &str) -> Result<RunOutput, String> {
    run_confined_inner(facts, grants, &SyscallFilter::NotRequested, script)
}

/// Run `script` through the launcher with exactly `grants` and `syscalls`
/// installed.
fn run_confined_with_syscalls(
    facts: &HostFacts,
    grants: Grants,
    syscalls: BTreeSet<Syscall>,
    script: &str,
) -> Result<RunOutput, String> {
    run_confined_inner(facts, grants, &SyscallFilter::Allow(syscalls), script)
}

fn run_confined_inner(
    facts: &HostFacts,
    grants: Grants,
    syscalls: &SyscallFilter,
    script: &str,
) -> Result<RunOutput, String> {
    let argv = crate::launch::build(&grants, syscalls, PROBE_SHELL, &["-c".to_string(), script.to_string()]);
    let mut command = Command::new(facts.launcher());
    for arg in &argv {
        command.arg(arg);
    }
    let output = command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("{}: {e}", facts.launcher().display()))?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    Ok(RunOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        diagnostic: format!(
            "exit {}, launcher refused: {}, stderr: {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "signalled".to_string()),
            stderr.contains(FAILURE_MARKER),
            if stderr.is_empty() { "<empty>" } else { stderr.as_str() }
        ),
    })
}

/// Wrap a command so it runs in a *grandchild* of the process the launcher
/// became.
///
/// `exit 0` keeps the script's own status out of every measurement: the
/// observable under test is the effect — a file, its size, a line of output —
/// never an exit code, which a shell can produce without the action having been
/// attempted.
fn nested(inner: &str) -> String {
    // No `2>/dev/null`. Redirecting to the null device opens it *for writing*,
    // and a default-deny write policy denies that — so the redirection fails, the
    // shell never reaches the command, and every measurement reads as
    // inconclusive for a reason that has nothing to do with what was under test.
    // Noise is not a problem here; stderr is captured and only ever reported
    // inside a diagnostic.
    format!("{PROBE_SHELL} -c {}; exit 0", shell_word(inner))
}

/// Single-quote a value for the one place this crate builds a shell script.
///
/// This is *only* used for paths and commands the probe itself constructs under a
/// temporary directory whose name it chose. No caller-supplied value reaches it:
/// the confined program's own argv is passed as argv and never travels through a
/// shell — see [`crate::launch`].
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// A directory that removes itself.
///
/// Rolled by hand rather than pulled in as a dependency: a probe scratch
/// directory is not a reason to widen this crate's dependency list.
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// Create a uniquely named directory under the system temporary directory.
    pub(crate) fn new(prefix: &str) -> std::io::Result<Self> {
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

    /// Where it is.
    pub(crate) fn path(&self) -> &Path {
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
            Ok((false, "exit 121, launcher refused: true".to_string())),
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

    /// Every attempt must be nested, or descendant coverage is not what is being
    /// measured.
    #[test]
    fn every_attempt_runs_in_a_grandchild() {
        let script = nested("printf x > /tmp/f");
        assert!(script.starts_with(PROBE_SHELL), "{script}");
        assert!(script.contains("printf x > /tmp/f"), "{script}");
        // A redirection to the null device opens it for writing, which a
        // default-deny write policy denies — so it must not appear here.
        assert!(!script.contains("/dev/null"), "{script}");
    }

    /// **The property the whole controlled-pair design rests on.** The baseline
    /// must be in both runs, and each control run must exceed it by exactly the
    /// one path under test.
    ///
    /// An earlier draft passed `Grants::default()` as the test run's grants, so
    /// the test run had no read access to `/bin` or `/lib` and the confined shell
    /// could not start. The effect was absent — but because no program ran, not
    /// because the grant under test was missing, and the pair would have reported
    /// `Denied` for a boundary that denied nothing in particular. This asserts
    /// the shape that cannot do that.
    #[test]
    fn the_only_difference_between_the_runs_is_the_grant_under_test() {
        let dir = Path::new("/tmp");
        let baseline = system_grants();
        assert!(
            !baseline.read.is_empty(),
            "the baseline grants nothing, so a confined shell cannot start in either run"
        );
        assert!(
            baseline.write.is_empty(),
            "the baseline grants a write nobody asked for"
        );

        let read = read_grant(dir);
        assert_eq!(
            read.read.difference(&baseline.read).collect::<Vec<_>>(),
            ["/tmp"],
            "the read control differs from the baseline by more than the path under test"
        );
        assert_eq!(read.write, baseline.write);

        let write = write_grant(dir);
        assert_eq!(
            write.read, baseline.read,
            "the write control differs from the baseline in its READ grants too"
        );
        assert_eq!(
            write.write.difference(&baseline.write).collect::<Vec<_>>(),
            ["/tmp"],
            "the write control differs from the baseline by more than the path under test"
        );
    }

    /// A path with a quote in it must not be able to end the quoting and start a
    /// new command. The probe only ever quotes its own paths, but a temporary
    /// directory inherits the host's `TMPDIR`, which is not this crate's to trust.
    ///
    /// Asserted by *running a shell*, not by inspecting the escaped string: the
    /// question is what `sh` does with it, and a string assertion answers a
    /// different question.
    #[test]
    fn shell_quoting_survives_an_embedded_quote() {
        if !Path::new(PROBE_SHELL).exists() {
            return;
        }
        for hostile in ["a'b", "a'; id; 'b", "$(id)", "`id`", "a\"b", "; id"] {
            let output = Command::new(PROBE_SHELL)
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
    fn an_unmeasured_probe_denies_nothing_and_covers_nothing() {
        let probe = ConfinementProbe::unmeasured("host is not Linux");
        assert!(!probe.filesystem_read.is_denied());
        assert!(!probe.filesystem_write.is_denied());
        assert!(!probe.syscall.is_denied());
        assert!(!probe.covers_descendants());
    }

    /// The syscall pair's control and test allowlists must differ by exactly
    /// `write` — the same discipline
    /// [`the_only_difference_between_the_runs_is_the_grant_under_test`] holds
    /// for the filesystem grant pairs, restated for syscalls.
    #[test]
    fn the_syscall_allowlists_differ_by_exactly_write() {
        let baseline = syscall_baseline();
        assert!(
            !baseline.contains(&Syscall::Write),
            "the baseline already permits the syscall under test"
        );
        let with_write = syscall_baseline_with_write();
        let added: Vec<&Syscall> = with_write.difference(&baseline).collect();
        assert_eq!(
            added,
            [&Syscall::Write],
            "the control allowlist differs by more than `write`"
        );
    }

    #[test]
    fn temp_dir_removes_itself() {
        let path = {
            let dir = TempDir::new("aa-native-probe-test").expect("temp dir");
            let path = dir.path().to_path_buf();
            assert!(path.exists());
            path
        };
        assert!(!path.exists(), "{} outlived its handle", path.display());
    }
}
