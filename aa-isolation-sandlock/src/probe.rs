//! Live confinement measurements, each with its own control.
//!
//! # Why this exists at all
//!
//! Everything else this crate could say about the boundary is second-hand: a
//! binary is on `PATH`, a kernel release parses, a security module is listed in
//! `/sys`. None of those is a statement that an action was stopped. ADR 0035's
//! validation bar is that availability must never be promoted into enforcement,
//! and the only thing that clears it is watching a real attempt fail.
//!
//! So the backend measures, once, at construction, before it will report any
//! domain as capable of prevention.
//!
//! # Every measurement is a controlled pair
//!
//! "The effect did not happen" is not evidence of denial on its own. It is
//! equally consistent with a command that never ran, a directory that was never
//! writable, or a probe that was silently wrong. So each measurement runs the
//! *same confined command twice*, and the two runs differ by exactly one flag
//! group:
//!
//! | Measurement | Control run | Test run |
//! |---|---|---|
//! | filesystem read | grant read of the scratch tree | no grant |
//! | filesystem write | grant write of the target directory | no grant |
//! | process ceiling | no process ceiling | ceiling of one |
//! | network egress | permit the loopback destination | no destination permitted |
//!
//! A measurement counts only when the control run produced the effect and the
//! test run did not. If the control run *also* fails, nothing has been measured
//! — the outcome is [`Observation::Inconclusive`], never a denial — because a
//! probe that cannot succeed cannot fail either.
//!
//! This shape has a second property worth stating: because the control run is
//! itself confined, a sandbox that failed to start makes the control fail, so
//! "the mechanism never engaged" can never be read as "the mechanism denied it".
//!
//! # Why the attempt comes from a grandchild
//!
//! ADR 0035 §6 makes descendant coverage part of correctness: an agent that
//! escapes by spawning a child has no boundary at all. Every attempt here is
//! made by `sh -c '… sh -c "…"'`, so the process performing the action is two
//! `fork`/`exec` steps below the one the backend launched. A boundary covering
//! only the launched process would let these through, and the probe would see
//! the effect.

use std::io::Read;
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::host::HostFacts;
use crate::lower::{ARG_SEPARATOR, FLAG_FS_READ, FLAG_FS_WRITE, FLAG_MAX_PROCESSES, FLAG_NET_ALLOW, SUBCOMMAND_RUN};

/// The shell every probe drives. The one executable a Linux host is entitled to
/// assume; its absence makes a probe inconclusive rather than negative.
const PROBE_SHELL: &str = "/bin/sh";

/// The interpreter the egress probe needs, because no POSIX shell can open a
/// TCP connection. Absent on some hosts, which costs the egress measurement and
/// nothing else.
const PROBE_CONNECT_INTERPRETER: &str = "python3";

/// System directories the confined runs are granted read access to, so the
/// dynamic loader and the shell work and the *only* thing under test is the
/// grant that differs between the two runs. Filtered by existence before use.
const SYSTEM_READ_PATHS: &[&str] = &["/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/dev"];

/// What one controlled pair established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    /// The control run produced the effect and the test run did not. The
    /// boundary stopped it.
    Denied,
    /// Both runs produced the effect. The boundary demonstrably did not stop
    /// it.
    Permitted,
    /// The control run did not produce the effect, so the test run's silence
    /// means nothing. Unknown, not known-absent — the distinction
    /// [`DescendantCoverage::Unmeasured`](aa_isolation::DescendantCoverage)
    /// draws, for the same reason.
    Inconclusive {
        /// What went wrong, including the backend's own diagnostics, so a CI
        /// log says which of the probe's assumptions failed.
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
            Self::Permitted => "observed: the action succeeded under confinement; this boundary does not \
                                stop it"
                .to_string(),
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
    /// Whether a process ceiling stopped a grandchild from existing.
    pub process_ceiling: Observation,
    /// Whether a grandchild was denied a connection the policy did not permit.
    pub network_egress: Observation,
}

impl ConfinementProbe {
    /// A probe that measured nothing, for hosts where the backend is not
    /// usable at all.
    pub fn unmeasured(detail: impl Into<String>) -> Self {
        let detail = detail.into();
        let o = Observation::Inconclusive { detail };
        Self {
            filesystem_read: o.clone(),
            filesystem_write: o.clone(),
            process_ceiling: o.clone(),
            network_egress: o,
        }
    }

    /// Whether both filesystem directions were denied to a *grandchild*.
    ///
    /// The basis for reporting
    /// [`DescendantCoverage::ProcessTree`](aa_isolation::DescendantCoverage) on
    /// the filesystem domains, and the reason that value is reported only when
    /// it was seen rather than because inheritance is documented.
    pub fn filesystem_covers_descendants(&self) -> bool {
        self.filesystem_read.is_denied() && self.filesystem_write.is_denied()
    }
}

/// Run every measurement described in the module documentation.
///
/// Costs eight confined process launches, once per backend construction, never
/// per plan.
pub fn measure(facts: &HostFacts, always: &[String]) -> ConfinementProbe {
    let Ok(scratch) = TempDir::new("aa-sandlock-probe") else {
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
        filesystem_read: measure_filesystem_read(facts, always, &secret),
        filesystem_write: measure_filesystem_write(facts, always, &target),
        process_ceiling: measure_process_ceiling(facts, always, &target),
        network_egress: measure_network_egress(facts, always),
    }
}

/// The content the read probe looks for. Distinctive so it cannot be produced
/// by a diagnostic that happens to mention the path.
const PROBE_SECRET: &str = "aa-sandlock-probe-secret-9f2c";

/// Read: the control run grants read of the file's directory, the test run does
/// not.
fn measure_filesystem_read(facts: &HostFacts, always: &[String], secret: &Path) -> Observation {
    let dir = secret.parent().unwrap_or(secret);
    let script = nested(&format!("cat {}", shell_word(&secret.to_string_lossy())));
    let control = run_confined(facts, always, &[format!("{FLAG_FS_READ}={}", dir.display())], &script);
    let test = run_confined(facts, always, &[], &script);
    compare(
        "filesystem read",
        control.map(|o| o.stdout.contains(PROBE_SECRET)),
        test.map(|o| o.stdout.contains(PROBE_SECRET)),
    )
}

/// Write: the control run grants write of the directory, the test run does not.
fn measure_filesystem_write(facts: &HostFacts, always: &[String], dir: &Path) -> Observation {
    let control_target = dir.join("control-write");
    let test_target = dir.join("test-write");
    let control = run_confined(
        facts,
        always,
        &[format!("{FLAG_FS_WRITE}={}", dir.display())],
        &nested(&format!("printf x > {}", shell_word(&control_target.to_string_lossy()))),
    );
    let test = run_confined(
        facts,
        always,
        &[],
        &nested(&format!("printf x > {}", shell_word(&test_target.to_string_lossy()))),
    );
    compare(
        "filesystem write",
        control.map(|_| control_target.exists()),
        test.map(|_| test_target.exists()),
    )
}

/// Process ceiling: both runs may write, and only the ceiling differs. The
/// effect is produced *by the grandchild*, so a ceiling of one — which leaves
/// room for the launched shell and nothing below it — removes it.
fn measure_process_ceiling(facts: &HostFacts, always: &[String], dir: &Path) -> Observation {
    let grant = [format!("{FLAG_FS_WRITE}={}", dir.display())];
    let control_target = dir.join("control-fork");
    let test_target = dir.join("test-fork");
    let mut ceiling: Vec<String> = grant.to_vec();
    ceiling.push(format!("{FLAG_MAX_PROCESSES}=1"));
    let control = run_confined(
        facts,
        always,
        &grant,
        &nested(&format!("printf x > {}", shell_word(&control_target.to_string_lossy()))),
    );
    let test = run_confined(
        facts,
        always,
        &ceiling,
        &nested(&format!("printf x > {}", shell_word(&test_target.to_string_lossy()))),
    );
    compare(
        "process ceiling",
        control.map(|_| control_target.exists()),
        test.map(|_| test_target.exists()),
    )
}

/// Egress: a listener this process owns, on loopback, permitted in the control
/// run and not in the test run.
///
/// Loopback rather than a public host so the measurement is hermetic — it needs
/// no DNS, no route and no third party, and it cannot pass because a remote
/// endpoint happened to be down.
fn measure_network_egress(facts: &HostFacts, always: &[String]) -> Observation {
    if which(PROBE_CONNECT_INTERPRETER).is_none() {
        return Observation::Inconclusive {
            detail: format!(
                "{PROBE_CONNECT_INTERPRETER} is not on PATH, and no POSIX shell can open a TCP \
                 connection, so egress enforcement was not measured on this host"
            ),
        };
    }
    let Ok(listener) = TcpListener::bind("127.0.0.1:0") else {
        return Observation::Inconclusive {
            detail: "no loopback listener could be bound, so there was nothing to connect to".to_string(),
        };
    };
    let Ok(addr) = listener.local_addr() else {
        return Observation::Inconclusive {
            detail: "the loopback listener would not report its address".to_string(),
        };
    };
    let destination = format!("127.0.0.1:{}", addr.port());
    let script = nested(&format!(
        "{PROBE_CONNECT_INTERPRETER} -c \"import socket;socket.create_connection(('127.0.0.1',{}),3);print('{PROBE_SECRET}')\"",
        addr.port()
    ));
    let control = run_confined(facts, always, &[format!("{FLAG_NET_ALLOW}={destination}")], &script);
    let test = run_confined(facts, always, &[], &script);
    drop(listener);
    compare(
        "network egress",
        control.map(|o| o.stdout.contains(PROBE_SECRET)),
        test.map(|o| o.stdout.contains(PROBE_SECRET)),
    )
}

/// Turn a control/test pair into an [`Observation`].
///
/// The asymmetry is the point: a control that did not produce the effect makes
/// the pair inconclusive whatever the test run did, so no measurement can be
/// read as a denial on the strength of two failures.
fn compare(what: &str, control: Result<bool, String>, test: Result<bool, String>) -> Observation {
    let control = match control {
        Ok(true) => true,
        Ok(false) => {
            return Observation::Inconclusive {
                detail: format!(
                    "the {what} control run did not produce its effect even though the policy permitted \
                     it, so the test run's failure is not attributable to the boundary"
                ),
            }
        }
        Err(detail) => {
            return Observation::Inconclusive {
                detail: format!("the {what} control run could not be executed: {detail}"),
            }
        }
    };
    debug_assert!(control);
    match test {
        Ok(true) => Observation::Permitted,
        Ok(false) => Observation::Denied,
        Err(detail) => Observation::Inconclusive {
            detail: format!("the {what} test run could not be executed: {detail}"),
        },
    }
}

/// What one confined run produced.
struct RunOutput {
    stdout: String,
}

/// Run `script` under the backend with `extra` flags added to the fixed system
/// read grants.
fn run_confined(facts: &HostFacts, always: &[String], extra: &[String], script: &str) -> Result<RunOutput, String> {
    let mut command = Command::new(facts.executable());
    command.arg(SUBCOMMAND_RUN);
    for path in SYSTEM_READ_PATHS.iter().filter(|p| Path::new(p).exists()) {
        command.arg(format!("{FLAG_FS_READ}={path}"));
    }
    for arg in always.iter().chain(extra.iter()) {
        command.arg(arg);
    }
    command
        .arg(ARG_SEPARATOR)
        .arg(PROBE_SHELL)
        .arg("-c")
        .arg(script)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = command
        .output()
        .map_err(|e| format!("{}: {e}", facts.executable().display()))?;
    Ok(RunOutput {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
    })
}

/// Wrap a command so it runs in a *grandchild* of the process the backend
/// launched.
///
/// `exit 0` keeps the script's own status out of every measurement: the
/// observable under test is the effect — a file, a byte on a socket, a line of
/// output — never an exit code, which a shell can produce without the action
/// having been attempted.
fn nested(inner: &str) -> String {
    format!("{PROBE_SHELL} -c {} 2>/dev/null; exit 0", shell_word(inner))
}

/// Single-quote a value for the one place this crate builds a shell script.
///
/// This is *only* used for paths and commands the probe itself constructs
/// under a temporary directory whose name it chose. No caller-supplied value
/// reaches it: the confined program's own argv is passed as argv and never
/// travels through a shell — see [`crate::lower`].
fn shell_word(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// Whether an executable is on `PATH`.
fn which(program: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(program).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim().to_string());
    path.exists().then_some(path)
}

/// Drain a stream with a deadline, so a probe cannot hang a discovery call.
///
/// Unused on the current measurement set — kept private and exercised by the
/// unit test below so it cannot rot into something that compiles but does not
/// work when a future probe needs it.
#[allow(dead_code)]
fn read_with_timeout(mut stream: TcpStream, timeout: Duration) -> std::io::Result<Vec<u8>> {
    stream.set_read_timeout(Some(timeout))?;
    let mut buffer = Vec::new();
    let _ = stream.read_to_end(&mut buffer);
    Ok(buffer)
}

/// A directory that removes itself.
///
/// Rolled by hand rather than pulled in as a dependency: this crate's whole
/// dependency list is two path dependencies, and a probe scratch directory is
/// not a reason to widen it.
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
        let outcome = compare("filesystem write", Ok(false), Ok(false));
        assert!(matches!(outcome, Observation::Inconclusive { .. }), "{outcome:?}");
    }

    #[test]
    fn a_denial_requires_the_control_to_have_succeeded() {
        assert_eq!(compare("x", Ok(true), Ok(false)), Observation::Denied);
        assert_eq!(compare("x", Ok(true), Ok(true)), Observation::Permitted);
        assert!(matches!(
            compare("x", Err("boom".into()), Ok(false)),
            Observation::Inconclusive { .. }
        ));
    }

    /// Every attempt must be nested, or descendant coverage is not what is
    /// being measured.
    #[test]
    fn every_attempt_runs_in_a_grandchild() {
        let script = nested("printf x > /tmp/f");
        assert!(script.starts_with(PROBE_SHELL), "{script}");
        assert!(script.contains("printf x > /tmp/f"), "{script}");
    }

    /// A path with a quote in it must not be able to end the quoting and start
    /// a new command. The probe only ever quotes its own paths, but a
    /// temporary directory inherits the host's `TMPDIR`, which is not this
    /// crate's to trust.
    ///
    /// Asserted by *running a shell*, not by inspecting the escaped string: the
    /// question is what `sh` does with it, and a string assertion answers a
    /// different question. `id` writes to stdout, so if the injection escaped
    /// the quoting the output would carry `uid=` as well as the literal text.
    #[test]
    fn shell_quoting_survives_an_embedded_quote() {
        for hostile in ["a'b", "a'; id; 'b", "$(id)", "`id`", "a\"b", "; id"] {
            let output = Command::new(PROBE_SHELL)
                .arg("-c")
                .arg(format!("printf %s {}", shell_word(hostile)))
                .output()
                .expect("the host has a shell");
            assert_eq!(
                String::from_utf8_lossy(&output.stdout),
                hostile,
                "`{hostile}` did not survive quoting verbatim"
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
        assert!(!probe.filesystem_covers_descendants());
    }

    #[test]
    fn temp_dir_removes_itself() {
        let path = {
            let dir = TempDir::new("aa-sandlock-probe-test").expect("temp dir");
            let path = dir.path().to_path_buf();
            assert!(path.exists());
            path
        };
        assert!(!path.exists(), "{} outlived its handle", path.display());
    }

    #[test]
    fn read_with_timeout_returns_rather_than_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let client = TcpStream::connect(addr).expect("connect");
        let _accepted = listener.accept().expect("accept");
        let read = read_with_timeout(client, Duration::from_millis(50)).expect("read");
        assert!(read.is_empty());
    }
}
