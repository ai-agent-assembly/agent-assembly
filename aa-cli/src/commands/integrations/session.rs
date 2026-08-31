//! Getting a connected, authenticated DI-API client — including starting the
//! runtime when there is not one (AAASM-5280, ADR 0030 §7.1).
//!
//! # Why the CLI starts the runtime instead of falling back to in-process work
//!
//! ADR 0030 §7.1 retires `aa-cli`'s in-process adapter construction and makes
//! `aasm` a DI-API client, with the consequence recorded in the same row: "an
//! in-process `--local` fallback is **deliberately not offered** — it would be
//! a second code path with a different trust model, which is what ADR 0004
//! rejected for transports."
//!
//! That decision is correct and it has a UX cost, which is paid here rather
//! than by the user. A missing socket does not mean "something went wrong"; it
//! means *the runtime is not running*, which is a bootstrap action. So this
//! module performs the bootstrap, says so on stderr, and waits for readiness —
//! the same shape [`crate::commands::start`] already uses for the gateway.
//!
//! Three rules it keeps:
//!
//! 1. **Never silently retry a missing socket.** Absence is diagnosed once, and
//!    either bootstrapped or reported. There is no loop that hides a runtime
//!    that will never appear.
//! 2. **Suppressible.** `--no-autostart` turns a missing runtime into
//!    [`Outcome::RuntimeUnavailable`] immediately, which is what CI wants: a
//!    build agent should fail rather than leave a daemon behind.
//! 3. **Visible.** The bootstrap prints to **stderr**, so `--output json` on
//!    stdout stays machine-readable while a human still sees what happened.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use aa_runtime::devint::provenance::{self, ProvenanceStanding, ProvenanceVerdict, RuntimeMultiplicity};
use aa_runtime::devint::{self, ClientError, DevIntClient, EnrolmentError};

use super::exit::Outcome;

/// What a command is about to do, and therefore what provenance it needs.
///
/// The distinction the owner decision draws for AAASM-5628. It is *not* a
/// severity dial: both levels refuse a runtime that was shown to be the wrong
/// one. What separates them is what they do when the runtime's identity is
/// simply **unknowable** — an absence, not a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensitivity {
    /// Reads state and reports it, changing nothing and asserting nothing about
    /// enforcement.
    ///
    /// May proceed while provenance is unverifiable, **provided it says so** —
    /// refusing here would make an unidentifiable runtime undiagnosable, since
    /// the read-only surfaces are exactly the ones an operator uses to find out
    /// which runtime is answering and stop the wrong one.
    ReadOnly,
    /// Writes host state, or asserts that enforcement is established.
    ///
    /// Refuses while provenance is unverifiable. Each of these produces a claim
    /// *about a build* — a changed file, a `Host Enforced` verdict, a recorded
    /// measurement — and a claim attributed to a runtime that cannot be
    /// identified is not a weaker claim, it is an unfounded one.
    Privileged,
}

impl Sensitivity {
    /// Whether a merely-unverifiable runtime is enough for this operation.
    pub const fn tolerates_unverifiable(self) -> bool {
        matches!(self, Sensitivity::ReadOnly)
    }
}

/// How long to wait for a freshly started runtime to bind its socket.
const READY_TIMEOUT: Duration = Duration::from_secs(10);

/// How often to look for the socket while waiting.
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// The agent identity a CLI-started runtime runs under.
///
/// `aa-runtime` requires `AA_AGENT_ID`, and a runtime started to serve the
/// lifecycle surface is not enforcing for any particular agent. A fixed,
/// recognisable id is better than a random one: an operator who finds this
/// process in `ps` can tell what started it and why.
const AUTOSTART_AGENT_ID: &str = "aasm-integrations";

/// Why a session could not be established.
#[derive(Debug)]
pub struct Failure {
    /// What went wrong.
    pub detail: String,
    /// What the user should do about it.
    pub remediation: String,
    /// Which exit code this is.
    pub outcome: Outcome,
}

impl Failure {
    /// Build a failure with the exit code it should produce.
    ///
    /// # Panics
    ///
    /// In debug builds, if `outcome` is [`Outcome::Success`]. A failure that
    /// exits `0` would be reported as `unchanged` by the ratified contract
    /// (AAASM-5499) — a *success* token on a run that did not reach the end
    /// state — which is the one classification the vocabulary must never
    /// produce.
    pub fn new(outcome: Outcome, detail: impl Into<String>, remediation: impl Into<String>) -> Self {
        debug_assert_ne!(
            outcome,
            Outcome::Success,
            "a Failure that exits 0 would report the successful `unchanged` outcome"
        );
        Self {
            detail: detail.into(),
            remediation: remediation.into(),
            outcome,
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}\n  → {}", self.detail, self.remediation)
    }
}

/// Starts an `aa-runtime` process.
///
/// A trait so the auto-start flow can be driven end to end in a test without
/// spawning a real daemon — the same seam
/// [`GatewaySpawner`](crate::commands::start::GatewaySpawner) uses.
pub trait RuntimeSpawner {
    /// Detach a runtime configured to serve the DI-API, returning its PID.
    fn spawn_runtime(&self) -> std::io::Result<u32>;
}

/// The default spawner: the real `aa-runtime` binary.
pub struct ProcessSpawner;

impl ProcessSpawner {
    /// The `aa-runtime` binary to launch.
    ///
    /// Prefers the one sitting beside this `aasm`, because the runtime and the
    /// CLI are shipped as one versioned unit (ADR 0030 §6.4) and a `PATH` hit
    /// from a different installation would negotiate against a core the user
    /// did not install. Falls back to `PATH` when there is no sibling.
    fn binary() -> PathBuf {
        let sibling = std::env::current_exe()
            .ok()
            .and_then(|exe| exe.parent().map(|dir| dir.join("aa-runtime")))
            .filter(|path| path.exists());
        sibling.unwrap_or_else(|| PathBuf::from("aa-runtime"))
    }

    fn command(&self) -> Command {
        let mut cmd = Command::new(Self::binary());
        cmd.env("AA_DEVINT_ENABLED", "1")
            .env("AA_AGENT_ID", AUTOSTART_AGENT_ID)
            // The lifecycle surface is all this runtime was started for; it has
            // no gateway to talk to and no policy to enforce, and inheriting a
            // stale endpoint would make it log connection failures forever.
            .env("AA_GATEWAY_ENDPOINT", "")
            // Without this, the health/metrics server inherits the code
            // default (0.0.0.0:8080) and — before AAASM-5985's bind rule —
            // served unauthenticated governance-degradation state to the
            // network. Loopback keeps local diagnostics (`curl
            // localhost:8080/health`) working without exposing anything
            // off-host; this runtime has nothing to enforce, so there is no
            // remote consumer that legitimately needs this address anyway.
            .env("AA_METRICS_ADDR", "127.0.0.1:8080")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        cmd
    }
}

impl RuntimeSpawner for ProcessSpawner {
    fn spawn_runtime(&self) -> std::io::Result<u32> {
        Ok(self.command().spawn()?.id())
    }
}

/// How the session should behave when no runtime is listening.
#[derive(Debug, Clone, Copy)]
pub struct SessionOptions {
    /// Report a missing runtime instead of starting one.
    pub no_autostart: bool,
    /// How long to wait for a started runtime to bind.
    pub ready_timeout: Duration,
    /// Proceed against a runtime whose identity could not be established.
    ///
    /// Off by default, and deliberately opt-in per invocation: the failure
    /// AAASM-5628 records is a *confident wrong answer*, so the default has to
    /// be refusal. The escape hatch exists for a legitimately mixed
    /// installation, and it downgrades the refusal to a stderr warning rather
    /// than suppressing it — the provenance still reaches `--output json`, so
    /// a result recorded through it is still marked as unverified.
    pub allow_unverified_runtime: bool,
    /// What the command about to run will do, which decides whether an
    /// *unverifiable* runtime is tolerable. See [`Sensitivity`].
    ///
    /// Defaults to [`Sensitivity::Privileged`]: a command that has not declared
    /// itself read-only gets the stricter rule, so adding one and forgetting to
    /// classify it fails closed rather than silently gaining a pass.
    pub sensitivity: Sensitivity,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            no_autostart: false,
            ready_timeout: READY_TIMEOUT,
            allow_unverified_runtime: false,
            sensitivity: Sensitivity::Privileged,
        }
    }
}

/// A connected client plus what the connection negotiated.
///
/// `Debug` reports only the negotiated facts. The client itself holds the
/// capability token, and a derived `Debug` would put it into any panic message
/// that formatted a `Result<Session, _>`.
///
/// # `#[non_exhaustive]` (AAASM-5669)
///
/// `aa-cli` ships a library target as well as the `aasm` binary, so this `pub`
/// struct with `pub` fields is reachable from outside the crate and every field
/// added to it is a source break for a struct literal — `provenance` and
/// `multiplicity` already were. It is constructed only by [`connect_with`],
/// which is the supported way in; marking it non-exhaustive says so in the type
/// system and makes the next field additive.
#[non_exhaustive]
pub struct Session {
    /// The negotiated client.
    pub client: DevIntClient,
    /// Whether the runtime was started by this invocation.
    pub started_runtime: bool,
    /// Which build answered, and whether it is this one (AAASM-5628).
    ///
    /// Carried on the session rather than recomputed by each command, so every
    /// surface reports the *same* verdict about the *same* connection.
    ///
    /// **It is a snapshot taken at the handshake, and it does not track the
    /// runtime afterwards.** `executable_present` in particular is the peer's
    /// assertion about the instant it answered `Hello`; a worktree deleted
    /// between then and the verb this command is about to send is not observed,
    /// so a `verified` standing on a report means "the runtime was identifiable
    /// when the session opened", never "it still is". Re-verifying per verb was
    /// not adopted: the peer would have to be asked again on every call, and the
    /// window it would close is a few milliseconds wide while the window this
    /// check exists to close — a stale runtime serving a whole campaign — is
    /// hours or days. The narrowing is worth naming rather than implying.
    pub provenance: ProvenanceVerdict,
    /// How many runtimes were reachable when this session opened.
    ///
    /// Also a snapshot: a runtime that starts after `survey_runtimes` ran is
    /// not counted. See that function for the scan's other two limits.
    pub multiplicity: RuntimeMultiplicity,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("di_api_version", &self.client.negotiated().di_api_version)
            .field("core_version", &self.client.negotiated().core_version)
            .field("started_runtime", &self.started_runtime)
            .field("provenance", &self.provenance.as_str())
            .field("reachable_runtimes", &self.multiplicity.reachable_count())
            .finish()
    }
}

/// Connect to the DI-API, starting the runtime if that is what is missing.
pub async fn connect(options: SessionOptions) -> Result<Session, Failure> {
    connect_with(options, &ProcessSpawner, &mut std::io::stderr()).await
}

/// [`connect`] with an injectable spawner and notice sink, for tests.
pub async fn connect_with<S: RuntimeSpawner>(
    options: SessionOptions,
    spawner: &S,
    notices: &mut impl Write,
) -> Result<Session, Failure> {
    let socket = devint::devint_socket_path().map_err(|e| {
        Failure::new(
            Outcome::RuntimeUnavailable,
            format!("cannot resolve the Agent Assembly runtime socket: {e}"),
            "set AA_DEVINT_SOCKET to the runtime's Developer Integration socket",
        )
    })?;

    let mut started_runtime = false;
    if !socket.exists() {
        // Absence means "not running". Diagnosed exactly once — never retried
        // in the hope that it appears.
        if options.no_autostart {
            return Err(Failure::new(
                Outcome::RuntimeUnavailable,
                format!(
                    "the Agent Assembly runtime is not running (no socket at {})",
                    socket.display()
                ),
                "start it with `aa-runtime` (AA_DEVINT_ENABLED=1), or drop --no-autostart to let aasm start it",
            ));
        }
        let _ = writeln!(notices, "Starting Agent Assembly runtime…");
        start_runtime(spawner, &socket, options.ready_timeout)?;
        started_runtime = true;
    }

    let token_path = devint::enrolment_path().map_err(enrolment_error)?;
    let token = devint::read_local_token(&token_path).map_err(enrolment_error)?;

    let client = DevIntClient::connect(
        &socket,
        "aasm",
        env!("CARGO_PKG_VERSION"),
        Some(token.expose().to_string()),
    )
    .await
    .map_err(client_error)?;

    if client.negotiated().degraded {
        let _ = writeln!(
            notices,
            "warning: this aasm and the running Agent Assembly core negotiated a reduced feature set — {}",
            client.negotiated().degraded_reason
        );
    }

    // Which build answered, before any command gets to record what it said.
    let verdict = client.negotiated().provenance_verdict();
    let multiplicity = survey_runtimes(&socket);
    guard_provenance(&verdict, &multiplicity, options, notices)?;

    Ok(Session {
        client,
        started_runtime,
        provenance: verdict,
        multiplicity,
    })
}

/// How many DI-API runtimes are reachable beside the one that answered.
///
/// Scans the directory the answering socket lives in. A socket reached through
/// an `AA_DEVINT_SOCKET` override outside that directory is still counted —
/// [`provenance::multiplicity`] folds it in — so the count is never lower than
/// what is demonstrably true.
///
/// # The evidence is one-directional
///
/// A count above one **proves** ambiguity: those sockets were connected to, so
/// those runtimes exist. A count of one proves nothing in the other direction,
/// because the scan has four limits and each of them can hide a runtime:
///
/// 1. **Name-filtered.** Only files matching `devint*.sock` are probed, so a
///    runtime bound to any other name is invisible.
/// 2. **One directory.** Only the answering socket's own directory is read, so
///    a runtime bound elsewhere — which is exactly what `AA_DEVINT_SOCKET`
///    makes easy — is not seen unless it is the one that answered.
/// 3. **Point in time.** The scan runs once, as the session opens. A runtime
///    that binds a moment later is not counted.
/// 4. **Time-bounded.** Each socket is probed under a deadline the whole scan
///    shares, so a socket that does not complete a connection in time is not
///    reported (AAASM-5667). Waiting instead would let any same-UID process
///    that binds a `devint*.sock` and never accepts hang this command — the one
///    an operator runs to find out which runtime is answering.
///
/// So `reachable_runtimes == 1` means "nothing else was found", never "nothing
/// else is listening", and no surface may present it as a uniqueness guarantee.
fn survey_runtimes(socket: &Path) -> RuntimeMultiplicity {
    let reachable = socket.parent().map(devint::reachable_runtimes).unwrap_or_default();
    provenance::multiplicity(socket, &reachable)
}

/// Decide whether a session may be handed back, given what the caller intends.
///
/// # Why a refusal, and not a warning
///
/// Both of AAASM-5628's reproductions produced a *plausible product answer*
/// from the wrong runtime — `DI-API v2` where the checkout declared v3, and
/// `not_installed` for a tool that was installed and healthy. A warning on
/// stderr beside a confident answer on stdout is exactly the shape that got
/// mistaken for a regression; the answer has to not arrive.
///
/// # Why *refuted* and *unverifiable* are not the same refusal
///
/// A runtime shown to be the wrong build, or one of several, is a **positive
/// finding**: something is demonstrably wrong, every answer it gives describes
/// something other than what the caller asked about, and every command refuses
/// (exit 10).
///
/// A runtime whose identity is merely unknowable is an **absence**. Refusing
/// every command there would make the situation undiagnosable — the read-only
/// surfaces are precisely the ones an operator uses to see *which* runtime
/// answered and stop the wrong one — while still leaving the real hazard
/// unaddressed, since the hazard is a claim made *about a build*. So read-only
/// commands proceed and report it, and everything that writes state or asserts
/// enforcement refuses (exit 11).
///
/// Multiplicity is checked first. With two runtimes answering, "which one did
/// I just verify?" has no answer, so the identity verdict below it is not yet
/// a meaningful thing to report.
fn guard_provenance(
    verdict: &ProvenanceVerdict,
    multiplicity: &RuntimeMultiplicity,
    options: SessionOptions,
    notices: &mut impl Write,
) -> Result<(), Failure> {
    // More than one runtime is a positive observation, not an absence: whatever
    // this connection proves, it does not say which process did the work.
    let (outcome, detail, remediation) = if !multiplicity.is_unambiguous() {
        (
            Outcome::RuntimeUnverified,
            multiplicity.detail(),
            multiplicity.remediation(),
        )
    } else {
        match verdict.standing() {
            ProvenanceStanding::Verified => return Ok(()),
            ProvenanceStanding::Refuted => (Outcome::RuntimeUnverified, verdict.detail(), verdict.remediation()),
            ProvenanceStanding::Unverifiable => {
                if options.sensitivity.tolerates_unverifiable() {
                    // Proceed — and say so. The verdict also reaches
                    // `--output json`, so a result recorded through this
                    // session stays marked unverifiable rather than passing as
                    // verified.
                    let _ = writeln!(
                        notices,
                        "warning: the Agent Assembly runtime that answered could not be identified — this result is \
                         reported as unverifiable, not verified: {}",
                        verdict.detail()
                    );
                    return Ok(());
                }
                (Outcome::RuntimeUnverifiable, verdict.detail(), verdict.remediation())
            }
        }
    };

    if options.allow_unverified_runtime {
        let _ = writeln!(
            notices,
            "warning: proceeding against an unverified Agent Assembly runtime — {detail}"
        );
        return Ok(());
    }

    Err(Failure::new(outcome, detail, remediation))
}

fn start_runtime<S: RuntimeSpawner>(spawner: &S, socket: &Path, timeout: Duration) -> Result<u32, Failure> {
    let pid = spawner.spawn_runtime().map_err(|e| {
        Failure::new(
            Outcome::RuntimeUnavailable,
            format!("could not start the Agent Assembly runtime: {e}"),
            "install the aa-runtime binary alongside aasm, or start it yourself and re-run with --no-autostart",
        )
    })?;

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if socket.exists() {
            return Ok(pid);
        }
        std::thread::sleep(READY_POLL_INTERVAL);
    }

    Err(Failure::new(
        Outcome::RuntimeUnavailable,
        format!(
            "the Agent Assembly runtime (pid {pid}) did not open its Developer Integration socket at {} within {}s",
            socket.display(),
            timeout.as_secs()
        ),
        "check the runtime's logs, then re-run; `AA_DEVINT_ENABLED=1` must be set for it to serve this surface",
    ))
}

/// Map an enrolment failure onto an actionable message.
///
/// Every arm is [`Outcome::Denied`]: the runtime is reachable and this client
/// has no usable credential for it. None of them echoes the token.
fn enrolment_error(error: EnrolmentError) -> Failure {
    match error {
        EnrolmentError::NotEnrolled { ref path } => Failure::new(
            Outcome::Denied,
            format!(
                "this aasm is not enrolled with the running runtime (no token at {})",
                path.display()
            ),
            "restart the Agent Assembly runtime — it enrols the local CLI as it starts",
        ),
        EnrolmentError::Permissions { ref path, actual } => Failure::new(
            Outcome::Denied,
            format!(
                "the capability token at {} is mode {actual:o} and is therefore not a secret",
                path.display()
            ),
            "run `chmod 600` on it and restart the runtime so a fresh token is issued",
        ),
        other => Failure::new(
            Outcome::Denied,
            other.to_string(),
            "restart the Agent Assembly runtime to re-enrol this client",
        ),
    }
}

/// Map a client failure onto an actionable message and the right exit code.
fn client_error(error: ClientError) -> Failure {
    match error {
        ClientError::RuntimeNotRunning { ref path } => Failure::new(
            Outcome::RuntimeUnavailable,
            format!(
                "the Agent Assembly runtime stopped before this command could reach it ({})",
                path.display()
            ),
            "re-run the command; aasm will start the runtime again",
        ),
        ClientError::Incompatible(ref incompatible) => Failure::new(
            Outcome::Incompatible,
            incompatible.reason.clone(),
            incompatible.remediation.clone(),
        ),
        ClientError::Denied(ref denied) => {
            Failure::new(Outcome::Denied, denied.message.clone(), denied.remediation.clone())
        }
        other => Failure::new(
            Outcome::InternalError,
            other.to_string(),
            "re-run the command; if it persists, check the runtime's logs",
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spawner that never starts anything, so the wait always times out.
    struct NeverReady;
    impl RuntimeSpawner for NeverReady {
        fn spawn_runtime(&self) -> std::io::Result<u32> {
            Ok(4242)
        }
    }

    /// A spawner that cannot start the binary at all.
    struct Unspawnable;
    impl RuntimeSpawner for Unspawnable {
        fn spawn_runtime(&self) -> std::io::Result<u32> {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no such binary"))
        }
    }

    /// Point the DI socket/token env vars at `dir` for the duration of the
    /// returned guard, then remove them on drop.
    ///
    /// The vars are process-global, so leaving them set leaks into unrelated
    /// tests that inherit the environment — e.g. `run`'s
    /// `no_gateway_credential_reaches_the_launched_tool`, which asserts no
    /// `AA_*TOKEN*` key reaches a launched tool and would fail on our stray
    /// `AA_DEVINT_TOKEN_FILE` under the shared-process `cargo test` harness.
    /// Holding [`env_guard`] serializes the mutation; the drop restores the
    /// prior (unset) state. The caller must bind the guard (`let _g = …`).
    #[must_use]
    fn redirect(dir: &Path) -> RedirectGuard {
        let lock = crate::test_support::env_guard();
        std::env::set_var("AA_DEVINT_SOCKET", dir.join("devint.sock"));
        std::env::set_var("AA_DEVINT_TOKEN_FILE", dir.join("devint.token"));
        RedirectGuard { _lock: lock }
    }

    /// Removes the DI env vars set by [`redirect`] when dropped, so they never
    /// outlive the test that set them.
    struct RedirectGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Drop for RedirectGuard {
        fn drop(&mut self) {
            std::env::remove_var("AA_DEVINT_SOCKET");
            std::env::remove_var("AA_DEVINT_TOKEN_FILE");
        }
    }

    #[tokio::test]
    async fn no_autostart_reports_a_stopped_runtime_without_spawning_anything() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _redirect = redirect(dir.path());
        let mut notices = Vec::new();
        let error = connect_with(
            SessionOptions {
                no_autostart: true,
                ..Default::default()
            },
            &Unspawnable,
            &mut notices,
        )
        .await
        .expect_err("no runtime is listening");

        assert_eq!(error.outcome, Outcome::RuntimeUnavailable);
        assert!(error.remediation.contains("--no-autostart"), "{error}");
        assert!(
            notices.is_empty(),
            "--no-autostart must not announce a start it did not perform"
        );
    }

    #[tokio::test]
    async fn autostart_announces_itself_on_the_notice_stream() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _redirect = redirect(dir.path());
        let mut notices = Vec::new();
        let error = connect_with(
            SessionOptions {
                ready_timeout: Duration::from_millis(120),
                ..Default::default()
            },
            &NeverReady,
            &mut notices,
        )
        .await
        .expect_err("the fake runtime never binds");

        assert_eq!(error.outcome, Outcome::RuntimeUnavailable);
        assert_eq!(
            String::from_utf8(notices).expect("utf8"),
            "Starting Agent Assembly runtime…\n"
        );
        assert!(error.detail.contains("did not open"), "{error}");
    }

    #[tokio::test]
    async fn a_runtime_that_cannot_be_started_is_actionable_rather_than_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let _redirect = redirect(dir.path());
        let mut notices = Vec::new();
        let error = connect_with(SessionOptions::default(), &Unspawnable, &mut notices)
            .await
            .expect_err("the binary is missing");
        assert_eq!(error.outcome, Outcome::RuntimeUnavailable);
        assert!(error.remediation.contains("aa-runtime"), "{error}");
    }

    /// The auto-start command is what makes a started runtime serve the
    /// lifecycle surface at all. Asserted directly, because a missing
    /// `AA_DEVINT_ENABLED` would produce a runtime that starts fine and never
    /// binds — a timeout whose cause is invisible.
    #[test]
    fn the_autostart_command_asks_the_runtime_for_the_di_api() {
        let cmd = ProcessSpawner.command();
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert!(
            envs.contains(&("AA_DEVINT_ENABLED".to_string(), Some("1".to_string()))),
            "{envs:?}"
        );
        assert!(
            envs.iter()
                .any(|(k, v)| k == "AA_AGENT_ID" && v.as_deref() == Some(AUTOSTART_AGENT_ID)),
            "{envs:?}"
        );
    }

    /// AAASM-5985: this spawner's runtime has no gateway and no policy, so
    /// it has nothing to report that legitimately needs a network-reachable
    /// address — without this, it inherited the code default
    /// (`0.0.0.0:8080`) and served unauthenticated governance-degradation
    /// state to the network.
    #[test]
    fn the_autostart_command_binds_health_metrics_to_loopback() {
        let cmd = ProcessSpawner.command();
        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        let metrics_addr = envs
            .iter()
            .find(|(k, _)| k == "AA_METRICS_ADDR")
            .and_then(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("AA_METRICS_ADDR must be set explicitly: {envs:?}"));
        let addr: std::net::SocketAddr = metrics_addr.parse().expect("must be a valid socket address");
        assert!(
            addr.ip().is_loopback(),
            "AA_METRICS_ADDR={metrics_addr} is not loopback"
        );
    }
}
