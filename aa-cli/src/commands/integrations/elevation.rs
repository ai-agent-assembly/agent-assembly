//! Terminal-first administrator authorization for the one privileged
//! managed-settings write — AAASM-6491.
//!
//! # Who does what
//!
//! The runtime applies a plan inside a detached daemon with no terminal, so it
//! cannot ask for a password. While the request is in flight it sends *this*
//! process — the one that owns the operator's terminal — an elevation request
//! over the same connection (DI-API 8). This module answers it by running
//! `sudo`, which prompts the operator directly on `/dev/tty`. `aasm` and the
//! runtime stay the invoking user; the only thing that runs as root is one
//! `/usr/bin/install` (or `/bin/rm`) on one path.
//!
//! # Rules this module will not bend
//!
//! * **No password ever passes through AASM.** `sudo` reads it from the tty.
//!   There is no `-S`, no `-A`, no shell, and stdin and stdout are null.
//! * **The target is this binary's own constant.** The path the runtime sent is
//!   informational; a runtime that sent another path would still have only
//!   [`MANAGED_SETTINGS_PATH`] touched. The one exception is a test seam
//!   (`AASM_TEST_ELEVATION_HELPER`), honoured **only** when the runtime-sent
//!   target is *not* the canonical path, so it can never redirect the real one.
//! * **The staged file is untrusted until proven otherwise.** It is opened
//!   `O_NOFOLLOW`, must be a small regular file this user owns in a private
//!   directory, and must hash to the digest the runtime stated — and, for the
//!   reviewed placement, to the digest the operator reviewed. That is repeated
//!   after authentication and before the placement, because a prompt can sit
//!   open for minutes.
//! * **The sudo timestamp is dropped.** If this module authenticated, `sudo -k`
//!   runs on every exit path, so the operator is not left holding a live root
//!   ticket they did not ask for.
//!
//! macOS `install(1)` refuses a non-regular source (`/dev/stdin` fails with
//! "Inappropriate file type"), so verified bytes cannot be piped in; the staged
//! file is installed in place and re-verified immediately beforehand.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use aa_core::integration::sha256_hex;
use aa_devtool_claude_code::MANAGED_SETTINGS_PATH;
use aa_proto::assembly::devint::v1 as wire;
use aa_runtime::devint::ElevationHandler;
use clap::ValueEnum;

use super::exit::Outcome;
use super::session::Failure;

/// The only `sudo` this module will run.
pub const SUDO: &str = "/usr/bin/sudo";
const INSTALL: &str = "/usr/bin/install";
const RM: &str = "/bin/rm";
/// What `sudo` and its children get as `PATH`; nothing else of the caller's
/// environment crosses, because `sudo` is about to act on the caller's say-so.
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// The test seam: a stub that stands in for `sudo`. See the module docs.
pub const TEST_HELPER_ENV: &str = "AASM_TEST_ELEVATION_HELPER";
/// A staged settings document is a few hundred bytes; anything near this is not
/// one.
const MAX_STAGED_BYTES: u64 = 64 * 1024;
const STDERR_CAP: usize = 4096;

/// How administrator authorization is obtained (`--admin-auth`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum AdminAuthArg {
    /// `sudo` in this terminal. The default.
    Terminal,
    /// The macOS authorization dialog. Never chosen implicitly.
    Gui,
}

impl AdminAuthArg {
    /// The token the wire carries.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Terminal => "terminal",
            Self::Gui => "gui",
        }
    }

    /// One line the plan and removal preview print, so the operator knows how
    /// they will be asked before they confirm.
    pub fn disclosure_line(self) -> &'static str {
        match self {
            Self::Terminal => "authorization: sudo in this terminal",
            Self::Gui => "authorization: macOS dialog (--admin-auth gui)",
        }
    }
}

// ── argv construction — pure, so the whole command surface is unit-tested ────

/// `sudo -v`: authenticate, run nothing.
pub fn auth_argv(sudo: &str, target: &str) -> Vec<OsString> {
    vec![sudo.into(), "-v".into(), "-p".into(), prompt_text(target).into()]
}

/// The prompt `sudo` shows. `%u` is sudo's own escape for the user name; every
/// other `%` in what we interpolate is doubled so a path can never inject one.
pub fn prompt_text(target: &str) -> String {
    format!(
        "[aasm] password for %u to place one root-owned file, {}: ",
        target.replace('%', "%%")
    )
}

/// Create the managed directory, root-owned, only when it is missing.
pub fn mkdir_argv(sudo: &str, dir: &str) -> Vec<OsString> {
    [
        sudo, "-n", "--", INSTALL, "-d", "-m", "755", "-o", "root", "-g", "wheel", "--", dir,
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// Place the staged file at the target, root-owned.
pub fn install_argv(sudo: &str, staged: &str, target: &str) -> Vec<OsString> {
    [
        sudo, "-n", "--", INSTALL, "-m", "644", "-o", "root", "-g", "wheel", "--", staged, target,
    ]
    .iter()
    .map(OsString::from)
    .collect()
}

/// Delete the target. `-f` so an already-absent file is a success.
pub fn remove_argv(sudo: &str, target: &str) -> Vec<OsString> {
    [sudo, "-n", "--", RM, "-f", "--", target]
        .iter()
        .map(OsString::from)
        .collect()
}

/// Forget the sudo timestamp this module created.
pub fn drop_argv(sudo: &str) -> Vec<OsString> {
    [sudo, "-k"].iter().map(OsString::from).collect()
}

/// The method to state on a request that may elevate.
///
/// Stated when the caller already knows a privileged step is involved, and
/// otherwise whenever the connection can carry one (DI-API 8), so a removal or
/// repair that turns out to reach the managed file is never left with a runtime
/// that has been told nothing — at v8 that is refused, not defaulted. Below v8
/// and with nothing privileged in sight it stays empty, which keeps every
/// ordinary command working against an older runtime.
pub fn method_to_send(admin: AdminAuthArg, likely_privileged: bool, negotiated_version: u32) -> &'static str {
    if likely_privileged || negotiated_version >= aa_runtime::devint::DI_API_TERMINAL_ELEVATION_SINCE {
        admin.as_wire()
    } else {
        ""
    }
}

// ── preflight ───────────────────────────────────────────────────────────────

/// What a host can offer, gathered once so the decision is a pure function.
#[derive(Debug, Clone, Copy)]
pub struct Facts {
    /// Whether this host is macOS, the only platform with a managed-settings path.
    pub is_macos: bool,
    /// Whether the `sudo` in use is a regular file owned by root.
    pub sudo_is_root_owned_regular_file: bool,
    /// Whether `/dev/tty` opens read-write, i.e. there is a controlling terminal.
    pub tty_opens: bool,
}

impl Facts {
    /// Read the real host.
    pub fn gather(sudo: &Path) -> Self {
        Self {
            is_macos: cfg!(target_os = "macos"),
            sudo_is_root_owned_regular_file: std::fs::metadata(sudo)
                .map(|m| m.is_file() && m.uid() == 0)
                .unwrap_or(false),
            tty_opens: OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok(),
        }
    }
}

/// Decide whether terminal authorization can work, before anything is planned.
///
/// The controlling terminal is tested by opening `/dev/tty`, **not** by asking
/// whether stdin is a terminal: `sudo` prompts there regardless of how stdin or
/// stdout are redirected, so a piped stdin does not make the prompt impossible,
/// and a tty-less session is exactly the one where it is.
///
/// # Errors
///
/// A [`Failure`] whose exit code follows the contract: no tty is `aborted`
/// (nothing is wrong with the host, nobody can answer), no `sudo` or not macOS
/// is `unsupported`.
pub fn preflight_with(facts: Facts) -> Result<(), Failure> {
    if !facts.is_macos {
        return Err(Failure::new(
            Outcome::Unsupported,
            "endpoint-managed settings are a macOS mechanism; nothing was changed",
            "run this on macOS, or install without --install-managed-settings",
        ));
    }
    if !facts.sudo_is_root_owned_regular_file {
        return Err(Failure::new(
            Outcome::Unsupported,
            format!("Unavailable: {SUDO} is not a root-owned regular file, so terminal authorization cannot be used; nothing was changed"),
            "repair the system's sudo, or pass --admin-auth gui to use the macOS dialog",
        ));
    }
    if !facts.tty_opens {
        return Err(Failure::new(
            Outcome::Aborted,
            "Unavailable: administrator authorization needs an interactive terminal, and this session has no \
             controlling terminal (/dev/tty could not be opened); nothing was changed",
            "run this from an interactive terminal (SSH with a tty, or tmux), or pass --admin-auth gui on a \
             machine with a logged-in desktop session",
        ));
    }
    Ok(())
}

/// Preflight against the real host, honouring the test seam only when the
/// managed root is redirected (the same condition under which the runtime would
/// not touch the real path).
pub fn preflight() -> Result<(), Failure> {
    let facts = match test_helper_when_redirected() {
        Some(helper) => Facts {
            is_macos: true,
            sudo_is_root_owned_regular_file: helper.is_file(),
            tty_opens: Facts::gather(Path::new(SUDO)).tty_opens,
        },
        None => Facts::gather(Path::new(SUDO)),
    };
    preflight_with(facts)
}

fn test_helper_when_redirected() -> Option<PathBuf> {
    let redirected = std::env::var_os("AASM_CLAUDE_MANAGED_ROOT").is_some_and(|v| !v.is_empty());
    if !redirected {
        return None;
    }
    std::env::var_os(TEST_HELPER_ENV)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

// ── staged-file hardening ───────────────────────────────────────────────────

/// Open the staged file and return its bytes only if every check passes.
///
/// `uid` is the invoking user. Every check is on the opened descriptor (or on
/// the parent directory), never on a path that could be swapped between the
/// check and the use.
pub fn read_verified_staged(path: &Path, uid: u32, expected_sha256: &str) -> Result<String, String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("the staged file cannot be opened without following a symlink: {e}"))?;
    let meta = file
        .metadata()
        .map_err(|e| format!("the staged file cannot be inspected: {e}"))?;
    if !meta.is_file() {
        return Err("the staged file is not a regular file".to_string());
    }
    if meta.uid() != uid {
        return Err("the staged file is not owned by the invoking user".to_string());
    }
    if meta.nlink() != 1 {
        return Err("the staged file has more than one hard link".to_string());
    }
    if meta.mode() & 0o022 != 0 {
        return Err("the staged file is writable by someone other than its owner".to_string());
    }
    if meta.len() >= MAX_STAGED_BYTES {
        return Err("the staged file is too large to be a settings document".to_string());
    }
    let parent = path
        .parent()
        .ok_or_else(|| "the staged file has no parent directory".to_string())?;
    let parent_meta =
        std::fs::symlink_metadata(parent).map_err(|e| format!("the staging directory cannot be inspected: {e}"))?;
    if !parent_meta.is_dir() || parent_meta.uid() != uid || parent_meta.mode() & 0o077 != 0 {
        return Err("the staging directory is not a private directory owned by the invoking user".to_string());
    }
    let mut body = String::new();
    (&file)
        .take(MAX_STAGED_BYTES)
        .read_to_string(&mut body)
        .map_err(|e| format!("the staged file is not readable as UTF-8 text: {e}"))?;
    let actual = sha256_hex(&body);
    if !actual.eq_ignore_ascii_case(expected_sha256) {
        return Err(format!(
            "the staged file hashes to sha256:{actual}, not the sha256:{expected_sha256} that was expected"
        ));
    }
    Ok(body)
}

// ── running sudo ────────────────────────────────────────────────────────────

/// Ignore `SIGINT`/`SIGQUIT` in this process while `sudo` owns the terminal, so
/// a ^C aimed at a password prompt cannot kill `aasm` between the placement and
/// its bookkeeping. `sudo` itself still receives them.
struct SignalGuard {
    previous: [(libc::c_int, libc::sighandler_t); 2],
}

impl SignalGuard {
    fn ignore() -> Self {
        let mut previous = [(libc::SIGINT, libc::SIG_DFL), (libc::SIGQUIT, libc::SIG_DFL)];
        for entry in &mut previous {
            // SAFETY: `signal` with `SIG_IGN` installs no handler code; it only
            // changes the disposition, and the old one is restored in `Drop`.
            entry.1 = unsafe { libc::signal(entry.0, libc::SIG_IGN) };
        }
        Self { previous }
    }
}

impl Drop for SignalGuard {
    fn drop(&mut self) {
        for (signal, handler) in self.previous {
            // SAFETY: restoring a disposition `signal` itself returned.
            unsafe { libc::signal(signal, handler) };
        }
    }
}

/// What one `sudo` invocation reported.
struct Ran {
    success: bool,
    stderr: String,
}

fn run(argv: &[OsString]) -> Result<Ran, String> {
    let (program, args) = argv.split_first().ok_or_else(|| "empty command".to_string())?;
    let _guard = SignalGuard::ignore();
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("TERM", std::env::var("TERM").unwrap_or_else(|_| "dumb".to_string()))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: runs between fork and exec and only calls async-signal-safe
    // `signal`, undoing the ignore above so `sudo` gets default dispositions
    // (an ignored signal would otherwise survive the exec).
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGINT, libc::SIG_DFL);
            libc::signal(libc::SIGQUIT, libc::SIG_DFL);
            Ok(())
        });
    }
    let mut child = command
        .spawn()
        .map_err(|e| format!("{} could not be started: {e}", program.to_string_lossy()))?;
    let mut captured = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = (&mut stderr).take(STDERR_CAP as u64).read_to_end(&mut captured);
        // Past the cap, keep draining into the void: a child that writes more
        // than the pipe holds would otherwise block forever on a reader that
        // stopped reading, and `wait` below would never return.
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    }
    let status = child.wait().map_err(|e| format!("waiting for sudo failed: {e}"))?;
    Ok(Ran {
        success: status.success(),
        stderr: String::from_utf8_lossy(&captured).trim().to_string(),
    })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

// ── the elevator ────────────────────────────────────────────────────────────

/// What the last elevation concluded, kept so the command can pick its exit code
/// from what `sudo` itself said — never from the runtime's prose.
pub type Record = Arc<Mutex<Option<aa_core::integration::ElevationOutcome>>>;

/// Answers the runtime's elevation requests with `sudo`.
pub struct Elevator {
    uid: u32,
    /// The digest of the document the operator reviewed in the plan, for the
    /// reviewed placement.
    reviewed_sha256: Option<String>,
    record: Record,
    /// When no reviewed digest is on record (a repair re-places a document the
    /// operator did not just review), show the digest and ask instead of
    /// refusing.
    ask_when_unreviewed: bool,
    /// The sudo binary in use for the current mode, and whether this module
    /// authenticated with it (so `sudo -k` is owed).
    authenticated_with: Option<String>,
}

impl Elevator {
    pub fn new(reviewed_sha256: Option<String>, record: Record) -> Self {
        Self {
            // SAFETY: `getuid` has no preconditions and cannot fail.
            uid: unsafe { libc::getuid() },
            reviewed_sha256,
            record,
            ask_when_unreviewed: false,
            authenticated_with: None,
        }
    }

    /// Ask the operator, on the terminal, about a placement they did not review
    /// in a plan — used by `repair`.
    #[must_use]
    pub fn asking_when_unreviewed(mut self) -> Self {
        self.ask_when_unreviewed = true;
        self
    }

    /// Wrap this elevator as the client's handler. Dropping the handler (when
    /// the client is dropped) drops the sudo timestamp.
    pub fn into_handler(mut self) -> ElevationHandler {
        Box::new(move |request| {
            let (outcome, detail) = self.handle(request);
            *self.record.lock().expect("elevation record") = Some(outcome.clone());
            let code = match &outcome {
                aa_core::integration::ElevationOutcome::Completed => wire::ElevationResultCode::Completed,
                aa_core::integration::ElevationOutcome::Denied(_) => wire::ElevationResultCode::Denied,
                aa_core::integration::ElevationOutcome::Cancelled(_) => wire::ElevationResultCode::Cancelled,
                aa_core::integration::ElevationOutcome::Unavailable(_) => wire::ElevationResultCode::Unavailable,
                aa_core::integration::ElevationOutcome::NonInteractive(_) => wire::ElevationResultCode::NonInteractive,
            };
            wire::ElevationResult {
                outcome: code as i32,
                detail,
                ..Default::default()
            }
        })
    }

    fn handle(&mut self, request: &wire::ElevationRequest) -> (aa_core::integration::ElevationOutcome, String) {
        use aa_core::integration::ElevationOutcome as O;
        let outcome = self.perform(request);
        let detail = match &outcome {
            O::Completed => String::new(),
            O::Denied(d) | O::Cancelled(d) | O::Unavailable(d) | O::NonInteractive(d) => d.clone(),
        };
        (outcome, detail)
    }

    fn perform(&mut self, request: &wire::ElevationRequest) -> aa_core::integration::ElevationOutcome {
        use aa_core::integration::ElevationOutcome as O;
        let kind = wire::ElevationKind::try_from(request.kind).unwrap_or(wire::ElevationKind::Unspecified);
        let purpose = wire::ElevationPurpose::try_from(request.purpose).unwrap_or(wire::ElevationPurpose::Unspecified);

        // The target: canonical constant unless this is the redirected test seam.
        let canonical = Path::new(request.target.as_str()) == Path::new(MANAGED_SETTINGS_PATH);
        let (sudo, target): (String, String) = if canonical {
            (SUDO.to_string(), MANAGED_SETTINGS_PATH.to_string())
        } else {
            match std::env::var(TEST_HELPER_ENV).ok().filter(|v| !v.is_empty()) {
                Some(helper) => (helper, request.target.clone()),
                None => {
                    return O::Unavailable(format!(
                        "refusing to elevate for {}: only {MANAGED_SETTINGS_PATH} is ever authorized",
                        request.target
                    ))
                }
            }
        };

        let facts = if canonical {
            Facts::gather(Path::new(SUDO))
        } else {
            Facts {
                is_macos: true,
                sudo_is_root_owned_regular_file: Path::new(&sudo).is_file(),
                tty_opens: Facts::gather(Path::new(SUDO)).tty_opens,
            }
        };
        if let Err(failure) = preflight_with(facts) {
            return match failure.outcome {
                Outcome::Aborted => O::NonInteractive(failure.detail),
                _ => O::Unavailable(failure.detail),
            };
        }

        match (kind, purpose) {
            (wire::ElevationKind::InstallFile, wire::ElevationPurpose::PlaceReviewed)
            | (wire::ElevationKind::InstallFile, wire::ElevationPurpose::RestoreBackup) => {
                self.install(request, purpose, &sudo, &target)
            }
            (wire::ElevationKind::DeleteFile, wire::ElevationPurpose::Remove) => self.delete(&sudo, &target),
            _ => O::Cancelled("the runtime asked for an operation this client does not perform".to_string()),
        }
    }

    fn authenticate(&mut self, sudo: &str, target: &str) -> Option<aa_core::integration::ElevationOutcome> {
        use aa_core::integration::ElevationOutcome as O;
        match run(&auth_argv(sudo, target)) {
            Ok(ran) if ran.success => {
                self.authenticated_with = Some(sudo.to_string());
                None
            }
            Ok(ran) => Some(O::Denied(format!(
                "sudo did not authenticate you{}",
                if ran.stderr.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", first_line(&ran.stderr))
                }
            ))),
            Err(e) => Some(O::Unavailable(e)),
        }
    }

    fn install(
        &mut self,
        request: &wire::ElevationRequest,
        purpose: wire::ElevationPurpose,
        sudo: &str,
        target: &str,
    ) -> aa_core::integration::ElevationOutcome {
        use aa_core::integration::ElevationOutcome as O;
        let staged = Path::new(&request.staged_path);
        let body = match read_verified_staged(staged, self.uid, &request.staged_sha256) {
            Ok(body) => body,
            Err(e) => return O::Cancelled(format!("refusing to install an unverified staged file: {e}")),
        };
        let digest = sha256_hex(&body);
        match purpose {
            wire::ElevationPurpose::PlaceReviewed => match &self.reviewed_sha256 {
                Some(reviewed) if reviewed.eq_ignore_ascii_case(&digest) => {}
                Some(reviewed) => {
                    return O::Cancelled(format!(
                        "the staged document (sha256:{digest}) is not the one you reviewed (sha256:{reviewed}); \
                         nothing was placed"
                    ))
                }
                None if self.ask_when_unreviewed => {
                    if !confirm_on_tty(&format!(
                        "Agent Assembly needs to re-place the managed-settings document (sha256:{digest}) at {target}. Continue?"
                    )) {
                        return O::Cancelled("re-placing the managed settings was declined".to_string());
                    }
                }
                None => return O::Cancelled("no reviewed document digest is on record; nothing was placed".to_string()),
            },
            wire::ElevationPurpose::RestoreBackup => {
                if !confirm_on_tty(&format!(
                    "Agent Assembly needs to restore the previous managed-settings file (sha256:{digest}) over {target}. Continue?"
                )) {
                    return O::Cancelled("restoring the previous file was declined".to_string());
                }
            }
            _ => return O::Cancelled("the runtime asked for an operation this client does not perform".to_string()),
        }

        if let Some(denied) = self.authenticate(sudo, target) {
            return denied;
        }
        // A prompt can stay open for minutes; check again that what is about to
        // be installed is still what was verified.
        if let Err(e) = read_verified_staged(staged, self.uid, &digest) {
            return O::Cancelled(format!("the staged file changed while authorization was pending: {e}"));
        }

        let dir = Path::new(target).parent().unwrap_or(Path::new("/"));
        if !dir.exists() {
            match run(&mkdir_argv(sudo, &dir.to_string_lossy())) {
                Ok(ran) if ran.success => {}
                Ok(ran) => return self.noninteractive_or(ran, "creating the managed directory"),
                Err(e) => return O::Unavailable(e),
            }
        }
        match run(&install_argv(sudo, &request.staged_path, target)) {
            Ok(ran) if ran.success => O::Completed,
            Ok(ran) => self.noninteractive_or(ran, "placing the file"),
            Err(e) => O::Unavailable(e),
        }
    }

    fn delete(&mut self, sudo: &str, target: &str) -> aa_core::integration::ElevationOutcome {
        use aa_core::integration::ElevationOutcome as O;
        if let Some(denied) = self.authenticate(sudo, target) {
            return denied;
        }
        match run(&remove_argv(sudo, target)) {
            Ok(ran) if ran.success => O::Completed,
            Ok(ran) => self.noninteractive_or(ran, "removing the file"),
            Err(e) => O::Unavailable(e),
        }
    }

    /// A `-n` invocation that fails because `sudo` would not reuse the
    /// authentication (`timestamp_timeout=0`, a per-command ticket policy) is
    /// not a refusal by the operator; it is a host that cannot do this, and the
    /// remedy is the other method.
    fn noninteractive_or(&self, ran: Ran, doing: &str) -> aa_core::integration::ElevationOutcome {
        use aa_core::integration::ElevationOutcome as O;
        let text = ran.stderr.to_ascii_lowercase();
        if text.contains("password is required") || text.contains("a terminal is required") || text.contains("no tty") {
            return O::Unavailable(
                "sudo will not reuse the authentication you just gave (its timestamp_timeout may be 0), so the \
                 placement cannot run without a second prompt; pass --admin-auth gui"
                    .to_string(),
            );
        }
        O::Cancelled(format!(
            "{doing} failed: {}",
            if ran.stderr.is_empty() {
                "sudo reported an error".to_string()
            } else {
                first_line(&ran.stderr)
            }
        ))
    }
}

impl Drop for Elevator {
    fn drop(&mut self) {
        if let Some(sudo) = self.authenticated_with.take() {
            let _ = run(&drop_argv(&sudo));
        }
    }
}

/// Ask a yes/no question on the controlling terminal.
fn confirm_on_tty(question: &str) -> bool {
    use std::io::{BufRead, BufReader, Write};
    let Ok(tty) = OpenOptions::new().read(true).write(true).open("/dev/tty") else {
        return false;
    };
    let Ok(mut out) = tty.try_clone() else {
        return false;
    };
    let _ = write!(out, "{question} [y/N] ");
    let _ = out.flush();
    let mut answer = String::new();
    if BufReader::new(tty).read_line(&mut answer).is_err() {
        return false;
    }
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// Pick the failure to report from what `sudo` said, falling back to the
/// ordinary verb failure when nothing was elevated or the elevation succeeded
/// (a read-back mismatch after a completed placement is a genuine internal
/// error, exactly as before).
pub fn failure_after(base: Failure, record: &Record) -> Failure {
    use aa_core::integration::ElevationOutcome as O;
    let recorded = record.lock().expect("elevation record").clone();
    match recorded {
        None | Some(O::Completed) => base,
        Some(O::Denied(detail)) | Some(O::Cancelled(detail)) => Failure::new(
            Outcome::Aborted,
            format!(
                "Permission Required: administrator authorization was not granted ({detail}); nothing was changed"
            ),
            "re-run and enter your password when sudo asks, or pass --admin-auth gui to use the macOS dialog",
        ),
        Some(O::NonInteractive(detail)) => Failure::new(
            Outcome::Aborted,
            format!("Unavailable: administrator authorization needs an interactive terminal ({detail}); nothing was changed"),
            "run this from an interactive terminal, or pass --admin-auth gui",
        ),
        Some(O::Unavailable(detail)) => Failure::new(
            Outcome::Unsupported,
            format!("Unavailable: terminal authorization could not be used ({detail}); nothing was changed"),
            "pass --admin-auth gui to use the macOS dialog",
        ),
    }
}

/// A fresh record.
pub fn new_record() -> Record {
    Arc::new(Mutex::new(None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn strings(argv: &[OsString]) -> Vec<String> {
        argv.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    #[test]
    fn the_install_argv_is_exactly_one_install_as_root_with_option_terminators() {
        let argv = strings(&install_argv(SUDO, "/state/staged.json", MANAGED_SETTINGS_PATH));
        assert_eq!(
            argv,
            vec![
                "/usr/bin/sudo",
                "-n",
                "--",
                "/usr/bin/install",
                "-m",
                "644",
                "-o",
                "root",
                "-g",
                "wheel",
                "--",
                "/state/staged.json",
                MANAGED_SETTINGS_PATH
            ]
        );
    }

    #[test]
    fn no_command_ever_reads_a_password_from_aasm_or_goes_through_a_shell() {
        let all = [
            auth_argv(SUDO, MANAGED_SETTINGS_PATH),
            mkdir_argv(SUDO, "/Library/Application Support/ClaudeCode"),
            install_argv(SUDO, "/s", "/t"),
            remove_argv(SUDO, "/t"),
            drop_argv(SUDO),
        ];
        for argv in all {
            let argv = strings(&argv);
            assert_eq!(argv[0], "/usr/bin/sudo");
            for banned in ["-S", "-A", "-s", "-i", "sh", "/bin/sh", "-c", "bash", "zsh"] {
                assert!(!argv.iter().any(|a| a == banned), "{banned} in {argv:?}");
            }
        }
    }

    #[test]
    fn the_prompt_escapes_percent_except_sudos_own_user_escape() {
        let text = prompt_text("/odd%path/x%u");
        assert!(
            text.starts_with("[aasm] password for %u to place one root-owned file, "),
            "{text}"
        );
        assert!(text.contains("/odd%%path/x%%u"), "{text}");
        assert_eq!(
            text.matches("%u").count(),
            2,
            "one real escape, one escaped-literal: {text}"
        );
    }

    #[test]
    fn authentication_uses_v_with_a_prompt_and_runs_nothing() {
        let argv = strings(&auth_argv(SUDO, MANAGED_SETTINGS_PATH));
        assert_eq!(&argv[..3], ["/usr/bin/sudo", "-v", "-p"]);
        assert_eq!(argv.len(), 4);
    }

    #[test]
    fn mkdir_and_remove_name_exactly_the_paths_given_after_a_terminator() {
        let mk = strings(&mkdir_argv(SUDO, "/Library/Application Support/ClaudeCode"));
        assert_eq!(mk[mk.len() - 2], "--");
        assert_eq!(mk[mk.len() - 1], "/Library/Application Support/ClaudeCode");
        let rm = strings(&remove_argv(SUDO, MANAGED_SETTINGS_PATH));
        assert_eq!(
            rm,
            vec![
                "/usr/bin/sudo",
                "-n",
                "--",
                "/bin/rm",
                "-f",
                "--",
                MANAGED_SETTINGS_PATH
            ]
        );
        assert_eq!(strings(&drop_argv(SUDO)), vec!["/usr/bin/sudo", "-k"]);
    }

    // ── preflight ──────────────────────────────────────────────────────────

    #[test]
    fn preflight_maps_each_missing_precondition_to_its_exit_code() {
        let ok = Facts {
            is_macos: true,
            sudo_is_root_owned_regular_file: true,
            tty_opens: true,
        };
        assert!(preflight_with(ok).is_ok());

        let no_tty = preflight_with(Facts { tty_opens: false, ..ok }).expect_err("no tty");
        assert_eq!(no_tty.outcome, Outcome::Aborted);
        assert!(no_tty.detail.contains("Unavailable"), "{no_tty}");
        assert!(no_tty.detail.contains("needs an interactive terminal"), "{no_tty}");
        assert!(no_tty.remediation.contains("--admin-auth gui"), "{no_tty}");

        let no_sudo = preflight_with(Facts {
            sudo_is_root_owned_regular_file: false,
            ..ok
        })
        .expect_err("no sudo");
        assert_eq!(no_sudo.outcome, Outcome::Unsupported);

        let not_macos = preflight_with(Facts { is_macos: false, ..ok }).expect_err("not macOS");
        assert_eq!(not_macos.outcome, Outcome::Unsupported);
    }

    // ── staged-file hardening ──────────────────────────────────────────────

    struct Staged {
        _dir: tempfile::TempDir,
        dir: PathBuf,
        file: PathBuf,
        uid: u32,
        sha: String,
    }

    fn staged(body: &str) -> Staged {
        let dir = tempfile::tempdir().expect("tempdir");
        let private = dir.path().join("state");
        std::fs::create_dir(&private).expect("mkdir");
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).expect("chmod");
        let file = private.join("managed-settings.staged.json");
        std::fs::write(&file, body).expect("write");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let uid = std::fs::metadata(&file).expect("meta").uid();
        Staged {
            sha: sha256_hex(body),
            _dir: dir,
            dir: private,
            file,
            uid,
        }
    }

    #[test]
    fn a_well_formed_staged_file_verifies() {
        let s = staged("{\"a\":1}");
        assert_eq!(
            read_verified_staged(&s.file, s.uid, &s.sha).expect("verifies"),
            "{\"a\":1}"
        );
    }

    #[test]
    fn a_wrong_digest_is_refused() {
        let s = staged("{\"a\":1}");
        let err = read_verified_staged(&s.file, s.uid, &"0".repeat(64)).expect_err("refused");
        assert!(err.contains("hashes to"), "{err}");
    }

    #[test]
    fn a_symlink_is_never_followed() {
        let s = staged("{\"a\":1}");
        let link = s.dir.join("link.json");
        std::os::unix::fs::symlink(&s.file, &link).expect("symlink");
        assert!(read_verified_staged(&link, s.uid, &s.sha).is_err());
    }

    #[test]
    fn another_owner_is_refused() {
        let s = staged("{\"a\":1}");
        let err = read_verified_staged(&s.file, s.uid.wrapping_add(1), &s.sha).expect_err("refused");
        assert!(err.contains("not owned"), "{err}");
    }

    #[test]
    fn a_second_hard_link_is_refused() {
        let s = staged("{\"a\":1}");
        std::fs::hard_link(&s.file, s.dir.join("alias.json")).expect("link");
        let err = read_verified_staged(&s.file, s.uid, &s.sha).expect_err("refused");
        assert!(err.contains("hard link"), "{err}");
    }

    #[test]
    fn a_group_or_world_writable_file_is_refused() {
        let s = staged("{\"a\":1}");
        std::fs::set_permissions(&s.file, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = read_verified_staged(&s.file, s.uid, &s.sha).expect_err("refused");
        assert!(err.contains("writable"), "{err}");
    }

    #[test]
    fn an_oversized_file_is_refused() {
        let body = "x".repeat(70 * 1024);
        let s = staged(&body);
        let err = read_verified_staged(&s.file, s.uid, &s.sha).expect_err("refused");
        assert!(err.contains("too large"), "{err}");
    }

    #[test]
    fn a_non_private_staging_directory_is_refused() {
        let s = staged("{\"a\":1}");
        std::fs::set_permissions(&s.dir, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let err = read_verified_staged(&s.file, s.uid, &s.sha).expect_err("refused");
        assert!(err.contains("private directory"), "{err}");
    }

    #[test]
    fn a_directory_is_not_a_staged_file() {
        let s = staged("{\"a\":1}");
        assert!(read_verified_staged(&s.dir, s.uid, &s.sha).is_err());
    }

    // ── what the runtime may and may not steer ─────────────────────────────

    fn request_for(target: &str, staged: &Path, sha: &str) -> wire::ElevationRequest {
        wire::ElevationRequest {
            request_id: 1,
            sequence: 1,
            kind: wire::ElevationKind::InstallFile as i32,
            purpose: wire::ElevationPurpose::PlaceReviewed as i32,
            target: target.to_string(),
            staged_path: staged.display().to_string(),
            staged_sha256: sha.to_string(),
        }
    }

    #[test]
    fn a_non_canonical_target_without_the_test_seam_is_never_elevated_for() {
        // The seam is an environment variable of *this* process; the runtime
        // cannot set it, so a runtime-chosen target gets no elevation at all.
        let s = staged("{\"a\":1}");
        if std::env::var_os(TEST_HELPER_ENV).is_some() {
            return; // an ambient seam would make this test meaningless
        }
        let record = new_record();
        let mut elevator = Elevator::new(Some(s.sha.clone()), record);
        let outcome = elevator.perform(&request_for("/etc/sudoers", &s.file, &s.sha));
        assert!(
            matches!(&outcome, aa_core::integration::ElevationOutcome::Unavailable(d) if d.contains("only")),
            "{outcome:?}"
        );
    }

    #[test]
    fn the_exit_mapping_follows_what_sudo_said_not_what_the_runtime_said() {
        use aa_core::integration::ElevationOutcome as O;
        let base = || Failure::new(Outcome::InternalError, "the runtime's own words", "look");
        let with = |o: Option<O>| {
            let record = new_record();
            *record.lock().unwrap() = o;
            failure_after(base(), &record)
        };
        assert_eq!(with(None).outcome, Outcome::InternalError);
        assert_eq!(
            with(Some(O::Completed)).outcome,
            Outcome::InternalError,
            "read-back mismatch stays internal"
        );
        let denied = with(Some(O::Denied("3 incorrect attempts".into())));
        assert_eq!(denied.outcome, Outcome::Aborted);
        assert!(denied.detail.contains("Permission Required"), "{denied}");
        assert!(denied.detail.contains("nothing was changed"), "{denied}");
        assert_eq!(with(Some(O::Cancelled("x".into()))).outcome, Outcome::Aborted);
        let ni = with(Some(O::NonInteractive("no tty".into())));
        assert_eq!(ni.outcome, Outcome::Aborted);
        assert!(
            ni.detail.contains("Unavailable") && ni.detail.contains("needs an interactive terminal"),
            "{ni}"
        );
        assert_eq!(
            with(Some(O::Unavailable("no sudo".into()))).outcome,
            Outcome::Unsupported
        );
    }

    #[test]
    fn the_disclosure_lines_name_the_method() {
        assert_eq!(
            AdminAuthArg::Terminal.disclosure_line(),
            "authorization: sudo in this terminal"
        );
        assert_eq!(
            AdminAuthArg::Gui.disclosure_line(),
            "authorization: macOS dialog (--admin-auth gui)"
        );
        assert_eq!(AdminAuthArg::Terminal.as_wire(), "terminal");
        assert_eq!(AdminAuthArg::Gui.as_wire(), "gui");
    }
}
