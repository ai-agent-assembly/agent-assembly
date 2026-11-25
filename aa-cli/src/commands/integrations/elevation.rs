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
//! runtime stay the invoking user; what runs as root is a fixed set of commands
//! on fixed paths (`tee`, `install`, `rm`, and `rmdir`/`install -d` for the
//! directory), never anything the runtime chose.
//!
//! # Rules this module will not bend
//!
//! * **No password ever passes through AASM.** `sudo` reads it from the tty.
//!   There is no `-S`, no `-A`, no shell, and stdout is null.
//! * **Root never reads a path the user can write.** The staged file is opened
//!   `O_NOFOLLOW`, must be a small regular file this user owns in a private
//!   directory, and must hash to the digest the runtime stated — and, for the
//!   reviewed placement, to the digest the operator reviewed. Those verified
//!   bytes are then held **in memory** and fed to `sudo tee` on stdin into a
//!   temporary *inside the root-owned managed directory*, which the user cannot
//!   write; `install` then moves that root-owned temporary into place. No argv
//!   run as root contains the staged path, so swapping the staged file after
//!   verification changes nothing root sees.
//! * **The target is this binary's own constant.** The path the runtime sent is
//!   informational. The one exception is a test seam
//!   (`AASM_TEST_ELEVATION_HELPER`), honoured only when
//!   `AASM_CLAUDE_MANAGED_ROOT` is also set and the runtime-sent target is
//!   exactly that redirected root's file — never for the canonical path.
//! * **Each verb gets only its own operations.** An install may place the
//!   reviewed document, and may restore or delete only to roll back a placement
//!   that already completed in the same run. A removal may delete (after a y/N
//!   unless `--yes`) or restore a backup (always asking, showing the digest).
//! * **The sudo ticket does not outlive the operation.** `sudo -k` runs
//!   immediately after every elevated operation, success or failure, with the
//!   `Drop` as a backstop and `SIGINT`/`SIGQUIT` ignored around the whole
//!   handler so ^C cannot skip it. This also drops a ticket the operator held
//!   before the run; that is accepted, and it means every elevated operation
//!   prompts for the password afresh.
//!
//! macOS `install(1)` refuses a non-regular source (`/dev/stdin` fails with
//! "Inappropriate file type"), which is why the bytes are not piped to
//! `install` directly but to `tee`, whose output lands in a root-owned file that
//! `install` can then use as an ordinary regular source.

use std::ffi::OsString;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use aa_core::integration::{sha256_hex, ElevationOutcome};
use aa_devtool_claude_code::managed_settings::MANAGED_SETTINGS_FILE;
use aa_devtool_claude_code::MANAGED_SETTINGS_PATH;
use aa_proto::assembly::devint::v1 as wire;
use aa_runtime::devint::ElevationHandler;
use clap::ValueEnum;

use super::exit::Outcome;
use super::session::Failure;

/// The only `sudo` this module will run.
pub const SUDO: &str = "/usr/bin/sudo";
const INSTALL: &str = "/usr/bin/install";
const TEE: &str = "/usr/bin/tee";
const RM: &str = "/bin/rm";
const RMDIR: &str = "/bin/rmdir";
/// The temporary the verified bytes are written to, inside the root-owned
/// managed directory.
const TMP_NAME: &str = ".managed-settings.json.aasm-new";
/// What `sudo` and its children get as `PATH`; nothing else of the caller's
/// environment crosses, because `sudo` is about to act on the caller's say-so.
const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
/// The test seam: a stub that stands in for `sudo`. See the module docs.
pub const TEST_HELPER_ENV: &str = "AASM_TEST_ELEVATION_HELPER";
const MANAGED_ROOT_ENV: &str = "AASM_CLAUDE_MANAGED_ROOT";
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

// ── where things are ────────────────────────────────────────────────────────

/// The managed-settings file this invocation means: the canonical constant, or
/// the redirected root's file when the test seam's root is set.
pub fn effective_managed_target() -> String {
    match std::env::var_os(MANAGED_ROOT_ENV).filter(|v| !v.is_empty()) {
        Some(root) => PathBuf::from(root)
            .join(MANAGED_SETTINGS_FILE)
            .to_string_lossy()
            .into_owned(),
        None => MANAGED_SETTINGS_PATH.to_string(),
    }
}

/// Whether any of `paths` is the managed-settings file — the one question that
/// decides whether a removal or repair has to elevate. Decided by path, never by
/// a step's privilege marker, scope token or an id substring, none of which a
/// removal or drift report reliably carries.
pub fn involves_managed_file<'a>(paths: impl IntoIterator<Item = &'a str>) -> bool {
    let managed = effective_managed_target();
    paths.into_iter().any(|p| Path::new(p) == Path::new(&managed))
}

/// The test seam's stand-in for `sudo`, when — and only when — the managed root
/// is redirected. Preflight and every elevation use this one condition.
fn test_seam() -> Option<String> {
    let redirected = std::env::var_os(MANAGED_ROOT_ENV).is_some_and(|v| !v.is_empty());
    if !redirected {
        return None;
    }
    std::env::var(TEST_HELPER_ENV).ok().filter(|v| !v.is_empty())
}

/// The fixed paths one elevated operation acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// The `sudo` (or stub) to run.
    pub sudo: String,
    /// The file placed or deleted.
    pub target: String,
    /// Its directory.
    pub dir: String,
    /// The root-owned temporary beside it.
    pub tmp: String,
}

impl Paths {
    /// Paths for `target` run through `sudo`.
    pub fn new(sudo: &str, target: &str) -> Self {
        let dir = Path::new(target)
            .parent()
            .map_or_else(|| "/".to_string(), |d| d.to_string_lossy().into_owned());
        let tmp = Path::new(&dir).join(TMP_NAME).to_string_lossy().into_owned();
        Self {
            sudo: sudo.to_string(),
            target: target.to_string(),
            dir,
            tmp,
        }
    }
}

// ── argv construction — pure, so the whole command surface is unit-tested ────

/// `sudo -v`: authenticate, run nothing. `verb` is what the operator is about to
/// authorize (`place` or `delete`), so the prompt never claims the wrong thing.
pub fn auth_argv(sudo: &str, target: &str, verb: &str) -> Vec<OsString> {
    vec![sudo.into(), "-v".into(), "-p".into(), prompt_text(target, verb).into()]
}

/// The prompt `sudo` shows. `%u` is sudo's own escape for the user name; every
/// other `%` in what we interpolate is doubled so a path can never inject one.
pub fn prompt_text(target: &str, verb: &str) -> String {
    format!(
        "[aasm] password for %u to {verb} one root-owned file, {}: ",
        target.replace('%', "%%")
    )
}

fn argv(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(OsString::from).collect()
}

/// Create the managed directory, root-owned, only when it is missing.
pub fn mkdir_argv(sudo: &str, dir: &str) -> Vec<OsString> {
    argv(&[
        sudo, "-n", "--", INSTALL, "-d", "-m", "755", "-o", "root", "-g", "wheel", "--", dir,
    ])
}

/// Write stdin to the root-owned temporary. The verified bytes arrive on stdin.
pub fn tee_argv(sudo: &str, tmp: &str) -> Vec<OsString> {
    argv(&[sudo, "-n", "--", TEE, "--", tmp])
}

/// Move the root-owned temporary into place, root-owned and world-readable.
pub fn install_argv(sudo: &str, tmp: &str, target: &str) -> Vec<OsString> {
    argv(&[
        sudo, "-n", "--", INSTALL, "-m", "644", "-o", "root", "-g", "wheel", "--", tmp, target,
    ])
}

/// Delete a path. `-f` so an already-absent file is a success.
pub fn remove_argv(sudo: &str, path: &str) -> Vec<OsString> {
    argv(&[sudo, "-n", "--", RM, "-f", "--", path])
}

/// Remove a directory this run created, only if it is empty (`rmdir` refuses
/// otherwise).
pub fn rmdir_argv(sudo: &str, dir: &str) -> Vec<OsString> {
    argv(&[sudo, "-n", "--", RMDIR, "--", dir])
}

/// Forget the sudo timestamp.
pub fn drop_argv(sudo: &str) -> Vec<OsString> {
    argv(&[sudo, "-k"])
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

/// Refuse, before anything is sent, a terminal-authorized operation that
/// involves the managed file against a runtime that cannot carry it: it would
/// ignore the field and open the GUI dialog.
///
/// # Errors
///
/// `incompatible` (exit 4), naming both remedies.
pub fn refuse_terminal_below_v8(admin: AdminAuthArg, involves_managed: bool, negotiated: u32) -> Result<(), Failure> {
    if !involves_managed
        || !matches!(admin, AdminAuthArg::Terminal)
        || negotiated >= aa_runtime::devint::DI_API_TERMINAL_ELEVATION_SINCE
    {
        return Ok(());
    }
    Err(Failure::new(
        Outcome::Incompatible,
        format!(
            "nothing was changed: this runtime negotiated DI-API {negotiated} and cannot carry terminal \
             authorization, so it would open the macOS authorization dialog from a background process"
        ),
        "upgrade the runtime, or pass --admin-auth gui",
    ))
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
            tty_opens: tty_opens(),
        }
    }

    /// Facts under the test seam: the stub stands in for `sudo` (it need only be
    /// a regular file) and the host is treated as macOS; the terminal is real.
    fn for_seam(stub: &str) -> Self {
        Self {
            is_macos: true,
            sudo_is_root_owned_regular_file: Path::new(stub).is_file(),
            tty_opens: tty_opens(),
        }
    }
}

fn tty_opens() -> bool {
    OpenOptions::new().read(true).write(true).open("/dev/tty").is_ok()
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

/// Preflight against the real host, under the same seam condition elevation uses.
///
/// # Errors
///
/// See [`preflight_with`].
pub fn preflight() -> Result<(), Failure> {
    let facts = match test_seam() {
        Some(stub) => Facts::for_seam(&stub),
        None => Facts::gather(Path::new(SUDO)),
    };
    preflight_with(facts)
}

// ── staged-file hardening ───────────────────────────────────────────────────

/// Open the staged file and return its bytes only if every check passes.
///
/// `uid` is the invoking user. Every check is on the opened descriptor (or on
/// the parent directory), never on a path that could be swapped between the
/// check and the use — and the returned bytes are what is sent to root, so the
/// path is never consulted again.
///
/// # Errors
///
/// Which check failed, as a sentence.
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
/// a ^C aimed at a password prompt cannot kill `aasm` between an operation and
/// its cleanup. `sudo` itself still receives them. Nests: each guard restores
/// what it found.
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

/// Run `argv`, optionally feeding `input` on stdin (otherwise stdin is null).
fn run(argv: &[OsString], input: Option<&[u8]>) -> Result<Ran, String> {
    let (program, args) = argv.split_first().ok_or_else(|| "empty command".to_string())?;
    let _guard = SignalGuard::ignore();
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .env("PATH", SAFE_PATH)
        .env("TERM", std::env::var("TERM").unwrap_or_else(|_| "dumb".to_string()))
        .stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() })
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
    // Written from a thread so a child that stops reading cannot deadlock the
    // stderr read below; a closed pipe (EPIPE) is the child's refusal, reported
    // by its exit status.
    let writer = input.zip(child.stdin.take()).map(|(bytes, mut stdin)| {
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            let _ = stdin.write_all(&bytes);
        })
    });
    let mut captured = Vec::new();
    if let Some(mut stderr) = child.stderr.take() {
        let _ = (&mut stderr).take(STDERR_CAP as u64).read_to_end(&mut captured);
        // Past the cap, keep draining into the void: a child that writes more
        // than the pipe holds would otherwise block forever on a reader that
        // stopped reading, and `wait` below would never return.
        let _ = std::io::copy(&mut stderr, &mut std::io::sink());
    }
    let status = child.wait().map_err(|e| format!("waiting for sudo failed: {e}"))?;
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    Ok(Ran {
        success: status.success(),
        stderr: String::from_utf8_lossy(&captured).trim().to_string(),
    })
}

fn first_line(text: &str) -> String {
    text.lines().next().unwrap_or("").to_string()
}

// ── the elevator ────────────────────────────────────────────────────────────

/// What elevation did so far, kept so the command can pick its exit code and
/// its words from what `sudo` itself said — never from the runtime's prose.
#[derive(Debug, Default, Clone)]
pub struct State {
    /// The most recent operation's outcome.
    pub last: Option<ElevationOutcome>,
    /// Whether any elevated operation completed, i.e. the managed file may
    /// differ from what it was when the command started.
    pub changed: bool,
}

/// The shared handle to [`State`].
pub type Record = Arc<Mutex<State>>;

/// A fresh record.
pub fn new_record() -> Record {
    Arc::new(Mutex::new(State::default()))
}

/// Which verb this elevator serves, and so which operations it may perform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `install`: place the reviewed document; roll back only a completed placement.
    Install,
    /// `remove`: delete or restore.
    Remove,
    /// `repair`: re-place after asking; roll back only a completed placement.
    Repair,
}

/// Answers the runtime's elevation requests with `sudo`.
pub struct Elevator {
    uid: u32,
    mode: Mode,
    /// The digest of the document the operator reviewed in the plan.
    reviewed_sha256: Option<String>,
    assume_yes: bool,
    record: Record,
    /// The sudo in use when this module last authenticated, so `sudo -k` is owed.
    authenticated_with: Option<String>,
}

impl Elevator {
    /// An elevator for `mode`. `reviewed_sha256` is the digest the operator saw
    /// in the plan, for the reviewed placement.
    pub fn new(mode: Mode, reviewed_sha256: Option<String>, record: Record) -> Self {
        Self {
            // SAFETY: `getuid` has no preconditions and cannot fail.
            uid: unsafe { libc::getuid() },
            mode,
            reviewed_sha256,
            assume_yes: false,
            record,
            authenticated_with: None,
        }
    }

    /// `--yes` was given: the command's own confirmation already covers a
    /// delete, so it is not asked a second time. The sudo prompt still is.
    #[must_use]
    pub fn assuming_yes(mut self, yes: bool) -> Self {
        self.assume_yes = yes;
        self
    }

    /// Wrap this elevator as the client's handler. Dropping the handler (when
    /// the client is dropped) is the backstop for the sudo timestamp.
    pub fn into_handler(mut self) -> ElevationHandler {
        Box::new(move |request| {
            // Around the whole handler, not just each child: ^C must not skip the
            // `sudo -k` or the cleanup that follow an operation.
            let _guard = SignalGuard::ignore();
            let outcome = self.perform(request);
            {
                let mut state = self.record.lock().expect("elevation record");
                if outcome == ElevationOutcome::Completed {
                    state.changed = true;
                }
                state.last = Some(outcome.clone());
            }
            let (code, detail) = match outcome {
                ElevationOutcome::Completed => (wire::ElevationResultCode::Completed, String::new()),
                ElevationOutcome::Denied(d) => (wire::ElevationResultCode::Denied, d),
                ElevationOutcome::Cancelled(d) => (wire::ElevationResultCode::Cancelled, d),
                ElevationOutcome::Unavailable(d) => (wire::ElevationResultCode::Unavailable, d),
                ElevationOutcome::NonInteractive(d) => (wire::ElevationResultCode::NonInteractive, d),
            };
            wire::ElevationResult {
                outcome: code as i32,
                detail,
                ..Default::default()
            }
        })
    }

    fn changed(&self) -> bool {
        self.record.lock().expect("elevation record").changed
    }

    /// Whether this verb may perform `(kind, purpose)` right now.
    fn allowed(&self, kind: wire::ElevationKind, purpose: wire::ElevationPurpose) -> bool {
        use wire::{ElevationKind as K, ElevationPurpose as P};
        // A rollback is only legitimate after this run placed something.
        let rolling_back = self.changed();
        match (self.mode, kind, purpose) {
            (Mode::Install | Mode::Repair, K::InstallFile, P::PlaceReviewed) => true,
            (Mode::Install | Mode::Repair, K::InstallFile, P::RestoreBackup)
            | (Mode::Install | Mode::Repair, K::DeleteFile, P::Remove) => rolling_back,
            (Mode::Remove, K::DeleteFile, P::Remove) | (Mode::Remove, K::InstallFile, P::RestoreBackup) => true,
            _ => false,
        }
    }

    fn perform(&mut self, request: &wire::ElevationRequest) -> ElevationOutcome {
        use ElevationOutcome as O;
        let kind = wire::ElevationKind::try_from(request.kind).unwrap_or(wire::ElevationKind::Unspecified);
        let purpose = wire::ElevationPurpose::try_from(request.purpose).unwrap_or(wire::ElevationPurpose::Unspecified);

        // Where: the canonical constant, or the redirected test seam — and only
        // when the runtime named exactly that redirected file.
        let (sudo, target) = if Path::new(&request.target) == Path::new(MANAGED_SETTINGS_PATH) {
            (SUDO.to_string(), MANAGED_SETTINGS_PATH.to_string())
        } else {
            match test_seam() {
                Some(stub) if request.target == effective_managed_target() => (stub, request.target.clone()),
                _ => {
                    return O::Unavailable(format!(
                        "refusing to elevate for {}: only {MANAGED_SETTINGS_PATH} is ever authorized",
                        request.target
                    ))
                }
            }
        };
        let paths = Paths::new(&sudo, &target);

        let facts = if sudo == SUDO {
            Facts::gather(Path::new(SUDO))
        } else {
            Facts::for_seam(&sudo)
        };
        if let Err(failure) = preflight_with(facts) {
            return match failure.outcome {
                Outcome::Aborted => O::NonInteractive(failure.detail),
                _ => O::Unavailable(failure.detail),
            };
        }

        if !self.allowed(kind, purpose) {
            return O::Cancelled(
                "the runtime asked for an operation this command does not perform; nothing was changed".to_string(),
            );
        }

        match kind {
            wire::ElevationKind::InstallFile => {
                let body = match read_verified_staged(Path::new(&request.staged_path), self.uid, &request.staged_sha256)
                {
                    Ok(body) => body,
                    Err(e) => return O::Cancelled(format!("refusing to install an unverified staged file: {e}")),
                };
                if let Some(refusal) = self.review(purpose, &sha256_hex(&body), &target) {
                    return refusal;
                }
                self.place(&paths, &body)
            }
            _ => {
                if self.mode == Mode::Remove
                    && !self.assume_yes
                    && !confirm_on_tty(&format!(
                        "Delete the administrator-owned managed-settings file {target}?"
                    ))
                {
                    return O::Cancelled("deleting the managed-settings file was declined".to_string());
                }
                self.delete(&paths)
            }
        }
    }

    /// The operator's say on the document about to be placed, by purpose.
    fn review(&self, purpose: wire::ElevationPurpose, digest: &str, target: &str) -> Option<ElevationOutcome> {
        use ElevationOutcome as O;
        match purpose {
            wire::ElevationPurpose::PlaceReviewed => match &self.reviewed_sha256 {
                Some(reviewed) if reviewed.eq_ignore_ascii_case(digest) => None,
                Some(reviewed) => Some(O::Cancelled(format!(
                    "the staged document (sha256:{digest}) is not the one you reviewed (sha256:{reviewed}); \
                     nothing was placed"
                ))),
                // A repair re-places a document the operator did not just
                // review: show its digest and ask.
                None if self.mode == Mode::Repair => {
                    if confirm_on_tty(&format!(
                        "Agent Assembly needs to re-place the managed-settings document (sha256:{digest}) at {target}. Continue?"
                    )) {
                        None
                    } else {
                        Some(O::Cancelled("re-placing the managed settings was declined".to_string()))
                    }
                }
                None => Some(O::Cancelled(
                    "no reviewed document digest is on record; nothing was placed".to_string(),
                )),
            },
            // The digest of the file this install displaced is not on the
            // wire, so it cannot be compared with a recorded one; the strongest
            // check available without new IPC is to show this digest and ask.
            wire::ElevationPurpose::RestoreBackup => {
                if confirm_on_tty(&format!(
                    "Agent Assembly needs to restore the previous managed-settings file (sha256:{digest}) over {target}. Continue?"
                )) {
                    None
                } else {
                    Some(O::Cancelled("restoring the previous file was declined".to_string()))
                }
            }
            _ => Some(O::Cancelled(
                "the runtime asked for an operation this command does not perform".to_string(),
            )),
        }
    }

    fn authenticate(&mut self, paths: &Paths, verb: &str) -> Option<ElevationOutcome> {
        use ElevationOutcome as O;
        match run(&auth_argv(&paths.sudo, &paths.target, verb), None) {
            Ok(ran) if ran.success => {
                self.authenticated_with = Some(paths.sudo.clone());
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

    /// Forget the sudo timestamp now. Idempotent; `Drop` is the backstop.
    fn drop_ticket(&mut self) {
        if let Some(sudo) = self.authenticated_with.take() {
            let _ = run(&drop_argv(&sudo), None);
        }
    }

    /// Place `body` — bytes already verified and held in memory — at the target.
    ///
    /// Root sees only fixed paths inside the managed directory: the bytes go to a
    /// root-owned temporary through `tee`'s stdin, `install` moves that into
    /// place, and the temporary is removed on every path.
    pub fn place(&mut self, paths: &Paths, body: &str) -> ElevationOutcome {
        let outcome = self.place_inner(paths, body);
        self.drop_ticket();
        outcome
    }

    fn place_inner(&mut self, paths: &Paths, body: &str) -> ElevationOutcome {
        use ElevationOutcome as O;
        if let Some(denied) = self.authenticate(paths, "place") {
            return denied;
        }
        let mut created_dir = false;
        if !Path::new(&paths.dir).exists() {
            match run(&mkdir_argv(&paths.sudo, &paths.dir), None) {
                Ok(ran) if ran.success => created_dir = true,
                Ok(ran) => return self.noninteractive_or(ran, "creating the managed directory"),
                Err(e) => return O::Unavailable(e),
            }
        }
        let written = run(&tee_argv(&paths.sudo, &paths.tmp), Some(body.as_bytes()));
        let outcome = match written {
            Ok(ran) if ran.success => match run(&install_argv(&paths.sudo, &paths.tmp, &paths.target), None) {
                Ok(ran) if ran.success => O::Completed,
                Ok(ran) => self.noninteractive_or(ran, "placing the file"),
                Err(e) => O::Unavailable(e),
            },
            Ok(ran) => self.noninteractive_or(ran, "writing the temporary file"),
            Err(e) => O::Unavailable(e),
        };
        // The temporary goes on every path, success included.
        let _ = run(&remove_argv(&paths.sudo, &paths.tmp), None);
        if outcome != O::Completed && created_dir {
            // Only a directory this run created, and `rmdir` refuses a non-empty one.
            let _ = run(&rmdir_argv(&paths.sudo, &paths.dir), None);
        }
        outcome
    }

    /// Delete the target.
    pub fn delete(&mut self, paths: &Paths) -> ElevationOutcome {
        use ElevationOutcome as O;
        let outcome = match self.authenticate(paths, "delete") {
            Some(denied) => denied,
            None => match run(&remove_argv(&paths.sudo, &paths.target), None) {
                Ok(ran) if ran.success => O::Completed,
                Ok(ran) => self.noninteractive_or(ran, "removing the file"),
                Err(e) => O::Unavailable(e),
            },
        };
        self.drop_ticket();
        outcome
    }

    /// A `-n` invocation that fails because `sudo` would not reuse the
    /// authentication (`timestamp_timeout=0`, a per-command ticket policy) is
    /// not a refusal by the operator; it is a host that cannot do this, and the
    /// remedy is the other method.
    fn noninteractive_or(&self, ran: Ran, doing: &str) -> ElevationOutcome {
        use ElevationOutcome as O;
        let text = ran.stderr.to_ascii_lowercase();
        if text.contains("password is required") || text.contains("a terminal is required") || text.contains("no tty") {
            return O::Unavailable(
                "sudo will not reuse the authentication you just gave (its timestamp_timeout may be 0), so the \
                 operation cannot run without a second prompt; pass --admin-auth gui"
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
        self.drop_ticket();
    }
}

/// Ask a yes/no question on the controlling terminal.
fn confirm_on_tty(question: &str) -> bool {
    use std::io::{BufRead, BufReader};
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
/// ordinary verb failure when nothing was elevated or the last elevation
/// succeeded (a read-back mismatch after a completed placement is a genuine
/// internal error, exactly as before).
///
/// If an operation completed earlier in the run and a later one (the rollback)
/// did not, the host **was** changed and the report says so: "nothing was
/// changed" would be false.
pub fn failure_after(base: Failure, record: &Record) -> Failure {
    use ElevationOutcome as O;
    let state = record.lock().expect("elevation record").clone();
    let Some(last) = state.last else { return base };
    let detail = match &last {
        O::Completed => return base,
        O::Denied(d) | O::Cancelled(d) | O::Unavailable(d) | O::NonInteractive(d) => d.clone(),
    };
    if state.changed {
        return Failure::new(
            Outcome::InternalError,
            format!(
                "the managed-settings file WAS changed earlier in this run, and a later administrator operation \
                 did not complete ({detail}); the host is not in the state it started in"
            ),
            "run `aasm integrations status claude-code`, then `aasm integrations repair claude-code` or \
             `aasm integrations remove claude-code` to reconcile it",
        );
    }
    match last {
        O::Denied(detail) | O::Cancelled(detail) => Failure::new(
            Outcome::Aborted,
            format!(
                "Permission Required: administrator authorization was not granted ({detail}); nothing was changed"
            ),
            "re-run and enter your password when sudo asks, or pass --admin-auth gui to use the macOS dialog",
        ),
        O::NonInteractive(detail) => Failure::new(
            Outcome::Aborted,
            format!("Unavailable: administrator authorization needs an interactive terminal ({detail}); nothing was changed"),
            "run this from an interactive terminal, or pass --admin-auth gui",
        ),
        O::Unavailable(detail) => Failure::new(
            Outcome::Unsupported,
            format!("Unavailable: terminal authorization could not be used ({detail}); nothing was changed"),
            "pass --admin-auth gui to use the macOS dialog",
        ),
        O::Completed => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aa_core::integration::ElevationOutcome as O;
    use std::os::unix::fs::PermissionsExt;

    fn strings(argv: &[OsString]) -> Vec<String> {
        argv.iter().map(|s| s.to_string_lossy().into_owned()).collect()
    }

    const TMP: &str = "/Library/Application Support/ClaudeCode/.managed-settings.json.aasm-new";

    #[test]
    fn the_install_argv_moves_a_root_owned_temporary_never_a_user_path() {
        let argv = strings(&install_argv(SUDO, TMP, MANAGED_SETTINGS_PATH));
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
                TMP,
                MANAGED_SETTINGS_PATH
            ]
        );
    }

    #[test]
    fn no_argv_run_as_root_names_a_staged_path_and_every_path_is_inside_the_managed_directory() {
        let paths = Paths::new(SUDO, MANAGED_SETTINGS_PATH);
        assert_eq!(paths.dir, "/Library/Application Support/ClaudeCode");
        assert_eq!(paths.tmp, TMP);
        let all = [
            auth_argv(SUDO, &paths.target, "place"),
            mkdir_argv(SUDO, &paths.dir),
            tee_argv(SUDO, &paths.tmp),
            install_argv(SUDO, &paths.tmp, &paths.target),
            remove_argv(SUDO, &paths.tmp),
            remove_argv(SUDO, &paths.target),
            rmdir_argv(SUDO, &paths.dir),
            drop_argv(SUDO),
        ];
        for argv in &all {
            let argv = strings(argv);
            assert!(!argv.iter().any(|a| a.contains("staged")), "{argv:?}");
            for arg in argv
                .iter()
                .filter(|a| a.starts_with('/') && !a.starts_with("/usr/") && !a.starts_with("/bin/"))
            {
                assert!(
                    arg.starts_with("/Library/Application Support/ClaudeCode"),
                    "{arg} in {argv:?}"
                );
            }
        }
        assert_eq!(
            strings(&tee_argv(SUDO, TMP)),
            vec!["/usr/bin/sudo", "-n", "--", "/usr/bin/tee", "--", TMP]
        );
    }

    #[test]
    fn no_command_ever_reads_a_password_from_aasm_or_goes_through_a_shell() {
        let all = [
            auth_argv(SUDO, MANAGED_SETTINGS_PATH, "place"),
            mkdir_argv(SUDO, "/Library/Application Support/ClaudeCode"),
            tee_argv(SUDO, "/t"),
            install_argv(SUDO, "/s", "/t"),
            remove_argv(SUDO, "/t"),
            rmdir_argv(SUDO, "/d"),
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
    fn the_prompt_escapes_percent_and_names_what_is_being_authorized() {
        let text = prompt_text("/odd%path/x%u", "place");
        assert!(
            text.starts_with("[aasm] password for %u to place one root-owned file, "),
            "{text}"
        );
        assert!(text.contains("/odd%%path/x%%u"), "{text}");
        assert_eq!(text.matches("%u").count(), 2, "{text}");
        assert!(prompt_text("/t", "delete").contains("to delete one root-owned file"));
    }

    #[test]
    fn authentication_uses_v_with_a_prompt_and_runs_nothing() {
        let argv = strings(&auth_argv(SUDO, MANAGED_SETTINGS_PATH, "place"));
        assert_eq!(&argv[..3], ["/usr/bin/sudo", "-v", "-p"]);
        assert_eq!(argv.len(), 4);
    }

    #[test]
    fn remove_rmdir_and_drop_name_exactly_the_paths_given_after_a_terminator() {
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
        assert_eq!(
            strings(&rmdir_argv(SUDO, "/d")),
            vec!["/usr/bin/sudo", "-n", "--", "/bin/rmdir", "--", "/d"]
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

    #[test]
    fn a_terminal_operation_on_the_managed_file_is_refused_below_v8_with_exit_4() {
        let refused = refuse_terminal_below_v8(AdminAuthArg::Terminal, true, 7).expect_err("refused");
        assert_eq!(refused.outcome, Outcome::Incompatible);
        assert!(refused.remediation.contains("--admin-auth gui"), "{refused}");
        assert!(refuse_terminal_below_v8(AdminAuthArg::Terminal, true, 8).is_ok());
        assert!(refuse_terminal_below_v8(AdminAuthArg::Gui, true, 7).is_ok());
        assert!(
            refuse_terminal_below_v8(AdminAuthArg::Terminal, false, 7).is_ok(),
            "an operation that never reaches the managed file is unaffected"
        );
    }

    #[test]
    fn the_managed_file_is_recognised_by_path_alone() {
        assert!(
            std::env::var_os(MANAGED_ROOT_ENV).is_none(),
            "the redirect must not be set in this test's environment"
        );
        assert!(involves_managed_file(["/x/y", MANAGED_SETTINGS_PATH]));
        assert!(!involves_managed_file([
            "/Users/a/.claude/settings.json",
            "endpoint-managed-settings"
        ]));
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

    fn request_for(target: &str, kind: wire::ElevationKind, purpose: wire::ElevationPurpose) -> wire::ElevationRequest {
        wire::ElevationRequest {
            request_id: 1,
            sequence: 1,
            kind: kind as i32,
            purpose: purpose as i32,
            target: target.to_string(),
            staged_path: String::new(),
            staged_sha256: String::new(),
        }
    }

    #[test]
    fn a_non_canonical_target_without_the_test_seam_is_never_elevated_for() {
        assert!(
            std::env::var_os(TEST_HELPER_ENV).is_none() && std::env::var_os(MANAGED_ROOT_ENV).is_none(),
            "the seam must not be set in this test's environment"
        );
        let mut elevator = Elevator::new(Mode::Install, None, new_record());
        let outcome = elevator.perform(&request_for(
            "/etc/sudoers",
            wire::ElevationKind::InstallFile,
            wire::ElevationPurpose::PlaceReviewed,
        ));
        assert!(
            matches!(&outcome, O::Unavailable(d) if d.contains("only")),
            "{outcome:?}"
        );
    }

    #[test]
    fn each_verb_may_perform_only_its_own_operations() {
        use wire::{ElevationKind as K, ElevationPurpose as P};
        let can = |mode: Mode, changed: bool, kind: K, purpose: P| {
            let record = new_record();
            record.lock().unwrap().changed = changed;
            Elevator::new(mode, None, record).allowed(kind, purpose)
        };
        for mode in [Mode::Install, Mode::Repair] {
            assert!(can(mode, false, K::InstallFile, P::PlaceReviewed));
            assert!(
                !can(mode, false, K::DeleteFile, P::Remove),
                "{mode:?}: no delete before a placement"
            );
            assert!(!can(mode, false, K::InstallFile, P::RestoreBackup));
            assert!(
                can(mode, true, K::DeleteFile, P::Remove),
                "{mode:?}: rollback after a placement"
            );
            assert!(can(mode, true, K::InstallFile, P::RestoreBackup));
        }
        assert!(can(Mode::Remove, false, K::DeleteFile, P::Remove));
        assert!(can(Mode::Remove, false, K::InstallFile, P::RestoreBackup));
        assert!(
            !can(Mode::Remove, true, K::InstallFile, P::PlaceReviewed),
            "a removal never places the reviewed document"
        );
        assert!(!can(Mode::Install, true, K::DeleteFile, P::Unspecified));
    }

    // ── what the operator is told ──────────────────────────────────────────

    #[test]
    fn the_exit_mapping_follows_what_sudo_said_not_what_the_runtime_said() {
        let base = || Failure::new(Outcome::InternalError, "the runtime's own words", "look");
        let with = |last: Option<O>, changed: bool| {
            let record = new_record();
            *record.lock().unwrap() = State { last, changed };
            failure_after(base(), &record)
        };
        assert_eq!(with(None, false).outcome, Outcome::InternalError);
        assert_eq!(
            with(Some(O::Completed), true).outcome,
            Outcome::InternalError,
            "read-back mismatch stays internal"
        );
        let denied = with(Some(O::Denied("3 incorrect attempts".into())), false);
        assert_eq!(denied.outcome, Outcome::Aborted);
        assert!(denied.detail.contains("Permission Required"), "{denied}");
        assert!(denied.detail.contains("nothing was changed"), "{denied}");
        assert_eq!(with(Some(O::Cancelled("x".into())), false).outcome, Outcome::Aborted);
        let ni = with(Some(O::NonInteractive("no tty".into())), false);
        assert_eq!(ni.outcome, Outcome::Aborted);
        assert!(
            ni.detail.contains("Unavailable") && ni.detail.contains("needs an interactive terminal"),
            "{ni}"
        );
        assert_eq!(
            with(Some(O::Unavailable("no sudo".into())), false).outcome,
            Outcome::Unsupported
        );
    }

    #[test]
    fn a_denied_rollback_after_a_completed_placement_says_the_file_was_changed() {
        let record = new_record();
        // The placement completed, then the rollback's authorization was refused.
        *record.lock().unwrap() = State {
            last: Some(O::Denied("sudo did not authenticate you".into())),
            changed: true,
        };
        let failure = failure_after(Failure::new(Outcome::InternalError, "x", "y"), &record);
        assert!(!failure.detail.contains("nothing was changed"), "{failure}");
        assert!(failure.detail.contains("WAS changed"), "{failure}");
        assert!(failure.remediation.contains("aasm integrations repair"), "{failure}");
        assert!(failure.remediation.contains("aasm integrations remove"), "{failure}");
        assert_eq!(failure.outcome, Outcome::InternalError);
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

    // ── root receives exactly the verified bytes ───────────────────────────

    /// A stand-in for `sudo` that records its arguments and, for `tee`, copies
    /// stdin to the named file; for `install`/`rm`/`rmdir` it acts as the
    /// ordinary user. `-v` and `-k` succeed without a terminal. A `fail-install`
    /// marker beside it makes the `install` step fail.
    fn write_stub(dir: &Path, record: &Path) -> PathBuf {
        let path = dir.join("sudo-stub.sh");
        let script = format!(
            r#"#!/bin/sh
for a in "$@"; do printf 'ARG:%s\n' "$a" >> '{rec}'; done
echo CALL_END >> '{rec}'
case "$1" in -v|-k) exit 0 ;; esac
shift
[ "$1" = "--" ] && shift
cmd=$1; shift
last=; penult=
for a in "$@"; do penult=$last; last=$a; done
case "$cmd" in
  /usr/bin/tee) cat > "$last" ;;
  /usr/bin/install)
    if [ "$1" = "-d" ]; then mkdir -p "$last"; exit 0; fi
    [ -e '{fail}' ] && exit 1
    cp "$penult" "$last" ;;
  /bin/rm) rm -f "$last" ;;
  /bin/rmdir) rmdir "$last" ;;
  *) exit 1 ;;
esac
"#,
            rec = record.display(),
            fail = dir.join("fail-install").display()
        );
        std::fs::write(&path, script).expect("write stub");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        path
    }

    #[test]
    fn root_receives_the_verified_bytes_even_if_the_staged_file_is_swapped_afterwards() {
        let s = staged("{\"reviewed\":true}");
        let scratch = tempfile::tempdir().expect("tempdir");
        let record = scratch.path().join("record");
        let stub = write_stub(scratch.path(), &record);
        let target = scratch.path().join("ClaudeCode").join("managed-settings.json");

        // Verified, held in memory ...
        let verified = read_verified_staged(&s.file, s.uid, &s.sha).expect("verifies");
        // ... then swapped on disk before anything reaches root.
        std::fs::write(&s.file, "{\"EVIL\":true}").expect("swap");

        let paths = Paths::new(stub.to_str().unwrap(), target.to_str().unwrap());
        let mut elevator = Elevator::new(Mode::Install, Some(s.sha.clone()), new_record());
        assert_eq!(elevator.place(&paths, &verified), O::Completed);

        assert_eq!(std::fs::read_to_string(&target).expect("placed"), "{\"reviewed\":true}");
        let seen = std::fs::read_to_string(&record).expect("record");
        assert!(
            !seen.contains(s.file.to_str().unwrap()),
            "the staged path reached the root side: {seen}"
        );
        assert!(!seen.contains("EVIL"), "{seen}");
        assert!(
            !scratch.path().join("ClaudeCode").join(TMP_NAME).exists(),
            "the temporary must be removed"
        );
        // authenticate, mkdir, tee, install, rm tmp, sudo -k
        assert_eq!(seen.matches("CALL_END").count(), 6, "{seen}");
        assert!(
            seen.trim_end().ends_with("ARG:-k\nCALL_END"),
            "the ticket is dropped last: {seen}"
        );
    }

    #[test]
    fn a_failed_install_removes_the_temporary_and_a_directory_this_run_created() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let record = scratch.path().join("record");
        let stub = write_stub(scratch.path(), &record);
        std::fs::write(scratch.path().join("fail-install"), "").expect("marker");
        let managed_dir = scratch.path().join("ClaudeCode");
        let target = managed_dir.join("managed-settings.json");
        let paths = Paths::new(stub.to_str().unwrap(), target.to_str().unwrap());

        let outcome = Elevator::new(Mode::Install, None, new_record()).place(&paths, "body");

        assert!(matches!(outcome, O::Cancelled(_)), "{outcome:?}");
        assert!(
            !managed_dir.exists(),
            "the directory this run created, and nothing else, is removed"
        );
        let seen = std::fs::read_to_string(&record).expect("record");
        assert!(seen.contains("ARG:/bin/rmdir"), "{seen}");
        assert!(
            seen.trim_end().ends_with("ARG:-k\nCALL_END"),
            "the ticket is dropped last: {seen}"
        );
    }

    #[test]
    fn a_directory_that_already_existed_is_never_removed() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let record = scratch.path().join("record");
        let stub = write_stub(scratch.path(), &record);
        std::fs::write(scratch.path().join("fail-install"), "").expect("marker");
        let managed_dir = scratch.path().join("ClaudeCode");
        std::fs::create_dir_all(&managed_dir).expect("dir");
        let paths = Paths::new(
            stub.to_str().unwrap(),
            managed_dir.join("managed-settings.json").to_str().unwrap(),
        );

        let outcome = Elevator::new(Mode::Install, None, new_record()).place(&paths, "body");

        assert!(matches!(outcome, O::Cancelled(_)), "{outcome:?}");
        assert!(managed_dir.exists());
        assert!(!managed_dir.join(TMP_NAME).exists());
        let seen = std::fs::read_to_string(&record).expect("record");
        assert!(!seen.contains("rmdir"), "{seen}");
    }

    #[test]
    fn deleting_prompts_for_a_delete_and_drops_the_ticket_straight_after() {
        let scratch = tempfile::tempdir().expect("tempdir");
        let record = scratch.path().join("record");
        let stub = write_stub(scratch.path(), &record);
        let target = scratch.path().join("managed-settings.json");
        std::fs::write(&target, "x").expect("target");
        let paths = Paths::new(stub.to_str().unwrap(), target.to_str().unwrap());

        assert_eq!(
            Elevator::new(Mode::Remove, None, new_record()).delete(&paths),
            O::Completed
        );

        assert!(!target.exists());
        let seen = std::fs::read_to_string(&record).expect("record");
        assert!(seen.contains("to delete one root-owned file"), "{seen}");
        assert!(seen.trim_end().ends_with("ARG:-k\nCALL_END"), "{seen}");
    }
}
