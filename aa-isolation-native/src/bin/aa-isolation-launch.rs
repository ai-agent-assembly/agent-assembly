//! The launcher: install the boundary on this process, then become the program.
//!
//! # What this binary is for
//!
//! ADR 0035 decision 5, restated by the AAASM-5801 amendment's "Launcher shape"
//! section: *"Where process-level sandbox initialization requires
//! post-fork/pre-exec work, implementation should prefer a deliberately small
//! and auditable launcher/helper boundary. Complex Landlock/seccomp/namespace
//! setup must not be casually accumulated in an async runtime's `pre_exec`
//! callback, where post-fork restrictions make ordinary allocation, locks and
//! library behavior unsafe or difficult to audit."*
//!
//! `aasm run`'s supervisor is a Tokio runtime. This binary is how the boundary
//! setup stays out of its `pre_exec` closure. It is not an alternative to that
//! rule — it is the shape the rule asks for.
//!
//! # Everything this binary does, in order
//!
//! 1. Parse its own argument vector through `aa_isolation_native::launch` —
//!    the same code the supervisor built it with.
//! 2. Compute the kernel rules through `aa_isolation_native::rules::plan` and
//!    the cBPF program through `aa_isolation_native::seccomp::program` — both
//!    pure functions, unit-tested on every platform.
//! 3. Install the Landlock rules on itself.
//! 4. Install the syscall filter on itself, when one was requested
//!    (`aa_isolation_native::launch::SyscallFilter::Allow` —
//!    see `confine_and_exec`'s own documentation for why ordering here matters).
//! 5. `execve` the program.
//!
//! There is no branch that skips step 3 or 4, no error arm that falls through to
//! step 5, and no flag that turns the boundary off. Any failure writes a
//! `FAILURE_MARKER` line and exits `EXIT_LAUNCH_REFUSED` **without
//! executing anything**, which is the property
//! `tests/linux_confinement_native.rs` measures by asserting the program's
//! *effect* did not happen rather than by reading the exit code.
//!
//! # What this binary deliberately does not do
//!
//! No async runtime, no logging framework, no configuration file, no network, no
//! environment inspection, and no policy. The environment and working directory
//! the confined program receives are set by the supervisor on this process and
//! inherited across `execve`, so credential values never travel on a command
//! line that `/proc/<pid>/cmdline` publishes to every other process on the host.

fn main() -> std::process::ExitCode {
    let argv: Vec<String> = match std::env::args_os().skip(1).map(|a| a.into_string()).collect() {
        Ok(argv) => argv,
        // Refusing beats lossy conversion for the same reason
        // `aa_isolation::ExecutionSpec` gives: this launch is described in an
        // evidence record, and an argv that differs from the one that ran is
        // worse than a launch that did not happen.
        Err(_) => return refuse("an argument was not valid UTF-8 and this launcher will not convert it lossily"),
    };

    let parsed = match aa_isolation_native::launch::parse(argv) {
        Ok(parsed) => parsed,
        Err(error) => return refuse(&error.to_string()),
    };
    let plan = aa_isolation_native::rules::plan(&parsed.grants);
    let filter = match aa_isolation_native::seccomp::program(&parsed.syscalls) {
        Ok(filter) => filter,
        Err(reason) => return refuse(&reason),
    };

    confine_and_exec(&plan, &parsed.syscalls, &filter, &parsed.program, &parsed.args)
}

/// Install the boundary and become the program. Never returns on success.
///
/// # Ordering is load-bearing
///
/// 1. [`aa_isolation_native::rules::install`] first — it opens paths and calls
///    `landlock_*`, which are outside the syscall filter's vocabulary and must
///    run before that filter is installed, or installing the filter first
///    would kill the Landlock setup itself.
/// 2. The `CString` program name and the argv pointer array are built next —
///    the only allocation in this function — **before** the syscall filter,
///    because allocating after it would depend on `mmap`/`brk` being in the
///    filter's permitted set on every path, not just the loader's.
/// 3. `SIGPIPE` is reset to `SIG_DFL`, preserving what `Command::exec` used to
///    do before this function replaced it.
/// 4. The syscall filter is installed, only when one was requested
///    ([`aa_isolation_native::launch::SyscallFilter::Allow`]) — see that
///    type's own documentation for why `NotRequested` installs nothing at all.
/// 5. `execve` immediately, with **no allocation** between steps 4 and 5.
///
/// After step 4, [`refuse`]'s `eprintln!` depends on `write`, which the filter
/// denies unless policy named it. A failed `execve` past that point surfaces to
/// the supervisor as `SIGSYS` with no [`aa_isolation_native::launch::FAILURE_MARKER`]
/// line — fail-closed, which is correct, but it means no test in this crate may
/// assert on that marker for a failure past this point; only on the effect
/// (`tests/linux_confinement_native.rs`'s discipline throughout).
#[cfg(target_os = "linux")]
fn confine_and_exec(
    plan: &aa_isolation_native::rules::RulePlan,
    syscalls: &aa_isolation_native::launch::SyscallFilter,
    filter: &aa_isolation_native::seccomp::FilterProgram,
    program: &str,
    args: &[String],
) -> std::process::ExitCode {
    use std::ffi::CString;

    if let Err(reason) = aa_isolation_native::rules::install(plan) {
        return refuse(&reason);
    }

    let Ok(program_c) = CString::new(program) else {
        return refuse("the program name contains a NUL byte and cannot be passed to execve");
    };
    let mut argv_c: Vec<CString> = Vec::with_capacity(args.len() + 2);
    argv_c.push(program_c.clone());
    for arg in args {
        match CString::new(arg.as_str()) {
            Ok(c) => argv_c.push(c),
            Err(_) => return refuse("an argument contains a NUL byte and cannot be passed to execve"),
        }
    }
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    // SAFETY: resets the disposition of a signal on this process, which
    // affects only this process and takes no pointer that must remain valid
    // afterward. Preserves what `Command::exec` (the launcher's earlier shape)
    // installed by default.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    if let aa_isolation_native::launch::SyscallFilter::Allow(_) = syscalls {
        if let Err(reason) = aa_isolation_native::seccomp::install(filter) {
            return refuse(&reason);
        }
    }

    // SAFETY: `program_c` and every element of `argv_c` are NUL-terminated and
    // alive until this call returns (or this process becomes `program`, in
    // which case they are never freed because nothing after this line runs in
    // this process's old image); `argv_ptrs` is NUL-terminated per `execvp`'s
    // contract. `execvp` replaces this process image and, on success, never
    // returns to the code below. `execvp` rather than `execve` preserves the
    // PATH-search semantics `Command::exec` had before this function replaced
    // it, and the environment is inherited unchanged (this process's own,
    // already set by the supervisor before this binary was started) exactly as
    // `Command::exec` would have passed it through with no explicit `env`.
    unsafe {
        libc::execvp(program_c.as_ptr(), argv_ptrs.as_ptr());
    }
    // Only reached if `execvp` itself failed.
    refuse(&format!(
        "the boundary was installed and `{program}` could not be executed: {}",
        std::io::Error::last_os_error()
    ))
}

/// The non-Linux arm: refuse, rather than execute unconfined.
///
/// This binary is built on every platform because the crate is, and a build that
/// silently executed the program where it cannot confine it would be the exact
/// silent-unconfined fallback ADR 0035 forbids. It is an error even though the
/// backend reports itself unavailable off Linux first — the two are different
/// processes, and this one cannot assume the other ran.
#[cfg(not(target_os = "linux"))]
fn confine_and_exec(
    _plan: &aa_isolation_native::rules::RulePlan,
    _syscalls: &aa_isolation_native::launch::SyscallFilter,
    _filter: &aa_isolation_native::seccomp::FilterProgram,
    program: &str,
    _args: &[String],
) -> std::process::ExitCode {
    refuse(&format!(
        "this launcher confines Linux processes and cannot establish a boundary on {}; `{program}` was \
         NOT executed",
        std::env::consts::OS
    ))
}

/// Report a refusal in the one form a supervisor can recognise, and exit.
fn refuse(reason: &str) -> std::process::ExitCode {
    eprintln!("{}{reason}", aa_isolation_native::launch::FAILURE_MARKER);
    // `as u8` is exact: `EXIT_LAUNCH_REFUSED` is 121, and a process exit status
    // is a byte on every platform this runs on.
    std::process::ExitCode::from(aa_isolation_native::launch::EXIT_LAUNCH_REFUSED as u8)
}
