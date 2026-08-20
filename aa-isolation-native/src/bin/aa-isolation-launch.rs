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
//! 2. Compute the kernel rules through `aa_isolation_native::rules::plan` — a
//!    pure function, unit-tested on every platform.
//! 3. Install them on itself.
//! 4. `execve` the program.
//!
//! There is no branch that skips step 3, no error arm that falls through to step
//! 4, and no flag that turns the boundary off. Any failure writes a
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
//!
//! It also installs no system-call filter. That is AAASM-5803, and the
//! separation is why step 3 above is a single call into a module that a
//! follow-on ticket extends rather than a block of setup inlined here.

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

    confine_and_exec(&plan, &parsed.program, &parsed.args)
}

/// Install the boundary and become the program. Never returns on success.
#[cfg(target_os = "linux")]
fn confine_and_exec(
    plan: &aa_isolation_native::rules::RulePlan,
    program: &str,
    args: &[String],
) -> std::process::ExitCode {
    use std::os::unix::process::CommandExt;

    if let Err(reason) = aa_isolation_native::rules::install(plan) {
        return refuse(&reason);
    }

    // `exec` replaces this process. Everything above has already happened, so
    // the program cannot run without the boundary: there is no path from here
    // that reaches `Command::spawn`, and the only way this line returns is if
    // the exec itself failed.
    let error = std::process::Command::new(program).args(args).exec();
    refuse(&format!(
        "the boundary was installed and `{program}` could not be executed: {error}"
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
