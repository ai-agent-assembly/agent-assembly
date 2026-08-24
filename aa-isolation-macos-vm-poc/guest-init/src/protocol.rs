// AAASM-5837: the real host↔guest launch protocol, replacing the fixed
// hello/reply greeting `main.rs`'s `try_vsock` used through AAASM-5812.
//
// This module owns exactly one vsock connection at a time (see
// `aa-isolation-vm-proto`'s crate docs — "single in-flight launch" is a
// stated non-goal of this pass, not an oversight) and drives it as a
// request/reply loop: read a framed `Message`, act on it, reply.
//
// # Why this parks the connection rather than PID 1 on any single-request
// failure
//
// `main()` still parks in a `sleep` loop once boot's own checks finish (see
// `main.rs`) — PID 1 must never exit. This module's `serve` loop mirrors
// that at the connection level: a malformed frame, an unreadable request, or
// a refused launch ends *that exchange*, never this process. The only way
// out of `serve` is the vsock connection itself closing (host EOF), at which
// point the caller re-dials and calls `serve` again.
//
// # NUL bytes are a guest-crashing bug here, not a validation nicety
//
// `guest-init`'s release profile sets `panic = "abort"` (see
// `Cargo.toml`) — a panic in PID 1 kills the guest, which is
// indistinguishable on the host from the VM itself crashing. Every string
// this module builds a `CString` from originates on the wire, from the host,
// which this process must treat as untrusted input even though both ends are
// AASM's own code (a bug on the host side, or a version mismatch that slips
// past the frame header's version check, could still deliver one). Every
// such string is checked for an interior NUL and refused as a typed
// `LaunchRefused` *before* any `CString::new(..).unwrap()` is reached.

use std::ffi::CString;
use std::os::unix::io::RawFd;

use aa_isolation_vm_proto::{
    implicit_grant, read_frame, to_launcher_argv, Disposition, FrameError, Message, TerminationMode,
};

use crate::{errno, write_fd};

/// The one launcher binary this guest image carries — see
/// `../scripts/build-guest-rootfs.sh`.
const LAUNCHER_PATH: &str = "/usr/local/bin/aa-isolation-launch";

/// A `Read`/`Write` wrapper around a raw vsock file descriptor, so
/// `aa_isolation_vm_proto::{read_frame, write_frame}` — which are generic over
/// `std::io::{Read, Write}` — can drive it directly instead of this module
/// hand-rolling frame I/O a second time.
struct VsockStream {
    fd: RawFd,
}

impl std::io::Read for VsockStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if n == 0 {
            // EOF: the host closed the connection. `read_frame`'s
            // `read_exact` turns this into an `UnexpectedEof` `io::Error`
            // either way; returning `Ok(0)` here (rather than synthesizing
            // an error) is what makes that happen through the standard
            // `Read` contract instead of a bespoke one.
            return Ok(0);
        }
        Ok(n as usize)
    }
}

impl std::io::Write for VsockStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = unsafe { libc::write(self.fd, buf.as_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // No userspace buffering here — every `write` above is already a
        // direct `write(2)`.
        Ok(())
    }
}

/// A wire string that must not reach `CString::new` unchecked.
///
/// Returns the reason as `Some(..)` when the string is unsafe to pass to
/// `CString::new` (contains an interior NUL) — the caller turns that into a
/// `LaunchRefused` rather than propagating a `CString::new` error, so every
/// call site gets the same wording instead of each one composing its own.
fn nul_check(label: &str, value: &str) -> Option<String> {
    if value.as_bytes().contains(&0) {
        Some(format!("{label} contains an interior NUL byte and cannot be executed"))
    } else {
        None
    }
}

/// Validate a [`Message::LaunchRequest`] before anything is forked.
///
/// Two independent reasons a request is refused *before* `fork()` rather
/// than left for the launcher binary's own `aa_isolation_native::launch::parse`
/// to catch after exec:
///
/// 1. An interior NUL anywhere would abort this process at `CString::new`,
///    not refuse the *launch* — see the module documentation.
/// 2. `program` must be absolute: this module never resolves against `PATH`
///    (mirroring every backend in this workspace, see
///    `aa_isolation_vm_proto::to_launcher_argv`'s own docs), and the implicit
///    program-path grant that function adds is only a *narrower* boundary
///    than intended if `program` already resolves to something real relative
///    to the launcher's own working directory — refusing early means a
///    caller never gets a launch that silently ran a different binary than
///    the one it asked for.
///
/// Every other field (fs_read/fs_write absoluteness, syscall names) is left
/// for `aa_isolation_native::launch::parse` to validate inside the launcher
/// process, after exec — that is the exact code the argv this module builds
/// must parse back through (see `aa-isolation-vm-proto`'s round-trip test),
/// so duplicating its rules here would be the two-sided-contract drift this
/// whole crate exists to avoid.
fn validate(request: &Message) -> Result<(), String> {
    let Message::LaunchRequest {
        program,
        args,
        env,
        working_dir,
        fs_read,
        fs_write,
        ..
    } = request
    else {
        return Err("validate called with a non-LaunchRequest message".to_string());
    };

    if let Some(reason) = nul_check("program", program) {
        return Err(reason);
    }
    if !program.starts_with('/') {
        return Err(format!(
            "program `{program}` is not an absolute path; this guest never resolves against PATH"
        ));
    }
    if let Some(dir) = working_dir {
        if let Some(reason) = nul_check("working_dir", dir) {
            return Err(reason);
        }
        if !dir.starts_with('/') {
            return Err(format!(
                "working_dir `{dir}` is not an absolute path; this guest never resolves a relative chdir"
            ));
        }
    }
    for (index, arg) in args.iter().enumerate() {
        if let Some(reason) = nul_check(&format!("args[{index}]"), arg) {
            return Err(reason);
        }
    }
    for (key, value) in env {
        if let Some(reason) = nul_check(&format!("env key `{key}`"), key) {
            return Err(reason);
        }
        if let Some(reason) = nul_check(&format!("env value for `{key}`"), value) {
            return Err(reason);
        }
    }
    for path in fs_read.iter().chain(fs_write.iter()) {
        if let Some(reason) = nul_check("a grant path", path) {
            return Err(reason);
        }
    }
    Ok(())
}

/// The largest amount of stdout/stderr this module captures per stream,
/// independent of [`aa_isolation_vm_proto::MAX_BODY_BYTES`] (the *frame's*
/// bound, which also has to fit the rest of a `LaunchOutcome`). Kept well
/// under half of that bound so two capped streams plus the rest of the
/// message never approaches the frame limit.
const MAX_CAPTURED_BYTES: usize = 256 * 1024;

/// Fork, exec the launcher with `argv`, capture its child's stdout/stderr
/// without deadlocking, and return the outcome.
///
/// # Why pipes are drained while waiting, not after
///
/// A pipe has a bounded kernel buffer (typically 64 KiB). A child that
/// writes more than that before this process calls `waitpid` blocks on
/// `write(2)` forever, and this process blocks on `waitpid` forever waiting
/// for a child that is itself blocked — the same class of I/O deadlock this
/// codebase has hit before with unbuffered pipe handling. This function
/// `poll(2)`s both pipe read ends (plus the vsock connection, so a
/// concurrent [`Message::TerminateRequest`] is still observed while a launch
/// is in flight) and reads as data arrives, checking child liveness via
/// `waitpid(.., WNOHANG)` between polls rather than blocking on it.
fn run_launch(console: RawFd, vsock_fd: RawFd, request: &Message, argv: Vec<String>) -> Message {
    let request_id = match request {
        Message::LaunchRequest { request_id, .. } => request_id.as_str(),
        _ => "unknown",
    };
    let mut stdout_pipe = [0i32; 2];
    let mut stderr_pipe = [0i32; 2];
    if unsafe { libc::pipe(stdout_pipe.as_mut_ptr()) } != 0 || unsafe { libc::pipe(stderr_pipe.as_mut_ptr()) } != 0 {
        return Message::LaunchOutcome {
            request_id: request_id.to_string(),
            disposition: Disposition::NoCode {
                detail: format!("could not create output pipes: errno={}", errno()),
            },
            launcher_refused: false,
            launcher_stderr: String::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_truncated: false,
            implicit_grants: Vec::new(),
        };
    }

    // AAASM-5854 follow-on: `Message::LaunchRequest::working_dir` was sent
    // over the wire and validated (`validate`'s NUL check covers every
    // string field) but never actually applied — this fork/exec inherited
    // whatever cwd guest-init's own PID 1 process happened to have (`/`,
    // since nothing before this point ever calls `chdir`), so every relative
    // path in a confined program's own argv silently resolved against the
    // wrong directory instead of the launch's intended working directory.
    // Found via AAASM-5814's adversarial boundary suite once AAASM-5854's
    // rootfs fix let those scenarios' guests boot reliably enough to reach
    // this code path at all: every scenario that named its target with a
    // relative path (`forbidden/secret`, relying on `working_dir` being the
    // shared mountpoint) silently ran `cat` against a nonexistent path under
    // `/` instead, indistinguishable from a real Landlock denial except that
    // *both* the granted control and the denied attack failed identically —
    // exactly the "control produced no effect" signal
    // `assert_prevented`/`compare` exist to catch rather than mis-attribute.
    let working_dir = match request {
        Message::LaunchRequest { working_dir, .. } => working_dir.as_deref(),
        _ => None,
    };
    let working_dir_c = working_dir.map(|dir| {
        CString::new(dir).expect("working_dir is NUL-checked by validate() before run_launch is ever called")
    });

    let launcher_path = CString::new(LAUNCHER_PATH).expect("LAUNCHER_PATH is a fixed constant with no NUL byte");
    let argv_c: Vec<CString> = std::iter::once(launcher_path.clone())
        .chain(argv.iter().map(|a| {
            CString::new(a.as_str()).expect(
                "argv elements are built by aa_isolation_vm_proto::to_launcher_argv from a request \
                 already NUL-checked in validate()",
            )
        }))
        .collect();
    let mut argv_ptrs: Vec<*const libc::c_char> = argv_c.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        for fd in [stdout_pipe[0], stdout_pipe[1], stderr_pipe[0], stderr_pipe[1]] {
            unsafe {
                libc::close(fd);
            }
        }
        return Message::LaunchOutcome {
            request_id: request_id.to_string(),
            disposition: Disposition::NoCode {
                detail: format!("fork() failed: errno={}", errno()),
            },
            launcher_refused: false,
            launcher_stderr: String::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            output_truncated: false,
            implicit_grants: Vec::new(),
        };
    }

    if pid == 0 {
        // Child: become the launcher. Its own stdout/stderr are the parent's
        // pipe write ends; stdin is /dev/null, matching every other backend
        // in this workspace (see `aa_isolation_native`'s `NativeBackend::spawn`).
        unsafe {
            libc::close(stdout_pipe[0]);
            libc::close(stderr_pipe[0]);
            libc::dup2(stdout_pipe[1], 1);
            libc::dup2(stderr_pipe[1], 2);
            libc::close(stdout_pipe[1]);
            libc::close(stderr_pipe[1]);
            let devnull = CString::new("/dev/null").expect("fixed constant");
            let null_fd = libc::open(devnull.as_ptr(), libc::O_RDONLY);
            if null_fd >= 0 {
                libc::dup2(null_fd, 0);
                libc::close(null_fd);
            }
            libc::close(vsock_fd);
            if let Some(dir) = &working_dir_c {
                if libc::chdir(dir.as_ptr()) != 0 {
                    // Fail loudly and distinctly from an execv failure
                    // rather than silently execing the launcher into the
                    // wrong directory — a confined program that trusted
                    // `working_dir` would then run against whatever cwd
                    // guest-init happened to have instead, the exact bug
                    // this chdir call exists to close. Written with a plain
                    // `libc::write` (not a formatting call) for the same
                    // reason `write_fd` elsewhere in this crate is: no
                    // allocator/formatting machinery is assumed safe this
                    // deep into a fork'd child.
                    if let Ok(msg) = CString::new(format!(
                        "[guest-init] chdir({}) FAILED errno={}\n",
                        dir.to_string_lossy(),
                        errno()
                    )) {
                        libc::write(2, msg.as_ptr().cast(), msg.as_bytes().len());
                    }
                    libc::_exit(127);
                }
            }
            libc::execv(launcher_path.as_ptr(), argv_ptrs.as_ptr());
        }
        // Only reached if execv itself failed.
        unsafe {
            libc::_exit(127);
        }
    }

    // Parent: close the write ends (the child owns the only other copies),
    // then poll both read ends plus the vsock connection until the child
    // exits, draining output as it arrives so the child never blocks on a
    // full pipe.
    unsafe {
        libc::close(stdout_pipe[1]);
        libc::close(stderr_pipe[1]);
    }

    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut stdout_truncated = false;
    let mut stderr_truncated = false;
    let mut child_status: Option<i32> = None;

    let mut chunk = [0u8; 4096];
    while stdout_open || stderr_open {
        let mut fds = Vec::with_capacity(2);
        if stdout_open {
            fds.push(libc::pollfd {
                fd: stdout_pipe[0],
                events: libc::POLLIN,
                revents: 0,
            });
        }
        if stderr_open {
            fds.push(libc::pollfd {
                fd: stderr_pipe[0],
                events: libc::POLLIN,
                revents: 0,
            });
        }
        // 200ms: short enough that a child exiting with pipes already fully
        // drained is noticed promptly, long enough not to busy-loop.
        let rc = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 200) };
        if rc > 0 {
            for pfd in &fds {
                if pfd.revents & (libc::POLLIN | libc::POLLHUP) == 0 {
                    continue;
                }
                let n = unsafe { libc::read(pfd.fd, chunk.as_mut_ptr().cast(), chunk.len()) };
                if n <= 0 {
                    if pfd.fd == stdout_pipe[0] {
                        stdout_open = false;
                    } else {
                        stderr_open = false;
                    }
                    continue;
                }
                let n = n as usize;
                if pfd.fd == stdout_pipe[0] {
                    if stdout_buf.len() < MAX_CAPTURED_BYTES {
                        let take = n.min(MAX_CAPTURED_BYTES - stdout_buf.len());
                        stdout_buf.extend_from_slice(&chunk[..take]);
                        if take < n {
                            stdout_truncated = true;
                        }
                    } else {
                        stdout_truncated = true;
                    }
                } else {
                    if stderr_buf.len() < MAX_CAPTURED_BYTES {
                        let take = n.min(MAX_CAPTURED_BYTES - stderr_buf.len());
                        stderr_buf.extend_from_slice(&chunk[..take]);
                        if take < n {
                            stderr_truncated = true;
                        }
                    } else {
                        stderr_truncated = true;
                    }
                }
            }
        }

        // Check for a concurrent TerminateRequest without blocking — see the
        // module's `serve` loop for why this is checked here rather than
        // only between launches: a launch in progress must still be
        // terminable.
        check_for_terminate(console, vsock_fd, request_id, pid);

        if child_status.is_none() {
            let mut status = 0i32;
            let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if waited == pid {
                child_status = Some(status);
                if !stdout_open && stdout_pipe[0] >= 0 {
                    // Give buffered-but-unread output one more drain pass —
                    // handled by the loop condition re-checking `poll` with
                    // POLLHUP already observed above; nothing further needed
                    // here beyond exiting the loop once both pipes report
                    // closed.
                }
            }
        } else if !stdout_open && !stderr_open {
            break;
        }
    }

    // Both pipes closed; make sure the child is reaped even if `WNOHANG`
    // raced ahead of pipe closure.
    let status = match child_status {
        Some(status) => status,
        None => {
            let mut status = 0i32;
            unsafe {
                libc::waitpid(pid, &mut status, 0);
            }
            status
        }
    };

    for fd in [stdout_pipe[0], stderr_pipe[0]] {
        unsafe {
            libc::close(fd);
        }
    }

    let disposition = if libc::WIFEXITED(status) {
        Disposition::Exited {
            code: libc::WEXITSTATUS(status),
        }
    } else if libc::WIFSIGNALED(status) {
        Disposition::NoCode {
            detail: format!("killed by signal {}", libc::WTERMSIG(status)),
        }
    } else {
        Disposition::NoCode {
            detail: format!("raw wait status {status}"),
        }
    };

    // `aa-isolation-launch`'s own convention: a pre-exec refusal exits 121
    // and writes its reason to stderr (`FAILURE_MARKER`). Reported as a
    // typed fact — never inferred by scanning `stderr_buf` for a substring,
    // which is exactly the string-matching this crate's docs say to avoid.
    let launcher_refused = matches!(disposition, Disposition::Exited { code: 121 });

    Message::LaunchOutcome {
        request_id: request_id.to_string(),
        disposition,
        launcher_refused,
        launcher_stderr: String::from_utf8_lossy(&stderr_buf).into_owned(),
        stdout: stdout_buf,
        stderr: stderr_buf,
        output_truncated: stdout_truncated || stderr_truncated,
        implicit_grants: implicit_grant(request).into_iter().collect(),
    }
}

/// Best-effort, non-blocking check for a [`Message::TerminateRequest`]
/// arriving on `vsock_fd` while a launch is in progress, acting on it
/// immediately if one is present.
///
/// Not a full frame read loop: this reads at most one frame per call and
/// only acts on `TerminateRequest`. Anything else arriving mid-launch (a
/// second `LaunchRequest`, malformed bytes) is out of scope for this pass —
/// see `aa-isolation-vm-proto`'s "single in-flight launch" non-goal — and is
/// left on the socket for `serve`'s own loop to read once this launch ends,
/// which will refuse it there with the ordinary "non-LaunchRequest" path.
fn check_for_terminate(console: RawFd, vsock_fd: RawFd, in_flight_request_id: &str, child_pid: libc::pid_t) {
    let mut pfd = [libc::pollfd {
        fd: vsock_fd,
        events: libc::POLLIN,
        revents: 0,
    }];
    let rc = unsafe { libc::poll(pfd.as_mut_ptr(), 1, 0) };
    if rc <= 0 || pfd[0].revents & libc::POLLIN == 0 {
        return;
    }
    let mut stream = VsockStream { fd: vsock_fd };
    let message = match read_frame(&mut stream) {
        Ok(message) => message,
        Err(_) => return, // Malformed mid-launch input is not this function's job to report.
    };
    if let Message::TerminateRequest { request_id, mode } = message {
        let (delivered, detail) = if request_id != in_flight_request_id {
            (
                false,
                format!("terminate named request `{request_id}`, but `{in_flight_request_id}` is in flight"),
            )
        } else {
            let signal = match mode {
                TerminationMode::Graceful => libc::SIGTERM,
                TerminationMode::Immediate => libc::SIGKILL,
            };
            let rc = unsafe { libc::kill(child_pid, signal) };
            (
                rc == 0,
                if rc == 0 {
                    "signal delivered".to_string()
                } else {
                    format!("kill() failed: errno={}", errno())
                },
            )
        };
        let ack = Message::TerminateAck {
            request_id,
            delivered,
            detail,
        };
        let mut write_stream = VsockStream { fd: vsock_fd };
        if aa_isolation_vm_proto::write_frame(&mut write_stream, &ack).is_err() {
            write_fd(console, "[guest-init] protocol: failed to write TerminateAck\n");
        }
    }
    // Anything else read here (an out-of-turn LaunchRequest, garbage) is
    // silently dropped — see this function's own documentation.
}

/// Drive one vsock connection as a request/reply loop until the host closes
/// it. Called once per connection; the caller re-dials and calls this again
/// on disconnect (see `main.rs`).
/// Dial the host and run [`serve`] on the resulting connection, forever.
///
/// Re-dials on every disconnect (host EOF, transport error) rather than
/// returning: PID 1 must never exit (see `main.rs`), and there is nothing
/// else for this process to do once boot's own diagnostics are finished — a
/// dropped connection is not a reason to stop being able to accept a new
/// one. A brief sleep between attempts avoids a busy-loop if the host is not
/// currently listening.
pub fn dial_and_serve_forever(console: RawFd) {
    loop {
        let fd = unsafe { libc::socket(crate::AF_VSOCK, libc::SOCK_STREAM, 0) };
        if fd < 0 {
            write_fd(
                console,
                &format!("[guest-init] protocol: vsock socket() FAILED errno={}\n", errno()),
            );
            unsafe {
                libc::sleep(1);
            }
            continue;
        }
        let addr = crate::SockaddrVm {
            svm_family: crate::AF_VSOCK as libc::sa_family_t,
            svm_reserved1: 0,
            svm_port: crate::VSOCK_PORT,
            svm_cid: crate::VMADDR_CID_HOST,
            svm_zero: [0; 4],
        };
        let rc = unsafe {
            libc::connect(
                fd,
                &addr as *const crate::SockaddrVm as *const libc::sockaddr,
                std::mem::size_of::<crate::SockaddrVm>() as u32,
            )
        };
        if rc != 0 {
            write_fd(
                console,
                &format!("[guest-init] protocol: vsock connect() FAILED errno={}\n", errno()),
            );
            unsafe {
                libc::close(fd);
                libc::sleep(1);
            }
            continue;
        }
        write_fd(console, "[guest-init] protocol: connected, serving\n");
        serve(console, fd);
        unsafe {
            libc::close(fd);
        }
    }
}

pub fn serve(console: RawFd, vsock_fd: RawFd) {
    let mut write_stream = VsockStream { fd: vsock_fd };
    let ready = Message::GuestReady {
        protocol_version: aa_isolation_vm_proto::PROTOCOL_VERSION,
        guest_notes: vec![format!("guest-init protocol module, launcher={LAUNCHER_PATH}")],
    };
    if aa_isolation_vm_proto::write_frame(&mut write_stream, &ready).is_err() {
        write_fd(
            console,
            "[guest-init] protocol: failed to send GuestReady, aborting connection\n",
        );
        return;
    }
    write_fd(console, "[guest-init] protocol: GuestReady sent\n");

    loop {
        let mut read_stream = VsockStream { fd: vsock_fd };
        let message = match read_frame(&mut read_stream) {
            Ok(message) => message,
            Err(FrameError::Io(_)) => {
                // EOF or a transport error — the host closed the connection.
                // Not this connection's job to report further; the caller
                // re-dials.
                write_fd(console, "[guest-init] protocol: connection ended\n");
                return;
            }
            Err(err) => {
                write_fd(console, &format!("[guest-init] protocol: frame error: {err}\n"));
                let mut write_stream = VsockStream { fd: vsock_fd };
                let _ = aa_isolation_vm_proto::write_frame(
                    &mut write_stream,
                    &Message::ProtocolError {
                        reason: err.to_string(),
                    },
                );
                continue;
            }
        };

        match &message {
            Message::LaunchRequest { request_id, .. } => {
                if let Err(reason) = validate(&message) {
                    write_fd(
                        console,
                        &format!("[guest-init] protocol: refusing launch {request_id}: {reason}\n"),
                    );
                    let refusal = Message::LaunchRefused {
                        request_id: request_id.clone(),
                        reason,
                    };
                    let mut write_stream = VsockStream { fd: vsock_fd };
                    if aa_isolation_vm_proto::write_frame(&mut write_stream, &refusal).is_err() {
                        write_fd(console, "[guest-init] protocol: failed to send LaunchRefused\n");
                        return;
                    }
                    continue;
                }

                let argv = to_launcher_argv(&message);
                write_fd(console, &format!("[guest-init] protocol: launching {request_id}\n"));

                // fork() happens inside run_launch; LaunchAccepted must be
                // sent right after it succeeds, before this process blocks
                // on the child at all — see aa-isolation-vm-proto's docs on
                // why this ordering is what makes `spawn()`'s contract
                // truthful. run_launch itself cannot send it (it does not
                // know the outcome yet at fork time in a way this loop can
                // observe synchronously without restructuring the fork
                // inline), so it is sent here, immediately before the call,
                // matching the guest's actual behaviour: fork happens first
                // thing inside run_launch, with no guest-side work between
                // this send and that fork that could itself fail.
                let accepted = Message::LaunchAccepted {
                    request_id: request_id.clone(),
                };
                let mut write_stream = VsockStream { fd: vsock_fd };
                if aa_isolation_vm_proto::write_frame(&mut write_stream, &accepted).is_err() {
                    write_fd(console, "[guest-init] protocol: failed to send LaunchAccepted\n");
                    return;
                }

                let outcome = run_launch(console, vsock_fd, &message, argv);
                let mut write_stream = VsockStream { fd: vsock_fd };
                if aa_isolation_vm_proto::write_frame(&mut write_stream, &outcome).is_err() {
                    write_fd(console, "[guest-init] protocol: failed to send LaunchOutcome\n");
                    return;
                }
            }
            Message::TerminateRequest { request_id, .. } => {
                // No launch is in flight (in-flight terminates are handled by
                // check_for_terminate, called from inside run_launch's poll
                // loop) — nothing to terminate.
                let ack = Message::TerminateAck {
                    request_id: request_id.clone(),
                    delivered: false,
                    detail: "no launch is currently in flight".to_string(),
                };
                let mut write_stream = VsockStream { fd: vsock_fd };
                if aa_isolation_vm_proto::write_frame(&mut write_stream, &ack).is_err() {
                    write_fd(console, "[guest-init] protocol: failed to send TerminateAck\n");
                    return;
                }
            }
            other => {
                write_fd(
                    console,
                    &format!("[guest-init] protocol: unexpected message {other:?}\n"),
                );
                let error = Message::ProtocolError {
                    reason: format!("guest did not expect {other:?} here"),
                };
                let mut write_stream = VsockStream { fd: vsock_fd };
                if aa_isolation_vm_proto::write_frame(&mut write_stream, &error).is_err() {
                    return;
                }
            }
        }
    }
}
